#include "AssemblyPool.hpp"

#include <Windows.h>

AssemblyPool gAssemblyPool;

void AssemblySegment::Free() noexcept {
  gAssemblyPool.FreeSegment(*this);
}

AssemblySegment AssemblyPool::AllocateNear(size_t bytesCount, uintptr_t nearToAddress) {
  if (bytesCount > MEMORY_PAGE_SIZE)
    return AssemblySegment();

  for (auto& page : m_pages) {
    if (page.biggestFreeRangeSize < bytesCount)
      continue;

    if (nearToAddress != 0) {
      auto distance =
        std::abs(static_cast<ptrdiff_t>(page.address) - static_cast<ptrdiff_t>(nearToAddress));

      if (distance > NEAR_ALLOCATION_RANGE)
        continue;
    }

    return AllocateSegment(bytesCount, page);
  }

  auto page = AllocatePage(nearToAddress);
  if (page == nullptr)
    return AssemblySegment();

  return AllocateSegment(bytesCount, *page);
}

AssemblySegment AssemblyPool::AllocateSegment(size_t bytesCount, MemoryPage& page) noexcept {
  for (auto it = page.freeRanges.begin(); it != page.freeRanges.end(); ++it) {
    auto offset = it->first;
    auto size = it->second;

    if (size < bytesCount)
      continue;

    it->first += bytesCount;
    it->second -= bytesCount;
    RecountPageBiggestFreeRange(page);

    return AssemblySegment(page.address + offset, bytesCount);
  }

  // must be unreachable
  return AssemblySegment();
}

void AssemblyPool::FreeSegment(AssemblySegment const& segment) noexcept {
  if (segment.address == 0)
    return;

  auto page = GetSegmentPage(segment);

  if (page == nullptr)
    return;

  uint16_t segmentOffset = segment.address - page->address;

  if (page->freeRanges.empty()) {
    page->freeRanges.emplace_back(segmentOffset, segment.bytesCount);
  }
  else {
    bool emplaced = false;
    for (auto it = page->freeRanges.begin(); it != page->freeRanges.end(); ++it) {
      if (it->first > segmentOffset) {
        page->freeRanges.emplace(it, segmentOffset, segment.bytesCount);
        emplaced = true;
        break;
      }
    }

    if (!emplaced)
      page->freeRanges.emplace_back(segmentOffset, segment.bytesCount);
  }

  MergeFreeRanges(*page);
}

AssemblyPool::MemoryPage* AssemblyPool::GetSegmentPage(AssemblySegment const& segment) noexcept {
  for (auto& page : m_pages) {
    auto pageBegin = page.address;
    auto pageEnd = page.address + MEMORY_PAGE_SIZE;

    if (pageBegin <= segment.address && segment.address < pageEnd)
      return &page;
  }

  return nullptr;
}

void AssemblyPool::RecountPageBiggestFreeRange(MemoryPage& page) noexcept {
  size_t biggestSize = 0;

  for (auto const& range : page.freeRanges) {
    if (range.second > biggestSize)
      biggestSize = range.second;
  }

  page.biggestFreeRangeSize = biggestSize;
}

void AssemblyPool::MergeFreeRanges(MemoryPage& page) noexcept {
  // Note that we keep ranges sorted so it's really easy to merge them

  for (auto i = 1; i < page.freeRanges.size(); ++i) {
    auto& prev = page.freeRanges[i-1];
    auto& curr = page.freeRanges[i];

    if (prev.first + prev.second == curr.first) {
      // merge
      prev.second += curr.second;

      page.freeRanges.erase(page.freeRanges.begin() + i);
      --i;
    }
  }
}

static uintptr_t findPrevFreePage(uintptr_t from, uintptr_t to, uintptr_t granularity) noexcept {
  to -= to % granularity; // alignment
  to -= granularity;

  while (from < to) {
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery(reinterpret_cast<void*>(to), &mbi, sizeof(mbi)) == 0)
      break;

    if (mbi.State == MEM_FREE)
      return to;

    if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) < granularity)
      break;

    to = reinterpret_cast<uintptr_t>(mbi.AllocationBase) - granularity;
  }

  return 0;
}

static uintptr_t findNextFreePage(uintptr_t from, uintptr_t to, uintptr_t granularity) noexcept {
  from -= from % granularity; // alignment
  from += granularity;

  while (from <= to) {
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery(reinterpret_cast<void*>(from), &mbi, sizeof(mbi)) == 0)
      break;

    if (mbi.State == MEM_FREE)
      return from;

    if (reinterpret_cast<uintptr_t>(mbi.AllocationBase) < granularity)
      break;

    from = reinterpret_cast<uintptr_t>(mbi.AllocationBase) + mbi.RegionSize;

    from += granularity - 1;
    from -= from % granularity;
  }

  return 0;
}

AssemblyPool::MemoryPage* AssemblyPool::AllocatePage(uintptr_t nearToAddress) noexcept {
  if (nearToAddress == 0) {
    void* result =
      VirtualAlloc(nullptr, MEMORY_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (result == nullptr)
      return nullptr;

    auto page = m_pages.emplace(m_pages.end());
    page->address = reinterpret_cast<uintptr_t>(result);
    page->freeRanges.emplace_back(0, MEMORY_PAGE_SIZE);
    page->biggestFreeRangeSize = MEMORY_PAGE_SIZE;

    return &*page;
  }

  SYSTEM_INFO si;
  GetSystemInfo(&si);

  uintptr_t minAddress = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
  uintptr_t maxAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

  if (NEAR_ALLOCATION_RANGE <= nearToAddress && minAddress < nearToAddress - NEAR_ALLOCATION_RANGE)
    minAddress = nearToAddress - NEAR_ALLOCATION_RANGE;

  if (nearToAddress + NEAR_ALLOCATION_RANGE <= maxAddress)
    maxAddress = nearToAddress + NEAR_ALLOCATION_RANGE;

  // Make room for one page
  maxAddress -= MEMORY_PAGE_SIZE - 1;

  auto tryAllocateByLowerBound = [&] {
    void* result = nullptr;

    uintptr_t alloc = nearToAddress;
    while (minAddress <= alloc) {
      alloc = findPrevFreePage(minAddress, alloc, si.dwAllocationGranularity);
      if (alloc == 0)
        break; // no more pages

      result = VirtualAlloc(
        reinterpret_cast<void*>(alloc),
        MEMORY_PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      );

      if (result != nullptr)
        break; // successfully allocated
    }

    return result;
  };

  auto tryAllocateByUpperBound = [&] {
    void* result = nullptr;

    uintptr_t alloc = nearToAddress;
    while (alloc <= maxAddress) {
      alloc = findNextFreePage(alloc, maxAddress, si.dwAllocationGranularity);
      if (alloc == 0)
        break; // no more pages

      result = VirtualAlloc(
        reinterpret_cast<void*>(alloc),
        MEMORY_PAGE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
      );

      if (result != nullptr)
        break; // successfully allocated
    }

    return result;
  };

  void* result = tryAllocateByLowerBound();
  if (result == nullptr)
    result = tryAllocateByUpperBound();

  if (result == nullptr)
    return nullptr;

  auto page = m_pages.emplace(m_pages.end());
  page->address = reinterpret_cast<uintptr_t>(result);
  page->freeRanges.emplace_back(0, MEMORY_PAGE_SIZE);
  page->biggestFreeRangeSize = MEMORY_PAGE_SIZE;

  return &*page;
}
