#pragma once

#include "HookLib.hpp"
#include <list>
#include <stdint.h>
#include <vector>

// Handle to a segment of assembly code
class AssemblySegment {
  friend class AssemblyPool;

public:
  uintptr_t address = 0;
  size_t bytesCount = 0;

public:
  // Constructor for INVALID segment
  constexpr explicit AssemblySegment() noexcept = default;

private:
  constexpr AssemblySegment(uintptr_t address, size_t bytesCount) noexcept
    : address(address),
      bytesCount(bytesCount) {}

public:
  inline ~AssemblySegment() noexcept {
    Free();
  }

  AssemblySegment(AssemblySegment const&) = delete;
  AssemblySegment& operator=(AssemblySegment const&) = delete;

  constexpr AssemblySegment(AssemblySegment&& other) noexcept
    : address(other.address),
      bytesCount(other.bytesCount) {
    other.address = 0;
    other.bytesCount = 0;
  }

  inline AssemblySegment& operator=(AssemblySegment&& other) noexcept {
    Free();
    address = other.address;
    bytesCount = other.bytesCount;
    other.address = 0;
    other.bytesCount = 0;
    return *this;
  }

private:
  void Free() noexcept;
};

// Assembly pool to reduce memory usage.
// Because of memory protection we must allocate at least 4096 bytes (1 page) for every code
// segment we write. But it's really a waste when we use only 60 or fewer bytes from that page. So,
// this structure uses as much from every page we allocate as possible.
class AssemblyPool {
  friend AssemblySegment;

private:
  struct MemoryPage {
    uintptr_t address;
    std::vector<std::pair<uint16_t, size_t>> freeRanges; // offset & size
    size_t biggestFreeRangeSize;
  };

public:
  constexpr AssemblyPool() = default;

public:
  inline AssemblySegment Allocate(size_t bytesCount) {
    return AllocateNear(bytesCount, 0);
  }

  AssemblySegment AllocateNear(size_t bytesCount, uintptr_t nearToAddress);

private:
  AssemblySegment AllocateSegment(size_t bytesCount, MemoryPage& page) noexcept;
  void FreeSegment(AssemblySegment const& segment) noexcept;

  MemoryPage* GetSegmentPage(AssemblySegment const& segment) noexcept;

  void RecountPageBiggestFreeRange(MemoryPage& page) noexcept;
  void MergeFreeRanges(MemoryPage& page) noexcept;
  MemoryPage* AllocatePage(uintptr_t nearToAddress) noexcept;

private:
  std::list<MemoryPage> m_pages = {};

  HOOKLIB_FRIEND_TEST(AssemblyPoolTests, Initialization);
  HOOKLIB_FRIEND_TEST(AssemblyPoolTests, NotNearPageAllocation);
};

extern AssemblyPool gAssemblyPool;
