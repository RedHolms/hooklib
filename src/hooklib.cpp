#include <hooklib.hpp>

#include <stdlib.h>
#include <winnt.h>

namespace hooklib {
namespace impl {
namespace mem {

pointer alloc_aligned(size_t count) noexcept {
#if HKLIB_COMPILER == HKLIB_MSVC || HKLIB_COMPILER == HKLIB_CLANG
  return _aligned_malloc(count, 4096);
#else
  #error "Comiler not supported"
#endif

  return nullptr;
}

void free_aligned(pointer data) noexcept {
#if HKLIB_COMPILER == HKLIB_MSVC || HKLIB_COMPILER == HKLIB_CLANG
  return _aligned_free(data);
#else
  #error "Comiler not supported"
#endif
}

void flush_instruction_cache(pointer address, size_t size) noexcept {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
  FlushInstructionCache(GetCurrentProcess(), address, size);
#endif
}

void allow_execute(pointer address, size_t size) noexcept {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
  DWORD protection;
  VirtualProtect(address, size, PAGE_NOACCESS, &protection);
  
  if (protection == PAGE_READONLY)
    VirtualProtect(address, size, PAGE_EXECUTE_READ, &protection);
  else
    VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &protection);
#endif
}

void forbid_execute(pointer address, size_t size) noexcept {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
  DWORD protection;
  VirtualProtect(address, size, PAGE_NOACCESS, &protection);
  
  if (protection == PAGE_EXECUTE_READ)
    VirtualProtect(address, size, PAGE_READONLY, &protection);
  else
    VirtualProtect(address, size, PAGE_READWRITE, &protection);
#endif
}

void allow_write(pointer address, size_t size) noexcept {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
  DWORD protection;
  VirtualProtect(address, size, PAGE_NOACCESS, &protection);
  
  if (protection == PAGE_READONLY)
    VirtualProtect(address, size, PAGE_READWRITE, &protection);
  else
    VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &protection);
#endif
}

void forbid_write(pointer address, size_t size) noexcept {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
  DWORD protection;
  VirtualProtect(address, size, PAGE_NOACCESS, &protection);
  
  if (protection == PAGE_READWRITE)
    VirtualProtect(address, size, PAGE_READONLY, &protection);
  else
    VirtualProtect(address, size, PAGE_EXECUTE_READ, &protection);
#endif
}

} // namespace mem
} // namespace impl
} // namespace hooklib
