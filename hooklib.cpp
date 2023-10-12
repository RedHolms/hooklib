#include "hooklib.hpp"

#include <Windows.h>

static hooklib::internal::mem::prot convertWindowsToHooklibProtection(DWORD windows_protection) {
  using namespace hooklib::internal::mem;

  switch (windows_protection) {
    default:
    case PAGE_NOACCESS:
      return prot_noaccess;
    case PAGE_READONLY:
      return prot_readonly;
    case PAGE_EXECUTE_READ:
      return prot_execute_read;
    case PAGE_EXECUTE_READWRITE:
      return prot_execute_read_write;
  }
}

static DWORD convertHooklibToWindowsProtection(hooklib::internal::mem::prot protection) {
  using namespace hooklib::internal::mem;

  switch (protection) {
    default:
    case prot_noaccess:
      return PAGE_NOACCESS;
    case prot_readonly:
      return PAGE_READONLY;
    case prot_execute_read:
      return PAGE_EXECUTE_READ;
    case prot_execute_read_write:
      return PAGE_EXECUTE_READWRITE;
  }
}

namespace hooklib::internal {

  void flush_cpu_instructions_cache(uintptr_t address, size_t size) {
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)address, size);
  }

}

namespace hooklib::internal::mem {

  std::pair<bool, prot> set_protection(uintptr_t address, size_t size, prot protection) {
    DWORD new_protection = convertHooklibToWindowsProtection(protection);
    DWORD old_protection = PAGE_NOACCESS;

    BOOL success = VirtualProtect((LPVOID)address, size, PAGE_EXECUTE_READWRITE, &old_protection);

    return { success, convertWindowsToHooklibProtection(old_protection) };
  }

}
