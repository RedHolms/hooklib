#pragma once

#define _HOOKLIB_RESOLVE(X) X
#define HOOKLIB_RESOLVE(X) _HOOKLIB_RESOLVE(X)

// ABI Families enumeration
#define HOOKLIB_ABI_FAMILY_WINDOWS  0
#define HOOKLIB_ABI_FAMILY_SYSV     1

// Architectures enumeration
#define HOOKLIB_ARCH_AMD64          0
#define HOOKLIB_ARCH_I386           1
#define HOOKLIB_ARCH_ARM            2
#define HOOKLIB_ARCH_AARCH64        3

#define HOOKLIB_MAKE_ABI_ENUM(FAMILY, ARCH) \
  ((HOOKLIB_ABI_FAMILY_ ## FAMILY << 8) | HOOKLIB_ARCH_ ## ARCH)

// ABI enumeration (family + arch)
#define HOOKLIB_ABI_WINDOWS_AMD64   HOOKLIB_MAKE_ABI_ENUM(WINDOWS, AMD64)
#define HOOKLIB_ABI_WINDOWS_I386    HOOKLIB_MAKE_ABI_ENUM(WINDOWS, I386)
#define HOOKLIB_ABI_WINDOWS_ARM     HOOKLIB_MAKE_ABI_ENUM(WINDOWS, ARM)
#define HOOKLIB_ABI_WINDOWS_AARCH64 HOOKLIB_MAKE_ABI_ENUM(WINDOWS, AARCH64)
#define HOOKLIB_ABI_SYSV_AMD64      HOOKLIB_MAKE_ABI_ENUM(SYSV, AMD64)
#define HOOKLIB_ABI_SYSV_I386       HOOKLIB_MAKE_ABI_ENUM(SYSV, I386)
#define HOOKLIB_ABI_SYSV_ARM        HOOKLIB_MAKE_ABI_ENUM(SYSV, ARM)
#define HOOKLIB_ABI_SYSV_AARCH64    HOOKLIB_MAKE_ABI_ENUM(SYSV, AARCH64)

// Determine current ABI family
#if defined(_WIN32)
#define HOOKLIB_ABI_FAMILY HOOKLIB_ABI_FAMILY_WINDOWS
#else
// Assume SysV on any non-Windows system
#define HOOKLIB_ABI_FAMILY HOOKLIB_ABI_FAMILY_SYSV
#endif

#define HOOKLIB_ABI_FAMILY_IS(TARGET) \
  (HOOKLIB_ABI_FAMILY == HOOKLIB_RESOLVE(HOOKLIB_ABI_FAMILY_ ## TARGET))

#define HOOKLIB_ABI_FAMILY_IS_WINDOWS HOOKLIB_ABI_FAMILY_IS(WINDOWS)
#define HOOKLIB_ABI_FAMILY_IS_SYSV    HOOKLIB_ABI_FAMILY_IS(SYSV)

#if HOOKLIB_ABI_FAMILY_IS_WINDOWS
#define HOOKLIB_ABI_FAMILY_NAME     "Windows"
#define HOOKLIB_ABI_FAMILY_CODENAME WINDOWS
#elif HOOKLIB_ABI_FAMILY_IS_SYSV
#define HOOKLIB_ABI_FAMILY_NAME     "SysV"
#define HOOKLIB_ABI_FAMILY_CODENAME SYSV
#endif

// Determine current arch
#if defined(__amd64__) || defined(__amd64) || defined(_M_X64) || defined(_M_AMD64)
#define HOOKLIB_ARCH HOOKLIB_ARCH_AMD64
#elif defined(i386) || defined(__i386) || defined(__i386__) || defined(__i486__) || \
    defined(__i586__) || defined(__i686__) || defined(__IA32__) || defined(_M_IX86) || \
    defined(__X86__) || defined(_X86_) || defined(__I86__) || defined(__386)
#define HOOKLIB_ARCH HOOKLIB_ARCH_I386
#else
#error "Couldn't determine your architecture"
#endif

#define HOOKLIB_ARCH_IS(TARGET) \
  (HOOKLIB_ARCH == HOOKLIB_RESOLVE(HOOKLIB_ARCH_ ## TARGET))

#define HOOKLIB_ARCH_IS_AMD64 HOOKLIB_ARCH_IS(AMD64)
#define HOOKLIB_ARCH_IS_I386  HOOKLIB_ARCH_IS(I386)

#if HOOKLIB_ARCH_IS_AMD64
#define HOOKLIB_ARCH_NAME "AMD64"
#define HOOKLIB_ARCH_CODENAME AMD64
#elif HOOKLIB_ARCH_IS_I386
#define HOOKLIB_ARCH_NAME "i386"
#define HOOKLIB_ARCH_CODENAME I386
#endif

// Make ABI definition
#define _HOOKLIB_MAKE_ABI_2(FAMILY, ARCH) HOOKLIB_ABI_ ## FAMILY ## _ ## ARCH
#define _HOOKLIB_MAKE_ABI_1(FAMILY, ARCH) _HOOKLIB_MAKE_ABI_2(FAMILY, ARCH)
#define HOOKLIB_ABI _HOOKLIB_MAKE_ABI_1(HOOKLIB_ABI_FAMILY_CODENAME, HOOKLIB_ARCH_CODENAME)

#define HOOKLIB_ABI_IS(TARGET) \
  (HOOKLIB_ABI == HOOKLIB_RESOLVE(HOOKLIB_ABI_ ## TARGET))

#define HOOKLIB_ABI_IS_WINDOWS_AMD64   HOOKLIB_ABI_IS(WINDOWS_AMD64)
#define HOOKLIB_ABI_IS_WINDOWS_I386    HOOKLIB_ABI_IS(WINDOWS_I386)
#define HOOKLIB_ABI_IS_WINDOWS_ARM     HOOKLIB_ABI_IS(WINDOWS_ARM)
#define HOOKLIB_ABI_IS_WINDOWS_AARCH64 HOOKLIB_ABI_IS(WINDOWS_AARCH64)
#define HOOKLIB_ABI_IS_SYSV_AMD64      HOOKLIB_ABI_IS(SYSV_AMD64)
#define HOOKLIB_ABI_IS_SYSV_I386       HOOKLIB_ABI_IS(SYSV_I386)
#define HOOKLIB_ABI_IS_SYSV_ARM        HOOKLIB_ABI_IS(SYSV_ARM)
#define HOOKLIB_ABI_IS_SYSV_AARCH64    HOOKLIB_ABI_IS(SYSV_AARCH64)

#ifdef __cplusplus

// Include implementation for current ABI
#if HOOKLIB_ABI_IS_WINDOWS_AMD64
#include "HookLib/Impl/Windows_AMD64/HookLib.hpp"
#elif HOOKLIB_ABI_IS_WINDOWS_I386
#error "Current ABI (windows_i386) is not supported"
#elif HOOKLIB_ABI_IS_WINDOWS_ARM
#error "Current ABI (windows_arm) is not supported"
#elif HOOKLIB_ABI_IS_WINDOWS_AARCH64
#error "Current ABI (windows_aarch64) is not supported"
#elif HOOKLIB_ABI_IS_SYSV_AMD64
#error "Current ABI (sysv_amd64) is not supported"
#elif HOOKLIB_ABI_IS_SYSV_I386
#error "Current ABI (sysv_i386) is not supported"
#elif HOOKLIB_ABI_IS_SYSV_ARM
#error "Current ABI (sysv_arm) is not supported"
#elif HOOKLIB_ABI_IS_SYSV_AARCH64
#error "Current ABI (sysv_aarch64) is not supported"
#else
#error "Current ABI (unknown) is not supported"
#endif

#endif // #ifdef __cplusplus
