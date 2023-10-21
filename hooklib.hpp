#pragma once

#include <functional>
#include <optional>
#include <numeric>
#include <tuple>

#define HKLIB_X86 0
#define HKLIB_X64 1

#define HKLIB_MSVC 0
#define HKLIB_GNU 1
#define HKLIB_CLANG 2

#define HKLIB_WINDOWS 0
#define HKLIB_LINUX 1

#if !defined(_WIN32) || !defined(_MSC_VER)
#error "Accepted only MSVC with Windows"
#endif

#if defined(_WIN64)
#error "Accepted only 32 bit"
#endif

#define HKLIB_ARCH HKLIB_X86
#define HKLIB_SYSTEM HKLIB_WINDOWS
#define HKLIB_COMPILER HKLIB_MSVC

#if HKLIB_SYSTEM == HKLIB_WINDOWS
#include <Windows.h>
#endif

namespace hooklib {
  namespace detail {}
  namespace impl {}
}

namespace hooklib::detail {

  template <typename T>
  static constexpr size_t safe_sizeof_v = sizeof(T);

  // We can't do sizeof(void)
  template <>
  static constexpr size_t safe_sizeof_v<void> = 0;

  struct pointer {
    uintptr_t value;

    constexpr pointer()
      : value(0) {}

    constexpr pointer(uintptr_t value)
      : value(value) {}

    template <typename T>
    constexpr pointer(T* value)
      : value(reinterpret_cast<uintptr_t>(value)) {}

    constexpr pointer operator+(ptrdiff_t b) const noexcept {
      return pointer(value + b);
    }

    constexpr pointer& operator+=(ptrdiff_t b) noexcept {
      value += b;
      return *this;
    }

    constexpr pointer operator-(ptrdiff_t b) const noexcept {
      return pointer(value - b);
    }

    constexpr pointer& operator-=(ptrdiff_t b) noexcept {
      value -= b;
      return *this;
    }

    constexpr operator bool() const noexcept {
      return value != 0;
    }
    
    constexpr operator ptrdiff_t() const noexcept {
      return static_cast<ptrdiff_t>(value);
    }

    constexpr operator uintptr_t() const noexcept {
      return value;
    }

    template <typename T>
    constexpr operator T* () const noexcept {
      return reinterpret_cast<T*>(value);
    }
  };

  template <typename T>
  using optional_return_t = std::conditional_t<std::is_void_v<T>, bool, std::optional<T>>;

  template <typename FnT>
  struct blow_function;

  template <typename FnT>
  using blow_function_t = blow_function<FnT>::type;

  template <typename FnTrT>
  struct connect_function;

  template <typename FnTrT>
  using connect_function_t = connect_function<FnTrT>::type;

  template <typename RetT, typename ArgsTplT>
  struct build_function;

  template <typename RetT, typename... ArgsT>
  struct build_function<RetT, std::tuple<ArgsT...>> {
    using type = std::function<RetT(ArgsT...)>;
  };

  template <typename RetT, typename ArgsTplT>
  using build_function_t = build_function<RetT, ArgsTplT>::type;

} // namespace hooklib::detail

namespace hooklib::impl {

  enum mem_prot : uint32_t {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
    mem_prot_invalid = 0xFFFFFFFF,
    mem_prot_noaccess = PAGE_NOACCESS,
    mem_prot_readonly = PAGE_READONLY,
    mem_prot_execute = PAGE_EXECUTE,
    mem_prot_execute_read = PAGE_EXECUTE_READ,
    mem_prot_execute_read_write = PAGE_EXECUTE_READWRITE
#endif
  };

  inline void flush_instruction_cache(detail::pointer address, size_t size) {
#if HKLIB_SYSTEM == HKLIB_WINDOWS
    FlushInstructionCache(GetCurrentProcess(), address, size);
#endif
  }

  inline mem_prot set_memory_protection(detail::pointer address, size_t size, mem_prot protection) {
    if (protection == mem_prot_invalid)
      return mem_prot_invalid;

#if HKLIB_SYSTEM == HKLIB_WINDOWS
    DWORD old_protection;

    BOOL success = VirtualProtect(address, size, DWORD(protection), &old_protection);

    if (not success)
      return mem_prot_invalid;

    return mem_prot(old_protection);
#endif
  }

  namespace mem {

    constexpr void copy(detail::pointer destination, detail::pointer source, size_t size) noexcept {
      uint8_t* dst = destination;
      uint8_t* src = source;

      for (size_t i = 0; i < size; ++i)
        dst[i] = src[i];
    }

    template <typename T>
    constexpr void fill(detail::pointer destination, size_t count, T value) {
      T* dst = destination;

      for (size_t i = 0; i < count; ++i) {
        dst[i] = value;
      }
    }

    template <typename T>
    constexpr void write(detail::pointer address, T value) noexcept {
      static_cast<T*>(address)[0] = value;
    }

    template <typename T>
    constexpr void read(detail::pointer address) noexcept {
      return static_cast<T*>(address)[0];
    }
    
    template <typename T>
    inline T* alloc_aligned(size_t count) noexcept {
#if HKLIB_COMPILER == HKLIB_MSVC
      return reinterpret_cast<T*>(_aligned_malloc(count * sizeof(T), 4096));
#endif
    }

    inline void free_aligned(void* data) noexcept {
#if HKLIB_COMPILER == HKLIB_MSVC
      return _aligned_free(data);
#endif
    }

  }

  namespace relay {

    template <typename HookT, typename RetT, typename... ArgsT>
    inline RetT function_hook_relay(HookT* hook, ArgsT... args) {
      auto callback = hook->get_callback();

      if (callback) {
        auto retval = callback(args...);

        /* FIXME: Maybe wont work with Clang/GCC (not tested) */
        if constexpr (std::is_same_v<RetT, void>) {
          if (not retval)
            return;
        }
        else {
          if (retval.has_value())
            return retval.value();
        }
      }

      return hook->call(args...);
    }

  } // namespace relay

  namespace platform {

#if HKLIB_ARCH == HKLIB_X86

    enum class call_conv {
      ccdecl,
      cstdcall
    };

    template <typename RetT, call_conv CallConv, typename... ArgsT>
    struct function_traits {
      using type = function_traits<RetT, CallConv, ArgsT...>;

      using function_type = detail::connect_function_t<type>;

      using arguments_type = std::tuple<ArgsT...>;
      using return_type = RetT;

      static constexpr size_t get_arguments_size_in_bytes() {
        constexpr size_t arguments_sizes[] = { sizeof(ArgsT)... };

        return std::accumulate(std::begin(arguments_sizes), std::end(arguments_sizes), 0);
      }

      static constexpr size_t get_stack_frame_size() {
        using namespace detail;

        constexpr auto arguments_size_in_bytes = get_arguments_size_in_bytes();

        if constexpr (safe_sizeof_v<RetT> > sizeof(uintptr_t))
          return sizeof(RetT*) + arguments_size_in_bytes;
        else
          return arguments_size_in_bytes;
      }

      static constexpr size_t get_registers_count() {
        return 0;
      }

      static constexpr auto arguments_count = sizeof...(ArgsT);
      static constexpr auto stack_frame_size = get_stack_frame_size();
      static constexpr auto registers_count = get_registers_count();
      static constexpr auto calling_convention = CallConv;

      static constexpr bool return_value_fits_in_register = get_stack_frame_size() == get_arguments_size_in_bytes();
    };

    template <typename RetT, typename... ArgsT>
    struct detail::blow_function<RetT __cdecl(ArgsT...)> {
      using type = impl::platform::function_traits<RetT, impl::platform::call_conv::ccdecl, ArgsT...>;
    };

    template <typename RetT, typename... ArgsT>
    struct detail::blow_function<RetT __stdcall(ArgsT...)> {
      using type = impl::platform::function_traits<RetT, impl::platform::call_conv::cstdcall, ArgsT...>;
    };

    template <typename RetT, typename... ArgsT>
    struct detail::connect_function<function_traits<RetT, call_conv::ccdecl, ArgsT...>> {
      using type = RetT __cdecl(ArgsT...);
    };

    template <typename RetT, typename... ArgsT>
    struct detail::connect_function<function_traits<RetT, call_conv::cstdcall, ArgsT...>> {
      using type = RetT __stdcall(ArgsT...);
    };

    template <typename HookT, typename FnTrT>
    struct function_hook_relay_generator;

    template <typename HookT, typename RetT, call_conv CallConv, typename... ArgsT>
    struct function_hook_relay_generator<HookT, function_traits<RetT, CallConv, ArgsT...>> {
      static RetT __cdecl relay(HookT* hook, void*, ArgsT... args) {
        return impl::relay::function_hook_relay<HookT, RetT, ArgsT...>(hook, args...);
      }
    };

#endif // HKLIB_ARCH == HKLIB_X86

  } // namespace platform

  namespace relay {

    template <typename HookT, typename FnTrT>
    struct function_hook_relay_generator
      : impl::platform::function_hook_relay_generator<HookT, FnTrT> {};

  } // namespace relay

  namespace hde {

#if HKLIB_ARCH == HKLIB_X86
    /*
     * Hacker Disassembler Engine 32
     * Copyright (c) 2006-2009, Vyacheslav Patkov.
     * All rights reserved.
     */

    static constexpr uint32_t F_MODRM         = 0x00000001;
    static constexpr uint32_t F_SIB           = 0x00000002;
    static constexpr uint32_t F_IMM8          = 0x00000004;
    static constexpr uint32_t F_IMM16         = 0x00000008;
    static constexpr uint32_t F_IMM32         = 0x00000010;
    static constexpr uint32_t F_DISP8         = 0x00000020;
    static constexpr uint32_t F_DISP16        = 0x00000040;
    static constexpr uint32_t F_DISP32        = 0x00000080;
    static constexpr uint32_t F_RELATIVE      = 0x00000100;
    static constexpr uint32_t F_2IMM16        = 0x00000800;
    static constexpr uint32_t F_ERROR         = 0x00001000;
    static constexpr uint32_t F_ERROR_OPCODE  = 0x00002000;
    static constexpr uint32_t F_ERROR_LENGTH  = 0x00004000;
    static constexpr uint32_t F_ERROR_LOCK    = 0x00008000;
    static constexpr uint32_t F_ERROR_OPERAND = 0x00010000;
    static constexpr uint32_t F_PREFIX_REPNZ  = 0x01000000;
    static constexpr uint32_t F_PREFIX_REPX   = 0x02000000;
    static constexpr uint32_t F_PREFIX_REP    = 0x03000000;
    static constexpr uint32_t F_PREFIX_66     = 0x04000000;
    static constexpr uint32_t F_PREFIX_67     = 0x08000000;
    static constexpr uint32_t F_PREFIX_LOCK   = 0x10000000;
    static constexpr uint32_t F_PREFIX_SEG    = 0x20000000;
    static constexpr uint32_t F_PREFIX_ANY    = 0x3f000000;

    static constexpr uint8_t PREFIX_SEGMENT_CS   = 0x2e;
    static constexpr uint8_t PREFIX_SEGMENT_SS   = 0x36;
    static constexpr uint8_t PREFIX_SEGMENT_DS   = 0x3e;
    static constexpr uint8_t PREFIX_SEGMENT_ES   = 0x26;
    static constexpr uint8_t PREFIX_SEGMENT_FS   = 0x64;
    static constexpr uint8_t PREFIX_SEGMENT_GS   = 0x65;
    static constexpr uint8_t PREFIX_LOCK         = 0xf0;
    static constexpr uint8_t PREFIX_REPNZ        = 0xf2;
    static constexpr uint8_t PREFIX_REPX         = 0xf3;
    static constexpr uint8_t PREFIX_OPERAND_SIZE = 0x66;
    static constexpr uint8_t PREFIX_ADDRESS_SIZE = 0x67;

    static constexpr uint8_t C_NONE    = 0x00;
    static constexpr uint8_t C_MODRM   = 0x01;
    static constexpr uint8_t C_IMM8    = 0x02;
    static constexpr uint8_t C_IMM16   = 0x04;
    static constexpr uint8_t C_IMM_P66 = 0x10;
    static constexpr uint8_t C_REL8    = 0x20;
    static constexpr uint8_t C_REL32   = 0x40;
    static constexpr uint8_t C_GROUP   = 0x80;
    static constexpr uint8_t C_ERROR   = 0xff;

    static constexpr uint8_t PRE_ANY  = 0x00;
    static constexpr uint8_t PRE_NONE = 0x01;
    static constexpr uint8_t PRE_F2   = 0x02;
    static constexpr uint8_t PRE_F3   = 0x04;
    static constexpr uint8_t PRE_66   = 0x08;
    static constexpr uint8_t PRE_67   = 0x10;
    static constexpr uint8_t PRE_LOCK = 0x20;
    static constexpr uint8_t PRE_SEG  = 0x40;
    static constexpr uint8_t PRE_ALL  = 0xff;

    static constexpr uintptr_t DELTA_OPCODES      = 0x4a;
    static constexpr uintptr_t DELTA_FPU_REG      = 0xf1;
    static constexpr uintptr_t DELTA_FPU_MODRM    = 0xf8;
    static constexpr uintptr_t DELTA_PREFIXES     = 0x130;
    static constexpr uintptr_t DELTA_OP_LOCK_OK   = 0x1a1;
    static constexpr uintptr_t DELTA_OP2_LOCK_OK  = 0x1b9;
    static constexpr uintptr_t DELTA_OP_ONLY_MEM  = 0x1cb;
    static constexpr uintptr_t DELTA_OP2_ONLY_MEM = 0x1da;

    static constexpr uint8_t hde32_table[] = {
      0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,
      0xa8,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xac,0xaa,0xb2,0xaa,0x9f,0x9f,
      0x9f,0x9f,0xb5,0xa3,0xa3,0xa4,0xaa,0xaa,0xba,0xaa,0x96,0xaa,0xa8,0xaa,0xc3,
      0xc3,0x96,0x96,0xb7,0xae,0xd6,0xbd,0xa3,0xc5,0xa3,0xa3,0x9f,0xc3,0x9c,0xaa,
      0xaa,0xac,0xaa,0xbf,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0x90,
      0x82,0x7d,0x97,0x59,0x59,0x59,0x59,0x59,0x7f,0x59,0x59,0x60,0x7d,0x7f,0x7f,
      0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x9a,0x88,0x7d,
      0x59,0x50,0x50,0x50,0x50,0x59,0x59,0x59,0x59,0x61,0x94,0x61,0x9e,0x59,0x59,
      0x85,0x59,0x92,0xa3,0x60,0x60,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,
      0x59,0x59,0x9f,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xcc,0x01,0xbc,0x03,0xf0,
      0x10,0x10,0x10,0x10,0x50,0x50,0x50,0x50,0x14,0x20,0x20,0x20,0x20,0x01,0x01,
      0x01,0x01,0xc4,0x02,0x10,0x00,0x00,0x00,0x00,0x01,0x01,0xc0,0xc2,0x10,0x11,
      0x02,0x03,0x11,0x03,0x03,0x04,0x00,0x00,0x14,0x00,0x02,0x00,0x00,0xc6,0xc8,
      0x02,0x02,0x02,0x02,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0xca,
      0x01,0x01,0x01,0x00,0x06,0x00,0x04,0x00,0xc0,0xc2,0x01,0x01,0x03,0x01,0xff,
      0xff,0x01,0x00,0x03,0xc4,0xc4,0xc6,0x03,0x01,0x01,0x01,0xff,0x03,0x03,0x03,
      0xc8,0x40,0x00,0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,
      0x00,0x00,0x00,0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,
      0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0xff,0xff,0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x7f,0x00,0x00,0xff,0x4a,0x4a,0x4a,0x4a,0x4b,0x52,0x4a,0x4a,0x4a,0x4a,0x4f,
      0x4c,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x55,0x45,0x40,0x4a,0x4a,0x4a,
      0x45,0x59,0x4d,0x46,0x4a,0x5d,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,
      0x4a,0x4a,0x4a,0x4a,0x4a,0x61,0x63,0x67,0x4e,0x4a,0x4a,0x6b,0x6d,0x4a,0x4a,
      0x45,0x6d,0x4a,0x4a,0x44,0x45,0x4a,0x4a,0x00,0x00,0x00,0x02,0x0d,0x06,0x06,
      0x06,0x06,0x0e,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x00,0x06,0x06,0x02,0x06,
      0x00,0x0a,0x0a,0x07,0x07,0x06,0x02,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
      0x04,0x04,0x00,0x00,0x00,0x0e,0x05,0x06,0x06,0x06,0x01,0x06,0x00,0x00,0x08,
      0x00,0x10,0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,
      0x86,0x00,0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,
      0xf8,0xbb,0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,
      0xc4,0xff,0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,
      0x13,0x09,0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,
      0xb2,0xff,0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,
      0xe7,0x08,0x00,0xf0,0x02,0x00
    };

#pragma pack(push, 1)

    typedef struct {
      uint8_t len;
      uint8_t p_rep;
      uint8_t p_lock;
      uint8_t p_seg;
      uint8_t p_66;
      uint8_t p_67;
      uint8_t opcode;
      uint8_t opcode2;
      uint8_t modrm;
      uint8_t modrm_mod;
      uint8_t modrm_reg;
      uint8_t modrm_rm;
      uint8_t sib;
      uint8_t sib_scale;
      uint8_t sib_index;
      uint8_t sib_base;
      union {
        uint8_t imm8;
        uint16_t imm16;
        uint32_t imm32;
      } imm;
      union {
        uint8_t disp8;
        uint16_t disp16;
        uint32_t disp32;
      } disp;
      uint32_t flags;
    } hde32s;

#pragma pack(pop)

    inline uint32_t hde32_disasm(detail::pointer code, hde32s* hs);

// ^^^ HKLIB_ARCH == HKLIB_X86 ^^^
#elif HKLIB_ARCH == HKLIB_X64
    /*
     * Hacker Disassembler Engine 64
     * Copyright (c) 2008-2009, Vyacheslav Patkov.
     * All rights reserved.
     */

    static constexpr uint32_t F_MODRM         = 0x00000001;
    static constexpr uint32_t F_SIB           = 0x00000002;
    static constexpr uint32_t F_IMM8          = 0x00000004;
    static constexpr uint32_t F_IMM16         = 0x00000008;
    static constexpr uint32_t F_IMM32         = 0x00000010;
    static constexpr uint32_t F_IMM64         = 0x00000020;
    static constexpr uint32_t F_DISP8         = 0x00000040;
    static constexpr uint32_t F_DISP16        = 0x00000080;
    static constexpr uint32_t F_DISP32        = 0x00000100;
    static constexpr uint32_t F_RELATIVE      = 0x00000200;
    static constexpr uint32_t F_ERROR         = 0x00001000;
    static constexpr uint32_t F_ERROR_OPCODE  = 0x00002000;
    static constexpr uint32_t F_ERROR_LENGTH  = 0x00004000;
    static constexpr uint32_t F_ERROR_LOCK    = 0x00008000;
    static constexpr uint32_t F_ERROR_OPERAND = 0x00010000;
    static constexpr uint32_t F_PREFIX_REPNZ  = 0x01000000;
    static constexpr uint32_t F_PREFIX_REPX   = 0x02000000;
    static constexpr uint32_t F_PREFIX_REP    = 0x03000000;
    static constexpr uint32_t F_PREFIX_66     = 0x04000000;
    static constexpr uint32_t F_PREFIX_67     = 0x08000000;
    static constexpr uint32_t F_PREFIX_LOCK   = 0x10000000;
    static constexpr uint32_t F_PREFIX_SEG    = 0x20000000;
    static constexpr uint32_t F_PREFIX_REX    = 0x40000000;
    static constexpr uint32_t F_PREFIX_ANY    = 0x7f000000;

    static constexpr uint8_t PREFIX_SEGMENT_CS   = 0x2e;
    static constexpr uint8_t PREFIX_SEGMENT_SS   = 0x36;
    static constexpr uint8_t PREFIX_SEGMENT_DS   = 0x3e;
    static constexpr uint8_t PREFIX_SEGMENT_ES   = 0x26;
    static constexpr uint8_t PREFIX_SEGMENT_FS   = 0x64;
    static constexpr uint8_t PREFIX_SEGMENT_GS   = 0x65;
    static constexpr uint8_t PREFIX_LOCK         = 0xf0;
    static constexpr uint8_t PREFIX_REPNZ        = 0xf2;
    static constexpr uint8_t PREFIX_REPX         = 0xf3;
    static constexpr uint8_t PREFIX_OPERAND_SIZE = 0x66;
    static constexpr uint8_t PREFIX_ADDRESS_SIZE = 0x67;

    static constexpr uint8_t C_NONE    = 0x00;
    static constexpr uint8_t C_MODRM   = 0x01;
    static constexpr uint8_t C_IMM8    = 0x02;
    static constexpr uint8_t C_IMM16   = 0x04;
    static constexpr uint8_t C_IMM_P66 = 0x10;
    static constexpr uint8_t C_REL8    = 0x20;
    static constexpr uint8_t C_REL32   = 0x40;
    static constexpr uint8_t C_GROUP   = 0x80;
    static constexpr uint8_t C_ERROR   = 0xff;

    static constexpr uint8_t PRE_ANY  = 0x00;
    static constexpr uint8_t PRE_NONE = 0x01;
    static constexpr uint8_t PRE_F2   = 0x02;
    static constexpr uint8_t PRE_F3   = 0x04;
    static constexpr uint8_t PRE_66   = 0x08;
    static constexpr uint8_t PRE_67   = 0x10;
    static constexpr uint8_t PRE_LOCK = 0x20;
    static constexpr uint8_t PRE_SEG  = 0x40;
    static constexpr uint8_t PRE_ALL  = 0xff;

    static constexpr uintptr_t DELTA_OPCODES      = 0x4a;
    static constexpr uintptr_t DELTA_FPU_REG      = 0xfd;
    static constexpr uintptr_t DELTA_FPU_MODRM    = 0x104;
    static constexpr uintptr_t DELTA_PREFIXES     = 0x13c;
    static constexpr uintptr_t DELTA_OP_LOCK_OK   = 0x1ae;
    static constexpr uintptr_t DELTA_OP2_LOCK_OK  = 0x1c6;
    static constexpr uintptr_t DELTA_OP_ONLY_MEM  = 0x1d8;
    static constexpr uintptr_t DELTA_OP2_ONLY_MEM = 0x1e7;

    static constexpr uint8_t hde64_table[] = {
      0xa5,0xaa,0xa5,0xb8,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
      0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
      0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
      0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
      0xc0,0xc2,0xc0,0xe6,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
      0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
      0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
      0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
      0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
      0x5b,0x5b,0x86,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xbc,
      0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
      0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
      0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
      0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
      0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
      0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
      0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
      0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
      0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
      0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
      0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
      0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
      0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
      0x40,0x40,0x64,0x66,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
      0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
      0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
      0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
      0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
      0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
      0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
      0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
      0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,0x13,0x09,
      0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,0xb2,0xff,
      0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x08,
      0x00,0xf0,0x02,0x00
    };

#pragma pack(push, 1)

    typedef struct {
      uint8_t len;
      uint8_t p_rep;
      uint8_t p_lock;
      uint8_t p_seg;
      uint8_t p_66;
      uint8_t p_67;
      uint8_t rex;
      uint8_t rex_w;
      uint8_t rex_r;
      uint8_t rex_x;
      uint8_t rex_b;
      uint8_t opcode;
      uint8_t opcode2;
      uint8_t modrm;
      uint8_t modrm_mod;
      uint8_t modrm_reg;
      uint8_t modrm_rm;
      uint8_t sib;
      uint8_t sib_scale;
      uint8_t sib_index;
      uint8_t sib_base;
      union {
        uint8_t imm8;
        uint16_t imm16;
        uint32_t imm32;
        uint64_t imm64;
      } imm;
      union {
        uint8_t disp8;
        uint16_t disp16;
        uint32_t disp32;
      } disp;
      uint32_t flags;
    } hde64s;

#pragma pack(pop)

    inline uint32_t hde64_disasm(detail::pointer code, hde64s* hs);

#endif // HKLIB_ARCH == HKLIB_X64

  } // namespace hde

  namespace assembly {

    template <size_t CodeSize>
    class code_array {
    public:
      constexpr code_array() {
        m_data = mem::alloc_aligned<uint8_t>(CodeSize);

        set_memory_protection(m_data, CodeSize, mem_prot_execute_read_write);
      }

      constexpr ~code_array() {
        mem::free_aligned(m_data);
      }

    public:
      template <typename T>
      constexpr void write(T value) noexcept {
        mem::write(current(), value);
        m_size += sizeof(T);
      }

      constexpr void write_bytes(detail::pointer data, size_t count) noexcept {
        uint8_t* src = data;

        for (size_t i = 0; i < count; ++i)
          write<uint8_t>(src[i]);
      }

      template <typename T>
      constexpr void op_rel(detail::pointer destination, uint8_t opcode) noexcept {
        T offset = destination - current() - 5;

        write<uint8_t>(opcode);
        write<T>(offset);
      }

      constexpr void op_rel_jump(detail::pointer destination) noexcept {
        op_rel<uint32_t>(destination, 0xE9);
      }

      constexpr void op_rel_call(detail::pointer destination) noexcept {
        op_rel<uint32_t>(destination, 0xE8);
      }

      constexpr detail::pointer current() noexcept {
        return &m_data[m_size];
      }

      constexpr detail::pointer data() const noexcept {
        return m_data;
      }

      constexpr size_t size() const noexcept {
        return m_size;
      }

      constexpr void clear() noexcept {
        m_size = 0;
      }

    private:
      uint8_t* m_data = nullptr;
      size_t m_size = 0;
    };

  } // namespace assembly

} // namespace hooklib::impl

namespace hooklib {

  template <typename FnT>
  class function_hook {
  public:
    using type = function_hook<FnT>;

    using function_traits = detail::blow_function_t<std::remove_pointer_t<FnT>>;

    using function_type = function_traits::function_type;
    using function_pointer_type = function_type*;

    using arguments_type = function_traits::arguments_type;
    using return_type = function_traits::return_type;

    static constexpr auto arguments_count = function_traits::arguments_count;
    static constexpr auto stack_frame_size = function_traits::stack_frame_size;
    static constexpr auto registers_count = function_traits::registers_count;
    static constexpr auto calling_convention = function_traits::calling_convention;
    
    static constexpr bool return_value_fits_in_register = function_traits::return_value_fits_in_register;

    using callback_type = detail::build_function_t<detail::optional_return_t<return_type>, arguments_type>;
    using trampoline_type = std::function<function_type>;

    using relay_generator = impl::relay::function_hook_relay_generator<type, function_traits>;

    using code_array = impl::assembly::code_array<4096>;

  public:
    constexpr function_hook() = default;

    constexpr function_hook(detail::pointer target_function_address)
      : function_hook()
    {
      set_target(target_function_address);
    }

    constexpr ~function_hook() {
      remove();
    }

  public:
    constexpr void set_target(detail::pointer target_function_address) noexcept {
      m_target = target_function_address;

      m_code.clear();
      m_code_generated = false;
    }

    constexpr void set_callback(callback_type const& callback) noexcept {
      m_callback = callback;
    }

    constexpr bool is_installed() const noexcept {
      return m_installed;
    }

    constexpr function_pointer_type get_target() const noexcept {
      return static_cast<function_pointer_type>(m_target);
    }

    constexpr callback_type& get_callback() noexcept {
      return m_callback;
    }

    constexpr callback_type const& get_callback() const noexcept {
      return m_callback;
    }

    constexpr trampoline_type get_trampoline() noexcept {
      return trampoline_type(static_cast<function_pointer_type>(m_trampoline));
    }

    template <typename... ArgsT>
    constexpr return_type call(ArgsT... args) noexcept {
      return get_trampoline()(args...);
    }

    constexpr bool install() noexcept {
      if (m_installed)
        return false;

      if (not m_target)
        return false;

      if (not _generate_code())
        return false;

      if (not _do_hook(true))
        return false;

      m_installed = true;
      return true;
    }

    constexpr void remove() noexcept {
      if (not m_installed)
        return;

      _do_hook(false);

      m_installed = false;
    }

  private:
    constexpr bool _do_hook(bool state) noexcept {
      using namespace impl;

      mem_prot old_protection;

      old_protection = set_memory_protection(m_target, m_original_prologue_size, mem_prot_execute_read_write);

      if (old_protection == mem_prot_invalid)
        return false;

      if (state) {
        mem::fill<uint8_t>(m_target, m_original_prologue_size, 0x90);

        // Relative jump to m_relay_jumper
        mem::write<uint8_t>(m_target, 0xE9);
        mem::write<uint32_t>(m_target + 1, m_relay_jumper.value - m_target.value - 5);
      }
      else {
        mem::copy(m_target, m_original_prologue, m_original_prologue_size);
      }

      flush_instruction_cache(m_target, m_original_prologue_size);
      set_memory_protection(m_target, m_original_prologue_size, old_protection);

      return true;
    }

    constexpr bool _generate_code() {
      if (m_code_generated)
        return true;

      if (not _generate_relay_jump())
        return false;

      if (not _generate_trampoline())
        return false;

      m_code_generated = true;
      return true;
    }

    constexpr bool _generate_relay_jump() {
      using namespace impl::platform;

      /*
        All code in this function is pretty
        complicated and there's so much ways
        to make it better, but at least
        even now I like how it's works.
      */

      m_relay_jumper = m_code.current();

      if constexpr (not return_value_fits_in_register) {
        /*
          Now stack looks like this:
            [esp]     = ReturnAddress (target function caller)
            [esp + 4] = PointerToReturnStruct
            [esp + 8] = Arguments...

          But before calling relay_generator::relay we want it to look like this:
            [esp]       = PointerToReturnStruct
            [esp + 4]   = HookObjectPointer
            [esp + 8]   = ReturnAdress (target function caller)
            [esp + 12]  = Arguments...
        */

        // mov eax, [esp]
        m_code.write<uint8_t>(0x8B);
        m_code.write<uint8_t>(0x04);
        m_code.write<uint8_t>(0x24);

        // xchg [esp + 4], eax
        m_code.write<uint8_t>(0x87);
        m_code.write<uint8_t>(0x44);
        m_code.write<uint8_t>(0x24);
        m_code.write<uint8_t>(0x04);

        // add esp, 4
        m_code.write<uint8_t>(0x83);
        m_code.write<uint8_t>(0xC4);
        m_code.write<uint8_t>(0x04);
      }

      // push this
      m_code.write<uint8_t>(0x68);
      m_code.write<uintptr_t>(detail::pointer(this));

      if constexpr (not return_value_fits_in_register) {
        // push eax
        m_code.write<uint8_t>(0x50);
      }

      // relay is ALWAYS cdecl
      detail::pointer relay_address = &relay_generator::relay;

      // call relay_generator::relay
      m_code.op_rel_call(relay_address);

      if constexpr (not return_value_fits_in_register) {
        // pop eax
        m_code.write<uint8_t>(0x58);

        // xchg [esp + 4], eax
        m_code.write<uint8_t>(0x87);
        m_code.write<uint8_t>(0x44);
        m_code.write<uint8_t>(0x24);
        m_code.write<uint8_t>(0x04);
        
        // mov [esp], eax
        m_code.write<uint8_t>(0x89);
        m_code.write<uint8_t>(0x04);
        m_code.write<uint8_t>(0x24);

        // mov eax, [esp + 4]
        m_code.write<uint8_t>(0x8B);
        m_code.write<uint8_t>(0x44);
        m_code.write<uint8_t>(0x24);
        m_code.write<uint8_t>(0x04);
      }
      else {
        // add esp, 4
        m_code.write<uint8_t>(0x83);
        m_code.write<uint8_t>(0xC4);
        m_code.write<uint8_t>(0x04);
      }

      if constexpr (calling_convention == call_conv::cstdcall && stack_frame_size > 0) {
        // ret stack_frame_size
        m_code.write<uint8_t>(0xc2);
        m_code.write<uint16_t>(stack_frame_size);
      } else {
        // ret
        m_code.write<uint8_t>(0xc3);
      }

      return true;
    }

    constexpr bool _generate_trampoline() {
      using namespace impl;
      using namespace impl::hde;

      m_trampoline = m_code.current();

      hde32s hde;
      uintptr_t current = m_target;
      bool need_jump = true;

      while (true) {
        if (current - static_cast<ptrdiff_t>(m_target) >= 5) {
          break;
        }

        need_jump = true;

        hde32_disasm(current, &hde);
        
        if (hde.flags & F_ERROR)
          return false;

        if (hde.opcode == 0xE8) {
          uintptr_t absolute_target = static_cast<int32_t>(hde.imm.imm32) + current + 5;

          m_code.op_rel_call(absolute_target);
        }
        else if (hde.opcode == 0xE9 || hde.opcode == 0xEB) {
          uintptr_t absolute_target;

          if (hde.opcode == 0xE9)
            absolute_target = static_cast<int32_t>(hde.imm.imm32) + current + 5;
          else /* hde.opcode == 0xEB */
            absolute_target = static_cast<int8_t>(hde.imm.imm8) + current + 5;

          m_code.op_rel_jump(absolute_target);

          need_jump = false;
        }
        else if (
          (hde.opcode >= 0x70 && hde.opcode <= 0x7F) || // conditional 1-byte jump
          (hde.opcode == 0xF0 && hde.opcode2 >= 0x80 && hde.opcode2 <= 0x8F) // conditional 4-byte jump
        ) {
          uintptr_t absolute_target;

          if (hde.flags & F_IMM32)
            absolute_target = static_cast<int32_t>(hde.imm.imm32) + current + 5;
          else /* hde.flags & F_IMM8 */
            absolute_target = static_cast<int8_t>(hde.imm.imm8) + current + 5;

          uint8_t condition;

          if (hde.opcode == 0xF0)
            condition = hde.opcode2;
          else
            condition = hde.opcode & 0x0F;

          m_code.write<uint8_t>(0xF0);
          m_code.write<uint8_t>(0x80 | condition);
          m_code.write<uint32_t>(absolute_target - static_cast<ptrdiff_t>(m_code.current()) - 4);
        }
        else if (
          (hde.opcode >= 0xE0 && hde.opcode <= 0xE2) || // loop (1-byte)
          hde.opcode == 0xE3 // jump if ECX is 0
        ) {
          // FIXME
          // unsupported
          return false;
        }
        else {
          m_code.write_bytes(current, hde.len);
        }

        current += hde.len;
      }

      m_original_prologue_size = current - m_target.value;
      mem::copy(m_original_prologue, m_target, m_original_prologue_size);

      if (need_jump) {
        uintptr_t function_continue = m_target.value + m_original_prologue_size;
        m_code.op_rel_jump(function_continue);
      }

      return true;
    }

  private:
    bool m_installed = false;
    bool m_code_generated = false;

    uint8_t m_original_prologue[4 + 15] = { 0 };
    size_t m_original_prologue_size = 0;
    
    detail::pointer m_target;
    detail::pointer m_relay_jumper;
    detail::pointer m_trampoline;

    callback_type m_callback;

    code_array m_code;
  };

} // namespace hooklib

#if HKLIB_ARCH == HKLIB_X86

inline uint32_t hooklib::impl::hde::hde32_disasm(detail::pointer code, hde32s* hs) {
  using namespace hooklib::impl::hde;

  uint8_t x, c;
  uint8_t* p = code;
  uint8_t cflags, opcode, pref = 0;
  uint8_t const* ht = hde32_table;
  uint8_t m_mod, m_reg, m_rm, disp_size = 0;

  memset(hs, 0, sizeof(hde32s));

  for (x = 16; x; x--)
    switch (c = *p++) {
    case 0xf3:
      hs->p_rep = c;
      pref |= PRE_F3;
      break;
    case 0xf2:
      hs->p_rep = c;
      pref |= PRE_F2;
      break;
    case 0xf0:
      hs->p_lock = c;
      pref |= PRE_LOCK;
      break;
    case 0x26: case 0x2e: case 0x36:
    case 0x3e: case 0x64: case 0x65:
      hs->p_seg = c;
      pref |= PRE_SEG;
      break;
    case 0x66:
      hs->p_66 = c;
      pref |= PRE_66;
      break;
    case 0x67:
      hs->p_67 = c;
      pref |= PRE_67;
      break;
    default:
      goto pref_done;
    }
pref_done:

  hs->flags = (uint32_t)pref << 23;

  if (!pref)
    pref |= PRE_NONE;

  if ((hs->opcode = c) == 0x0f) {
    hs->opcode2 = c = *p++;
    ht += DELTA_OPCODES;
  }
  else if (c >= 0xa0 && c <= 0xa3) {
    if (pref & PRE_67)
      pref |= PRE_66;
    else
      pref &= ~PRE_66;
  }

  opcode = c;
  cflags = ht[ht[opcode / 4] + (opcode % 4)];

  if (cflags == C_ERROR) {
    hs->flags |= F_ERROR | F_ERROR_OPCODE;
    cflags = 0;
    if ((opcode & -3) == 0x24)
      cflags++;
  }

  x = 0;
  if (cflags & C_GROUP) {
    uint16_t t;
    t = *(uint16_t*)(ht + (cflags & 0x7f));
    cflags = (uint8_t)t;
    x = (uint8_t)(t >> 8);
  }

  if (hs->opcode2) {
    ht = hde32_table + DELTA_PREFIXES;
    if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
      hs->flags |= F_ERROR | F_ERROR_OPCODE;
  }

  if (cflags & C_MODRM) {
    hs->flags |= F_MODRM;
    hs->modrm = c = *p++;
    hs->modrm_mod = m_mod = c >> 6;
    hs->modrm_rm = m_rm = c & 7;
    hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

    if (x && ((x << m_reg) & 0x80))
      hs->flags |= F_ERROR | F_ERROR_OPCODE;

    if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
      uint8_t t = opcode - 0xd9;
      if (m_mod == 3) {
        ht = hde32_table + DELTA_FPU_MODRM + t * 8;
        t = ht[m_reg] << m_rm;
      }
      else {
        ht = hde32_table + DELTA_FPU_REG;
        t = ht[t] << m_reg;
      }
      if (t & 0x80)
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (pref & PRE_LOCK) {
      if (m_mod == 3) {
        hs->flags |= F_ERROR | F_ERROR_LOCK;
      }
      else {
        uint8_t const* table_end;
        uint8_t op = opcode;

        if (hs->opcode2) {
          ht = hde32_table + DELTA_OP2_LOCK_OK;
          table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
        }
        else {
          ht = hde32_table + DELTA_OP_LOCK_OK;
          table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
          op &= -2;
        }
        for (; ht != table_end; ht++)
          if (*ht++ == op) {
            if (!((*ht << m_reg) & 0x80))
              goto no_lock_error;
            else
              break;
          }
        hs->flags |= F_ERROR | F_ERROR_LOCK;
      no_lock_error:
        ;
      }
    }

    if (hs->opcode2) {
      switch (opcode) {
      case 0x20: case 0x22:
        m_mod = 3;
        if (m_reg > 4 || m_reg == 1)
          goto error_operand;
        else
          goto no_error_operand;
      case 0x21: case 0x23:
        m_mod = 3;
        if (m_reg == 4 || m_reg == 5)
          goto error_operand;
        else
          goto no_error_operand;
      }
    }
    else {
      switch (opcode) {
      case 0x8c:
        if (m_reg > 5)
          goto error_operand;
        else
          goto no_error_operand;
      case 0x8e:
        if (m_reg == 1 || m_reg > 5)
          goto error_operand;
        else
          goto no_error_operand;
      }
    }

    if (m_mod == 3) {
      uint8_t const* table_end;
      if (hs->opcode2) {
        ht = hde32_table + DELTA_OP2_ONLY_MEM;
        table_end = ht + sizeof(hde32_table) - DELTA_OP2_ONLY_MEM;
      }
      else {
        ht = hde32_table + DELTA_OP_ONLY_MEM;
        table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
      }
      for (; ht != table_end; ht += 2)
        if (*ht++ == opcode) {
          if (*ht++ & pref && !((*ht << m_reg) & 0x80))
            goto error_operand;
          else
            break;
        }
      goto no_error_operand;
    }
    else if (hs->opcode2) {
      switch (opcode) {
      case 0x50: case 0xd7: case 0xf7:
        if (pref & (PRE_NONE | PRE_66))
          goto error_operand;
        break;
      case 0xd6:
        if (pref & (PRE_F2 | PRE_F3))
          goto error_operand;
        break;
      case 0xc5:
        goto error_operand;
      }
      goto no_error_operand;
    }
    else
      goto no_error_operand;

  error_operand:
    hs->flags |= F_ERROR | F_ERROR_OPERAND;
  no_error_operand:

    c = *p++;
    if (m_reg <= 1) {
      if (opcode == 0xf6)
        cflags |= C_IMM8;
      else if (opcode == 0xf7)
        cflags |= C_IMM_P66;
    }

    switch (m_mod) {
    case 0:
      if (pref & PRE_67) {
        if (m_rm == 6)
          disp_size = 2;
      }
      else
        if (m_rm == 5)
          disp_size = 4;
      break;
    case 1:
      disp_size = 1;
      break;
    case 2:
      disp_size = 2;
      if (!(pref & PRE_67))
        disp_size <<= 1;
    }

    if (m_mod != 3 && m_rm == 4 && !(pref & PRE_67)) {
      hs->flags |= F_SIB;
      p++;
      hs->sib = c;
      hs->sib_scale = c >> 6;
      hs->sib_index = (c & 0x3f) >> 3;
      if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
        disp_size = 4;
    }

    p--;
    switch (disp_size) {
    case 1:
      hs->flags |= F_DISP8;
      hs->disp.disp8 = *p;
      break;
    case 2:
      hs->flags |= F_DISP16;
      hs->disp.disp16 = *(uint16_t*)p;
      break;
    case 4:
      hs->flags |= F_DISP32;
      hs->disp.disp32 = *(uint32_t*)p;
    }
    p += disp_size;
  }
  else if (pref & PRE_LOCK)
    hs->flags |= F_ERROR | F_ERROR_LOCK;

  if (cflags & C_IMM_P66) {
    if (cflags & C_REL32) {
      if (pref & PRE_66) {
        hs->flags |= F_IMM16 | F_RELATIVE;
        hs->imm.imm16 = *(uint16_t*)p;
        p += 2;
        goto disasm_done;
      }
      goto rel32_ok;
    }
    if (pref & PRE_66) {
      hs->flags |= F_IMM16;
      hs->imm.imm16 = *(uint16_t*)p;
      p += 2;
    }
    else {
      hs->flags |= F_IMM32;
      hs->imm.imm32 = *(uint32_t*)p;
      p += 4;
    }
  }

  if (cflags & C_IMM16) {
    if (hs->flags & F_IMM32) {
      hs->flags |= F_IMM16;
      hs->disp.disp16 = *(uint16_t*)p;
    }
    else if (hs->flags & F_IMM16) {
      hs->flags |= F_2IMM16;
      hs->disp.disp16 = *(uint16_t*)p;
    }
    else {
      hs->flags |= F_IMM16;
      hs->imm.imm16 = *(uint16_t*)p;
    }
    p += 2;
  }
  if (cflags & C_IMM8) {
    hs->flags |= F_IMM8;
    hs->imm.imm8 = *p++;
  }

  if (cflags & C_REL32) {
  rel32_ok:
    hs->flags |= F_IMM32 | F_RELATIVE;
    hs->imm.imm32 = *(uint32_t*)p;
    p += 4;
  }
  else if (cflags & C_REL8) {
    hs->flags |= F_IMM8 | F_RELATIVE;
    hs->imm.imm8 = *p++;
  }

disasm_done:

  if ((hs->len = (uint8_t)(p - static_cast<ptrdiff_t>(code))) > 15) {
    hs->flags |= F_ERROR | F_ERROR_LENGTH;
    hs->len = 15;
  }

  return (unsigned int)hs->len;
}

// ^^^ HKLIB_ARCH == HKLIB_X86 ^^^
#elif HKLIB_ARCH == HKLIB_X64

inline uint32_t hooklib::impl::hde::hde64_disasm(detail::pointer code, hde64s* hs) {
  uint8_t x, c;
  uint8_t* p = code;
  uint8_t cflags, opcode, pref = 0;
  uint8_t const* ht = hde64_table;
  uint8_t m_mod, m_reg, m_rm, disp_size = 0;
  uint8_t op64 = 0;

  memset(hs, 0, sizeof(hde64s));

  for (x = 16; x; x--)
    switch (c = *p++) {
    case 0xf3:
      hs->p_rep = c;
      pref |= PRE_F3;
      break;
    case 0xf2:
      hs->p_rep = c;
      pref |= PRE_F2;
      break;
    case 0xf0:
      hs->p_lock = c;
      pref |= PRE_LOCK;
      break;
    case 0x26: case 0x2e: case 0x36:
    case 0x3e: case 0x64: case 0x65:
      hs->p_seg = c;
      pref |= PRE_SEG;
      break;
    case 0x66:
      hs->p_66 = c;
      pref |= PRE_66;
      break;
    case 0x67:
      hs->p_67 = c;
      pref |= PRE_67;
      break;
    default:
      goto pref_done;
    }
pref_done:

  hs->flags = (uint32_t)pref << 23;

  if (!pref)
    pref |= PRE_NONE;

  if ((c & 0xf0) == 0x40) {
    hs->flags |= F_PREFIX_REX;
    if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
      op64++;
    hs->rex_r = (c & 7) >> 2;
    hs->rex_x = (c & 3) >> 1;
    hs->rex_b = c & 1;
    if (((c = *p++) & 0xf0) == 0x40) {
      opcode = c;
      goto error_opcode;
    }
  }

  if ((hs->opcode = c) == 0x0f) {
    hs->opcode2 = c = *p++;
    ht += DELTA_OPCODES;
  }
  else if (c >= 0xa0 && c <= 0xa3) {
    op64++;
    if (pref & PRE_67)
      pref |= PRE_66;
    else
      pref &= ~PRE_66;
  }

  opcode = c;
  cflags = ht[ht[opcode / 4] + (opcode % 4)];

  if (cflags == C_ERROR) {
  error_opcode:
    hs->flags |= F_ERROR | F_ERROR_OPCODE;
    cflags = 0;
    if ((opcode & -3) == 0x24)
      cflags++;
  }

  x = 0;
  if (cflags & C_GROUP) {
    uint16_t t;
    t = *(uint16_t*)(ht + (cflags & 0x7f));
    cflags = (uint8_t)t;
    x = (uint8_t)(t >> 8);
  }

  if (hs->opcode2) {
    ht = hde64_table + DELTA_PREFIXES;
    if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
      hs->flags |= F_ERROR | F_ERROR_OPCODE;
  }

  if (cflags & C_MODRM) {
    hs->flags |= F_MODRM;
    hs->modrm = c = *p++;
    hs->modrm_mod = m_mod = c >> 6;
    hs->modrm_rm = m_rm = c & 7;
    hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

    if (x && ((x << m_reg) & 0x80))
      hs->flags |= F_ERROR | F_ERROR_OPCODE;

    if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
      uint8_t t = opcode - 0xd9;
      if (m_mod == 3) {
        ht = hde64_table + DELTA_FPU_MODRM + t * 8;
        t = ht[m_reg] << m_rm;
      }
      else {
        ht = hde64_table + DELTA_FPU_REG;
        t = ht[t] << m_reg;
      }
      if (t & 0x80)
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (pref & PRE_LOCK) {
      if (m_mod == 3) {
        hs->flags |= F_ERROR | F_ERROR_LOCK;
      }
      else {
        uint8_t const* table_end;
        uint8_t op = opcode;
        if (hs->opcode2) {
          ht = hde64_table + DELTA_OP2_LOCK_OK;
          table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
        }
        else {
          ht = hde64_table + DELTA_OP_LOCK_OK;
          table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
          op &= -2;
        }
        for (; ht != table_end; ht++)
          if (*ht++ == op) {
            if (!((*ht << m_reg) & 0x80))
              goto no_lock_error;
            else
              break;
          }
        hs->flags |= F_ERROR | F_ERROR_LOCK;
      no_lock_error:
        ;
      }
    }

    if (hs->opcode2) {
      switch (opcode) {
      case 0x20: case 0x22:
        m_mod = 3;
        if (m_reg > 4 || m_reg == 1)
          goto error_operand;
        else
          goto no_error_operand;
      case 0x21: case 0x23:
        m_mod = 3;
        if (m_reg == 4 || m_reg == 5)
          goto error_operand;
        else
          goto no_error_operand;
      }
    }
    else {
      switch (opcode) {
      case 0x8c:
        if (m_reg > 5)
          goto error_operand;
        else
          goto no_error_operand;
      case 0x8e:
        if (m_reg == 1 || m_reg > 5)
          goto error_operand;
        else
          goto no_error_operand;
      }
    }

    if (m_mod == 3) {
      uint8_t const* table_end;
      if (hs->opcode2) {
        ht = hde64_table + DELTA_OP2_ONLY_MEM;
        table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
      }
      else {
        ht = hde64_table + DELTA_OP_ONLY_MEM;
        table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
      }
      for (; ht != table_end; ht += 2)
        if (*ht++ == opcode) {
          if (*ht++ & pref && !((*ht << m_reg) & 0x80))
            goto error_operand;
          else
            break;
        }
      goto no_error_operand;
    }
    else if (hs->opcode2) {
      switch (opcode) {
      case 0x50: case 0xd7: case 0xf7:
        if (pref & (PRE_NONE | PRE_66))
          goto error_operand;
        break;
      case 0xd6:
        if (pref & (PRE_F2 | PRE_F3))
          goto error_operand;
        break;
      case 0xc5:
        goto error_operand;
      }
      goto no_error_operand;
    }
    else
      goto no_error_operand;

  error_operand:
    hs->flags |= F_ERROR | F_ERROR_OPERAND;
  no_error_operand:

    c = *p++;
    if (m_reg <= 1) {
      if (opcode == 0xf6)
        cflags |= C_IMM8;
      else if (opcode == 0xf7)
        cflags |= C_IMM_P66;
    }

    switch (m_mod) {
    case 0:
      if (pref & PRE_67) {
        if (m_rm == 6)
          disp_size = 2;
      }
      else
        if (m_rm == 5)
          disp_size = 4;
      break;
    case 1:
      disp_size = 1;
      break;
    case 2:
      disp_size = 2;
      if (!(pref & PRE_67))
        disp_size <<= 1;
    }

    if (m_mod != 3 && m_rm == 4) {
      hs->flags |= F_SIB;
      p++;
      hs->sib = c;
      hs->sib_scale = c >> 6;
      hs->sib_index = (c & 0x3f) >> 3;
      if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
        disp_size = 4;
    }

    p--;
    switch (disp_size) {
    case 1:
      hs->flags |= F_DISP8;
      hs->disp.disp8 = *p;
      break;
    case 2:
      hs->flags |= F_DISP16;
      hs->disp.disp16 = *(uint16_t*)p;
      break;
    case 4:
      hs->flags |= F_DISP32;
      hs->disp.disp32 = *(uint32_t*)p;
    }
    p += disp_size;
  }
  else if (pref & PRE_LOCK)
    hs->flags |= F_ERROR | F_ERROR_LOCK;

  if (cflags & C_IMM_P66) {
    if (cflags & C_REL32) {
      if (pref & PRE_66) {
        hs->flags |= F_IMM16 | F_RELATIVE;
        hs->imm.imm16 = *(uint16_t*)p;
        p += 2;
        goto disasm_done;
      }
      goto rel32_ok;
    }
    if (op64) {
      hs->flags |= F_IMM64;
      hs->imm.imm64 = *(uint64_t*)p;
      p += 8;
    }
    else if (!(pref & PRE_66)) {
      hs->flags |= F_IMM32;
      hs->imm.imm32 = *(uint32_t*)p;
      p += 4;
    }
    else
      goto imm16_ok;
  }


  if (cflags & C_IMM16) {
  imm16_ok:
    hs->flags |= F_IMM16;
    hs->imm.imm16 = *(uint16_t*)p;
    p += 2;
  }
  if (cflags & C_IMM8) {
    hs->flags |= F_IMM8;
    hs->imm.imm8 = *p++;
  }

  if (cflags & C_REL32) {
  rel32_ok:
    hs->flags |= F_IMM32 | F_RELATIVE;
    hs->imm.imm32 = *(uint32_t*)p;
    p += 4;
  }
  else if (cflags & C_REL8) {
    hs->flags |= F_IMM8 | F_RELATIVE;
    hs->imm.imm8 = *p++;
  }

disasm_done:

  if ((hs->len = (uint8_t)(p - code.getp<uint8_t>())) > 15) {
    hs->flags |= F_ERROR | F_ERROR_LENGTH;
    hs->len = 15;
  }

  return (unsigned int)hs->len;
}

#endif
