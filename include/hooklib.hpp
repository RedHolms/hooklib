#pragma once

#include <cstddef>
#include <stdint.h>

#include <functional>
#include <optional>
#include <numeric>
#include <tuple>

// HKLIB_ARCH
#define HKLIB_X86 0
#define HKLIB_X64 1

// HKLIB_COMPILER
#define HKLIB_MSVC  0
#define HKLIB_GNU   1
#define HKLIB_CLANG 2

// HKLIB_SYSTEM
#define HKLIB_WINDOWS 0
#define HKLIB_LINUX   1

#define HKLIB_SYSTEM   HKLIB_WINDOWS
#define HKLIB_ARCH     HKLIB_X86
#define HKLIB_COMPILER HKLIB_CLANG

#if HKLIB_SYSTEM == HKLIB_WINDOWS
#include <Windows.h>
#endif

#if HKLIB_ARCH == HKLIB_X86
#include <hooklib/hde32.h>
#else
#include <hooklib/hde64.h>
#endif

namespace hooklib {

  namespace impl {

    struct pointer {
      uintptr_t value;

      constexpr pointer()
        : value(0) {}

      constexpr pointer(uintptr_t value)
        : value(value) {}

      template <typename T>
      constexpr pointer(T* value)
        : value(reinterpret_cast<uintptr_t>(value)) {}

      constexpr pointer(std::nullptr_t)
        :value(0) {}

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
    static constexpr size_t safe_sizeof_v = sizeof(T);

    template <>
    static constexpr size_t safe_sizeof_v<void> = 0;

    template <typename T>
    using optional_return_t = std::conditional_t<std::is_void_v<T>, bool, std::optional<T>>;

    template <typename FnT>
    struct make_traits;
    
    template <typename FnT>
    using make_traits_t = make_traits<FnT>::type;

    template <typename FnTrT>
    struct make_function;
    
    template <typename FnTrT>
    using make_function_t = make_function<FnTrT>::type;

    enum call_conv {
      ccdecl,
      cstdcall,
      cthiscall
    };

    template <typename RetT, typename ArgsTplT>
    struct build_function;

    template <typename RetT, typename... ArgsT>
    struct build_function<RetT, std::tuple<ArgsT...>> {
      using type = std::function<RetT(ArgsT...)>;
    };

    template <typename RetT, typename ArgsTplT>
    using build_function_t = build_function<RetT, ArgsTplT>::type;

    template <typename RetT, call_conv CallConv, typename... ArgsT>
    struct function_traits {
      using type = function_traits<RetT, CallConv, ArgsT...>;

      using connected_function    = make_function<type>;
      using function_type         = connected_function::type;
      using function_pointer_type = connected_function::pointer_type;

      using arguments_type = std::tuple<ArgsT...>;
      using return_type = RetT;

      static constexpr size_t get_arguments_size_in_bytes() {
        constexpr size_t arguments_sizes[] = { sizeof(ArgsT)... };

        return std::accumulate(std::begin(arguments_sizes) + get_registers_count(), std::end(arguments_sizes), 0);
      }

      static constexpr size_t get_stack_frame_size() {
        constexpr auto arguments_size_in_bytes = get_arguments_size_in_bytes();

        if constexpr (safe_sizeof_v<RetT> > sizeof(uintptr_t))
          return sizeof(RetT*) + arguments_size_in_bytes;
        else
          return arguments_size_in_bytes;
      }

      static constexpr size_t get_registers_count() {
        if constexpr (CallConv == call_conv::cthiscall)
          return 1;
        else
          return 0;
      }

      static constexpr auto arguments_count = sizeof...(ArgsT);
      static constexpr auto registers_count = get_registers_count();
      static constexpr auto stack_frame_size = get_stack_frame_size();
      static constexpr auto calling_convention = CallConv;

      static constexpr bool return_value_fits_in_register = get_stack_frame_size() == get_arguments_size_in_bytes();
    };

      template <typename RetT, typename... ArgsT>
      struct make_traits<RetT(__cdecl*)(ArgsT...)> {
        using type = function_traits<RetT, ccdecl, ArgsT...>;
      };

      template <typename RetT, typename... ArgsT>
      struct make_traits<RetT(__stdcall*)(ArgsT...)> {
        using type = function_traits<RetT, cstdcall, ArgsT...>;
      };

      template <typename RetT, typename... ArgsT>
      struct make_traits<RetT(__thiscall*)(ArgsT...)> {
        using type = function_traits<RetT, cthiscall, ArgsT...>;
      };

      template <typename RetT, typename... ArgsT>
      struct make_function<function_traits<RetT, ccdecl, ArgsT...>> {
        using type          = RetT __cdecl(ArgsT...);
        using pointer_type  = RetT(__cdecl*)(ArgsT...);
      };

      template <typename RetT, typename... ArgsT>
      struct make_function<function_traits<RetT, cstdcall, ArgsT...>> {
        using type          = RetT __stdcall(ArgsT...);
        using pointer_type  = RetT(__stdcall*)(ArgsT...);
      };

      template <typename RetT, typename... ArgsT>
      struct make_function<function_traits<RetT, cthiscall, ArgsT...>> {
        using type          = RetT(__thiscall*)(ArgsT...);
        using pointer_type  = RetT(__thiscall*)(ArgsT...);
      };

    namespace mem {

      constexpr void copy(pointer destination, pointer source, size_t size) noexcept {
        uint8_t* dst = destination;
        uint8_t* src = source;

        for (size_t i = 0; i < size; ++i)
          dst[i] = src[i];
      }

      template <typename T>
      constexpr void fill(pointer destination, size_t count, T value) {
        T* dst = destination;

        for (size_t i = 0; i < count; ++i) {
          dst[i] = value;
        }
      }

      template <typename T>
      constexpr void write(pointer address, T value) noexcept {
        static_cast<T*>(address)[0] = value;
      }

      template <typename T>
      constexpr void read(pointer address) noexcept {
        return static_cast<T*>(address)[0];
      }
      
      pointer alloc_aligned(size_t count) noexcept;
      void free_aligned(pointer data) noexcept;
      void flush_instruction_cache(pointer address, size_t size) noexcept;

      void allow_execute(pointer address, size_t size) noexcept;
      void forbid_execute(pointer address, size_t size) noexcept;
      void allow_write(pointer address, size_t size) noexcept;
      void forbid_write(pointer address, size_t size) noexcept;

    } // namespace mem

    namespace relay {

      template <typename HookT, typename RetT, typename... ArgsT>
      inline RetT function_hook_relay(HookT* hook, ArgsT... args) {
        auto callback = hook->get_callback();

        if (callback) {
          auto retval = callback(args...);

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

    template <typename HookT, typename FnTrT>
    struct function_hook_relay_generator;

    template <typename HookT, typename RetT, call_conv CallConv, typename... ArgsT>
    struct function_hook_relay_generator<HookT, function_traits<RetT, CallConv, ArgsT...>> {
      static RetT __cdecl relay(HookT* hook, void*, ArgsT... args) {
        return relay::function_hook_relay<HookT, RetT, ArgsT...>(hook, args...);
      }
    };

    namespace assembly {

      static constexpr size_t page_size = 4096;

      class code_array {
      public:
        code_array() {
          m_p = m_frame = m_data = mem::alloc_aligned(page_size);

          mem::forbid_execute(m_data, page_size);
          mem::allow_write(m_data, page_size);
        }

        constexpr ~code_array() {
          mem::free_aligned(m_data);
        }

      public:
        template <typename T>
        constexpr void write(T value) noexcept {
          mem::write(m_p, value);
          m_p += sizeof(T);
        }

        constexpr void write_bytes(pointer data, size_t count) noexcept {
          uint8_t* src = data;

          for (size_t i = 0; i < count; ++i)
            write<uint8_t>(src[i]);
        }

        template <typename T>
        constexpr void op_rel(pointer destination, uint8_t opcode) noexcept {
          T offset = destination - current() - 5;

          write<uint8_t>(opcode);
          write<T>(offset);
        }

        constexpr void op_rel_jump(pointer destination) noexcept {
          op_rel<uint32_t>(destination, 0xE9);
        }

        constexpr void op_rel_call(pointer destination) noexcept {
          op_rel<uint32_t>(destination, 0xE8);
        }

        constexpr pointer current() noexcept {
          return m_p;
        }

        constexpr pointer data() const noexcept {
          return m_data;
        }

        constexpr size_t size() const noexcept {
          return m_p - m_data;
        }

        constexpr size_t frame_size() const noexcept {
          return m_p - m_frame;
        }

        constexpr void clear() noexcept {
          m_p = m_frame = m_data;
          mem::allow_write(m_data, page_size);
        }

        constexpr pointer flush() noexcept {
          mem::forbid_write(m_frame, frame_size());
          mem::allow_execute(m_data, frame_size());

          pointer frame = m_frame;
          m_frame = m_p;

          return frame;
        }

      private:
        pointer m_data = nullptr;
        pointer m_frame = nullptr;
        pointer m_p = nullptr;
      };

    }

  } // namespace impl

  template <typename FnT>
  class function_hook {
  public:
    using type = function_hook<FnT>;

    using function_traits = impl::make_traits_t<FnT>;

    using function_type = function_traits::function_type;
    using function_pointer_type = function_traits::function_pointer_type;

    using arguments_type = function_traits::arguments_type;
    using return_type = function_traits::return_type;

    static constexpr auto arguments_count = function_traits::arguments_count;
    static constexpr auto stack_frame_size = function_traits::stack_frame_size;
    static constexpr auto registers_count = function_traits::registers_count;
    static constexpr auto calling_convention = function_traits::calling_convention;
    
    static constexpr bool return_value_fits_in_register = function_traits::return_value_fits_in_register;

    using callback_type = impl::build_function_t<impl::optional_return_t<return_type>, arguments_type>;

    using relay_generator = impl::function_hook_relay_generator<type, function_traits>;

  public:
    constexpr function_hook() = default;

    constexpr function_hook(impl::pointer target_function_address)
      : function_hook()
    {
      set_target(target_function_address);
    }

    constexpr ~function_hook() {
      remove();
    }

  public:
    constexpr void set_target(impl::pointer target_function_address) noexcept {
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

    constexpr function_pointer_type get_trampoline() noexcept {
      return static_cast<function_pointer_type>(m_trampoline);
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

      mem::allow_write(m_target, m_original_prologue_size);

      if (state) {
        mem::fill<uint8_t>(m_target, m_original_prologue_size, 0x90);

        // Relative jump to m_relay_jumper
        mem::write<uint8_t>(m_target, 0xE9);
        mem::write<uint32_t>(m_target + 1, m_relay_jumper.value - m_target.value - 5);
      }
      else {
        mem::copy(m_target, m_original_prologue, m_original_prologue_size);
      }

      mem::flush_instruction_cache(m_target, m_original_prologue_size);
      mem::forbid_write(m_target, m_original_prologue_size);

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
      using namespace impl;

      // push ecx to the stack as an argument
      if (function_traits::calling_convention == impl::cthiscall) {
        // sub esp, 4
        m_code.write<uint8_t>(0x83);
        m_code.write<uint8_t>(0xEC);
        m_code.write<uint8_t>(0x04);

        // mov eax, [esp + 4]
        m_code.write<uint8_t>(0x8B);
        m_code.write<uint8_t>(0x44);
        m_code.write<uint8_t>(0x24);
        m_code.write<uint8_t>(0x04);
        
        // mov [esp], eax
        m_code.write<uint8_t>(0x89);
        m_code.write<uint8_t>(0x04);
        m_code.write<uint8_t>(0x24);

        if (not return_value_fits_in_register) {
          // mov eax, [esp + 8]
          m_code.write<uint8_t>(0x8B);
          m_code.write<uint8_t>(0x44);
          m_code.write<uint8_t>(0x24);
          m_code.write<uint8_t>(0x08);
          
          // mov [esp + 4], eax
          m_code.write<uint8_t>(0x89);
          m_code.write<uint8_t>(0x44);
          m_code.write<uint8_t>(0x24);
          m_code.write<uint8_t>(0x04);
          
          // mov [esp + 8], ecx
          m_code.write<uint8_t>(0x89);
          m_code.write<uint8_t>(0x4C);
          m_code.write<uint8_t>(0x24);
          m_code.write<uint8_t>(0x08);
        }
        else {
          // mov [esp + 4], ecx
          m_code.write<uint8_t>(0x89);
          m_code.write<uint8_t>(0x4C);
          m_code.write<uint8_t>(0x24);
          m_code.write<uint8_t>(0x04);
        }
      }

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
      m_code.write<void*>(this);

      if constexpr (not return_value_fits_in_register) {
        // push eax
        m_code.write<uint8_t>(0x50);
      }

      // relay is ALWAYS cdecl
      pointer relay_address = &relay_generator::relay;

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

      if constexpr (calling_convention == cstdcall && stack_frame_size > 0) {
        // ret stack_frame_size
        m_code.write<uint8_t>(0xC2);
        m_code.write<uint16_t>(stack_frame_size);
      }
      else {
        // ret
        m_code.write<uint8_t>(0xC3);
      }

      m_relay_jumper = m_code.flush();

      return true;
    }

    constexpr bool _generate_trampoline() {
      using namespace impl;
      using namespace impl::hde;

      hde32s hde;
      uintptr_t current = m_target;
      bool need_jump = true;

      while (true) {
        if (current - static_cast<ptrdiff_t>(m_target) >= 5) {
          break;
        }

        need_jump = true;

        hde32_disasm(pointer(current), &hde);
        
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

      m_trampoline = m_code.flush();

      return true;
    }

  private:
    bool m_installed = false;
    bool m_code_generated = false;

    uint8_t m_original_prologue[4 + 15] = { 0 };
    size_t m_original_prologue_size = 0;
    
    impl::pointer m_target;
    impl::pointer m_relay_jumper;
    impl::pointer m_trampoline;

    callback_type m_callback;

    impl::assembly::code_array m_code;
  };

} // namespace hooklib
