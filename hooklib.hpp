#pragma once
#define HKLIB_HEADER_ONLY 1

#include <stdint.h>

#include <functional>
#include <optional>
#include <tuple>
#include <memory>

#if !defined(_WIN32) || !defined(_MSC_VER)
#error "Accepted only MSVC with Windows"
#endif

#if defined(_WIN64)
#error "Accepted only 32 bit"
#endif

namespace hooklib {
  template <typename FnT>
  class function_hook;

  namespace internal {}
}

namespace hooklib::internal {

  template <typename T>
  struct optional_return {
    using type = std::optional<T>;
  };

  template <>
  struct optional_return<void> {
    using type = bool;
  };

  template <typename T>
  using optional_return_t = optional_return<T>::type;

  template <typename FnTrT>
  struct connect_function {
    using type = void;
  };

  template <typename FnTrT>
  using connect_function_t = connect_function<FnTrT>::type;

  template <typename FnT>
  struct build_function_traits {
    using type = void;
  };

  template <typename FnT>
  using build_function_traits_t = build_function_traits<FnT>::type;

  template <typename RetT, typename ArgsTplT>
  struct build_overlapping_callback {
    using type = void;
  };

  template <typename RetT, typename... ArgsT>
  struct build_overlapping_callback<RetT, std::tuple<ArgsT...>> {
    using type = std::function<optional_return_t<RetT>(ArgsT...)>;
  };

  template <typename RetT, typename ArgsTplT>
  using build_overlapping_callback_t = build_overlapping_callback<RetT, ArgsTplT>::type;


  enum calling_conv {
    cc_cdecl,
    cc_stdcall
  };

  template <typename RetT, calling_conv CConv, typename... ArgsT>
  struct function_traits {
    using type = function_traits<RetT, CConv, ArgsT...>;

    using function_type = connect_function_t<type>;

    using return_type = RetT;
    using optional_return_type = optional_return_t<return_type>;

    using arguments_type = std::tuple<ArgsT...>;
    static constexpr auto arguments_count = sizeof...(ArgsT);

    static constexpr auto calling_convention = CConv;
  };

  template <typename RetT, typename... ArgsT>
  struct connect_function<function_traits<RetT, cc_cdecl, ArgsT...>> {
    using type = RetT __cdecl(ArgsT...);
  };

  template <typename RetT, typename... ArgsT>
  struct connect_function<function_traits<RetT, cc_stdcall, ArgsT...>> {
    using type = RetT __stdcall(ArgsT...);
  };

  template <typename RetT, typename... ArgsT>
  struct build_function_traits<RetT __cdecl(ArgsT...)> {
    using type = function_traits<RetT, cc_cdecl, ArgsT...>;
  };

  template <typename RetT, typename... ArgsT>
  struct build_function_traits<RetT __stdcall(ArgsT...)> {
    using type = function_traits<RetT, cc_stdcall, ArgsT...>;
  };


  struct pointer_wrapper {
    uintptr_t pointer;

    constexpr pointer_wrapper()
      : pointer(0) {}

    constexpr pointer_wrapper(uintptr_t ptr)
      : pointer(ptr) {}

    template <typename T>
    constexpr pointer_wrapper(T* ptr)
      : pointer(reinterpret_cast<uintptr_t>(ptr)) {}

    template <typename T>
    constexpr T* get_pointer() const noexcept {
      return reinterpret_cast<T*>(pointer);
    }

    template <typename T>
    constexpr T get() const noexcept {
      return reinterpret_cast<T>(pointer);
    }

    constexpr operator bool() const noexcept {
      return pointer != 0;
    }

    constexpr operator uintptr_t() const noexcept {
      return pointer;
    }
  };

  void flush_cpu_instructions_cache(uintptr_t address, size_t size);

  namespace mem {

    constexpr void copy(pointer_wrapper destination, pointer_wrapper source, size_t size) {
      auto dst = destination.get_pointer<uint8_t>();
      auto src = source.get_pointer<uint8_t>();

      for (size_t i = 0; i < size; ++i)
        dst[i] = src[i];
    }

    template <typename T>
    constexpr void write(pointer_wrapper address, T value) {
      address.get_pointer<T>()[0] = value;
    }

    template <typename T>
    constexpr void read(pointer_wrapper address) {
      return address.get_pointer<T>()[0];
    }

    enum prot : uint8_t {
      prot_noaccess,
      prot_readonly,
      prot_execute,
      prot_execute_read,
      prot_execute_read_write
    };

    std::pair<bool, prot> set_protection(uintptr_t address, size_t size, prot protection);

  } // namespace mem

  template <typename HookT, typename RetT, typename... ArgsT>
  inline RetT function_hook_relay(HookT* hook, ArgsT... args) {
    auto callback = hook->get_callback();

    if (callback) {
      auto retval = callback(args...);

      if (retval.has_value())
        return retval.value();
    }

    return hook->call(args...);
  }

  template <typename HookT, typename FnTrT>
  struct function_hook_relay_wrapper;

  template <typename HookT, typename RetT, typename... ArgsT>
  struct function_hook_relay_wrapper<HookT, function_traits<RetT, cc_cdecl, ArgsT...>> {
    static RetT __cdecl relay(HookT* hook, ArgsT... args) {
      return function_hook_relay<HookT, RetT, ArgsT...>(hook, args...);
    }
  };

  template <typename HookT, typename RetT, typename... ArgsT>
  struct function_hook_relay_wrapper<HookT, function_traits<RetT, cc_stdcall, ArgsT...>> {
    static RetT __stdcall relay(HookT* hook, ArgsT... args) {
      return function_hook_relay<HookT, RetT, ArgsT...>(hook, args...);
    }
  };

} // namespace hooklib::internal

namespace hooklib {

  template <typename FnT>
  class function_hook {
  public:
    using type = function_hook<FnT>;

    using function_traits = internal::build_function_traits_t<std::remove_pointer_t<FnT>>;

    static_assert(not std::is_same_v<function_traits, void>, "Invalid function type");

    using function_type = function_traits::function_type;
    using function_pointer_type = function_type*;

    using return_type = function_traits::return_type;

    using arguments_type = function_traits::arguments_type;

    static constexpr auto calling_convention = function_traits::calling_convention;

    using callback_type = internal::build_overlapping_callback_t<return_type, arguments_type>;

    using relay_wrapper_type = internal::function_hook_relay_wrapper<type, function_traits>;

  public:
    constexpr function_hook()
      : m_installed(false),
        m_have_installed(false),
        m_original_code{ 0 },
        m_hook_code{ 0 },
        m_relay_call_code(nullptr),
        m_return_address(0) {}

    constexpr function_hook(internal::pointer_wrapper target_function_address)
      : function_hook()
    {
      set_target(target_function_address);
    }

    constexpr ~function_hook() {
      remove();

      if (m_relay_call_code)
        delete[] m_relay_call_code;
    }

  public:
    constexpr void set_target(internal::pointer_wrapper target_function_address) noexcept {
      m_target = target_function_address;
    }

    constexpr function_pointer_type get_target() const noexcept {
      return m_target.get_pointer<function_type>();
    }

    constexpr void set_callback(callback_type const& callback) noexcept {
      m_callback = callback;
    }

    constexpr callback_type& get_callback() noexcept {
      return m_callback;
    }

    constexpr callback_type const& get_callback() const noexcept {
      return m_callback;
    }

    constexpr bool is_installed() const noexcept {
      return m_installed;
    }

    template <typename... ArgsT>
    constexpr return_type call(ArgsT... args) {
      return_type return_value;

      remove();
      return_value = m_target.get_pointer<function_type>()(args...);
      install();

      return return_value;
    }

    constexpr bool install() {
      if (m_installed)
        return false;

      _try_install();

      return m_installed;
    }

    constexpr void remove() {
      if (not m_installed)
        return;

      _try_remove();
    }

  private:
    constexpr void _try_install() {
      using namespace internal;

      std::pair<bool, mem::prot> protection
        = mem::set_protection(m_target, 5, mem::prot_execute_read_write);

      if (not protection.first)
        return;

      if (not _gen_code())
        return;
      
      if (not _patch(true))
        return;

      mem::set_protection(m_target, 5, protection.second);

      m_have_installed = true;
      m_installed = true;
    }

    constexpr bool _patch(bool enable_hook) {
      using namespace internal;

      if (enable_hook)
        mem::copy(m_target, &m_hook_code[0], 5);
      else
        mem::copy(m_target, &m_original_code[0], 5);

      flush_cpu_instructions_cache(m_target, 5);

      return true;
    }

    constexpr bool _gen_code() {
      using namespace internal;

      if (m_have_installed)
        return true;

      mem::copy(&m_original_code[0], m_target, 5);

      if (not _gen_handler_call_code())
        return false;

      if (not _gen_hook_code())
        return false;

      return true;
    }

    constexpr bool _gen_hook_code() {
      using namespace internal;

      if (not m_relay_call_code)
        return false;

      pointer_wrapper relay_caller = m_relay_call_code;
      pointer_wrapper hook_code = m_hook_code;

      // relative jump
      mem::write<uint8_t>(
        hook_code.pointer,
        0xE9
      );

      // jump to m_relay_call_code
      mem::write<uintptr_t>(
        hook_code.pointer + 1,
        relay_caller.pointer - m_target.pointer - 5
      );

      return true;
    }

    constexpr bool _gen_handler_call_code() {
      using namespace internal;

      if (m_relay_call_code)
        return true;

      /*
        pop eax
        mov [m_return_address], eax
        push this
        call relay_wrapper_type::relay
        nop
        push eax
        mov eax, [m_return_address]
        mov [esp + 4], eax
        pop eax
        ret
      */
      static constexpr uint8_t CDECL_CODE[] = {
        0x58, 0xa3, 0x11, 0x11, 0x11, 0x11, 0x68, 0x22,
        0x22, 0x22, 0x22, 0xe8, 0x23, 0x33, 0x33, 0x33,
        0x90, 0x50, 0xa1, 0x11, 0x11, 0x11, 0x11, 0x89,
        0x44, 0x24, 0x04, 0x58, 0xc3
      };

      /*
        pop eax
        mov [m_return_address], eax
        push this
        call relay_wrapper_type::relay
        push eax
        push eax
        mov eax, [m_return_address]
        mov [esp + 4], eax
        pop eax
        ret
      */
      static constexpr uint8_t STDCALL_CODE[] = {
        0x58, 0xa3, 0x11, 0x11, 0x11, 0x11, 0x68, 0x22,
        0x22, 0x22, 0x22, 0xe8, 0x23, 0x33, 0x33, 0x33,
        0x50, 0x50, 0xa1, 0x11, 0x11, 0x11, 0x11, 0x89,
        0x44, 0x24, 0x04, 0x58, 0xc3
      };

      static_assert(sizeof(CDECL_CODE) == sizeof(STDCALL_CODE), "Invalid relay caller code");

      static constexpr auto CODE_SIZE = sizeof(CDECL_CODE);

      pointer_wrapper return_address_variable = &m_return_address;
      pointer_wrapper handler_address = &relay_wrapper_type::relay;

      m_relay_call_code = new uint8_t[CODE_SIZE];

      if constexpr (calling_convention == cc_cdecl)
        mem::copy(m_relay_call_code, CDECL_CODE, CODE_SIZE);
      else if constexpr (calling_convention == cc_stdcall)
        mem::copy(m_relay_call_code, STDCALL_CODE, CODE_SIZE);

      mem::write<uintptr_t>(
        m_relay_call_code + 2,
        return_address_variable.pointer
      );

      mem::write<uintptr_t>(
        m_relay_call_code + 7,
        pointer_wrapper(this).pointer
      );

      mem::write<uintptr_t>(
        m_relay_call_code + 12,
        handler_address.pointer - (pointer_wrapper(m_relay_call_code).pointer + 11) - 5
      );

      mem::write<uintptr_t>(
        m_relay_call_code + 19,
        return_address_variable.pointer
      );

      if (
        not mem::set_protection(
          pointer_wrapper(m_relay_call_code).pointer,
          CODE_SIZE, mem::prot_execute_read_write
        ).first
      ) {
        delete[] m_relay_call_code;
        m_relay_call_code = nullptr;

        return false;
      }

      return true;
    }

    constexpr void _try_remove() {
      using namespace internal;

      // Don't check anything because it's meaningless
      // Jump hope that everything will go well

      std::pair<bool, mem::prot> protection
        = mem::set_protection(m_target, 5, mem::prot_execute_read_write);

      _patch(false);

      mem::set_protection(m_target, 5, protection.second);

      m_installed = false;
    }

  private:
    bool m_installed;
    bool m_have_installed;
    internal::pointer_wrapper m_target;
    callback_type m_callback;
    uint8_t m_original_code[5];
    uint8_t m_hook_code[5];
    uint8_t* m_relay_call_code;
    uintptr_t m_return_address;
  };

} // namespace hooklib
