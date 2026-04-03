#pragma once

#include "FuncUtils.hpp"
#include "HookLib/Utils.hpp"
#include <functional>
#include <memory>

namespace HookLib {

template <typename FuncT>
class FunctionHook;

namespace Details {

struct FuncHookOpts {
  bool xmmRetVal;
  bool xmmReg[4];

  template <typename FuncT>
  static consteval FuncHookOpts GetForFunc() noexcept {
    using FInfo = FuncTypeInfo<FuncT>;

    FuncHookOpts result {};
    result.xmmRetVal = IsOneOf<typename FInfo::ReturnType, float, double, __m128, __m128i, __m128d>;

    FInfo::ArgsCollection::ForEach([&result]<typename T>(std::type_identity<T>, size_t index) {
      result.xmmReg[index] = IsOneOf<T, float, double>;
    });

    return result;
  }
};

using FuncHookRelay = void (*)(void* callObj, void* payload);

class FuncHookImpl {
public:
  explicit FuncHookImpl(
    FuncHookOpts const& options,
    uintptr_t target,
    FuncHookRelay relay,
    void* relayPayload
  );
  ~FuncHookImpl();

public:
  uintptr_t GetTarget() const noexcept;
  void SetTarget(uintptr_t target) noexcept;

  void Install();
  void Remove();

private:
  struct Data;
  std::unique_ptr<Data> m;
};

__declspec(align(16)) union HookedReg {
  // Used if respective FuncInfo::xmmReg[N] is true
  __m128 xmm;

  // Used if respective FuncInfo::xmmReg[N] is false
  uintptr_t reg;
};

static_assert(sizeof(HookedReg) == 16, "Invalid HookedReg size");

// Internal structure of HookedCall<>
__declspec(align(16)) struct HookedCallData {
  // Will original call be canceled?
  //  if canceled, will return to the caller with "returnValue"
  //  if not, will call the original function
  bool canceled;

  // Values of 4 registers arguments CAN be passed with (RCX, RDX, R8, R9 or XMM[0-3]).
  // What type of register is hooked (GPR or XMM) is determined by respective FuncHookOpts::xmmReg
  HookedReg (&hookedRegs)[4];

  // Address of where stack arguments of a function will start
  uintptr_t stackArgsStart;

  // Unused. Just an explicit padding for "returnValue"
  uintptr_t __padding;

  // Return value to be used if original call was canceled
  // What field in union will be used (rax or xmm0) is determined by FuncHookOpts::xmmRetVal
  union {
    uintptr_t rax;
    __m128 xmm0;
  } returnValue;
};

static_assert(sizeof(HookedCallData) == 48, "Invalid HookedCallData size");

} // namespace Details

template <typename FuncT>
class HookedCall final : private Details::HookedCallData {
private:
  using FuncInfo = Details::FuncTypeInfo<FuncT>;

private:
  // This class is constructed in assembly
  HookedCall() = delete;
  ~HookedCall() = delete;
  HookedCall(HookedCall const&) = delete;
  HookedCall(HookedCall&&) = delete;
  HookedCall& operator=(HookedCall const&) = delete;
  HookedCall& operator=(HookedCall&&) = delete;

private:
public:
  __forceinline void Cancel() noexcept {
    canceled = true;
  }

  __forceinline void SetReturnValue(uintptr_t rax) noexcept {
    canceled = true;
    returnValue.rax = rax;
  }

  // Get reference to an argument at index "I"
  template <size_t I>
  constexpr auto& Arg() noexcept {
    using ArgT = FuncInfo::ArgsCollection::template Nth<I>;

    constexpr bool canBePacked =
      (sizeof(ArgT) == 1 || sizeof(ArgT) == 2 || sizeof(ArgT) == 4 || sizeof(ArgT) == 8) &&
      std::is_trivially_copyable_v<ArgT> && std::is_standard_layout_v<ArgT>;

    constexpr size_t index = I;

    if constexpr (index < 4) {
      auto& regValue = hookedRegs[index];
      if constexpr (canBePacked) {
        if constexpr (std::is_same_v<ArgT, float> || std::is_same_v<ArgT, double>) {
          return static_cast<ArgT&>(*reinterpret_cast<ArgT*>(&regValue.xmm));
        }
        else {
          return static_cast<ArgT&>(*reinterpret_cast<ArgT*>(&regValue.reg));
        }
      }
      else {
        // Passed py pointer
        return static_cast<ArgT&>(*reinterpret_cast<ArgT*>(regValue.reg));
      }
    }
    else {
      uintptr_t valueAddr = stackArgsStart + (index * sizeof(uintptr_t));
      if constexpr (canBePacked) {
        return static_cast<ArgT&>(*reinterpret_cast<ArgT*>(valueAddr));
      }
      else {
        return static_cast<ArgT&>(**reinterpret_cast<ArgT**>(valueAddr));
      }
    }
  }
};

/**
 * Hook that installs on a function and hooks all calls to that function.
 */
template <typename FuncT>
class FunctionHook final {
public:
  using Call = HookedCall<FuncT>;
  using Callback = std::function<void(Call& call)>;

private:
  static void _Relay(void* callObj, void* payload) {
    auto self = static_cast<FunctionHook*>(payload);
    if (self->m_callback) {
      self->m_callback(*static_cast<Call*>(callObj));
    }
  }

public:
  inline FunctionHook() : FunctionHook(0) {}

  inline explicit FunctionHook(uintptr_t target)
    : m_impl(Details::FuncHookOpts::GetForFunc<FuncT>(), target, _Relay, this) {}

  FunctionHook(FunctionHook const&) = delete;
  FunctionHook(FunctionHook&&) = delete;
  FunctionHook& operator=(FunctionHook const&) = delete;
  FunctionHook& operator=(FunctionHook&&) = delete;

public:
  inline uintptr_t GetTarget() const noexcept {
    return m_impl.GetTarget();
  }

  inline void SetTarget(uintptr_t target) noexcept {
    m_impl.SetTarget(target);
  }

  inline void SetCallback(Callback&& callback) {
    m_callback = std::move(callback);
  }

  inline void SetCallback(Callback const& callback) {
    m_callback = callback;
  }

  inline void Install() {
    m_impl.Install();
  }

  inline void Remove() {
    m_impl.Remove();
  }

private:
  Details::FuncHookImpl m_impl;
  Callback m_callback;
};

} // namespace HookLib
