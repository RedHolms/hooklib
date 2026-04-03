#pragma once

#include "FuncUtils.hpp"
#include "HookLib/Utils.hpp"
#include <bit>
#include <functional>
#include <memory>

namespace HookLib {

template <typename FuncT>
class HookedCall;

template <typename FuncT>
class FunctionHook;

namespace Details {

// FIXME: We need only lower 64 bits from XMM anyway, so why allocating so much space?
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

  // Address of HookedCall<> object
  uintptr_t hookObject;

  // Return value to be used if original call was canceled
  // What field in union will be used (rax or xmm0) is determined by FuncHookOpts::xmmRetVal
  union {
    uintptr_t rax;
    __m128 xmm0;
  } returnValue;
};

static_assert(sizeof(HookedCallData) == 48, "Invalid HookedCallData size");

using FuncHookRelay = void (*)(HookedCallData* callObj);

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

  uintptr_t GetTrampoline() const noexcept;

  void Install();
  void Remove();

private:
  struct Data;
  std::unique_ptr<Data> m;
};

template <typename FuncT>
class _HookedCallBase0 : protected HookedCallData {
private:
  using FuncInfo = FuncTypeInfo<FuncT>;

public:
  template <typename... ArgsT>
  constexpr auto CallOriginal(ArgsT&&... args) const noexcept {
    auto func = std::bit_cast<typename FuncInfo::PtrType>(GetHook()->GetTrampoline());
    return std::invoke(func, std::forward<ArgsT>(args)...);
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

protected:
  constexpr FuncHookImpl* GetHook() const noexcept {
    return reinterpret_cast<FuncHookImpl*>(hookObject);
  }
};

template <typename FuncT>
class _HookedCallBase1_VoidRet : public _HookedCallBase0<FuncT> {
public:
  constexpr void Cancel() noexcept {
    this->canceled = true;
  }
};

template <typename FuncT>
class _HookedCallBase1_NonVoidRet : public _HookedCallBase0<FuncT> {
private:
  using FuncInfo = FuncTypeInfo<FuncT>;

public:
  constexpr void SetReturnValue(FuncInfo::ReturnType const& retVal) noexcept {
    // TODO big values (ptr as first parameter)
    using RetT = FuncInfo::ReturnType;

    constexpr bool xmmRet = FuncHookOpts::GetForFunc<FuncT>().xmmRetVal;

    if constexpr (xmmRet) {
      auto& xmmRef = this->returnValue.xmm0;

      if constexpr (std::is_same_v<RetT, float>) {
        xmmRef.m128_f32[0] = retVal;
      }
      else if constexpr (std::is_same_v<RetT, double>) {
        std::bit_cast<__m128d*>(&xmmRef)->m128d_f64[0] = retVal;
      }
      else if constexpr (std::is_same_v<RetT, __m128> || std::is_same_v<RetT, __m128d> ||
                         std::is_same_v<RetT, __m128i>) {
        xmmRef = std::bit_cast<__m128>(retVal);
      }
      else {
        static_assert(false, "Invalid XMM return type");
      }
    }
    else {
      this->returnValue.rax = retVal;
    }

    this->canceled = true;
  }
};

// Implements return values
template <typename FuncT>
using _HookedCallBase1 = std::conditional_t<
  std::is_void_v<typename FuncTypeInfo<FuncT>::ReturnType>,
  _HookedCallBase1_VoidRet<FuncT>,
  _HookedCallBase1_NonVoidRet<FuncT>>;

template <typename FuncT>
class _HookedCallBase : public _HookedCallBase1<FuncT> {};

} // namespace Details

template <typename FuncT>
class HookedCall final : public Details::_HookedCallBase<FuncT> {
  HookedCall() = delete;
  ~HookedCall() = delete;
  HookedCall(HookedCall const&) = delete;
  HookedCall(HookedCall&&) = delete;
  HookedCall& operator=(HookedCall const&) = delete;
  HookedCall& operator=(HookedCall&&) = delete;
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
  static void _Relay(Details::HookedCallData* callData) {
    auto self = reinterpret_cast<FunctionHook*>(callData->hookObject);
    if (self->m_callback) {
      self->m_callback(*reinterpret_cast<Call*>(callData));
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
