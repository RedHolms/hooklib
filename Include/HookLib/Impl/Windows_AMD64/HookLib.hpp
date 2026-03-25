#pragma once

#include <functional>
#include <memory>

namespace HookLib {

template <typename FuncT>
class FunctionHook;

namespace Details {

struct FuncInfo {
  // Will return value be placed in XMM0?
  bool xmmRetVal;
  // Will argument N be placed in XMM[N]?
  bool saveXMM[4];
};

template <typename FuncT>
struct FuncInfoGen {
  static constexpr FuncInfo Generate() {
    FuncInfo result {};

    result.xmmRetVal = false;
    result.saveXMM[0] = false;
    result.saveXMM[1] = false;
    result.saveXMM[2] = false;
    result.saveXMM[3] = false;

    return result;
  }

  static constexpr FuncInfo Value = Generate();
};

using FuncHookRelay = void (*)(void* callObj, void* payload);

class FuncHookImpl {
  template <typename FuncT>
  friend class FunctionHook;

private:
  // IMPORTANT: FuncInfo must be STATIC value because we're not copying it.
  explicit FuncHookImpl(
    FuncInfo const& targetInfo,
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

__declspec(align(16)) struct HookedCallData {
  bool canceled;

  /**
   * Stack frame looks like that:
   *    - RCX or XMM0 (second if FuncInfo::saveXMM[0])
   *    - RDX or XMM1 (second if FuncInfo::saveXMM[1])
   *    - R8 or XMM2 (second if FuncInfo::saveXMM[2])
   *    - R9 or XMM3 (second if FuncInfo::saveXMM[3])
   *    - ...Stack arguments
   */
  uintptr_t stackFrame;

  union {
    void* rax;
    __m128 xmm0;
  } returnValue;
};

static_assert(sizeof(HookedCallData) == 32, "Invalid HookedCallLayout size");

} // namespace Details

template <typename FuncT>
class HookedCall final : public Details::HookedCallData {
  HookedCall() = delete;
  ~HookedCall() = delete;

public:
};

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
    : m_impl(Details::FuncInfoGen<FuncT>::Value, target, _Relay, this) {}

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
