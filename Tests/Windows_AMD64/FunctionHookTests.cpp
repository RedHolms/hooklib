#include <gtest/gtest.h>

#include "HookLib/Impl/Windows_AMD64/HookLib.hpp"
#include "main.hpp"
#include <random>

static int Counter = 0;
static void IncrementCounter() {
  ++Counter;
}

static uintptr_t IncrementCounterAddress = reinterpret_cast<uintptr_t>(&IncrementCounter);

TEST(FunctionHookTests, NoArgsNoRet) {
  HookLib::FunctionHook<void()> hook { IncrementCounterAddress };

  EXPECT_EQ(Counter, 0);

  // Test without hook:
  IncrementCounter();
  EXPECT_EQ(Counter, 1);

  // Test with empty hook:
  hook.Install();
  IncrementCounter();
  EXPECT_EQ(Counter, 2);

  // Test after empty hook:
  hook.Remove();
  IncrementCounter();
  EXPECT_EQ(Counter, 3);

  // Test with non-canceling hook:
  static int callbackCalled = 0;
  hook.SetCallback([](auto&) { ++callbackCalled; });
  hook.Install();
  IncrementCounter();
  EXPECT_EQ(Counter, 4);
  EXPECT_EQ(callbackCalled, 1);

  // Test replacing callback on-the-fly:
  static int callback2Called = 0;
  hook.SetCallback([](auto&) { ++callback2Called; });
  IncrementCounter();
  EXPECT_EQ(Counter, 5);
  EXPECT_EQ(callback2Called, 1);

  // Test canceling hook:
  hook.SetCallback([](auto& call) { call.Cancel(); });
  IncrementCounter();
  EXPECT_EQ(Counter, 5);

  // Test after canceling hook:
  hook.Remove();
  IncrementCounter();
  EXPECT_EQ(Counter, 6);
}

static int Accumulator = 0;
static void Accumulate(int a, int b) {
  Accumulator += a + b;
}

static uintptr_t AccumulateAddress = reinterpret_cast<uintptr_t>(&Accumulate);

template <typename>
struct ShittyStruct;

using ArgT = typename HookLib::Details::FuncTypeInfo<void(int,int)>::ArgsCollection::template Nth<0>;

TEST(FunctionHookTests, ScalarArgsNoRet) {
  HookLib::FunctionHook<void(int, int)> hook { AccumulateAddress };

  EXPECT_EQ(Accumulator, 0);

  Accumulate(1, 2);
  EXPECT_EQ(Accumulator, 3);
  Accumulate(3, 4);
  EXPECT_EQ(Accumulator, 10);

  hook.SetCallback([](auto& call) {
    EXPECT_EQ(call.Arg<0>(), 5);
    EXPECT_EQ(call.Arg<1>(), 6);
  });
  hook.Install();

  Accumulate(5, 6);
  EXPECT_EQ(Accumulator, 21);

  hook.SetCallback([](HookLib::HookedCall<void(int,int)>& call) {
    auto& a = call.Arg<0>();
    auto& b = call.Arg<1>();
    EXPECT_EQ(a, 7);
    EXPECT_EQ(b, 8);
    a -= b;
    b = -b;
  });

  Accumulate(7, 8);
  EXPECT_EQ(Accumulator, 12);
}

static int Calculate(int a, int b, int c) {
  return a + b - (b * c);
}

static uintptr_t CalculateAddress = reinterpret_cast<uintptr_t>(&Calculate);

TEST(FunctionHookTests, ScalarArgsAndRet) {
  std::mt19937_64 rng(gRandomSeed ^ std::hash<std::string> {}(__FUNCTION__));

  HookLib::FunctionHook<int(int, int, int)> hook { CalculateAddress };

  EXPECT_EQ(Calculate(1, 2, 3), -3);

  hook.SetCallback([](auto& call) {
    call.SetReturnValue(42);
  });
  hook.Install();

  std::uniform_int_distribution<> dist {};
  for (size_t i = 0; i < 100; ++i) {
    auto a = dist(rng), b = dist(rng), c = dist(rng);
    EXPECT_EQ(Calculate(a, b, c), 42);
  }
}

static double XMMCalculate(double a, float b) {
  return a / (double)b;
}

static uintptr_t XMMCalculateAddress = reinterpret_cast<uintptr_t>(&XMMCalculate);

TEST(FunctionHookTests, XMMArgsAndRet) {
  std::mt19937_64 rng(gRandomSeed ^ std::hash<std::string> {}(__FUNCTION__));

  HookLib::FunctionHook<double(double, float)> hook { XMMCalculateAddress };

  EXPECT_NEAR(XMMCalculate(12.5, 3.42), 3.654970, 0.00001);

  std::uniform_real_distribution<> dist {};
  static double testA = dist(rng);
  static float testB = dist(rng);

  hook.SetCallback([](auto& call) {
    double a = call.Arg<0>();
    float b = call.Arg<1>();
    EXPECT_EQ(a, testA);
    EXPECT_EQ(b, testB);
  });
  hook.Install();

  XMMCalculate(testA, testB);
}
