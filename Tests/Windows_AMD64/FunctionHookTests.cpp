#include "HookLib/Impl/Windows_AMD64/HookLib.hpp"

#include <gtest/gtest.h>

static int FooCalls = 0;
static void foo() {
  ++FooCalls;
}

static uintptr_t foo_addr = reinterpret_cast<uintptr_t>(&foo);

TEST(FunctionHookTests, Simple) {
  HookLib::FunctionHook<void()> fooHook { foo_addr };

  EXPECT_EQ(FooCalls, 0);
  foo();
  EXPECT_EQ(FooCalls, 1);
  fooHook.Install();
  foo();
  EXPECT_EQ(FooCalls, 2);
  fooHook.Remove();
  foo();
  EXPECT_EQ(FooCalls, 3);

  static int callbackCalled = 0;
  fooHook.SetCallback([](auto& call) {
    ++callbackCalled;
  });
  fooHook.Install();

  foo();
  EXPECT_EQ(FooCalls, 4);
  EXPECT_EQ(callbackCalled, 1);

  static int callback2Called = 0;
  fooHook.SetCallback([](auto& call) {
    ++callback2Called;
  });
  foo();
  EXPECT_EQ(FooCalls, 5);
  EXPECT_EQ(callback2Called, 1);

  fooHook.SetCallback([](auto& call) {
    call.canceled = true;
  });

  foo();
  EXPECT_EQ(FooCalls, 5);

  fooHook.Remove();
  foo();
  EXPECT_EQ(FooCalls, 6);
}
