#include <gtest/gtest.h>

#include "Impl/Windows_AMD64/Trampolines.hpp"

static int FooCalls = 0;
static void foo() {
  ++FooCalls;
}

TEST(TrampolineTests, SIMPLE) {
  AssemblyWriter as;

  EXPECT_EQ(FooCalls, 0);
  foo();
  EXPECT_EQ(FooCalls, 1);

  CreateTrampoline(reinterpret_cast<uintptr_t>(&foo), as, true);
  auto seg = as.Commit(gAssemblyPool);

  foo();
  EXPECT_EQ(FooCalls, 2);

  auto fooTramp = reinterpret_cast<decltype(&foo)>(seg.address);
  fooTramp();
  EXPECT_EQ(FooCalls, 3);
}
