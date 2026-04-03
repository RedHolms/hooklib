#include <gtest/gtest.h>

#include "Impl/Windows_AMD64/Trampolines.hpp"

static int Counter = 0;
static void IncrementCounter() {
  ++Counter;
}

TEST(TrampolineTests, SIMPLE) {
  AssemblyWriter as;

  EXPECT_EQ(Counter, 0);
  IncrementCounter();
  EXPECT_EQ(Counter, 1);

  CreateTrampoline(reinterpret_cast<uintptr_t>(&IncrementCounter), as, true);
  auto seg = as.Commit(gAssemblyPool);

  IncrementCounter();
  EXPECT_EQ(Counter, 2);

  auto fooTramp = reinterpret_cast<decltype(&IncrementCounter)>(seg.address);
  fooTramp();
  EXPECT_EQ(Counter, 3);
}
