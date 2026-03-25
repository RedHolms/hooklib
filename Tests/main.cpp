#include <gtest/gtest.h>
#include <random>
#include <string.h>

uint64_t gRandomSeed = 0;

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "--seed=", 7) == 0) {
      gRandomSeed = std::stoull(argv[i] + 7);
    }
  }

  if (gRandomSeed == 0) {
    std::random_device rd;
    gRandomSeed = (static_cast<uint64_t>(rd()) << 32) | rd();
  }

  std::cout << "Test random seed: " << gRandomSeed << std::endl;

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
