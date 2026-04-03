#pragma once

#include <cstddef>
#include <cstdint>

/**
 * Handle to a memory range that contains assembly code.
 * Can be empty (invalid)
 */
class AssemblySegment {
  friend class AssemblyPool;

public:
  uintptr_t address = 0;
  size_t bytesCount = 0;

public:
  // Constructor for INVALID segment
  constexpr explicit AssemblySegment() noexcept = default;

private:
  // Accessible only from AssemblyPool
  constexpr AssemblySegment(uintptr_t address, size_t bytesCount) noexcept
    : address(address),
      bytesCount(bytesCount) {}

public:
  inline ~AssemblySegment() noexcept {
    if (*this != nullptr)
      Free();
  }

  AssemblySegment(AssemblySegment const&) = delete;
  AssemblySegment& operator=(AssemblySegment const&) = delete;

  constexpr AssemblySegment(AssemblySegment&& other) noexcept
    : address(other.address),
      bytesCount(other.bytesCount) {
    other.address = 0;
    other.bytesCount = 0;
  }

  inline AssemblySegment& operator=(AssemblySegment&& other) noexcept {
    if (*this != nullptr)
      Free();
    address = other.address;
    bytesCount = other.bytesCount;
    other.address = 0;
    other.bytesCount = 0;
    return *this;
  }

public:
  constexpr bool operator==(std::nullptr_t) const noexcept {
    return address == 0;
  }

  constexpr bool operator!=(std::nullptr_t) const noexcept {
    return address != 0;
  }

private:
  // Free the segment. Note that "address" will remain its value.
  void Free() noexcept;
};
