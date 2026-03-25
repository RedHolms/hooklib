#pragma once

#include "AssemblyPool.hpp"
#include <vector>

/**
 * Utility class to generate x86-64 assembly
 */
class AssemblyWriter {
public:
  inline AssemblyWriter() {
    m_buffer.reserve(64);
  }
  inline explicit AssemblyWriter(size_t prealloc) : m_buffer(prealloc) {}

public:
  inline size_t Size() const noexcept {
    return m_buffer.size();
  }

  inline void Clear() noexcept {
    m_buffer.clear();
    m_relatives.clear();
  }

  inline void byte(uint8_t byte) noexcept {
    *SpaceFor<uint8_t>() = byte;
  }

  inline void word(uint16_t word) noexcept {
    *SpaceFor<uint16_t>() = word;
  }

  inline void dword(uint32_t dword) noexcept {
    *SpaceFor<uint32_t>() = dword;
  }

  inline void qword(uint64_t qword) noexcept {
    *SpaceFor<uint64_t>() = qword;
  }

  inline void pointer(void const* ptr) noexcept {
    *SpaceFor<void const*>() = ptr;
  }

  inline void rel(uintptr_t ptr, size_t pivot = 4) noexcept {
    dword(0);
    PushRelative(Size() - 4, ptr, pivot);
  }

  inline void bytes(void const* data, size_t bytesCount) noexcept {
    memcpy(SpaceFor(bytesCount), data, bytesCount);
  }

  inline void bytes(std::initializer_list<uint8_t> bytesList) {
    bytes(bytesList.begin(), bytesList.size());
  }

  inline void absJmp(uintptr_t target) noexcept {
    byte(0xFF);         // JMP
    byte(0x25);
    dword(0x00000000);  // [RIP+0] (TARGET)
    qword(target);      // TARGET: .dq target
  }

  inline void absCall(uintptr_t target) noexcept {
    byte(0xFF);         // CALL
    byte(0x15);
    dword(0x00000002);  // [RIP+2] (TARGET)
    byte(0xEB);         // JMP
    byte(0x08);         // +0x08 (past TARGET)
    qword(target);      // TARGET: .dq target
  }

  inline void PushRelative(size_t offset, uintptr_t ptr, size_t pivot = 4) noexcept {
    m_relatives.emplace_back(offset, ptr - pivot);
  }

  // Puts generated assembly to a memory and clears the buffer
  // If allocation failed, empty segment is returned and buffer is not cleared
  inline AssemblySegment Commit(AssemblyPool& pool, uintptr_t nearToAddress = 0) noexcept {
    auto segment = pool.AllocateNear(m_buffer.size(), nearToAddress);
    if (segment.address == 0)
      return segment;

    memcpy(reinterpret_cast<void*>(segment.address), m_buffer.data(), m_buffer.size());

    for (auto rel : m_relatives) {
      auto offset = rel.first;
      auto dest = reinterpret_cast<uint32_t*>(segment.address + offset);
      *dest = rel.second - (segment.address + offset);
    }

    Clear();
    return segment;
  }

private:
  inline void* SpaceFor(size_t bytesCount) {
    m_buffer.insert(m_buffer.end(), bytesCount, 0);
    return &*(m_buffer.end() - bytesCount);
  }

  template <typename T>
  inline T* SpaceFor() {
    return static_cast<T*>(SpaceFor(sizeof(T)));
  }

private:
  std::vector<uint8_t> m_buffer;
  std::vector<std::pair<size_t, uintptr_t>> m_relatives;
};
