#include "HookLib/Impl/Windows_AMD64/HookLib.hpp"

#include "Assembly/AssemblyPool.hpp"
#include "Assembly/AssemblyWriter.hpp"
#include "Trampolines.hpp"
#include <assert.h>
#include <Windows.h>

using HookLib::Details::FuncHookImpl;
using HookLib::Details::HookedCallData;

struct FuncHookImpl::Data {
  bool installed = false;
  FuncHookOpts options;
  uintptr_t target = 0;
  FuncHookRelay relay = nullptr;
  void* relayPayload = nullptr;

  uint8_t originalCode[15] {};
  size_t originalCodeSize = 0;

  AssemblySegment hookBody;
  AssemblySegment trampoline;

  __forceinline Data(
    FuncHookOpts const& options,
    uintptr_t target,
    FuncHookRelay relay,
    void* relayPayload
  )
    : options(options),
      target(target),
      relay(relay),
      relayPayload(relayPayload) {}
};

FuncHookImpl::FuncHookImpl(
  FuncHookOpts const& options,
  uintptr_t target,
  FuncHookRelay relay,
  void* relayPayload
)
  : m(std::make_unique<Data>(options, target, relay, relayPayload)) {}

FuncHookImpl::~FuncHookImpl() = default;

inline uintptr_t FuncHookImpl::GetTarget() const noexcept {
  return m->target;
}

void FuncHookImpl::SetTarget(uintptr_t target) noexcept {
  if (m->target == target)
    return;

  bool wasInstalled = m->installed;

  if (wasInstalled)
    Remove();

  m->target = target;

  // Clear generated code
  m->trampoline = AssemblySegment();
  m->hookBody = AssemblySegment();

  if (wasInstalled)
    Install();
}

void FuncHookImpl::Install() {
  AssemblyWriter as;

  // gen trampoline
  if (m->trampoline.address == 0) {
    m->originalCodeSize = CreateTrampoline(m->target, as, true);
    m->trampoline = as.Commit(gAssemblyPool, m->target);
  }

  // gen body
  if (m->hookBody.address == 0) {
    // FIXME maybe using AVX?

    constexpr size_t SHADOW_SPACE_SIZE = sizeof(void*) * 4;

    size_t stackSpaceSize = 0;

    // 16-bytes alignment
    stackSpaceSize += 8;

    // Hooked registers
    stackSpaceSize += sizeof(HookedReg) * 4;

    // HookedCallData
    static_assert((sizeof(HookedCallData) % 16) == 0, "Invalid HookedCallData size");
    stackSpaceSize += sizeof(HookedCallData);

    // Shadow space for relay call
    stackSpaceSize += SHADOW_SPACE_SIZE;

    // Allocate space on the stack
    as.bytes({ 0x48, 0x81, 0xec }); // sub rsp, {stackSpaceSize}
    as.dword(stackSpaceSize);

    // Current stack layout:
    //    rsp                       = Shadow space for relay call
    //    +SHADOW_SPACE_SIZE        = HookedCallData
    //    +sizeof(HookedCallData)   = HookedReg[4]
    //    +(sizeof(HookedReg) * 4)  = <8 bytes padding>
    //    +8                        = return address
    //    +8                        = ...stack arguments
    size_t hookedCallDataOffset = SHADOW_SPACE_SIZE;
    size_t hookedRegsOffset = hookedCallDataOffset + sizeof(HookedCallData);
    size_t stackArgumentsOffset = hookedRegsOffset + (sizeof(HookedReg) * 4) + 8 + 8;

    for (size_t i = 0; i < std::size(m->options.xmmReg); ++i) {
      size_t offset = hookedRegsOffset + (i * sizeof(HookedReg));

      if (m->options.xmmReg[i]) {
        constexpr uint8_t b3[] = { 0x84, 0x8C, 0x94, 0x9C };
        as.bytes({ 0x0F, 0x29, b3[i], 0x24 }); // movaps xmmword ptr [rsp + {offset}], xmm{i}
        as.dword(offset);
      }
      else {
        constexpr uint8_t b1[] = { 0x48, 0x48, 0x4C, 0x4C };
        constexpr uint8_t b3[] = { 0x8C, 0x94, 0x84, 0x8C };
        as.bytes({ b1[i], 0x89, b3[i], 0x24 }); // mov qword ptr [rsp + {offset}], {reg}
        as.dword(offset);
      }
    }

    // Set RCX to HookedCallData*
    as.bytes({ 0x48, 0x8d, 0x4c, 0x24 }); // lea rcx, [rsp + {hookedCallDataOffset}]
    as.byte(hookedCallDataOffset);

    // Fill HookedCallData with zeroes
    as.bytes({ 0x51 });                                   // push rcx
    as.bytes({ 0x57 });                                   // push rdi
    as.bytes({ 0x48, 0x89, 0xcf });                       // mov rdi, rcx
    as.bytes({ 0x48, 0x31, 0xC0 });                       // xor rax, rax
    as.bytes({ 0x48, 0xC7, 0xC1 });                       // mov rcx, {qwordsCount}
    as.dword(sizeof(HookedCallData) / sizeof(uint64_t));  // {qwordsCount}
    as.bytes({ 0xF3, 0x48, 0xAB });                       // rep stosq qword ptr [rdi], rax
    as.bytes({ 0x5F });                                   // pop rdi
    as.bytes({ 0x59 });                                   // pop rcx

    // Set HookedCallData::hookedRegs
    as.bytes({ 0x48, 0x8D, 0x44, 0x24 }); // lea rax, [rsp + {hookedRegsOffset}]
    as.byte(hookedRegsOffset);
    as.bytes({ 0x48, 0x89, 0x41 }); // mov qword ptr [rcx + {offsetof(hookedRegs)}], rax
    as.byte(offsetof(HookedCallData, hookedRegs));

    // Set HookedCall<>::stackArgsStart
    as.bytes({ 0x48, 0x8D, 0x44, 0x24 }); // lea rax, [rsp + {stackArgumentsOffset}]
    as.byte(stackArgumentsOffset);
    as.bytes({ 0x48, 0x89, 0x41 }); // mov qword ptr [rcx + {offsetof(stackArgsStart)}], rax
    as.byte(offsetof(HookedCallData, stackArgsStart));

    // Put relay payload into RDX
    as.bytes({ 0x48, 0xba });    // mov rdx, {m->relayPayload}
    as.pointer(m->relayPayload);

    // Call the relay
    as.absCall(reinterpret_cast<uintptr_t>(m->relay));

    // Set RCX to HookedCallData*
    as.bytes({ 0x48, 0x8d, 0x4c, 0x24 }); // lea rcx, [rsp + {hookedCallDataOffset}]
    as.byte(hookedCallDataOffset);

    // Check HookedCall<>::canceled
    static_assert(
      offsetof(HookedCallData, canceled) == 0,
      "bool HookedCallData::canceled must be at offset 0"
    );
    as.bytes({ 0xf6, 0x01, 0xff }); // test byte ptr [rcx], 0xff
    as.bytes({ 0x74 });             // jnz CONTINUE_ORIGINAL
    as.byte(12);

    // Return to the caller

    if (m->options.xmmRetVal) {
      // Put return value to XMM0
      as.bytes({ 0x0F, 0x28, 0x41 }); // movaps xmm0, xmmword ptr [rcx + {offset}]
      as.byte(offsetof(HookedCallData, returnValue));
    }
    else {
      // Put return value to RAX
      as.bytes({ 0x48, 0x8b, 0x41 }); // mov rax, qword ptr [rcx + {offset}]
      as.byte(offsetof(HookedCallData, returnValue));
    }

    // Restore stack space
    as.bytes({ 0x48, 0x81, 0xc4 }); // add rsp, {stackSpaceSize}
    as.dword(stackSpaceSize);

    // Return!
    as.bytes({ 0xc3 }); // ret

    // ===================================
    // CONTINUE_ORIGINAL:

    // Return to the callee

    // Restore registers
    for (size_t i = 0; i < std::size(m->options.xmmReg); ++i) {
      size_t offset = hookedRegsOffset + (i * sizeof(HookedReg));

      if (m->options.xmmReg[i]) {
        constexpr uint8_t b3[] = { 0x84, 0x8C, 0x94, 0x9C };
        as.bytes({ 0x0F, 0x28, b3[i], 0x24 }); // movaps xmm{i}, xmmword ptr [rsp + {offset}]
        as.dword(offset);
      }
      else {
        constexpr uint8_t b1[] = { 0x48, 0x48, 0x4C, 0x4C };
        constexpr uint8_t b3[] = { 0x8C, 0x94, 0x84, 0x8C };
        as.bytes({ b1[i], 0x8B, b3[i], 0x24 }); // mov {reg}, qword ptr [rsp + {offset}]
        as.dword(offset);
      }
    }

    // Restore stack space
    as.bytes({ 0x48, 0x81, 0xc4 }); // add rsp, {stackSpaceSize}
    as.dword(stackSpaceSize);

    // Jump to the trampoline
    as.absJmp(m->trampoline.address);

    m->hookBody = as.Commit(gAssemblyPool, m->target);
  }

  // FIXME pages boundary
  auto targetVoidp = reinterpret_cast<void*>(m->target);

  DWORD prevProt;
  VirtualProtect(targetVoidp, m->originalCodeSize, PAGE_EXECUTE_READWRITE, &prevProt);

  memcpy(m->originalCode, targetVoidp, m->originalCodeSize);
  memset(targetVoidp, 0x90, m->originalCodeSize);

  *reinterpret_cast<uint8_t*>(m->target) = 0xE9; // jmp <rel32>
  *reinterpret_cast<uint32_t*>(m->target + 1) = m->hookBody.address - m->target - 5;

  VirtualProtect(targetVoidp, m->originalCodeSize, prevProt, &prevProt);
}

void FuncHookImpl::Remove() {
  // FIXME pages boundary
  auto targetVoidp = reinterpret_cast<void*>(m->target);

  DWORD prevProt;
  VirtualProtect(targetVoidp, m->originalCodeSize, PAGE_EXECUTE_READWRITE, &prevProt);
  memcpy(targetVoidp, m->originalCode, m->originalCodeSize);
  VirtualProtect(targetVoidp, m->originalCodeSize, prevProt, &prevProt);
}
