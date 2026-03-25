#include "HookLib/Impl/Windows_AMD64/HookLib.hpp"

#include "Assembly/AssemblyPool.hpp"
#include "Assembly/AssemblyWriter.hpp"
#include "Trampolines.hpp"
#include <Windows.h>

using HookLib::Details::FuncHookImpl;
using HookLib::Details::HookedCallData;

struct FuncHookImpl::Data {
  bool installed = false;
  FuncInfo const& targetInfo;
  uintptr_t target = 0;
  FuncHookRelay relay = nullptr;
  void* relayPayload = nullptr;

  uint8_t originalCode[15] {};
  size_t originalCodeSize = 0;

  AssemblySegment hookBody;
  AssemblySegment trampoline;

  __forceinline Data(
    FuncInfo const& targetInfo,
    uintptr_t target,
    FuncHookRelay relay,
    void* relayPayload
  )
    : targetInfo(targetInfo),
      target(target),
      relay(relay),
      relayPayload(relayPayload) {}
};

FuncHookImpl::FuncHookImpl(
  FuncInfo const& targetInfo,
  uintptr_t target,
  FuncHookRelay relay,
  void* relayPayload
)
  : m(std::make_unique<Data>(targetInfo, target, relay, relayPayload)) {}

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
    // FIXME TODO Handle XMM arguments

    // Copy registers into the shadow space
    as.bytes({ 0x48, 0x89, 0x4c, 0x24, 0x08 });           // mov qword ptr [rsp+0x08], rcx
    as.bytes({ 0x48, 0x89, 0x54, 0x24, 0x10 });           // mov qword ptr [rsp+0x10], rdx
    as.bytes({ 0x4c, 0x89, 0x44, 0x24, 0x18 });           // mov qword ptr [rsp+0x18], r8
    as.bytes({ 0x4c, 0x89, 0x4c, 0x24, 0x20 });           // mov qword ptr [rsp+0x20], r9

    // Calculate how much stack space we need:
    //    - HookedCall<> object
    //    - Shadow space for relay call
    //    - 16-bytes alignment
    size_t bytesToAlloc = sizeof(HookedCallData) + (4 * sizeof(void*));
    if ((bytesToAlloc % 16) != 0)
      bytesToAlloc += 16 - (bytesToAlloc % 16);

    // Allocate space on the stack
    as.bytes({ 0x48, 0x81, 0xec });                       // sub rsp, <imm32>
    as.dword(bytesToAlloc);                               // <imm32>

    // Put HookedCall<>* into RCX (first argument)
    as.bytes({ 0x48, 0x8d, 0x4c, 0x24 });                 // lea rcx, [rsp + <imm8>]
    as.byte(4 * sizeof(void*));                           // <imm8>

    // Fill HookedCall<> with zeroes
    as.bytes({ 0x51 });                                   // push rcx
    as.bytes({ 0x57 });                                   // push rdi
    as.bytes({ 0x48, 0x89, 0xcf });                       // mov rdi, rcx
    as.bytes({ 0x48, 0x31, 0xC0 });                       // xor rax, rax
    as.bytes({ 0x48, 0xC7, 0xC1 });                       // mov rcx, <imm32>
    as.dword(sizeof(HookedCallData) / sizeof(uint64_t));  // <imm32>
    as.bytes({ 0xF3, 0x48, 0xAB });                       // rep stosq qword ptr [rdi], rax
    as.bytes({ 0x5F });                                   // pop rdi
    as.bytes({ 0x59 });                                   // pop rcx

    // Set HookedCall<>::stackFrame
    as.bytes({ 0x48, 0x8d, 0x84, 0x24 });                 // lea rax, [rsp + <imm32>]
    as.dword(bytesToAlloc);                               // <imm32>
    as.bytes({ 0x48, 0x89, 0x41 });                       // mov qword ptr [rcx + <imm8>], rax
    as.byte(offsetof(HookedCallData, stackFrame));        // <imm8>

    // Put payload into RDX (second argument)
    as.bytes({ 0x48, 0xba });                             // mov rdx, <imm64>
    as.pointer(m->relayPayload);                          // <imm64>

    // Call the relay
    as.absCall(reinterpret_cast<uintptr_t>(m->relay));

    // Put HookedCall<>* into RCX
    as.bytes({ 0x48, 0x8d, 0x4c, 0x24 });                 // lea rcx, [rsp + <imm8>]
    as.byte(4 * sizeof(void*));                           // <imm8>

    // NOTE: We could restore stack space here assuming that our data won't be touched even if it's
    // below the stack pointer, but let's be extra-safe here as it CAN be touched in some really
    // shitty scenarios (i.e. debugger can modify it).

    // Check HookedCall<>::canceled
    as.bytes({ 0xf6, 0x01, 0xff });                       // test byte ptr [rcx], 0xff
    as.bytes({ 0x74 });                                   // jnz <rel8>
    as.byte(12);                                          // <rel8> (to CONTINUE_ORIGINAL)

    // Return to the callee. Get RAX value
    as.bytes({ 0x48, 0x8b, 0x41 });                       // mov rax, qword ptr [rcx + <imm8>]
    as.byte(offsetof(HookedCallData, returnValue));       // <imm8>

    // Restore stack space
    as.bytes({ 0x48, 0x81, 0xc4 });                       // add rsp, <imm32>
    as.dword(bytesToAlloc);                               // <imm32>

    // Return!
    as.bytes({ 0xc3 });                                   // ret
    // ===================================

    // CONTINUE_ORIGINAL:

    // Restore stack space
    as.bytes({ 0x48, 0x81, 0xc4 });                       // add rsp, <imm32>
    as.dword(bytesToAlloc);                               // <imm32>

    // Restore registers from the shadow space
    as.bytes({ 0x48, 0x8b, 0x4c, 0x24, 0x08 });           // mov rcx, qword ptr [rsp+0x08]
    as.bytes({ 0x48, 0x8b, 0x54, 0x24, 0x10 });           // mov rdx, qword ptr [rsp+0x10]
    as.bytes({ 0x4c, 0x8b, 0x44, 0x24, 0x18 });           // mov r8, qword ptr [rsp+0x18]
    as.bytes({ 0x4c, 0x8b, 0x4c, 0x24, 0x20 });           // mov r9, qword ptr [rsp+0x20]

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
