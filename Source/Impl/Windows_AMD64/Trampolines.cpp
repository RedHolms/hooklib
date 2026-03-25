#include "Trampolines.hpp"

#include "x86/HDE/hde64.h"

int CreateTrampoline(uintptr_t source, AssemblyWriter& dest, bool jumpBack) {
  hde64s hs;
  uintptr_t current = source;

  // Maximum target address of any JUMP instruction in first 5 bytes
  uintptr_t maxJumpTarget = 0;

  while (true) {
    if (current - source >= 5) {
      // We need at least 5 bytes to put relative jump at "source"

      if (jumpBack) {
        // Jump to the continuation of the original code
        dest.absJmp(current);
      }

      break;
    }

    auto instAddr = current;
    auto instPtr = reinterpret_cast<void*>(instAddr);

    // Parse current instruction
    hs = { 0 };
    hde64_disasm(instPtr, &hs);
    current += hs.len;

    if ((hs.flags & F_ERROR) != 0) {
      if ((hs.flags & F_ERROR_OPCODE) != 0)
        return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_HDE_OPCODE_ERROR;
      if ((hs.flags & F_ERROR_LENGTH) != 0)
        return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_HDE_LENGTH_ERROR;
      if ((hs.flags & F_ERROR_LOCK) != 0)
        return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_HDE_LOCK_ERROR;
      if ((hs.flags & F_ERROR_OPERAND) != 0)
        return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_HDE_OPERAND_ERROR;

      return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_HDE_UNKNOWN_ERROR;
    }

    // Copy or transform RIP-relative instructions

    if ((hs.modrm & 0xC7) == 0x05) {
      // RIP-relative addressing operands (mod=00, r/m=101)

      uintptr_t targetAddress = instAddr + hs.len + static_cast<int32_t>(hs.disp.disp32);

      auto dispOffset = hs.len - ((hs.flags & 0x3C) >> 2) - 4;

      dest.PushRelative(dest.Size() + dispOffset, targetAddress, hs.len - dispOffset);
      dest.bytes(instPtr, hs.len);

      if (hs.opcode == 0xFF && hs.modrm_reg == 4)
        break;
    }
    else if (hs.opcode == 0xE8) {
      // Relative call

      uintptr_t targetAddress = current + hs.len + hs.imm.imm32;
      dest.absCall(targetAddress);
    }
    else if ((hs.opcode & 0xFD) == 0xE9) {
      // Relative jump

      int32_t relative = (hs.opcode == 0xEB) ? hs.imm.imm8 : hs.imm.imm32;
      uintptr_t targetAddress = current + hs.len + relative;

      if (source <= targetAddress && targetAddress < (source + 5)) {
        if (targetAddress > maxJumpTarget)
          maxJumpTarget = targetAddress;

        dest.bytes(instPtr, hs.len);
      }
      else {
        dest.absJmp(targetAddress);

        if (source >= maxJumpTarget)
          break;
      }
    }
    else if (
      ((hs.opcode & 0xF0) == 0x70) || // 1-byte address
      ((hs.opcode & 0xFC) == 0xE0) || // loops, jump if RCX=0
      ((hs.opcode2 & 0xF0) == 0x80)   // 4-bytes address
    ) {
      int32_t relative =
        ((hs.opcode & 0xF0) == 0x70) || ((hs.opcode & 0xFC) == 0xE0) ? hs.imm.imm8 : hs.imm.imm32;

      uintptr_t targetAddress = current + hs.len + relative;
      if (source <= targetAddress && targetAddress < (source + 5)) {
        if (targetAddress > maxJumpTarget)
          maxJumpTarget = targetAddress;

        dest.bytes(instPtr, hs.len);
      }
      else if ((hs.opcode & 0xFC) == 0xE0) {
        return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_FAR_RCX_JUMPS_UNSUPPORTED;
      }
      else {
        uint8_t condition = (hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F;

        // Invert the condition to simplify assembly
        condition ^= 1;

        dest.byte(0x70 | condition); // Jcc
        dest.byte(0x0E);             // +16 (if ORIGINAL condition failed -> jump past absJmp)
        dest.absJmp(targetAddress);
      }
    }
    else if ((hs.opcode & 0xFE) == 0xC2) {
      // Procedure return

      dest.bytes(instPtr, hs.len);

      if (current >= maxJumpTarget)
        break;
    }
    else {
      // Generic instruction, just copy it
      dest.bytes(instPtr, hs.len);
    }
  }

  size_t count = current - source;
  if (count < 5)
    return 0;// HOOKLIB_X86_CREATE_TRAMPOLINE_FAIL_TOO_SMALL_PROCEDURE;

  return count;// HOOKLIB_SUCCESS;
}
