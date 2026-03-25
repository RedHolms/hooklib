#pragma once

#include "Assembly/AssemblyWriter.hpp"
#include <HookLib.hpp>

// Returns count of bytes of _original_ code that was replicated, or 0 on errors.
int CreateTrampoline(uintptr_t source, AssemblyWriter& dest, bool jumpBack = true);
