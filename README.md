# HookLib

In concept this'll be a multi-ABI hooking library with C interface
 for easy embedding into systems using FFI.
Unlike other C++ hook libraries, HookLib's C++ layer only collects information
 about a hook target that is necessary for doing the hook and then passes this
 info to a hooking function. Because of that, we can construct this info in any
 other programming language without need of C++.
Currently, all of this is really WIP. First two platforms will be 32-bit and
 64-bit Windows (aka Windows ABI for i386 and AMD64 archs).
In the future I will add support for SysV ABI family and ARM archs.
Also at the start library will be C++ only and only once it's working I will
 add C interface.

## ROADMAP
  - [ ] Implement basic stuff and function hooks for Windows AMD64
  - [ ] Implement the same stuff for Windows I386
  - [ ] Implement other variations of hooks (naked hooks, call hooks, etc.)
  - [ ] Implement hooks for SysV (I386/AMD64)
  - [ ] Implement ARM(32 and 64) for SysV
  - [ ] Implement ARM(32 and 64) for Windows

## Examples
```c++
#include <HookLib.hpp>

// Let's say target function look something like that:
extern int add(int a, int b) {
    return a + b;
}

constexpr uintptr_t add_addr = 0x...;

int main() {
    // NOTE: Function type can also be:
    //  int(*)(int, int)
    HookLib::FunctionHook<int(int, int)> addHook { add_addr };

    // EXAMPLE 1: Cancel original function call with custom return value
    addHook.SetCallback([](auto& call) {
        int& a = call.Arg<0>();
        int& b = call.Arg<1>();
        // NOTE: Setting return value will CANCEL original function call
        // But you can call it anyway later using "CallOriginal()"
        call.SetReturnValue(a - b);
    });
    
    assert( add(1, 2) == 3 );
    addHook.Install();
    assert( add(1, 2) == -1 );
    addHook.Remove();
    assert( add(1, 2) == 3 );
    
    // EXAMPLE 2: Modify arguments values
    addHook.SetCallback([](auto& call) {
        call.Arg<0>() += 1;
        // Because "SetReturnValue()" wasn't called, original function will be called
    });
    
    addHook.Install();
    assert( add(1, 2) == 4 );
    
    // EXAMPLE 3: Modify return value of the original function
    // NOTE: Callback can be replaced without re-installing
    addHook.SetCallback([](auto& call) {
        // NOTE: All lines below is identical
        /* int result = call.CallOriginal(call.Arg<0>(), call.Arg<1>()); */
        /* int result = call.CallOriginal(call.Args<0, 1>()); */ // call.Args<BEGIN, END>()
        int result = call.CallOriginal();
        
        call.SetReturnValue(result - 1);
    });
    
    assert( add(1, 2) == 2 );
}
```
