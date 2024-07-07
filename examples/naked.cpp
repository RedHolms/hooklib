#include <hooklib.hpp>

#include <iostream>

/*
foo:
  mov eax, [esp + 4]
    ; << HOOK HERE
  add eax, [esp + 8]
  ret
*/
static uint8_t ASSEMBLY[] = {
  0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08,
  0xc3
};

using foo_t = int(__cdecl*)(int, int);

static const foo_t foo = (foo_t)ASSEMBLY;
static const uint8_t* hook_address = ASSEMBLY + 4;

void foo_hooker(hooklib::naked_context& ctx) {
  using namespace hooklib::impl;

  // we have "a" in EAX

  int a = ctx.eax;
  std::cout << "[HOOK] a = " << a << std::endl;

  if (a == 6) {
    std::cout << "[HOOK] a = 6! Set b to 20" << std::endl;

    // "b" is stored at [esp + 8]
    mem::write<int>(ctx.esp + 8, 20);
  }
}

int main() {
  hooklib::impl::mem::allow_execute(ASSEMBLY, sizeof(ASSEMBLY));

  hooklib::naked_hook foo_hook(hook_address);

  foo_hook.set_callback(foo_hooker);

  foo_hook.install();

  volatile int result;

  result = foo(1, 2);
  std::cout << "foo(1, 2) = " << result << std::endl;

  result = foo(6, 4);
  std::cout << "foo(6, 4) = " << result << std::endl;

  foo_hook.remove();

  result = foo(5, 3);
  std::cout << "foo(5, 3) = " << result << std::endl;

  return 0;
}
