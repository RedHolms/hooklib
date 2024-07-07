#include <hooklib.hpp>

#include <iostream>

/*
bar: ; call foo
  push [esp + 8]
  push [esp + 4 + 4]
  call foo
  add esp, 8
  ret
foo:
  mov eax, [esp + 4]
  add eax, [esp + 8]
  ret
*/
static uint8_t ASSEMBLY[] = {
  0xff, 0x74, 0x24, 0x08, 0xff, 0x74, 0x24, 0x08,
  0xe8, 0x04, 0x00, 0x00, 0x00, 0x83, 0xc4, 0x08,
  0xc3, 0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24,
  0x08, 0xc3
};

using foo_t = int(__cdecl*)(int, int);
using bar_t = foo_t;

static const bar_t bar = (bar_t)ASSEMBLY;
static const foo_t foo = (bar_t)(ASSEMBLY + 0x11);
static const uint8_t* foo_call = ASSEMBLY + 0x8;

int main() {
  hooklib::impl::mem::allow_execute(ASSEMBLY, sizeof(ASSEMBLY));

  hooklib::call_hook<foo_t> foo_hook(foo_call);

  foo_hook.set_callback([&](int a, int b) -> int {
    std::cout << "[HOOK] foo(" << a << ", " << b << ")" << std::endl;

    if (a + b == 10) {
      std::cout << "[HOOK] a + b = 10! Return b - a" << std::endl;
      return b - a;
    }

    return foo_hook.call(a, b);
  });

  foo_hook.install();

  volatile int result;

  result = bar(1, 2);
  std::cout << "bar(1, 2) = " << result << std::endl;

  result = bar(6, 4);
  std::cout << "bar(6, 4) = " << result << std::endl;

  foo_hook.remove();

  result = bar(5, 3);
  std::cout << "bar(5, 3) = " << result << std::endl;

  return 0;
}
