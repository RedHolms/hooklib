#include <hooklib.hpp>

#include <iostream>

#include <intrin.h>

int __stdcall foo(int a, int b) {
  return a + b;
}

using foo_t = decltype(&foo);

std::optional<int> foo_hooker(int a, int b) {
  std::cout << "[HOOK] foo(" << a << ", " << b << ")" << std::endl;

  if (a + b == 10) {
    std::cout << "[HOOK] a + b = 10! Return 20" << std::endl;
    return 20;
  }

  return std::nullopt;
}
int main() {
  hooklib::function_hook<foo_t> foo_hook(&foo);

  foo_hook.set_callback(foo_hooker);

  foo_hook.install();

  // Needs volatile so compiler wont inline
  //  foo() call to std::cout << ...
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
