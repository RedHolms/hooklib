#include <hooklib.hpp>

#include <iostream>

void __cdecl foo(int a, int b, int* out_diff) {
  *out_diff = a - b;
}

using foo_t = decltype(&foo);

bool foo_hooker(int a, int b, int* out_diff) {
  std::cout << "[HOOK] foo(" << a << ", " << b << ", " << out_diff << ")" << std::endl;

  if (a + b == 10) {
    std::cout << "[HOOK] a + b = 10! Return b - a" << std::endl;
    *out_diff = b - a;
    return false;
  }

  return true;
}

int main() {
  hooklib::function_hook<foo_t> foo_hook(&foo);

  foo_hook.set_callback(foo_hooker);

  foo_hook.install();

  int result;

  foo(1, 2, &result);
  std::cout << "foo(1, 2) = " << result << std::endl;

  foo(6, 4, &result);
  std::cout << "foo(6, 4) = " << result << std::endl;

  foo_hook.remove();

  foo(5, 3, &result);
  std::cout << "foo(5, 3) = " << result << std::endl;

  return 0;
}
