#include <hooklib.hpp>

#include <iostream>
#include <optional>

int __cdecl foo() {
  return 10;
}

using foo_t = decltype(&foo);

std::optional<int> foo_hooker() {
  std::cout << "[HOOK] foo()" << std::endl;
  std::cout << "[HOOK] Return 20" << std::endl;
  return 20;
}

int main() {
  hooklib::function_hook<foo_t> foo_hook(&foo);

  foo_hook.set_callback(foo_hooker);

  foo_hook.install();

  volatile int result;

  result = foo();
  std::cout << "foo() = " << result << std::endl;

  foo_hook.remove();

  result = foo();
  std::cout << "foo() = " << result << std::endl;

  return 0;
}
