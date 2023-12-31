#include <hooklib.hpp>

#include <iostream>

struct foo_result {
  int diffab; // a - b
  int diffba; // b - a
  int sum;
};

std::ostream& operator<<(std::ostream& os, foo_result const& foo) {
  return os << "{ " << foo.diffab << ", " << foo.diffba << ", " << foo.sum << " }";
}

foo_result __cdecl foo(int a, int b) {
  return {
    a - b,
    b - a,
    a + b
  };
}

using foo_t = decltype(&foo);

std::optional<foo_result> foo_hooker(int a, int b) {
  std::cout << "[HOOK] foo(" << a << ", " << b << ")" << std::endl;

  if (a + b == 10) {
    std::cout << "[HOOK] a + b = 10! Return { 3, 3, 3 }" << std::endl;
    return foo_result{ 3, 3, 3 };
  }

  return std::nullopt;
}

int main() {
  hooklib::function_hook<foo_t> foo_hook(&foo);

  foo_hook.set_callback(foo_hooker);

  foo_hook.install();

  foo_result result;
  
  result = foo(1, 2);
  std::cout << "foo(1, 2) = " << result << std::endl;

  result = foo(6, 4);
  std::cout << "foo(6, 4) = " << result << std::endl;

  foo_hook.remove();

  result = foo(5, 3);
  std::cout << "foo(5, 3) = " << result << std::endl;

  return 0;
}
