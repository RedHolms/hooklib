#include <hooklib.hpp>

#include <iostream>

struct bar_result {
  int diffab; // a - b
  int diffba; // b - a
  int sum;
};

std::ostream& operator<<(std::ostream& os, bar_result const& foo) {
  return os << "{ " << foo.diffab << ", " << foo.diffba << ", " << foo.sum << " }";
}

class FooClass {
public:
  int c;

public:
  FooClass(int c)
    : c(c) {}

public:
  int Foo(int a, int b) {
    return a + b + c;
  }

  bar_result Bar(int a, int b) {
    return {
      a - b + c,
      b - a + c,
      a + b + c
    };
  }

public:
  static constexpr auto FooAddr = &FooClass::Foo;
  static constexpr auto BarAddr = &FooClass::Bar;
};

using FooClass__Foo_t = int(__thiscall*)(FooClass* self, int a, int b);
using FooClass__Bar_t = bar_result(__thiscall*)(FooClass* self, int a, int b);

static hooklib::function_hook<FooClass__Foo_t>* foo_hook = nullptr;
static hooklib::function_hook<FooClass__Bar_t>* bar_hook = nullptr;

std::optional<int> foo_hooker(FooClass* self, int a, int b) {
  std::cout << "[FOO HOOK] foo(" << a << ", " << b << ")" << std::endl;

  if (a + b == 10) {
    std::cout << "[FOO HOOK] a + b = 10! Change c to 20" << std::endl;
    int saved_c = self->c;
    self->c = 20;
    int result = foo_hook->call(self, a, b);
    self->c = saved_c;
    return result;
  }

  return std::nullopt;
}

std::optional<bar_result> bar_hooker(FooClass* self, int a, int b) {
  std::cout << "[BAR HOOK] bar(" << a << ", " << b << ")" << std::endl;

  if (a + b == 10) {
    std::cout << "[BAR HOOK] a + b = 10! Change c to 20" << std::endl;
    int saved_c = self->c;
    self->c = 20;
    bar_result result = bar_hook->call(self, a, b);
    self->c = saved_c;
    return result;
  }

  return std::nullopt;
}

int main() {
  foo_hook = new hooklib::function_hook<FooClass__Foo_t>((void*&)FooClass::FooAddr);
  bar_hook = new hooklib::function_hook<FooClass__Bar_t>((void*&)FooClass::BarAddr);
  
  foo_hook->set_callback(foo_hooker);
  foo_hook->install();

  bar_hook->set_callback(bar_hooker);
  bar_hook->install();

  FooClass foo = FooClass(3);

  volatile int result;

  result = foo.Foo(1, 2);
  std::cout << "foo(1, 2) = " << result << std::endl;

  result = foo.Foo(6, 4);
  std::cout << "foo(6, 4) = " << result << std::endl;

  foo_hook->remove();

  result = foo.Foo(5, 3);
  std::cout << "foo(5, 3) = " << result << std::endl;

  bar_result result2;

  result2 = foo.Bar(1, 2);
  std::cout << "bar(1, 2) = " << result2 << std::endl;

  result2 = foo.Bar(6, 4);
  std::cout << "bar(6, 4) = " << result2 << std::endl;

  bar_hook->remove();

  result2 = foo.Bar(5, 3);
  std::cout << "bar(5, 3) = " << result2 << std::endl;

  delete foo_hook;
  delete bar_hook;

  return 0;
}
