#pragma once

#include <type_traits>

#ifdef HOOKLIB_TESTS_TARGET
#include <gtest/gtest_prod.h>
#define HOOKLIB_FRIEND_TEST FRIEND_TEST
#else
#define HOOKLIB_FRIEND_TEST(...)
#endif

namespace HookLib {
namespace Details {

template <typename Needle, typename... Haystack>
constexpr bool IsOneOf = (std::is_same_v<Needle, Haystack> || ...);

template <typename>
constexpr bool AlwaysFalse = false;

template <size_t I, typename... Types>
struct GetNthType;

template <size_t I>
struct GetNthType<I> {
  static_assert(AlwaysFalse<std::integral_constant<size_t, I>>, "Index is out of bound");
};

template <typename T, typename... Rest>
struct GetNthType<0, T, Rest...> {
  using Type = T;
};

template <size_t I, typename T, typename... Rest>
struct GetNthType<I, T, Rest...> {
  using Type = GetNthType<I - 1, Rest...>::Type;
};

template <class Callable, size_t I, typename... Types>
struct _TypesCollection_ForEach_Impl;

template <class Callable, size_t I>
struct _TypesCollection_ForEach_Impl<Callable, I> {
  static consteval void Call(Callable&&) { /* end of the collection */ }
};

template <class Callable, size_t I, typename T, typename... Rest>
struct _TypesCollection_ForEach_Impl<Callable, I, T, Rest...> {
  using Next = _TypesCollection_ForEach_Impl<Callable, I + 1, Rest...>;

  static consteval void Call(Callable&& callback) {
    callback(std::type_identity<T>{}, I);
    Next::Call(std::forward<Callable>(callback));
  }
};

/**
 * Collection of multiple types
 */
template <typename... Types>
struct TypesCollection {
  static constexpr size_t Count = sizeof...(Types);

  template <size_t I>
  using Nth = GetNthType<I, Types...>::Type;

  // Calls callback for each type in the collection
  template <class Callable>
  static consteval void ForEach(Callable&& callback) {
    _TypesCollection_ForEach_Impl<Callable, 0, Types...>::Call(std::forward<Callable>(callback));
  }
};

} // namespace Details
} // namespace HookLib
