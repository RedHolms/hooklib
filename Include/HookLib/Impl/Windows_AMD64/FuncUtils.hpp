#pragma once

#include "HookLib/Utils.hpp"

namespace HookLib {
namespace Details {

template <typename FuncT>
struct FuncTypeInfo;

template <typename RetT, typename... ArgsT>
struct FuncTypeInfo<RetT(ArgsT...)> {
  using ReturnType = RetT;
  using ArgsCollection = TypesCollection<ArgsT...>;
  static constexpr bool IsMember = false;
  using Class = void;
};

template <typename RetT, typename... ArgsT>
struct FuncTypeInfo<RetT(*)(ArgsT...)> : FuncTypeInfo<RetT(ArgsT...)> {};

template <typename RetT, class C, typename... ArgsT>
struct FuncTypeInfo<RetT(C::*)(ArgsT...)> {
  using ReturnType = RetT;
  using ArgsCollection = TypesCollection<ArgsT...>;
  static constexpr bool IsMember = true;
  using Class = C;
};

} // namespace Details
} // namespace HookLib
