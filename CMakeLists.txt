cmake_minimum_required(VERSION 3.18)

project("hooklib" LANGUAGES CXX)

add_library(hooklib STATIC "src/hooklib.cpp" "include/hooklib.hpp")
target_include_directories(hooklib PUBLIC "include")
set_target_properties(hooklib PROPERTIES CXX_STANDARD 20)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  add_subdirectory("examples")
endif()
