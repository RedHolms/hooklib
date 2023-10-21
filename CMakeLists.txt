cmake_minimum_required(VERSION 3.18)

set(CMAKE_CXX_STANDARD 20)

project("hooklib" LANGUAGES CXX)

add_library(hooklib INTERFACE "hooklib.hpp")
target_include_directories(hooklib INTERFACE ".")

add_subdirectory("examples")
