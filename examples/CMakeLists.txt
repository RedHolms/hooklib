cmake_minimum_required(VERSION 3.18)

set(CMAKE_CXX_STANDARD 20)

project("hooklib_examples" LANGUAGES CXX)

add_executable(foo_example "foo_example.cpp")
target_link_libraries(foo_example PRIVATE hooklib)
