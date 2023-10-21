cmake_minimum_required(VERSION 3.18)

set(CMAKE_CXX_STANDARD 20)

project("hooklib_examples" LANGUAGES CXX)

file(GLOB EXAMPLES_SOURCES "*.cpp")

foreach(sourceFile IN LISTS EXAMPLES_SOURCES)
  get_filename_component(fileName ${sourceFile} NAME_WE)

  set(targetName "${fileName}_example")

  add_executable(${targetName} ${sourceFile})
  target_link_libraries(${targetName} PRIVATE hooklib)
endforeach()

