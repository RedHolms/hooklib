cmake_minimum_required(VERSION 4.1)
project("hooklib" LANGUAGES C CXX)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(HOOKLIB_ROOT_PROJECT ON)
else()
  set(HOOKLIB_ROOT_PROJECT OFF)
endif()

option(BUILD_TESTING "Build tests" ${HOOKLIB_ROOT_PROJECT})

if(NOT CMAKE_C_COMPILER_ARCHITECTURE_ID STREQUAL CMAKE_CXX_COMPILER_ARCHITECTURE_ID)
  message(FATAL_ERROR "C/CXX Architectures differ")
endif()

try_run(_DUMMY _DUMMY
  SOURCE_FROM_CONTENT
    "determine_abi.c" "
#include <stdio.h>
#include \"${CMAKE_CURRENT_SOURCE_DIR}/Include/HookLib.hpp\"
int main() {
  printf(\"%s;%s\", HOOKLIB_ABI_FAMILY_NAME, HOOKLIB_ARCH_NAME);
}"
  RUN_OUTPUT_VARIABLE DETERMINE_ABI_RESULT
)

list(GET DETERMINE_ABI_RESULT 0 HOOKLIB_ABI_FAMILY)
list(GET DETERMINE_ABI_RESULT 1 HOOKLIB_ARCH)

message(STATUS "[HookLib] Current ABI Family: ${HOOKLIB_ABI_FAMILY}")
message(STATUS "[HookLib] Current Architecture: ${HOOKLIB_ARCH}")

set(HOOKLIB_ABI ${HOOKLIB_ABI_FAMILY}_${HOOKLIB_ARCH})

file(GLOB_RECURSE PUBLIC_INCLUDES
  "Include/HookLib.hpp"
  "Include/HookLib/Impl/${HOOKLIB_ABI}/*.hpp"
)

file(GLOB_RECURSE SOURCES
  "Source/Impl/${HOOKLIB_ABI}/*.cpp"
  "Source/Impl/${HOOKLIB_ABI}/*.hpp"
  "Source/Impl/${HOOKLIB_ABI}/*.c"
  "Source/Impl/${HOOKLIB_ABI}/*.h"
)

if(HOOKLIB_ARCH STREQUAL "i386" OR HOOKLIB_ARCH STREQUAL "AMD64")
  file(GLOB_RECURSE x86_SOURCES
    "Source/x86/*.cpp"
    "Source/x86/*.hpp"
    "Source/x86/*.c"
    "Source/x86/*.h"
  )
  set(SOURCES ${SOURCES} ${x86_SOURCES})
endif()

# Internal target
add_library(__hooklib_internal INTERFACE)
target_sources(__hooklib_internal INTERFACE ${SOURCES} ${PUBLIC_INCLUDES})
target_include_directories(__hooklib_internal INTERFACE "Include" "Source")

if(BUILD_TESTING)
  include(CTest)
  add_subdirectory("Tests")
endif()
