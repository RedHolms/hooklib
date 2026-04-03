include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

file(GLOB_RECURSE SOURCES "${HOOKLIB_ABI}/*.cpp" "${HOOKLIB_ABI}/*.c")
set(SOURCES "main.cpp" "main.hpp" ${SOURCES})

add_executable(HookLib_Tests ${SOURCES})

target_compile_definitions(HookLib_Tests PRIVATE
  HOOKLIB_TESTS_TARGET=1
)

target_include_directories(HookLib_Tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(HookLib_Tests PRIVATE
  __hooklib_internal
  GTest::gtest
)

set_target_properties(HookLib_Tests PROPERTIES
  CXX_STANDARD 20
)

gtest_discover_tests(HookLib_Tests)
