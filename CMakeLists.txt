cmake_minimum_required(VERSION 3.11.0)

project(ShamanDBI)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

# ------------- Download all the needed Dependencies ---------------
include(FetchContent) # once in the project to include the module

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.11.0
)

FetchContent_Declare(
  cli11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11
  GIT_TAG v2.2.0
)

Include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.13.0 # or a later release
)

FetchContent_MakeAvailable(googletest)

# ------------------------------------------------------------------


option(BUILD_FOR_ARM "Build for ARM architecture" NO)
option(BUILD_FOR_INTEL "Build for INTEL architecture" YES)
option(BUILD_FOR_32_BIT "Build for 32 bits architecture only" NO)

FetchContent_MakeAvailable(spdlog)
FetchContent_MakeAvailable(cli11)

add_executable(shaman)

target_compile_features(shaman PUBLIC cxx_std_11)

set(ARCH_SRC
  src/arch/intel/x86_breakpoint.cpp
  src/arch/intel/x86_registers.cpp

  src/arch/intel/amd64_registers.cpp
  src/arch/intel/amd64_registers.cpp
  src/arch/intel/amd64_syscall.cpp

  src/arch/arm/arm32_breakpoint.cpp
  src/arch/arm/arm32_registers.cpp
  src/arch/arm/arm32_syscall.cpp

  src/arch/arm/arm64_breakpoint.cpp
  src/arch/arm/arm64_registers.cpp
  src/arch/arm/arm64_syscall.cpp
)


set(SRC
  src/memory.cpp
  src/modules.cpp
  src/debugger.cpp
  src/debug_opts.cpp
  src/breakpoint.cpp
  src/breakpoint_mngr.cpp
  src/breakpoint_reader.cpp
  src/coverage_trace_writer.cpp
  src/tracee.cpp
  src/linux_debugger.cpp
  src/syscall_mngr.cpp
  src/syscall.cpp
)


target_sources(shaman PRIVATE ${SRC} ${ARCH_SRC} src/main.cpp)
target_include_directories(shaman PRIVATE src/arch/intel)
target_include_directories(shaman PRIVATE src)

target_link_libraries(shaman PRIVATE spdlog CLI11::CLI11)


# -- Testing configuration

add_executable(test_prog test/test_prog/prog.c)
target_link_libraries(test_prog pthread)

set(TEST_SRC
  test/unittest/test.cpp
)
include(GoogleTest)

add_executable(tests ${TEST_SRC})
target_include_directories(tests PRIVATE src/arch/intel)
target_include_directories(tests PRIVATE src)
target_sources(tests PRIVATE ${SRC} ${ARCH_SRC})
target_link_libraries(tests PRIVATE spdlog)
target_link_libraries(tests PRIVATE GTest::gtest_main gmock)