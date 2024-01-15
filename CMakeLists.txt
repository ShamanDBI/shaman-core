cmake_minimum_required(VERSION 3.11.0)

project(ShamanDBI)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)
SET(CMAKE_EXE_LINKER_FLAGS "-static")

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

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.13.0 # or a later release
)

FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG        5.0.1
)

set(GRAPHVIZ_EXTERNAL_LIBS FALSE)
# only dependencies between libraries
set(GRAPHVIZ_EXECUTABLES FALSE)
# ------------------------------------------------------------------

FetchContent_MakeAvailable(spdlog)
FetchContent_MakeAvailable(cli11)
FetchContent_MakeAvailable(googletest)
FetchContent_MakeAvailable(capstone)

#-- Experimental Dissassembler Project
  
set(WITCH_SRC
  src/witch/basic_block.cpp
  src/witch/inst_analyzer.cpp
  src/witch/branch_data.cpp
)

add_executable(witch)

target_include_directories(witch PRIVATE src/witch)
target_sources(witch PRIVATE ${WITCH_SRC} src/witch/witch.cpp)
target_link_libraries(witch PRIVATE capstone)

#-- END

#-- SHARED IPC Start

set(SHAMAN_IPC_SRC
  src/mempipe/main.cpp
)

add_executable(shaman_ipc)
target_include_directories(witch PRIVATE src/mempipe)
target_sources(shaman_ipc PRIVATE ${SHAMAN_IPC_SRC} src/mempipe/main.cpp)

#-- SHARED IPC END

# Architecture specific files
set(ARCH_SRC
  src/arch/intel/x86_breakpoint.cpp
  src/arch/intel/x86_registers.cpp
  src/arch/intel/x86_syscall.cpp

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
  src/registers.hpp
  src/debug_opts.cpp
  src/debugger.cpp
  src/breakpoint.cpp
  src/breakpoint_mngr.cpp
  src/breakpoint_reader.cpp
  src/coverage_trace_writer.cpp
  src/tracee.cpp
  src/linux_debugger.cpp
  src/syscall_mngr.cpp
  src/syscall.cpp

  src/witch/inst_analyzer.cpp
  src/witch/branch_data.cpp
  src/witch/witch.cpp
)

# Main shaman Instrumentation project
add_executable(shaman)

target_sources(shaman PRIVATE ${WITCH_SRC})
target_include_directories(shaman PRIVATE src/witch)

target_sources(shaman PRIVATE ${SRC} ${ARCH_SRC} src/main.cpp)
target_include_directories(shaman PRIVATE src/arch/intel)
target_include_directories(shaman PRIVATE src)
target_include_directories(shaman PRIVATE witch)

# target_link_libraries(shaman -static)

target_link_libraries(shaman PRIVATE spdlog CLI11::CLI11 capstone)



# -- Testing configuration

add_executable(test_prog test/test_prog/prog.c)
target_link_libraries(test_prog pthread)

# Client Server
add_executable(client test/network/client.c)
add_executable(server test/network/server.c)

add_executable(oop_test test/oop_test.cpp)

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