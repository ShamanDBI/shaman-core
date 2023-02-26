cmake_minimum_required(VERSION 3.11.0)

project(ShamanDBI)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

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

option(BUILD_FOR_ARM "Build for ARM architecture" NO)
option(BUILD_FOR_INTEL "Build for INTEL architecture" YES)
option(BUILD_FOR_32_BIT "Build for 32 bits architecture only" NO)

FetchContent_MakeAvailable(spdlog)
FetchContent_MakeAvailable(cli11)

add_executable(shaman)

target_compile_features(shaman PUBLIC cxx_std_11)

set(ARCH_SRC
  src/arch/intel/breakpoint.cpp
  src/arch/intel/registers.cpp
  src/arch/intel/syscall_x64.cpp
)


set(SRC
  src/memory.cpp
  src/modules.cpp
  src/debugger.cpp
  src/breakpoint_mngr.cpp
  src/tracee.cpp
  src/main.cpp
  src/linux_debugger.cpp
  src/syscall_mngr.cpp
)


target_sources(shaman PRIVATE ${SRC} ${ARCH_SRC})
target_include_directories(shaman PRIVATE src/arch/intel)
target_include_directories(shaman PRIVATE src)

target_link_libraries(shaman PRIVATE spdlog CLI11::CLI11)

add_executable(test_prog test/test_prog/prog.c)
