cmake_minimum_required(VERSION 3.11.0)

project(ShamanDBI)

set(CMAKE_CXX_STANDARD 11)
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

FetchContent_MakeAvailable(spdlog)
FetchContent_MakeAvailable(cli11)

add_executable(shaman 
  src/memory.cpp
  src/modules.cpp
  src/debugger.cpp
)

target_link_libraries(shaman PRIVATE spdlog CLI11::CLI11)

add_executable(test_prog test/test_prog/prog.c)
