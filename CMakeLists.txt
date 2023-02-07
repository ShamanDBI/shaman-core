cmake_minimum_required(VERSION 3.9.1)

project(ShamanDBI)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(shaman src/ptrace.cpp src/debugger.cpp)

add_executable(test_prog test/test_prog/prog.c)
