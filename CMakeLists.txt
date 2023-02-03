cmake_minimum_required(VERSION 3.9.1)

project(PtraceDebugger)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(ptrace_debug src/ptrace.cpp src/debugger.cpp)