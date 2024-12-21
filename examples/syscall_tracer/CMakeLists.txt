cmake_minimum_required(VERSION 3.5.0)

project("syscall_tracer")

include(FetchContent) 

FetchContent_Declare(
  cli11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11
  GIT_TAG v2.4.2
)

FetchContent_MakeAvailable(cli11)

add_executable(${PROJECT_NAME})
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

set(CMAKE_PREFIX_PATH "../../builds/shaman_lib")
find_package(ShamanDBA CONFIG REQUIRED)
# find_package(spdlog CONFIG REQUIRED)

target_sources(${PROJECT_NAME}
    PRIVATE
    main.cpp
)

target_link_libraries(${PROJECT_NAME} PUBLIC ShamanDBA CLI11::CLI11 spdlog)
