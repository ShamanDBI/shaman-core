cmake_minimum_required(VERSION 3.5.0)

project(ShamanDBA)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)
set(CMAKE_EXE_LINKER_FLAGS "-static")

# ------------- Download all the needed Dependencies ---------------
include(FetchContent) # once in the project to include the module

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.11.0
)

FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG        5.0.1
)

# ------------------------------------------------------------------
set(SPDLOG_MASTER_PROJECT ON)
FetchContent_MakeAvailable(spdlog)
# FetchContent_MakeAvailable(cli11)
# FetchContent_MakeAvailable(googletest)

# You have to add this before FetchContent otherwise it won't work
set(CAPSTONE_ARM_SUPPORT ON)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF)
set(CAPSTONE_INSTALL ON)
FetchContent_MakeAvailable(capstone)

#-- Experimental Dissassembler Project
  
# set(WITCH_SRC
#   src/witch/basic_block.cpp
#   src/witch/inst_analyzer.cpp
#   src/witch/branch_data.cpp
# )

# add_executable(witch)

# target_include_directories(witch PRIVATE include)
# target_sources(witch PRIVATE ${WITCH_SRC} src/witch/witch.cpp)
# target_link_libraries(witch PRIVATE capstone spdlog)

#-- END

#-- SHARED IPC Start

# set(SHAMAN_IPC_SRC
#   src/mempipe/main.cpp
# )

# add_executable(shaman_ipc)
# # target_include_directories(witch PRIVATE src/mempipe)
# target_sources(shaman_ipc PRIVATE ${SHAMAN_IPC_SRC} src/mempipe/main.cpp)

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
  src/debug_opts.cpp
  src/debugger.cpp
  src/breakpoint.cpp
  src/breakpoint_mngr.cpp
  src/breakpoint_reader.cpp
  src/coverage_trace_writer.cpp
  src/tracee.cpp
  src/syscall_injector.cpp
  src/linux_debugger.cpp
  src/syscall_mngr.cpp
  src/syscall.cpp
  src/utils.cpp

  # Disassebler/Assember Module
  src/witch/inst_analyzer.cpp
  src/witch/branch_data.cpp
  src/witch/witch.cpp
)

set(PUBLIC_HEADER
  include/breakpoint.hpp
  include/breakpoint_mngr.hpp
  include/breakpoint_reader.hpp
  include/config.hpp
  include/coverage_trace_writer.hpp
  include/debugger.hpp
  include/debug_opts.hpp
  include/mempipe.hpp
  include/linux_debugger.hpp
  include/memory.hpp
  include/modules.hpp
  include/registers.hpp
  include/syscall_collections.hpp
  include/syscall.hpp
  include/syscall_injector.hpp
  include/syscall_mngr.hpp
  include/tracee.hpp
  include/utils.hpp
)

add_library(${PROJECT_NAME} STATIC)

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADER}")


set_target_properties(${PROJECT_NAME} PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}"
)

# Main shaman Instrumentation project

target_sources(${PROJECT_NAME} PRIVATE ${WITCH_SRC})

target_sources(${PROJECT_NAME} PRIVATE ${SRC} ${ARCH_SRC})

target_include_directories(${PROJECT_NAME}
  PRIVATE
  # where the library itself will look for its internal headers
  ${CMAKE_CURRENT_SOURCE_DIR}/src/witch
  PUBLIC
      # where top-level project will look for the library's public headers
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      # where external projects will look for the library's public headers
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS ${PROJECT_NAME}
    EXPORT "${PROJECT_NAME}Targets"
    # these get default values from GNUInstallDirs, no need to set them
    #RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
    #LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    #ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    # except for public headers, as we want them to be inside a library folder
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME} # include/SomeLibrary
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # include
)

install(TARGETS spdlog_header_only
    EXPORT "${PROJECT_NAME}Targets"
    # these get default values from GNUInstallDirs, no need to set them
    #RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
    #LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    #ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    # except for public headers, as we want them to be inside a library folder
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/spdlog_header_only
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # include
)

install(TARGETS capstone
    EXPORT "${PROJECT_NAME}Targets"
    # these get default values from GNUInstallDirs, no need to set them
    #RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
    #LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    #ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
    # except for public headers, as we want them to be inside a library folder
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME} # include/SomeLibrary
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # include
)

install(
  TARGETS spdlog 
  EXPORT "${PROJECT_NAME}Targets"
)

# install(
#   TARGETS capstone 
#   EXPORT "${PROJECT_NAME}Targets"
# )

# generate and install export file
install(EXPORT "${PROJECT_NAME}Targets"
    FILE "${PROJECT_NAME}Targets.cmake"
    # NAMESPACE ${namespace}::
    DESTINATION cmake
)

include(CMakePackageConfigHelpers)

# generate the version file for the config file
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION "0.1337"
    COMPATIBILITY AnyNewerVersion
)
# create config file
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION cmake
)
# install config files
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION cmake
)
# target_link_libraries(shaman -static)

target_link_libraries(${PROJECT_NAME} PUBLIC spdlog_header_only capstone)

# target_link_libraries(shaman PUBLIC spdlog CLI11::CLI11 capstone)

# add_subdirectory(apps)
# -- Testing configuration

set(TEST_TARGET_APP "test_target")

project(${TEST_TARGET_APP})

add_executable(${TEST_TARGET_APP})

target_sources(${TEST_TARGET_APP}
  PRIVATE
  test/test_prog/prog.c
)

target_link_libraries(${TEST_TARGET_APP} pthread)

# # Client Server
# add_executable(client test/network/client.c)
# add_executable(server test/network/server.c)

# add_executable(oop_test test/oop_test.cpp)

# set(TEST_SRC
#   test/unittest/test.cpp
# )
# include(GoogleTest)

# add_executable(tests ${TEST_SRC})
# target_include_directories(tests PRIVATE src/arch/intel)
# target_include_directories(tests PRIVATE src)
# target_sources(tests PRIVATE ${SRC} ${ARCH_SRC})
# target_link_libraries(tests PRIVATE spdlog)
# target_link_libraries(tests PRIVATE GTest::gtest_main gmock)