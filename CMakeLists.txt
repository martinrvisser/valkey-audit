cmake_minimum_required(VERSION 3.10)
project(ValkeyAudit VERSION 1.0.0 DESCRIPTION "Valkey Audit module")

find_package(Git)
find_package(Threads REQUIRED)
message(STATUS "GIT_EXECUTABLE='${GIT_EXECUTABLE}'")
include(GNUInstallDirs)

# CHANGED: Default to Release for performance testing
# You can override with: cmake -DCMAKE_BUILD_TYPE=Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/valkey.conf ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

# CHANGED: Conditional flags based on build type
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wunused -Wunused-parameter -pthread")

# Performance-focused flags for Release builds.
# WARNING: -march=native tunes the binary to the BUILDING host's CPU and is NOT
# portable -- a binary built this way may SIGILL on older CPUs. Distributable
# builds (see docker/Dockerfile.module) MUST override the baseline, e.g.
#   cmake -DAUDIT_C_FLAGS_RELEASE="-O2 -DNDEBUG -march=x86-64-v2 -flto"
# Indirection through a CACHE variable is deliberate: a plain
# set(CMAKE_C_FLAGS_RELEASE ...) would shadow and silently discard any
# -DCMAKE_C_FLAGS_RELEASE passed on the command line.
set(AUDIT_C_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -mtune=native -flto"
    CACHE STRING "C compiler flags for Release builds")
set(CMAKE_C_FLAGS_RELEASE "${AUDIT_C_FLAGS_RELEASE}")

# Alternative optimization levels for testing
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

# Debug flags (your original behavior)
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -DDEBUG")

file(GLOB SOURCES src/*.c)

# Define the library target
add_library(valkeyaudit SHARED ${SOURCES})

# Optional path to valkeymodule.h, e.g. when building against Valkey source
# instead of system-installed valkey-devel headers
# Usage: cmake -DVALKEY_INCLUDE_DIR=/opt/valkey-src/src
option(VALKEY_INCLUDE_DIR "Path to valkeymodule.h" "")
message(STATUS "Valkey include dir: ${VALKEY_INCLUDE_DIR}")

target_include_directories(valkeyaudit PRIVATE
    src
    ${VALKEY_INCLUDE_DIR}
)

target_link_libraries(valkeyaudit PRIVATE Threads::Threads)

target_compile_definitions(valkeyaudit PRIVATE
    _GNU_SOURCE
    _REENTRANT
    _THREAD_SAFE
)

# Thread-safe compilation options
target_compile_options(valkeyaudit PRIVATE
    -fPIC
    -pthread
)

set_target_properties(valkeyaudit PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    COMPILE_WARNING_AS_ERROR ON
    C_STANDARD 17
    POSITION_INDEPENDENT_CODE ON
)

# ADDED: Print build configuration for debugging
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C flags: ${CMAKE_C_FLAGS}")
message(STATUS "C flags for ${CMAKE_BUILD_TYPE}: ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}}")
message(STATUS "Threads found: ${Threads_FOUND}")
message(STATUS "Thread library: ${CMAKE_THREAD_LIBS_INIT}")

install(TARGETS valkeyaudit
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Tests are built by default but can be skipped (e.g. distributable artifact
# builds) to avoid the configure-time googletest FetchContent download.
option(VALKEY_AUDIT_TESTS "Build the test suite" ON)
enable_testing()
if(VALKEY_AUDIT_TESTS)
    add_subdirectory(test)
endif()