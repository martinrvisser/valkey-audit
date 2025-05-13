cmake_minimum_required(VERSION 3.10)
project(ValkeyAudit VERSION 0.0.1 DESCRIPTION "Valkey Audit module")
find_package(Git)
message(STATUS "GIT_EXECUTABLE='${GIT_EXECUTABLE}'")

include(GNUInstallDirs)
set(DEFAULT_BUILD_TYPE "Debug")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

include(FetchContent)
FetchContent_Declare(
    valkey
    GIT_REPOSITORY https://github.com/valkey-io/valkey.git
    GIT_TAG        8.0.2
)
FetchContent_MakeAvailable(valkey)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)

configure_file(${FETCHCONTENT_BASE_DIR}/valkey-src/src/valkeymodule.h ${CMAKE_CURRENT_BINARY_DIR}/include COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test/valkey.conf ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wunused -Wunused-parameter")

file(GLOB SOURCES src/*.c)

add_library(valkeyaudit SHARED ${SOURCES})

target_link_libraries(valkeyaudit)

target_include_directories(valkeyaudit PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}/include
)

set_target_properties(valkeyaudit PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    COMPILE_WARNING_AS_ERROR ON
    C_STANDARD 17)

install(TARGETS valkeyaudit
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

enable_testing()

add_subdirectory(test)
