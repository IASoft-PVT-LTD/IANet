cmake_minimum_required(VERSION 3.20)

project(ianet)
enable_testing()

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(ianet_IS_TOP_LEVEL ON)
else()
    set(ianet_IS_TOP_LEVEL OFF)
endif()

set(ianet_ROOT "${CMAKE_CURRENT_LIST_DIR}" CACHE INTERNAL "")

if(TARGET libauxid)
    message(STATUS "ianet: Using external LibAuxid provided by parent project")
else()
    message(STATUS "ianet: Building standalone, using local LibAuxid submodule")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libauxid/CMakeLists.txt")
        message(FATAL_ERROR "LibAuxid submodule missing! Run: git submodule update --init --recursive")
    endif()
    add_subdirectory(libauxid)
endif()

auxid_setup_project()

option(ianet_BUILD_TESTS "Build unit tests" ${ianet_IS_TOP_LEVEL})

include(cmake/find_deps.cmake)

add_subdirectory(src)

if(ianet_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sandbox")
    add_subdirectory(sandbox)
endif()
