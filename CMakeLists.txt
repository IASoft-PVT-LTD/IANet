cmake_minimum_required(VERSION 3.28)

project(IANET)
enable_testing()

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(IANET_IS_TOP_LEVEL ON)
else()
    set(IANET_IS_TOP_LEVEL OFF)
endif()

set(IANET_ROOT "${CMAKE_CURRENT_LIST_DIR}" CACHE INTERNAL "")

if(TARGET libauxid)
    message(STATUS "IANET: Using external LibAuxid provided by parent project")
else()
    message(STATUS "IANET: Building standalone, using local LibAuxid submodule")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libauxid/CMakeLists.txt")
        message(FATAL_ERROR "LibAuxid submodule missing! Run: git submodule update --init --recursive")
    endif()
    add_subdirectory(libauxid)
endif()

auxid_setup_project()

option(IANET_BUILD_TESTS "Build unit tests" ${IANET_IS_TOP_LEVEL})

include(cmake/find_deps.cmake)

add_subdirectory(src)

if(IANET_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sandbox")
    add_subdirectory(sandbox)
endif()
