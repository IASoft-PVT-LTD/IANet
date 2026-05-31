include(FetchContent)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

set(IANET_SAVED_MSVC_RUNTIME "${CMAKE_MSVC_RUNTIME_LIBRARY}" CACHE INTERNAL "")
set(IANET_SAVED_CXX_TARGET "${CMAKE_CXX_COMPILER_TARGET}" CACHE INTERNAL "")

FetchContent_Declare(
    MbedTLS
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.2
    GIT_SHALLOW    TRUE
)

if(WIN32 AND CMAKE_C_COMPILER_ID MATCHES "Clang")
  FetchContent_GetProperties(MbedTLS)
  if(NOT mbedtls_POPULATED)
    FetchContent_Populate(MbedTLS)
  endif()

  file(GLOB _IANET_MBEDTLS_LIBRARY_SOURCES CONFIGURE_DEPENDS "${mbedtls_SOURCE_DIR}/library/*.c")
  set(_IANET_MBEDTLS_EVEREST_SOURCES
      "${mbedtls_SOURCE_DIR}/3rdparty/everest/library/everest.c"
      "${mbedtls_SOURCE_DIR}/3rdparty/everest/library/x25519.c"
      "${mbedtls_SOURCE_DIR}/3rdparty/everest/library/Hacl_Curve25519_joined.c"
  )
  file(GLOB _IANET_MBEDTLS_P256M_SOURCES CONFIGURE_DEPENDS
       "${mbedtls_SOURCE_DIR}/3rdparty/p256-m/*.c"
       "${mbedtls_SOURCE_DIR}/3rdparty/p256-m/p256-m/*.c")

  add_library(ianet_mbedtls STATIC
      ${_IANET_MBEDTLS_LIBRARY_SOURCES}
      ${_IANET_MBEDTLS_EVEREST_SOURCES}
      ${_IANET_MBEDTLS_P256M_SOURCES}
  )

  target_include_directories(ianet_mbedtls
      PUBLIC "${mbedtls_SOURCE_DIR}/include"
      PRIVATE
          "${mbedtls_SOURCE_DIR}/library"
          "${mbedtls_SOURCE_DIR}/3rdparty/everest/include"
          "${mbedtls_SOURCE_DIR}/3rdparty/everest/include/everest"
          "${mbedtls_SOURCE_DIR}/3rdparty/everest/include/everest/kremlib"
          "${mbedtls_SOURCE_DIR}/3rdparty/p256-m"
          "${mbedtls_SOURCE_DIR}/3rdparty/p256-m/p256-m"
  )

  target_compile_options(ianet_mbedtls PRIVATE -Wno-everything)
  add_library(MbedTLS::mbedcrypto ALIAS ianet_mbedtls)
  add_library(MbedTLS::mbedx509 ALIAS ianet_mbedtls)
  add_library(MbedTLS::mbedtls ALIAS ianet_mbedtls)
else()
  FetchContent_MakeAvailable(MbedTLS)
endif()
