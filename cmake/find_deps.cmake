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

# AWS-LC backs the provider-neutral memory-BIO API exported by ianet.crypto.
# Keep its broad option names function-scoped so IANET remains composable as a
# subdirectory dependency.
function(ianet_add_aws_lc)
  set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
  set(BUILD_SHARED_LIBS OFF)
  set(BUILD_LIBSSL ON)
  set(BUILD_TESTING OFF)
  set(BUILD_TOOL OFF)
  set(DISABLE_GO ON)
  set(DISABLE_PERL ON)
  unset(ENABLE_PRE_SONAME_BUILD CACHE)

  FetchContent_Declare(aws_lc
      URL https://github.com/aws/aws-lc/archive/refs/tags/v1.73.0.tar.gz
      URL_HASH SHA256=e33ae89e7d09d7b23a900f68b62088d8813c260ac564b016e543ee3540ebcce3
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
      SYSTEM
      EXCLUDE_FROM_ALL
  )
  FetchContent_MakeAvailable(aws_lc)
endfunction()

ianet_add_aws_lc()

if(NOT TARGET ssl OR NOT TARGET crypto)
  message(FATAL_ERROR "IANET: AWS-LC did not provide its ssl and crypto targets")
endif()

add_library(IANET_CryptoProvider INTERFACE)
target_link_libraries(IANET_CryptoProvider INTERFACE ssl crypto)
add_library(IANET::CryptoProvider ALIAS IANET_CryptoProvider)
