include(FetchContent)

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
