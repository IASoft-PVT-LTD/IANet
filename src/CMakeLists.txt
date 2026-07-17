add_library(IANET STATIC
    cpp/client.cpp
    cpp/connection.cpp
    cpp/context.cpp
    cpp/server.cpp
    cpp/http.cpp
    cpp/tls_context.cpp
    cpp/crypto.cpp
    cpp/crypto_tls_profile.cpp
    cpp/crypto_tls_session.cpp
    cpp/vendor/picohttpparser/picohttpparser.c
)

target_sources(IANET
    PUBLIC FILE_SET ianet_modules TYPE CXX_MODULES
        BASE_DIRS "${CMAKE_CURRENT_LIST_DIR}/modules"
        FILES
            modules/ianet.cppm
            modules/ianet.tls.cppm
            modules/ianet.crypto.cppm
            modules/ianet.http.cppm
            modules/ianet.https.cppm
)

target_include_directories(IANET PRIVATE hpp cpp)

target_link_libraries(IANET PUBLIC libauxid)
target_link_libraries(IANET PRIVATE IANET::CryptoProvider)

if(WIN32)
    target_link_libraries(IANET PRIVATE ws2_32 bcrypt)
endif()

set_target_properties(IANET PROPERTIES CXX_SCAN_FOR_MODULES ON)
