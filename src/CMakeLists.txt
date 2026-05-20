add_library(IANET STATIC 
    cpp/client.cpp
    cpp/connection.cpp
    cpp/context.cpp
    cpp/server.cpp
    cpp/http_client.cpp
    cpp/http_server.cpp
    cpp/http_connection.cpp
    cpp/vendor/picohttpparser/picohttpparser.c
)

target_include_directories(IANET PUBLIC
    $<BUILD_INTERFACE:${IANET_ROOT}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(IANET PRIVATE hpp)

target_link_libraries(IANET PUBLIC libauxid)
target_link_libraries(IANET PRIVATE auxid_platform_standard)
