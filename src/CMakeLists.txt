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

target_sources(IANET
    PUBLIC FILE_SET ianet_modules TYPE CXX_MODULES
        BASE_DIRS "${CMAKE_CURRENT_LIST_DIR}/modules"
        FILES
            modules/ianet.cppm
            modules/ianet.http.cppm
)

target_include_directories(IANET PRIVATE hpp)

target_link_libraries(IANET PUBLIC libauxid)

if(WIN32)
    target_link_libraries(IANET PUBLIC ws2_32)
endif()

set_target_properties(IANET PROPERTIES CXX_SCAN_FOR_MODULES ON)
