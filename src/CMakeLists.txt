add_library(ianet STATIC 
    cpp/client.cpp
    cpp/connection.cpp
    cpp/context.cpp
    cpp/server.cpp
)

target_include_directories(ianet PUBLIC
    $<BUILD_INTERFACE:${ianet_ROOT}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(ianet PRIVATE hpp)

target_link_libraries(ianet PUBLIC libauxid)
target_link_libraries(ianet PRIVATE auxid_platform_standard)
