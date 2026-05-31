set(SRC_FILES

    "cpp/main.cpp"

    "cpp/socket_tests.cpp"

    "cpp/http_tests.cpp"

    "cpp/tls_tests.cpp"

)



add_executable(TestSuite ${SRC_FILES})



target_link_libraries(TestSuite PRIVATE libauxid IANET)



if(WIN32)

    target_link_libraries(TestSuite PRIVATE bcrypt)

endif()



set_target_properties(TestSuite PROPERTIES CXX_SCAN_FOR_MODULES ON)



add_test(NAME TestSuite COMMAND TestSuite WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")

