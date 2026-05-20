set(SRC_FILES
    "cpp/main.cpp"
    "cpp/socket_tests.cpp"
    "cpp/http_tests.cpp"
)

add_executable(TestSuite ${SRC_FILES})

target_link_libraries(TestSuite PRIVATE libauxid IANET)

if(MSVC)
    target_compile_options(TestSuite PRIVATE /EHsc)
else()
    target_compile_options(TestSuite PRIVATE -fexceptions)
endif()

add_test(NAME TestSuite COMMAND TestSuite)
