include_directories(
        ../main
)

add_executable(tests
        md5.cpp
)

target_link_libraries(tests PRIVATE
        catch2::catch2_with_main
        cracker-objects
)

catch_discover_tests(tests)
