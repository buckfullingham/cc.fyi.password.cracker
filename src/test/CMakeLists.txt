include_directories(
        ../main
)

add_executable(tests
        brute_force.cpp
        md5.cpp
        rainbow.cpp
        settings.cpp
)

target_link_libraries(tests PRIVATE
        catch2::catch2_with_main
        cracker-objects
)

catch_discover_tests(tests)
