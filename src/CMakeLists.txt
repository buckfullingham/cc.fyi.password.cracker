find_package(Catch2 REQUIRED)
find_package(benchmark REQUIRED)
include(CTest)
include(Catch)

add_subdirectory(main)
add_subdirectory(test)
#add_subdirectory(benchmark)


