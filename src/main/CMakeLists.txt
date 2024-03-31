add_library(cracker-objects OBJECT
        index.cpp
        io.cpp
        md5.cpp
        settings.cpp
)

target_link_libraries(cracker-objects PUBLIC
        Threads::Threads
)

add_executable(cracker
        cracker.cpp
)

target_link_libraries(cracker PRIVATE
        cracker-objects
)

install(TARGETS cracker)
