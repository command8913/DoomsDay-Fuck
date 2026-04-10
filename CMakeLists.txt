cmake_minimum_required(VERSION 3.20)
project(doomsdayfuck LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(doomsdayfuck main.cpp)

set_target_properties(doomsdayfuck PROPERTIES
        LINK_SEARCH_START_STATIC ON
        LINK_SEARCH_END_STATIC ON
)

target_link_options(doomsdayfuck PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
)

target_link_libraries(doomsdayfuck PRIVATE
        winpthread
)