# CMakeLists.txt for libzygisk.so

cmake_minimum_required(VERSION 3.18)
project(libzygisk C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(zygisk SHARED zygisk_entry.cpp)

target_link_libraries(zygisk
    dl
    log
)

target_compile_options(zygisk PRIVATE
    -Os
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
)

target_link_options(zygisk PRIVATE
    -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/zygisk.map
    -Wl,--exclude-libs,ALL
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(zygisk PRIVATE -s)
endif()
