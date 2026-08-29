# CMakeLists.txt for zygiskd
#
# Builds the zygiskd executable for the 4 Android ABIs.

cmake_minimum_required(VERSION 3.18)
project(zygiskd C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(zygiskd
    main.cpp
    daemon.cpp
    ptrace_inject.cpp
    modules.cpp
    config.cpp
)

target_link_libraries(zygiskd
    dl
    log
)

target_compile_options(zygiskd PRIVATE
    -Os
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
)

target_link_options(zygiskd PRIVATE
    -Wl,--gc-sections
    -Wl,--exclude-libs,ALL
    -pie
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(zygiskd PRIVATE -s)
endif()

install(TARGETS zygiskd DESTINATION bin)
