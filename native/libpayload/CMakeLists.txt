# CMakeLists.txt for libpayload.so
#
# Builds libpayload.so for the 4 Android ABIs.
# Use with the Android NDK toolchain file.
#
# Example:
#   mkdir build-arm64 && cd build-arm64
#   cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
#         -DCMAKE_BUILD_TYPE=Release ..
#   make -j

cmake_minimum_required(VERSION 3.18)
project(libpayload C)

add_library(payload SHARED payload.c)

target_link_libraries(payload
    log
)

# Strip on release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(payload PRIVATE -Wl,--gc-sections -s)
endif()

# Size-optimized build
target_compile_options(payload PRIVATE
    -Os
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

# Only the 4 documented symbols are exported.
set_target_properties(payload PROPERTIES
    OUTPUT_NAME payload
    PREFIX lib
)
target_link_options(payload PRIVATE
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/payload.map
)
