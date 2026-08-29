# Top-level CMakeLists.txt for the Zygisk Next native binaries.
#
# Build all 4 components (zygiskd, libzygisk.so, libzn_loader.so,
# libpayload.so) for one ABI per build directory. To produce all 4
# ABIs, invoke cmake 4 times with different -DANDROID_ABI values.
#
# Example build script (see scripts/build_native.sh):
#
#   mkdir build && cd build
#   cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-26 \
#         -DCMAKE_BUILD_TYPE=Release ..
#   make -j$(nproc)

cmake_minimum_required(VERSION 3.18)
project(zygisksu C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(native/libpayload)
add_subdirectory(native/libzygisk)
add_subdirectory(native/libzn_loader)
add_subdirectory(native/zygiskd)
