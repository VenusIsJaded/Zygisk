# SPDX-License-Identifier: Apache-2.0
# native/libzygisk/CMakeLists.txt
#
# libzygisk.so is the *very first* library our code runs in. It is the
# one that lands inside the Android zygote process via the
# ro.dalvik.vm.native.bridge property swap.
#
# Public ABI: exactly two symbols.
#   - JNI_OnLoad (called by libart.so when libzygisk.so is dlopen-ed)
#   - NativeBridge2Itf (Android's native bridge function table)
#
# Everything else is hidden. A reverse engineer can `readelf -a` this
# .so and see only those two exports + the standard C++ runtime stuff
# from libc++.

cmake_minimum_required(VERSION 3.18)

add_library(zygisk SHARED
    src/entry.cpp
)

# Name the output file libzygisk.so explicitly so it matches the path
# the daemon expects to set ro.dalvik.vm.native.bridge to.
set_target_properties(zygisk PROPERTIES
    OUTPUT_NAME zygisk
    PREFIX      lib
)

# libzygisk.so is loaded into every process via the native-bridge hook,
# which means we cannot depend on any symbol that is not already in
# libc.so at the time the runtime calls our entry. We therefore keep
# the dependency list to:
#   - libdl  (for dlsym to find the real native bridge)
#   - liblog (for ZS_LOG* macros)
target_link_libraries(zygisk
    dl
    log
)
