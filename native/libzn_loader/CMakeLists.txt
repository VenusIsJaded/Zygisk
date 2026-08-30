# SPDX-License-Identifier: Apache-2.0
# native/libzn_loader/CMakeLists.txt
#
# libzn_loader.so — optional bridge library that exposes the
# init-oriented Zygisk Study API (zygisk_study_api.h).
#
# Public ABI:
#   - The exported symbol named by ZYGISK_STUDY_API_VERSION_STRING
#     (a function-pointer table the module dereferences).
#   - The loader's own entry point (called by the daemon when it
#     wants to inject libzn_loader into a target process via ptrace
#     LD_PRELOAD swap, on platforms where the native-bridge trick
#     doesn't work).
#
# Dependencies:
#   - libdl  (for dlopen of libpayload)
#   - liblog (for ZS_LOG* macros)

cmake_minimum_required(VERSION 3.18)

add_library(zn_loader SHARED
    src/entry.cpp
)

set_target_properties(zn_loader PROPERTIES
    OUTPUT_NAME zn_loader
    PREFIX      lib
)

target_link_libraries(zn_loader
    dl
    log
)
