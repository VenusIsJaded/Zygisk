# SPDX-License-Identifier: Apache-2.0
# native/libpayload/CMakeLists.txt
#
# libpayload.so — the in-process trampoline + hide layer.
#
# Public ABI: exactly three symbols.
#   - zygisk_study_payload_init   (one-time setup, called by libzygisk)
#   - zygisk_study_payload_pre_fork   (called by our fork hook)
#   - zygisk_study_payload_post_fork  (called by our fork hook)
# Everything else is hidden.
#
# Dependencies:
#   - libdl   (for dlopen of third-party module .so files)
#   - liblog  (for ZS_LOG* macros)
#
# We deliberately do NOT link against libbinder, libcutils, libutils,
# or anything else from Android's framework layer. Everything we need
# (syscalls, libc functions) is in libc.so, which is already loaded
# in every process we end up in.

cmake_minimum_required(VERSION 3.18)

add_library(payload SHARED
    src/entry.cpp
    src/hide.cpp
    src/hide_advanced.cpp
)

set_target_properties(payload PROPERTIES
    OUTPUT_NAME payload
    PREFIX      lib
)

target_link_libraries(payload
    dl
    log
)
