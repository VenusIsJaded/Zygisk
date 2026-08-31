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
# Round 12: module_dispatch.cpp owns the module-facing machinery
# (registry, zygisk::Api implementation, JNIEnv acquisition, the
# onLoad / pre/post-specialize dispatch state machines).
#
# Round 7: the build now includes the per-architecture self-unmap
# trampoline (asm wrappers + the PIC blob). arm64-v8a and x86_64 get
# the full Tier A "vanish" path; other ABIs fall back to the Tier B
# hook-based hiding at runtime (zs_trampoline_supported() == 0).

cmake_minimum_required(VERSION 3.18)

set(PAYLOAD_SOURCES
    src/entry.cpp
    src/module_dispatch.cpp
    src/hide.cpp
    src/hide_advanced.cpp
    src/hide_stealth.cpp
)

# The trampoline blob is per-arch. The NDK's ANDROID_ABI (or a plain
# CMAKE_SYSTEM_PROCESSOR on host builds) selects the file.
if(ANDROID_ABI STREQUAL "arm64-v8a" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    list(APPEND PAYLOAD_SOURCES src/unmap_trampoline_aarch64.S)
    message(STATUS "payload: aarch64 trampoline enabled (Tier A)")
elseif(ANDROID_ABI STREQUAL "x86_64" OR ANDROID_ABI STREQUAL "x86_64-v7a" OR CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64)")
    list(APPEND PAYLOAD_SOURCES src/unmap_trampoline_x86_64.S)
    message(STATUS "payload: x86_64 trampoline enabled (Tier A)")
else()
    message(WARNING "payload: no trampoline for ABI '${ANDROID_ABI}' — "
                    "runtime falls back to Tier B (hook-based hiding)")
endif()

add_library(payload SHARED ${PAYLOAD_SOURCES})

set_target_properties(payload PROPERTIES
    OUTPUT_NAME payload
    PREFIX      lib
)

target_link_libraries(payload
    dl
    log
)

# Round 25: same NODELETE rationale as libzygisk (defense in depth on
# top of the runtime self-pin in zygisk_study_payload_init): no
# dlclose chain anywhere may ever reach DT_FINI, because Tier A
# children no longer have that code mapped.
#
# Round 27: 16 KB page-size alignment — same rationale as libzygisk
# (Android 15+/16+ 16 KB-kernel devices; see the comment there). The
# payload's own page math already uses sysconf(_SC_PAGESIZE) at every
# spot that matters (trampoline page, prop_info page roundings), so
# only the ELF alignment needed fixing.
target_link_options(payload PRIVATE "-Wl,-z,nodelete")
if(ANDROID)
    target_link_options(payload PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384")
endif()
