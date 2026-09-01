# SPDX-License-Identifier: Apache-2.0
# native/CMakeLists.txt — top-level build for the three C++ libraries
# (libzygisk.so, libpayload.so, libzn_loader.so) of Zygisk Study.
#
# The daemon `zygiskd` is built separately by Cargo (see native/zygiskd).
#
# This file is intentionally flat and obvious: there are three targets,
# each with its own small CMakeLists.txt under its own subdirectory.
# We just dispatch to them. A reader of the build script should be
# able to follow the structure without having to chase variables.

cmake_minimum_required(VERSION 3.18)

project(zygisk_study
    LANGUAGES C CXX ASM
    VERSION 0.1.0
)

# ROUND 32 (found by actually cross-compiling with the NDK — the first
# time this tree was ever built for Android): the payload's self-unmap
# trampoline is assembly (unmap_trampoline_aarch64.S /
# unmap_trampoline_x86_64.S), and CMake only compiles .S files when ASM
# is an enabled language. Without it the trampoline sources were
# silently DROPPED from the payload target — libpayload.so linked with
# undefined zs_fork_wrapper / zs_setresuid_wrapper / zs_setgid_wrapper /
# zs_setresgid_wrapper / zs_setuid_wrapper and could never build. The
# host test suite never caught this because tests/Makefile compiles the
# .cpp/.S sources directly with g++ instead of through CMake.

# All library outputs land directly in the build directory (not in
# per-target subdirectories) — scripts/build_module.sh and humans both
# expect <build>/libzygisk.so, <build>/libpayload.so, ...
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Common compile flags. We target C++17 for the standard library and
# insist on visibility=hidden so that only the symbols we explicitly
# mark with __attribute__((visibility("default"))) become part of the
# final ABI. This makes the .so files easy to enumerate with readelf
# or nm — anyone reverse engineering them will see a tiny export
# table, which is the goal ("easy to reverse engineer").
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

# ROUND 33 (stealth release — the -g/-O1 philosophy flips): the two
# libraries this build places in /system/lib[64] are world-readable by
# every app, and until this round the Release build shipped full DWARF
# (~1 MB of a 1.7 MB libpayload), a complete .symtab/.strtab, absolute
# build-host paths in .debug_str, and 500+ libc++_static symbols in
# .dynsym — a gift to any file-scanning detector. Release is now the
# STEALTH artifact: -O2, no debug info, logs compiled out (ZS_STEALTH,
# see native/common/log.h), string constants obfuscated (obfstr.h),
# static-archive symbols excluded from .dynsym (--exclude-libs,ALL),
# and no DT_SONAME. Debug builds (CMAKE_BUILD_TYPE=Debug) keep -g and
# full logs — that is the readable-for-study flavor now.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE   "-O2 -DNDEBUG")
endif()

# ROUND 33: ZS_STEALTH compiles the ZS_LOG* macros to nothing in the
# Android Release build (see native/common/log.h). Host unit tests and
# Debug builds never define it, so the study logs stay available where
# a human is looking.
if(ANDROID AND CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(ZS_STEALTH)
endif()

# Android-specific tweak: link against libdl and liblog (Android ships
# these as separate .so on every platform). libdl is needed for dlopen
# of third-party module .so files; liblog is needed for the logging
# helper under native/common/log.h.
if(ANDROID)
    link_libraries("dl" "log")
endif()

# Allow subdirectories to find the common headers.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

# Each library is its own subdirectory. They do not depend on each
# other at link time (libpayload loads libzygisk via dlopen, etc.),
# so they can be built in any order.
add_subdirectory(libzygisk)
add_subdirectory(libpayload)
add_subdirectory(libzn_loader)
