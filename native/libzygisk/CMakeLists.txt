# SPDX-License-Identifier: Apache-2.0
# native/libzygisk/CMakeLists.txt
#
# libzygisk.so is the *very first* library our code runs in. It is the
# one that lands inside the Android zygote process via the
# ro.dalvik.vm.native.bridge property swap.
#
# Public ABI: exactly two symbols.
#   - JNI_OnLoad (called by libart.so when libzygisk.so is dlopen-ed)
#   - NativeBridgeItf (Android's native bridge function table; the
#     historical NativeBridge2Itf alias is exported alongside it)
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

# Round 25: -z nodelete (DF_1_NODELETE). Every same-arch zygote child
# calls InitNonZygoteOrPostFork(kUnload) -> UnloadNativeBridge ->
# dlclose(our handle) — on EVERY studied Android version. When the
# refcount hits zero the linker calls DT_FINI; in a Tier A
# (self-unmapped) hidden child that address is already unmapped .text,
# which is a crash in every hidden Tier A child at
# callPostForkChildHooks. NODELETE makes bionic's soinfo_unload
# can_unload() check fail and return before any destructor call (the
# flag is honored since the L-era linker rewrite; unload logic read
# from the 8.1 sources this round, same lineage in 7.x). The flag
# composes with Tier A: our unmap is a raw munmap and never consults
# the linker's bookkeeping.
target_link_options(zygisk PRIVATE "-Wl,-z,nodelete")

# Round 27: 16 KB page-size alignment (Android 15+ supports 16 KB
# kernels; Pixel 9a and later ship them with Android 16+). The
# dynamic linker on a 16 KB device refuses ELF LOAD segments aligned
# below the kernel page size, so a 4 KB-aligned libzygisk.so fails
# to dlopen in the ZYGOTE — total injection failure, not just a
# warning (the "16 KB backcompat" loading mode is a package-manager
# concession for apps, not something to rely on for a bridge).
# max-page-size=16384 pads the LOAD segments to 16 KB alignment and
# is fully compatible with every 4 KB device ever shipped (the
# official NDK guidance: developer.android.com/guide/practices/
# page-sizes, fetched and read this round). common-page-size follows
# the same guidance.
if(ANDROID)
    target_link_options(zygisk PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384")
endif()
