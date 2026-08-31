// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/resolve_libc.h
//
// Portable libc symbol resolution shared by the payload TUs.
//
// Bionic exposes libc as "libc.so"; glibc's loadable name is
// "libc.so.6"; and on host test builds the RTLD_DEFAULT search finds
// everything anyway. Trying all three keeps the same code path
// working on device, in tests, and under sanitizers.

#pragma once

#include <dlfcn.h>

namespace zygisk_study {

inline void* zs_resolve_libc(const char* name) {
    void* h = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!h) h = dlopen("libc.so.6", RTLD_NOLOAD | RTLD_LAZY);
    void* fn = h ? dlsym(h, name) : nullptr;
    if (!fn) fn = dlsym(RTLD_DEFAULT, name);
    return fn;
}

} // namespace zygisk_study
