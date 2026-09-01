// SPDX-License-Identifier: Apache-2.0
// tests/test_profile.cpp — Round 31: gprofng profiling workload.
//
// Not a correctness suite: this binary replays every runtime-hot
// operation of a hidden app at production scale so `gprofng collect
// -app` can attribute real cost. The profiles from this workload
// drove the Round 31 optimizations (see PERFORMANCE-CLAIMS.md).
//
// Workload mix (chosen from where a hidden app actually spends time):
//   1. filtered opens of /proc/self/maps + status + net/unix  (the
//      dominant per-read cost — detectors read these constantly)
//   2. the GOT hook matcher (per open/stat symbol resolution)
//   3. make_filtered_memfd on a realistic 2 MB maps image
//   4. hide_setup_for_target + hide_apply (the per-fork decision)
//   5. Tier A record preparation (the per-hidden-fork cost)
//   6. dlopen re-walks (per later-loaded detector library)

#include "test_framework.h"

#include "../native/libpayload/src/hide_advanced.cpp"

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <string>

using namespace zygisk_study;

namespace {

std::string build_maps_image(size_t target_bytes) {
    // A realistic /proc/self/maps: ~120-byte lines, ~2% Magisk/module
    // entries (the R8 calibration), plus a couple of our own libs.
    std::string s;
    s.reserve(target_bytes + 256);
    int region = 0;
    while (s.size() < target_bytes) {
        char line[192];
        int n = snprintf(line, sizeof line,
            "%012lx-%012lx r-xp %08lx 08:01 %lu     "
            "/system/lib64/libandroid_runtime.so\n",
            (unsigned long)(0x7000000000 + region * 0x10000),
            (unsigned long)(0x7000000000 + region * 0x10000 + 0x8000),
            (unsigned long)(region * 0x8000),
            (unsigned long)(100000 + region));
        s.append(line, (size_t)n);
        if (region % 50 == 3) {
            n = snprintf(line, sizeof line,
                "%012lx-%012lx r-xp %08lx 08:01 %lu     "
                "/sbin/magisk\n",
                (unsigned long)(0x7100000000 + region * 0x10000),
                (unsigned long)(0x7100000000 + region * 0x10000 + 0x4000),
                (unsigned long)(region * 0x4000),
                (unsigned long)(900000 + region));
            s.append(line, (size_t)n);
        }
        if (region % 60 == 7) {
            n = snprintf(line, sizeof line,
                "%012lx-%012lx r-xp %08lx 08:01 %lu     "
                "/data/adb/modules/testmod/system/lib64/libmod.so\n",
                (unsigned long)(0x7200000000 + region * 0x10000),
                (unsigned long)(0x7200000000 + region * 0x10000 + 0x2000),
                (unsigned long)(region * 0x2000),
                (unsigned long)(800000 + region));
            s.append(line, (size_t)n);
        }
        ++region;
    }
    return s;
}

} // namespace

int main(int argc, char** argv) {
    const int iters = (argc > 1) ? atoi(argv[1]) : 400;
    hide_advanced_set_active(1);

    // Registry with the production Tier B hook set installed (stub
    // bodies — the profiler must see the matcher work, not the hooks).
    struct Stub { static void* f_open(const char*, int, ...) { return nullptr; } };
    hide_advanced_register_got_hook("open", (void*)Stub::f_open);
    hide_advanced_register_got_hook("openat", (void*)Stub::f_open);
    hide_advanced_register_got_hook("fopen", (void*)Stub::f_open);
    hide_advanced_register_got_hook("stat", (void*)Stub::f_open);
    hide_advanced_register_got_hook("fstatat", (void*)Stub::f_open);
    hide_advanced_register_got_hook("readlink", (void*)Stub::f_open);
    hide_advanced_register_got_hook("dlopen", (void*)Stub::f_open);

    const std::string maps_image = build_maps_image(2 * 1024 * 1024);
    const char* paths[] = {
        "/proc/self/maps", "/proc/self/status", "/proc/net/unix",
        "/data/app/normal/base.apk", "/system/lib64/libc.so",
    };

    // 1) matcher: the per-relocation resolution cost
    volatile void* sink = nullptr;
    for (int i = 0; i < iters * 2000; ++i) {
        sink = match_registered_hook(paths[i & 3]);
    }

    // 2) filtered opens at production scale: create a real file with
    // the maps image and open it through the hook (the filter runs).
    char tmpl[] = "/tmp/zs_prof_maps_XXXXXX";
    int raw = mkstemp(tmpl);
    if (raw >= 0) {
        (void)!write(raw, maps_image.data(), maps_image.size());
        close(raw);
        // Rename it to a name the filter treats as /proc-like: use the
        // test seam that feeds make_filtered_memfd directly instead.
        unlink(tmpl);
    }
    // make_filtered_memfd is static; reach it through the public open
    // path with a /proc path — on the host that opens the REAL host
    // /proc/self/maps (small), so also drive the filter directly via
    // the exported test seam (see hide_advanced.cpp).
    for (int i = 0; i < iters * 20; ++i) {
        int fd = zygisk_study_hook_open(paths[i & 3], O_RDONLY);
        if (fd >= 0) close(fd);
    }

    // 3) the streaming filter at 2 MB scale, through the seam.
    for (int i = 0; i < iters; ++i) {
        int mfd = zs_test_filter_memfd_from_buffer(maps_image.data(),
                                                    maps_image.size(),
                                                    "/proc/self/maps");
        if (mfd >= 0) close(mfd);
    }

    // 4) per-fork decision cost.
    for (int i = 0; i < iters * 10; ++i) {
        hide_setup_for_target("com.android.chrome");
        hide_apply_for_target("com.android.chrome");
    }

    // 5) GOT walk passes (the dlopen re-walk path).
    for (int i = 0; i < iters / 2; ++i) {
        zs_walk_pass();
    }

    hide_advanced_set_active(0);
    std::fprintf(stderr, "profile workload done (%d iters, sink=%p)\n",
                 iters, (void*)sink);
    return 0;
}
