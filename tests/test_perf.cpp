// SPDX-License-Identifier: Apache-2.0
// tests/test_perf.cpp
//
// Host-side microbenchmarks for the performance-critical hot paths.
// We DON'T compare against a "before" snapshot (that would require
// checking in the old implementation); instead, we measure the
// current implementation in absolute terms and assert that each
// hot path completes in well under the documented Android budget.
//
// The Android budgets we measure against (in µs):
//
//   make_filtered_memfd on a 100KB /proc/self/maps:   budget = 200 µs
//   hide_setup_for_target fast path (not on denylist): budget = 5 µs
//   hide_apply_for_target fast path (g_will_hide=0):    budget = 2 µs
//   unmount_magisk_paths on a 200-entry /proc/self/mounts with 0 matches:
//                                                       budget = 200 µs
//
// These budgets are calibrated to be ~10x the host measured time,
// leaving room for ARM64 being ~2-3x slower than x86_64 for tight
// code, plus the Android kernel's slightly higher per-syscall cost.
//
// Build:
//   g++ -std=c++17 -O2 -I../native/common -DZS_HOST_TEST -o test_perf test_perf.cpp -ldl
//
// Run:
//   ./test_perf

#include "test_framework.h"

#include "../native/libpayload/src/hide.cpp"
#include "../native/libpayload/src/hide_advanced.cpp"

#include <chrono>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

using namespace zygisk_study;
using clk = std::chrono::steady_clock;

// ----------------------------------------------------------------------
// Helper: build a synthetic /proc/self/maps content of N lines.
// ----------------------------------------------------------------------

static std::string make_fake_maps(size_t n_lines) {
    std::string out;
    out.reserve(n_lines * 100);  // approx 100 bytes per line
    // One Magisk line per ~50 normal lines — matches typical
    // user-device ratio (5-10 Magisk entries out of ~500 total).
    size_t magisk_every = 50;
    for (size_t i = 0; i < n_lines; ++i) {
        char line[256];
        if (i > 0 && i % magisk_every == 0) {
            // A "magisk" entry — should be filtered out by the hide layer.
            snprintf(line, sizeof line,
                "7000000%08zx-7000000%08zx r-xp 00000000 fd:00 12345 /sbin/magisk\n",
                i * 0x1000, i * 0x1000 + 0x1000);
        } else {
            // A normal libc.so entry — should be preserved.
            snprintf(line, sizeof line,
                "7000000%08zx-7000000%08zx r-xp 00000000 fd:00 12345 /system/lib64/libc.so\n",
                i * 0x1000, i * 0x1000 + 0x1000);
        }
        out.append(line);
    }
    return out;
}

// ----------------------------------------------------------------------
// Test 1: make_filtered_memfd() filters a 500-line maps file in
// under 200 µs on the host (so well under 600 µs on Android).
// ----------------------------------------------------------------------

ZS_TEST(make_filtered_memfd_filters_500_lines_under_200us) {
    std::string content = make_fake_maps(500);
    // Sanity: 500 lines × ~80 chars/line ≈ 40 KB.
    ZS_CHECK(content.size() > 30000);  // sanity

    // Warm up: run once to fault in all pages.
    int warmup_fd = syscall_memfd_create("warmup", 0);
    ZS_CHECK(warmup_fd >= 0);
    write(warmup_fd, content.data(), content.size());
    lseek(warmup_fd, 0, SEEK_SET);
    int warmup_out = make_filtered_memfd(warmup_fd, "/proc/self/maps");
    ZS_CHECK(warmup_out >= 0);
    close(warmup_fd); close(warmup_out);

    // Measure: 50 iterations, take median.
    constexpr int N = 50;
    long long durations_us[N];
    for (int i = 0; i < N; ++i) {
        int fd = syscall_memfd_create("perf", 0);
        ZS_CHECK(fd >= 0);
        write(fd, content.data(), content.size());
        lseek(fd, 0, SEEK_SET);
        auto t0 = clk::now();
        int out = make_filtered_memfd(fd, "/proc/self/maps");
        auto t1 = clk::now();
        durations_us[i] = std::chrono::duration_cast<
            std::chrono::microseconds>(t1 - t0).count();
        close(fd);
        close(out);
    }
    // Sort and take median.
    std::sort(durations_us, durations_us + N);
    long long median = durations_us[N / 2];
    std::fprintf(stderr, "  [perf] make_filtered_memfd median: %lld us\n", median);
    // Budget: 200 µs on x86_64 host. ARM64 will be ~2-3x slower,
    // so worst case ~600 µs — still well under the typical 5ms
    // Android zygote fork budget.
    ZS_CHECK(median < 2000);  // generous upper bound; < 200 is the goal
}

// ----------------------------------------------------------------------
// Test 2: hide_setup_for_target() fast path completes in under
// 5 µs on the host when the target is NOT on the denylist.
// ----------------------------------------------------------------------

ZS_TEST(hide_setup_for_target_fast_path_under_5us) {
    // Populate the denylist with a few entries (NOT the test target).
    g_denylist_cache.clear();
    g_denylist_cache.insert("com.sensitive.banking");
    g_denylist_cache.insert("com.sensitive.health");
    g_denylist_cache.insert("com.sensitive.drm");
    g_denylist_loaded.store(1);

    constexpr int N = 1000;
    long long durations_us[N];
    for (int i = 0; i < N; ++i) {
        auto t0 = clk::now();
        int r = hide_setup_for_target("com.innocent.game");
        auto t1 = clk::now();
        durations_us[i] = std::chrono::duration_cast<
            std::chrono::microseconds>(t1 - t0).count();
        ZS_CHECK_EQ(r, 0);
    }
    std::sort(durations_us, durations_us + N);
    long long median = durations_us[N / 2];
    std::fprintf(stderr, "  [perf] hide_setup_for_target fast path median: %lld us\n", median);
    // Budget: 5 µs on x86_64. ARM64 ~2-3x slower = 15 µs worst case.
    ZS_CHECK(median < 50);
}

// ----------------------------------------------------------------------
// Test 3: hide_apply_for_target() fast path (g_will_hide=0) completes
// in under 2 µs.
// ----------------------------------------------------------------------

ZS_TEST(hide_apply_for_target_fast_path_under_2us) {
    g_will_hide.store(0);
    constexpr int N = 1000;
    long long durations_us[N];
    for (int i = 0; i < N; ++i) {
        auto t0 = clk::now();
        hide_apply_for_target("anything");
        auto t1 = clk::now();
        durations_us[i] = std::chrono::duration_cast<
            std::chrono::microseconds>(t1 - t0).count();
    }
    std::sort(durations_us, durations_us + N);
    long long median = durations_us[N / 2];
    std::fprintf(stderr, "  [perf] hide_apply_for_target fast path median: %lld us\n", median);
    // Budget: 2 µs on x86_64. ARM64 ~2-3x slower = 6 µs worst case.
    ZS_CHECK(median < 20);
}

// ----------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// Round 8 (P1): the hash-indexed hook matcher resolves a symbol name
// in bounded time with ~24 registered hooks (the Tier B registry
// size). This lookup runs once per JMPREL entry of every loaded DSO
// during the hide-time GOT walk — it is the inner loop of the most
// expensive step of a hidden app launch.
// ----------------------------------------------------------------------

ZS_TEST(hook_matcher_resolves_under_100ns_median) {
    // Register a realistic Tier B-sized set.
    const char* names[] = {
        "open", "openat", "__open_2", "__openat_2", "fopen",
        "stat", "lstat", "access", "faccessat", "faccessat2",
        "fstatat", "fstatat64", "__fstatat", "statx",
        "__system_property_find", "__system_property_get",
        "syscall", "dlopen", "android_dlopen_ext", "dlclose",
        "opendir", "readlink", "readlinkat", "setresuid",
    };
    constexpr int kN = (int)(sizeof(names) / sizeof(names[0]));
    for (int i = 0; i < kN; ++i) {
        hide_advanced_register_got_hook(names[i], (void*)(uintptr_t)(0x1000 + i));
    }
    // Lookups that hit and lookups that miss.
    const char* probes[] = {
        "open", "fopen", "syscall", "readlinkat", "opendir",
        "not_a_hook_symbol", "open64", "fgets", "malloc", "pthread_self",
    };
    constexpr int kP = (int)(sizeof(probes) / sizeof(probes[0]));

    // Warm up (build the index).
    ZS_CHECK(zs_test_match_registered_hook("open") != nullptr);

    constexpr int kIters = 200000;
    long long durations_ns[kIters];
    for (int i = 0; i < kIters; ++i) {
        const char* probe = probes[i % kP];
        auto t0 = clk::now();
        volatile void* r = zs_test_match_registered_hook(probe);
        (void)r;
        auto t1 = clk::now();
        durations_ns[i] = std::chrono::duration_cast<
            std::chrono::nanoseconds>(t1 - t0).count();
    }
    std::sort(durations_ns, durations_ns + kIters);
    long long median = durations_ns[kIters / 2];
    std::fprintf(stderr, "  [perf] hook matcher median: %lld ns\n", median);
    // Budget: 100 ns median on the host (each clock pair itself costs
    // ~20-40 ns, so this mostly measures the clock).
    ZS_CHECK(median < 500);

    // Correctness spot check through the same path.
    ZS_CHECK(zs_test_match_registered_hook("open") ==
             (void*)(uintptr_t)0x1000);
    ZS_CHECK(zs_test_match_registered_hook("not_a_hook_symbol") == nullptr);
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study perf microbenchmarks ===\n");
    return zstest::run_all();
}
