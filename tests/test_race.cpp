// SPDX-License-Identifier: Apache-2.0
// tests/test_race.cpp — Round 31: race-condition testing.
//
// The hidden app is MULTITHREADED: every hook (open, dlopen, dlclose,
// chdir, fstat...) can fire on any thread at any time. Rounds 7-30
// were single-threaded by construction — every test ran in one thread,
// so data races in the hook layer were invisible even when they were
// crash-grade bugs.
//
// This suite hammers the exact interleavings that were racy before
// Round 31 (each is documented at the fix site in hide_advanced.cpp):
//
//   RACE 1  dlopen || dlopen      — concurrent GOT re-walks: two
//          walkers appending to g_walked_dsos / g_patched_slots, and
//          interleaved mprotect(RW)..write..mprotect(RX) on the same
//          GOT page (the thread-induced version of the R17 lazy-
//          binding crash).
//   RACE 2  dlopen || dlclose     — the mark-set GC compacting while
//          a walker reads it.
//   RACE 3  open || open          — fd shadow table registration from
//          two threads (torn g_fd_shadow_count).
//   RACE 4  chdir || open         — the cwd /proc prefix read while
//          another thread rewrites it.
//
// The build runs this file under ThreadSanitizer (make race) AND as a
// plain stress binary in the normal suite (make run): TSan reports the
// data races, the stress run proves liveness + post-state integrity
// (no torn registry, no shadow-table corruption, every GOT slot still
// points at its hook).
//
// Host-only seams used: hide_advanced_set_active() to enter the
// hidden state, the real dlopen/dlclose on a tiny fixture .so (so
// dl_iterate_phdr sees genuine load/unload churn), and real memfd
// filtered opens through zygisk_study_hook_open.

#include "test_framework.h"

#include "../native/libpayload/src/hide_advanced.cpp"

using namespace zygisk_study;

// Registry setup: the hammer tests need real entries in the live
// registry (production installs them at hide time). Stub functions
// stand in for the hook bodies — the race suite exercises the
// registry/walk machinery, not the hook semantics.
static void register_got_hook_safe(const char* name, void* fn);
static void* zs_race_stub_open(const char*, int, ...) { return nullptr; }
static void* zs_race_stub_openat(int, const char*, int, ...) { return nullptr; }
static void* zs_race_stub_dlopen(const char*, int) { return nullptr; }
static int   zs_race_stub_close(int) { return -1; }

static void race_resolve_real_fns() {
    // Production resolves these at Tier B install time; the race suite
    // resolves them directly so the hooks operate on real linker state.
    if (!g_real_dlopen) {
        g_real_dlopen = (DlopenFn)dlsym(RTLD_DEFAULT, "dlopen");
    }
    if (!g_real_dlclose) {
        g_real_dlclose = (DlcloseFn)dlsym(RTLD_DEFAULT, "dlclose");
    }
    if (!g_real_chdir) {
        g_real_chdir = (ChdirFn)dlsym(RTLD_DEFAULT, "chdir");
    }
}

static void race_registry_setup() {
    race_resolve_real_fns();
    register_got_hook_safe("open", (void*)zs_race_stub_open);
    register_got_hook_safe("openat", (void*)zs_race_stub_openat);
    register_got_hook_safe("dlopen", (void*)zs_race_stub_dlopen);
    register_got_hook_safe("close", (void*)zs_race_stub_close);
}
static void register_got_hook_safe(const char* name, void* fn) {
    hide_advanced_register_got_hook(name, fn);
}

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <string>

// A tiny fixture .so the hammer threads dlopen/dlclose. Built by the
// Makefile (race_fixture.so) — anything loadable works; we only need
// genuine linker activity so dl_iterate_phdr churns.
static const char* kFixtureSo = "./race_fixture.so";

static std::atomic<int> g_stop{0};

struct hammer_ctx {
    int                 iterations;
    std::atomic<long>*  ops;
};

// ---- RACE 1 + 2: dlopen/dlclose hammer -----------------------------------

static void* dlopen_hammer(void* arg) {
    hammer_ctx* ctx = (hammer_ctx*)arg;
    for (int i = 0; i < ctx->iterations && !g_stop.load(); ++i) {
        void* h = zygisk_study_hook_dlopen(kFixtureSo, RTLD_NOW | RTLD_LOCAL);
        if (h) {
            ctx->ops->fetch_add(1);
            zygisk_study_hook_dlclose(h);
        }
    }
    return nullptr;
}

// ---- RACE 3: concurrent filtered opens (fd shadow registration) --------

static void* open_hammer(void* arg) {
    hammer_ctx* ctx = (hammer_ctx*)arg;
    char maps_path[64];
    snprintf(maps_path, sizeof maps_path, "/proc/self/maps");
    for (int i = 0; i < ctx->iterations && !g_stop.load(); ++i) {
        int fd = zygisk_study_hook_open(maps_path, O_RDONLY);
        if (fd >= 0) {
            ctx->ops->fetch_add(1);
            close(fd);
        }
        // A second shape: /proc/self/status (a different filtered file)
        int fd2 = zygisk_study_hook_open("/proc/self/status", O_RDONLY);
        if (fd2 >= 0) close(fd2);
    }
    return nullptr;
}

// ---- RACE 4: chdir || relative open --------------------------------------

static void* chdir_hammer(void* arg) {
    hammer_ctx* ctx = (hammer_ctx*)arg;
    for (int i = 0; i < ctx->iterations && !g_stop.load(); ++i) {
        zygisk_study_hook_chdir("/proc/self");
        ctx->ops->fetch_add(1);
        zygisk_study_hook_chdir("/");
    }
    return nullptr;
}

static void* relative_open_hammer(void* arg) {
    hammer_ctx* ctx = (hammer_ctx*)arg;
    for (int i = 0; i < ctx->iterations && !g_stop.load(); ++i) {
        // Relative path: resolution consults the (concurrently
        // rewritten) cwd prefix.
        int fd = zygisk_study_hook_open("maps", O_RDONLY);
        if (fd >= 0) {
            ctx->ops->fetch_add(1);
            close(fd);
        }
        sched_yield();
    }
    return nullptr;
}

// ---- the suites -----------------------------------------------------------

ZS_TEST(race_dlopen_dlclose_hammer) {
    race_registry_setup();
    hide_advanced_set_active(1);
    std::atomic<long> ops{0};
    hammer_ctx ctx{.iterations = 120, .ops = &ops};
    pthread_t t[6];
    for (pthread_t& th : t) {
        ZS_CHECK_EQ(pthread_create(&th, nullptr, dlopen_hammer, &ctx), 0);
    }
    for (pthread_t& th : t) {
        pthread_join(th, nullptr);
    }
    hide_advanced_set_active(0);
    ZS_CHECK(ops.load() > 0);
    // Post-state integrity: the hook registry still resolves every
    // live hook (a torn count would corrupt the index or registry).
    ZS_CHECK(match_registered_hook("open") != nullptr);
    ZS_CHECK(match_registered_hook("openat") != nullptr);
    ZS_CHECK(match_registered_hook("dlopen") != nullptr);
}

ZS_TEST(race_open_hammer) {
    hide_advanced_set_active(1);
    std::atomic<long> ops{0};
    hammer_ctx ctx{.iterations = 200, .ops = &ops};
    pthread_t t[6];
    for (pthread_t& th : t) {
        ZS_CHECK_EQ(pthread_create(&th, nullptr, open_hammer, &ctx), 0);
    }
    for (pthread_t& th : t) {
        pthread_join(th, nullptr);
    }
    hide_advanced_set_active(0);
    ZS_CHECK(ops.load() > 0);
    // No matter how many concurrent registers happened, the shadow
    // table's high-water mark must stay within bounds (a torn count
    // could push it past the array).
    ZS_CHECK(g_fd_shadow_count <=
             sizeof g_fd_shadow / sizeof g_fd_shadow[0]);
    // And every live record must be well-formed (fd >= 0 entries carry
    // a NUL-terminated path).
    fd_shadow_lock();
    size_t live = 0;
    for (size_t i = 0; i < g_fd_shadow_count; ++i) {
        if (g_fd_shadow[i].fd >= 0) {
            ++live;
            size_t n = strnlen(g_fd_shadow[i].orig_path,
                               sizeof g_fd_shadow[i].orig_path);
            ZS_CHECK(n < sizeof g_fd_shadow[i].orig_path);
        }
    }
    fd_shadow_unlock();
    (void)live;
}

ZS_TEST(race_chdir_vs_relative_open) {
    hide_advanced_set_active(1);
    std::atomic<long> ops{0};
    hammer_ctx ctx{.iterations = 200, .ops = &ops};
    pthread_t churner[2];
    pthread_t opener[2];
    for (pthread_t& th : churner) {
        ZS_CHECK_EQ(pthread_create(&th, nullptr, chdir_hammer, &ctx), 0);
    }
    for (pthread_t& th : opener) {
        ZS_CHECK_EQ(pthread_create(&th, nullptr, relative_open_hammer,
                                   &ctx), 0);
    }
    for (pthread_t& th : churner) pthread_join(th, nullptr);
    for (pthread_t& th : opener) pthread_join(th, nullptr);
    hide_advanced_set_active(0);
    // Leave the cwd clean for later tests.
    chdir("/");
    // Post-state: the prefix must be a valid, NUL-terminated string.
    char snap[80];
    zs_cwd_prefix_copy(snap, sizeof snap);
    ZS_CHECK(strlen(snap) < sizeof snap);
    ZS_CHECK(ops.load() > 0);
}

ZS_TEST(race_mixed_everything) {
    // The full melee: dlopen + dlclose + opens + chdir concurrently.
    hide_advanced_set_active(1);
    std::atomic<long> ops{0};
    hammer_ctx ctx{.iterations = 150, .ops = &ops};
    pthread_t t[8];
    ZS_CHECK_EQ(pthread_create(&t[0], nullptr, dlopen_hammer, &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[1], nullptr, dlopen_hammer, &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[2], nullptr, open_hammer, &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[3], nullptr, open_hammer, &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[4], nullptr, chdir_hammer, &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[5], nullptr, relative_open_hammer,
                               &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[6], nullptr, dlopen_hammer, &ctx), 0);
    ZS_CHECK_EQ(pthread_create(&t[7], nullptr, open_hammer, &ctx), 0);
    for (pthread_t& th : t) pthread_join(th, nullptr);
    hide_advanced_set_active(0);
    chdir("/");
    ZS_CHECK(ops.load() > 0);
    ZS_CHECK(match_registered_hook("open") != nullptr);
    ZS_CHECK(match_registered_hook("close") != nullptr);
}

// Sanity for the single-walker protocol itself: the generation
// counters must be consistent after any sequence of passes (every
// request served, done <= req, active cleared).
ZS_TEST(walk_protocol_invariants) {
    race_registry_setup();
    hide_advanced_set_active(1);
    for (int i = 0; i < 50; ++i) {
        zs_walk_pass();
        ZS_CHECK(g_walk_done.load() <= g_walk_req.load());
        ZS_CHECK(g_walk_active.load() == 0);
    }
    // And a final index rebuild leaves the matcher fast-path on.
    ZS_CHECK(g_hook_idx_dirty.load() == 0);
    ZS_CHECK(match_registered_hook("open") != nullptr);
    hide_advanced_set_active(0);
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study Round 31 race-condition suite ===\n");
    return zstest::run_all();
}
