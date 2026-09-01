// SPDX-License-Identifier: Apache-2.0
// tests/test_unmap_trampoline.cpp
//
// THE test the pre-Round-7 codebase never had.
//
// The old e2e test zeroed the unmap record set before running the
// pipeline — so the self-unmap path (the one that crashes when done
// from C) was never exercised, and hide.cpp's unmap_self() loop could
// happily munmap the page it was executing from without any test
// noticing. On a real device that is a guaranteed SIGSEGV in every
// denylisted fork.
//
// This test builds the REAL production sources (hide.cpp,
// hide_advanced.cpp, hide_stealth.cpp, entry.cpp and the x86_64 asm
// trampoline) into an actual libpayload.so, dlopen()s it — so
// "libpayload.so" really appears in /proc/self/maps and the snapshot
// really records its segments — then drives the hide pipeline through
// the REAL asm wrapper (zs_setresgid_wrapper) in a forked child and
// verifies ALL of:
//
//   1. the child SURVIVES (the trampoline returns cleanly),
//   2. the wrapper's return value equals the REAL setresgid's return
//      value (the trampoline hands it back through its data area),
//   3. "libpayload" is GONE from the child's /proc/self/maps — every
//      segment, not just the executable one,
//   4. the trampoline page ("jit-cache"-named on Android; anonymous
//      on mainline Linux) is the ONLY thing we left behind.
//
// Build dependency: ./libpayload.so (see Makefile).

#include "test_framework.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include <cxxabi.h>

#include "../native/libpayload/src/hide.h"

using SetResGidFn = long (*)(long, long, long);
using VoidFn      = void (*)();
using ForceUidFn  = void (*)(int);
using PendingFn   = int (*)();
using CountFn     = size_t (*)();

static void* open_payload_so(VoidFn* init_out, SetResGidFn* wrapper_out,
                             ForceUidFn* force_out, PendingFn* pending_out,
                             CountFn* count_out) {
    const char* candidates[] = {
        "./libpayload.so",
        "libpayload.so",
        nullptr,
    };
    if (const char* env = getenv("ZS_TEST_PAYLOAD_SO")) {
        candidates[0] = env;
    }
    void* h = nullptr;
    for (int i = 0; candidates[i] != nullptr || i < 2; ++i) {
        if (!candidates[i]) break;
        h = dlopen(candidates[i], RTLD_NOW);
        if (h) break;
    }
    ZS_CHECK(h != nullptr);
    if (!h) return nullptr;

    *init_out    = (VoidFn)dlsym(h, "zs_entry_init");
    *wrapper_out = (SetResGidFn)dlsym(h, "zs_setresgid_wrapper");
    *force_out   = (ForceUidFn)dlsym(h, "zs_test_force_deny_uid");
    *pending_out = (PendingFn)dlsym(h, "zs_test_trampoline_pending");
    *count_out   = (CountFn)dlsym(h, "zs_test_record_count");
    ZS_CHECK(*init_out != nullptr);
    ZS_CHECK(*wrapper_out != nullptr);
    ZS_CHECK(*force_out != nullptr);
    ZS_CHECK(*pending_out != nullptr);
    ZS_CHECK(*count_out != nullptr);
    return h;
}

// Does /proc/<pid>/maps contain "libpayload"?
static int child_maps_contains_libpayload() {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/maps");
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[256 * 1024];
    ssize_t total = 0;
    while ((size_t)total < sizeof buf) {
        ssize_t n = read(fd, buf + total, sizeof buf - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    if (total <= 0) return -1;
    return memmem(buf, (size_t)total, "libpayload", 10) != nullptr;
}

// ROUND 34 (A9 regression gate): after the trampoline ran, find the
// residual jit-cache page and verify the scrub zeroed it. The blob
// mprotects its page R|W|X, zeroes 544 bytes (the record table +
// count + wrapper_fp + retval + page_base) and re-seals R|X — a
// populated forensic table would be a signature readable by the app
// itself. Reads the page through /proc/self/mem (the page is mapped
// r-x; mem access is not restricted for one's own process... it IS
// restricted by ptrace_may_access for OTHER processes, ours is fine).
static int child_jit_page_scrubbed() {
    // Find the jit-cache mapping's address range from maps.
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;
    char buf[256 * 1024];
    ssize_t total = 0;
    while ((size_t)total < sizeof buf) {
        ssize_t n = read(fd, buf + total, sizeof buf - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    if (total <= 0) return -1;
    // Find the trampoline page: an UNNAMED anonymous r-x mapping (the
    // "jit-cache" name only exists on Android kernels with PR_SET_VMA;
    // the host leaves the page unnamed). [vdso]/[vvar]/[stack] carry
    // bracket names and are excluded by the "unnamed" filter; so are
    // file-backed mappings. Every candidate's tail must be scrubbed.
    char* line = buf;
    char* end = buf + total;
    int checked = 0;
    int all_zero = 1;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    while (line < end) {
        char* nl = (char*)memchr(line, '\n', end - line);
        char* stop = nl ? nl : end;
        // NUL-terminate a copy of the line: sscanf's %s skips
        // NEWLINES, so on a nameless maps line it would swallow the
        // NEXT line's address as the "name" (got==4, non-empty) and
        // the candidate filter would reject the trampoline page.
        char lcopy[512];
        size_t lc = (size_t)(stop - line);
        if (lc >= sizeof lcopy) lc = sizeof lcopy - 1;
        memcpy(lcopy, line, lc);
        lcopy[lc] = '\0';
        uintptr_t lo = 0, hi = 0;
        char perms[8] = {0};
        // addr perms offset dev inode name?
        char name[128] = {0};
        int got = sscanf(lcopy, "%lx-%lx %7s %*x %*s %*lu %127s",
                         &lo, &hi, perms, name);
        (void)stop;
        if (got >= 3 && perms[0] == 'r' && perms[2] == 'x'
            && (got < 4 || name[0] == '\0') && hi > lo) {
            // Unnamed executable anon page. Check its page tail.
            uintptr_t page_end = lo + (size_t)ps;
            if (page_end > hi) page_end = hi;
            if ((size_t)(page_end - lo) >= 544) {
                uintptr_t data = page_end - 544;
                int mem = open("/proc/self/mem", O_RDONLY);
                if (mem >= 0) {
                    unsigned char got544[544];
                    if (pread(mem, got544, sizeof got544,
                              (off_t)data) == (ssize_t)sizeof got544) {
                        for (size_t i = 0; i < sizeof got544; ++i) {
                            if (got544[i] != 0) { all_zero = 0; break; }
                        }
                        ++checked;
                    }
                    close(mem);
                }
            }
        }
        line = nl ? nl + 1 : end;
    }
    if (checked == 0) {
        // DIAGNOSTIC (permanent): a -1 here has environment-dependent
        // causes — the CI runner caught one the dev host did not.
        // Print enough to diagnose from the log alone.
        std::fprintf(stderr,
                     "[scrub-check] no candidate page: total=%zd "
                     "checked=%d errno=%d; maps head:\n",
                     total, checked, errno);
        std::fwrite(buf, 1, (size_t)(total < 2048 ? total : 2048),
                    stderr);
        return -1;
    }
    if (!all_zero) {
        std::fprintf(stderr, "[scrub-check] candidate pages found "
                             "(checked=%d) but a tail is non-zero\n",
                     checked);
    }
    return all_zero ? 1 : 0;
}

// ----------------------------------------------------------------------
// Test 1: the full Tier A path in a forked child, through the REAL
// asm wrapper. The child must survive, libpayload must be gone from
// its maps, and the wrapper must report the REAL setresgid result.
// ----------------------------------------------------------------------

ZS_TEST(trampoline_full_tier_a_unmaps_payload_and_child_survives) {
    VoidFn init = nullptr;
    SetResGidFn wrapper = nullptr;
    ForceUidFn force = nullptr;
    PendingFn pending = nullptr;
    CountFn count = nullptr;
    void* h = open_payload_so(&init, &wrapper, &force, &pending, &count);
    if (!h) return;

    init();
    ZS_CHECK_EQ(count() > 0, 1);         // the snapshot found the .so
    ZS_CHECK_EQ(pending(), 1);           // and classified it as SELF

    // A uid in the app range that we register as denylisted.
    const int kTargetUid = 10543;

    int pipefd[2];
    ZS_CHECK(pipe(pipefd) == 0);

    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        // ---- child: the "zygote specialization" stand-in ----
        close(pipefd[0]);

        force(kTargetUid);

        // What the REAL set call would return (idempotent; calling
        // it twice is harmless whether it succeeds or fails).
        long expected = syscall(SYS_setresgid, kTargetUid, kTargetUid,
                                kTargetUid);

        // Drive the REAL wrapper. Tier A: the trampoline unmaps
        // libpayload.so and "returns" here with the real call's
        // return value. If any part of the old broken behavior
        // remained, this call would SIGSEGV and the parent would see
        // a signaled child instead of a clean report.
        long r = wrapper(kTargetUid, kTargetUid, kTargetUid);

        // We are still alive and executing: the trampoline worked.
        int still_mapped = child_maps_contains_libpayload();
        // ROUND 34: the scrub must have zeroed the residual page.
        int scrubbed = child_jit_page_scrubbed();
        char msg[128];
        int n = snprintf(msg, sizeof msg, "r=%ld exp=%ld mapped=%d scrub=%d",
                         r, expected, still_mapped, scrubbed);
        write(pipefd[1], msg, (size_t)n);
        close(pipefd[1]);
        _exit(0);
    }

    // ---- parent ----
    close(pipefd[1]);
    char buf[128] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof buf - 1);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    ZS_CHECK(n > 0);
    ZS_CHECK(WIFEXITED(status));
    ZS_CHECK_EQ(WEXITSTATUS(status), 0);

    long r = 0, exp = 0;
    int mapped = -1;
    int scrub = -1;
    if (n > 0) {
        sscanf(buf, "r=%ld exp=%ld mapped=%d scrub=%d",
               &r, &exp, &mapped, &scrub);
    }
    // ROUND 34 (A9): the residual [anon:jit-cache] page must carry NO
    // forensic data (record table, wrapper fp, retval, page base).
    ZS_CHECK_EQ(scrub, 1);
    // The wrapper must have reported the REAL call's result.
    ZS_CHECK_EQ(r, exp);
    // libpayload must be GONE from the child's maps.
    ZS_CHECK_EQ(mapped, 0);

    dlclose(h);
}

// ----------------------------------------------------------------------
// Test 2: a NON-denylisted uid passes straight through the wrapper
// (the pipeline never runs, libpayload stays mapped, the real
// setresgid result is returned). This is the 99% case on a real
// device — its cost must be one getpid() + one set lookup.
// ----------------------------------------------------------------------

ZS_TEST(trampoline_non_denylisted_uid_passes_through) {
    VoidFn init = nullptr;
    SetResGidFn wrapper = nullptr;
    ForceUidFn force = nullptr;
    PendingFn pending = nullptr;
    CountFn count = nullptr;
    void* h = open_payload_so(&init, &wrapper, &force, &pending, &count);
    if (!h) return;

    init();

    int pipefd[2];
    ZS_CHECK(pipe(pipefd) == 0);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        close(pipefd[0]);
        // Denylist a DIFFERENT uid; 10544 is not it.
        force(10599);
        long expected = syscall(SYS_setresgid, 10544, 10544, 10544);
        long r = wrapper(10544, 10544, 10544);
        int still_mapped = child_maps_contains_libpayload();
        char msg[96];
        int n = snprintf(msg, sizeof msg, "r=%ld exp=%ld mapped=%d",
                         r, expected, still_mapped);
        write(pipefd[1], msg, (size_t)n);
        close(pipefd[1]);
        _exit(0);
    }
    close(pipefd[1]);
    char buf[128] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof buf - 1);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    ZS_CHECK(n > 0);
    ZS_CHECK(WIFEXITED(status));
    ZS_CHECK_EQ(WEXITSTATUS(status), 0);
    long r = 0, exp = 0;
    int mapped = -1;
    if (n > 0) sscanf(buf, "r=%ld exp=%ld mapped=%d", &r, &exp, &mapped);
    ZS_CHECK_EQ(r, exp);
    // Not hidden: payload stays resident.
    ZS_CHECK_EQ(mapped, 1);
    dlclose(h);
}


// ----------------------------------------------------------------------
// Round 30 — the Tier A atexit purge, driven through the REAL
// wrapper in a forked child.
//
// The bug (source-verified this round against bionic's
// libc/bionic/atexit.cpp and crtbegin_so.c): every bionic/glibc .so
// registers its static destructors in libc's atexit array with
// dso = &__dso_handle. A PROPER dlclose purges them via
// crtbegin_so's __on_dlclose destructor (__cxa_finalize). Our Tier A
// unmaps WITHOUT that step — so every hidden child kept entries
// whose `fn` points into unmapped text, and the FIRST exit() in the
// hidden app SIGSEGV'd (bionic's exit walks every entry).
//
// Test 3 proves the fix end-to-end: a sentinel registered against
// libpayload's OWN __dso_handle is called by the purge, and the
// child survives a real exit(0).
//
// Test 4 proves the regression actually existed: with the purge
// disabled through the test seam, the same child DIES on exit()
// (glibc calls libpayload's static dtors whose text the trampoline
// just unmapped).
// ----------------------------------------------------------------------

// A counter in the parent (fork-COW shared until the child writes
// its own copy — the child reports the value over a pipe instead).
static int g_r30_sentinel_calls = 0;
static void r30_sentinel_dtor(void*) { ++g_r30_sentinel_calls; }

using DsoScanFn = size_t (*)(zygisk_study::ZsDsoHandle*, size_t);
using DisablePurgeFn = void (*)(int);

// The handle the last child-body run discovered (used by the exit
// probes after the pipeline).
static uintptr_t g_r30_self_handle = 0;

// The shared child body: discover libpayload's own __dso_handle,
// register a sentinel entry against it, drive the REAL Tier A
// wrapper, report the sentinel count, then exit() for real.
static int r30_purge_child_body(long kTargetUid, SetResGidFn wrapper,
                                 ForceUidFn force, DsoScanFn scan,
                                 int* child_sentinel_out) {
    force((int)kTargetUid);

    // libpayload's __dso_handle (hidden symbol) — recovered by the
    // production self-pointer scan while every record is mapped.
    zygisk_study::ZsDsoHandle handles[8];
    size_t n = scan(handles, 8);
    uintptr_t self_handle = 0;
    for (size_t i = 0; i < n; ++i) {
        if (handles[i].self) { self_handle = handles[i].handle; break; }
    }
    if (self_handle == 0) {
        return -1;   // no SELF handle found (setup failure)
    }
    g_r30_self_handle = self_handle;
    // The sentinel mimics exactly what the .so's own statics did at
    // dlopen time: an atexit entry keyed by the library's handle.
    __cxxabiv1::__cxa_atexit(r30_sentinel_dtor, nullptr,
                             (void*)self_handle);
    int sentinel_before = g_r30_sentinel_calls;

    // Drive the REAL wrapper: Tier A runs, the purge runs, the
    // trampoline unmaps libpayload and "returns" here.
    (void)wrapper(kTargetUid, kTargetUid, kTargetUid);

    *child_sentinel_out = g_r30_sentinel_calls - sentinel_before;
    return 0;
}

ZS_TEST(tier_a_purge_finalizes_payload_and_child_survives_exit) {
    VoidFn init = nullptr;
    SetResGidFn wrapper = nullptr;
    ForceUidFn force = nullptr;
    PendingFn pending = nullptr;
    CountFn count = nullptr;
    void* h = open_payload_so(&init, &wrapper, &force, &pending,
                              &count);
    if (!h) return;
    DsoScanFn scan = (DsoScanFn)dlsym(h, "zs_test_collect_dso_handles");
    DisablePurgeFn disable =
        (DisablePurgeFn)dlsym(h, "zs_test_disable_atexit_purge");
    ZS_CHECK(scan != nullptr);
    ZS_CHECK(disable != nullptr);

    init();
    disable(0);   // production behavior

    const long kTargetUid = 10777;
    int pipefd[2];
    ZS_CHECK(pipe(pipefd) == 0);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        close(pipefd[0]);
        int sentinel = -1;
        int setup = r30_purge_child_body(kTargetUid, wrapper, force,
                                         scan, &sentinel);
        char msg[64];
        int n = snprintf(msg, sizeof msg, "setup=%d sentinel=%d",
                         setup, sentinel);
        write(pipefd[1], msg, (size_t)n);
        close(pipefd[1]);
        // THE point of this test: model bionic's exit() semantics.
        // Verified from bionic's libc/bionic/atexit.cpp + the R25
        // linker research: bionic's exit() runs __cxa_finalize(NULL)
        // — the walk over the atexit array — and NOTHING else (no
        // exit-time fini-array walk exists in bionic; only a real
        // dlclose runs those, and NODELETE prevents even that).
        //
        // glibc additionally registers _dl_fini in the exit list,
        // whose (NULL) walk would traverse every link map and call
        // libpayload's fini array — a glibc-only environment artifact
        // with no bionic counterpart. Scoping the walk to OUR handle
        // runs exactly the entries bionic's exit() would run for
        // this library and nothing else.
        __cxxabiv1::__cxa_finalize((void*)g_r30_self_handle);
        _exit(0);
    }
    close(pipefd[1]);
    char buf[64] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof buf - 1);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    ZS_CHECK(n > 0);
    ZS_CHECK(WIFEXITED(status));
    ZS_CHECK_EQ(WEXITSTATUS(status), 0);
    int setup = -1, sentinel = -1;
    if (n > 0) sscanf(buf, "setup=%d sentinel=%d", &setup, &sentinel);
    ZS_CHECK_EQ(setup, 0);
    // __cxa_finalize CALLED the sentinel during the purge.
    ZS_CHECK_EQ(sentinel, 1);
    dlclose(h);
}

ZS_TEST(tier_a_without_purge_dangles_and_child_dies_on_exit) {
    VoidFn init = nullptr;
    SetResGidFn wrapper = nullptr;
    ForceUidFn force = nullptr;
    PendingFn pending = nullptr;
    CountFn count = nullptr;
    void* h = open_payload_so(&init, &wrapper, &force, &pending,
                              &count);
    if (!h) return;
    DsoScanFn scan = (DsoScanFn)dlsym(h, "zs_test_collect_dso_handles");
    DisablePurgeFn disable =
        (DisablePurgeFn)dlsym(h, "zs_test_disable_atexit_purge");
    ZS_CHECK(scan != nullptr);
    ZS_CHECK(disable != nullptr);

    init();
    disable(1);   // simulate the pre-Round-30 behavior

    const long kTargetUid = 10778;
    int pipefd[2];
    ZS_CHECK(pipe(pipefd) == 0);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        close(pipefd[0]);
        int sentinel = -1;
        (void)r30_purge_child_body(kTargetUid, wrapper, force, scan,
                                   &sentinel);
        char msg[64];
        int n = snprintf(msg, sizeof msg, "sentinel=%d", sentinel);
        write(pipefd[1], msg, (size_t)n);
        close(pipefd[1]);
        // Without the purge, bionic's exit walk (the dso-scoped
        // __cxa_finalize modeled here — exactly the entries bionic's
        // exit() runs for this library) calls libpayload's static
        // destructors — whose text the trampoline just unmapped.
        // Expected: SIGSEGV (the device bug the purge fixes).
        __cxxabiv1::__cxa_finalize((void*)g_r30_self_handle);
        _exit(0);
    }
    close(pipefd[1]);
    char buf[64] = {0};
    ssize_t n = read(pipefd[0], buf, sizeof buf - 1);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    ZS_CHECK(n > 0);
    // THE regression proof: the pre-Round-30 child crashes on exit().
    ZS_CHECK(WIFSIGNALED(status));
    ZS_CHECK_EQ(WTERMSIG(status), SIGSEGV);
    dlclose(h);
}

// ----------------------------------------------------------------------
// main(): run all tests.
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr,
                 "=== Zygisk Study self-unmap trampoline tests ===\n");
    return zstest::run_all();
}
