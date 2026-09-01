// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide_stealth.cpp
//
// Additional stealth layer. See hide_stealth.h for the public surface.
//
// Round 7 changes:
//
//   - readlink/readlinkat hooks now register through the shared GOT
//     registry in hide_advanced.cpp (one dl_iterate_phdr walk for the
//     entire payload instead of three) and are gated by the
//     per-process active flag like every other hook.
//
//   - PR_SET_DUMPABLE / PR_SET_NO_NEW_PRIVS / PR_SET_PDEATHSIG were
//     REMOVED from the app-child pipeline. Each one created a
//     difference from a stock app process — the opposite of stealth:
//       * dumpable=0 breaks debuggerd: no tombstones, no ANR traces,
//         and "no tombstone for a crashing app" is itself a signal.
//       * NoNewPrivs is 0 on stock Android <= 11 (readable from
//         /proc/self/status), so setting it there creates a probe.
//         Android 12+ zygote already sets it; our call was a no-op.
//       * PDEATHSIG is not set by stock app processes; a zygote
//         restart would have SIGKILLed every running app.
//     The functions stay (tests exercise them directly) but nothing
//     calls them in the shipped pipeline.
//
//   - The readlink rewrite picks app_process32 vs app_process64 by
//     pointer size (the old code hardcoded ...64, which would have
//     rewritten a 32-bit process's /proc/self/exe to the wrong
//     binary — an instant tell on any 32-bit app).
//
//   - fd-symlink rewrites now target /dev/null rather than the
//     app_process path (an fd symlink resolving to the exe path is
//     nonsense and is itself suspicious).

#include "hide_stealth.h"
#include "hide_advanced.h"
#include "log.h"
#include "resolve_libc.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

#define ZS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ZS_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace zygisk_study {

// ----------------------------------------------------------------------------
// 9. readlink / readlinkat hook
// ----------------------------------------------------------------------------

using ReadlinkFn   = ssize_t (*)(const char*, char*, size_t);
using ReadlinkAtFn = ssize_t (*)(int, const char*, char*, size_t);
static ReadlinkFn   g_real_readlink   = nullptr;
static ReadlinkAtFn g_real_readlinkat = nullptr;

extern "C" ssize_t zygisk_study_hook_readlink(const char* path,
                                              char* buf, size_t bufsiz);
extern "C" ssize_t zygisk_study_hook_readlinkat(int dirfd,
                                                const char* path,
                                                char* buf, size_t bufsiz);

// Substrings that, if present in the resolved path, trigger a rewrite.
static const char* const kRewriteSubstrings[] = {
    "magisk",
    "zygisk",
    "/sbin/",
    "/data/adb/",
    "/debug_ramdisk/",
    "zygisk_study",
};

// The stock zygote binary — chosen by ABI so 32-bit processes report
// app_process32 like a real 32-bit fork would.
static const char* stock_exe_path() {
#if __SIZEOF_POINTER__ == 4
    return "/system/bin/app_process32";
#else
    return "/system/bin/app_process64";
#endif
}

// Round 8 (S5): skip the "<pid>|self|thread-self" component and any
// following "task/<tid>/" component (per-thread paths:
// /proc/<pid>/task/<tid>/exe is the exe of a specific THREAD and was
// missed by the Round 7 matchers). Returns the pointer past them, or
// nullptr when the path does not have this shape.
static const char* skip_proc_pid_components(const char* p) {
    if (strncmp(p, "self", 4) == 0) {
        p += 4;
    } else if (strncmp(p, "thread-self", 11) == 0) {
        p += 11;
    } else {
        if (*p < '0' || *p > '9') return nullptr;
        while (*p >= '0' && *p <= '9') ++p;
    }
    if (*p != '/') return nullptr;
    ++p;
    // Optional per-thread component.
    if (strncmp(p, "task/", 5) == 0) {
        p += 5;
        if (*p < '0' || *p > '9') return nullptr;
        while (*p >= '0' && *p <= '9') ++p;
        if (*p != '/') return nullptr;
        ++p;
    }
    return p;
}

// Returns 1 if `path` looks like a /proc/<pid>[/task/<tid>]/exe path.
static int path_is_proc_exe(const char* path) {
    if (!path) return 0;
    static const char kProc[] = "/proc/";
    constexpr size_t kProcLen = sizeof(kProc) - 1;
    if (strncmp(path, kProc, kProcLen) != 0) return 0;
    const char* p = skip_proc_pid_components(path + kProcLen);
    if (!p) return 0;
    return strcmp(p, "exe") == 0;
}

// Returns 1 if `path` looks like a /proc/<pid>[/task/<tid>]/fd/<n>
// path (thread-self included — an fd of the calling thread).
static int path_is_proc_fd(const char* path) {
    if (!path) return 0;
    static const char kProc[] = "/proc/";
    constexpr size_t kProcLen = sizeof(kProc) - 1;
    if (strncmp(path, kProc, kProcLen) != 0) return 0;
    const char* p = skip_proc_pid_components(path + kProcLen);
    if (!p) return 0;

    // skip_proc_pid_components already consumed the separator after
    // the pid (and task) component, so the remainder is "fd/<n>".
    static const char kFd[] = "fd/";
    constexpr size_t kFdLen = sizeof(kFd) - 1;
    if (strncmp(p, kFd, kFdLen) != 0) return 0;
    p += kFdLen;

    if (*p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') ++p;
    return *p == '\0' ? 1 : 0;
}

// Extract the trailing fd number from a /proc/<pid>/fd/<n> path
// that path_is_proc_fd has already validated. Returns -1 when the
// digits overflow an int (never for real kernel fd numbers).
static int proc_fd_path_number(const char* path) {
    const char* p = path + strlen(path);
    while (p > path && p[-1] >= '0' && p[-1] <= '9') --p;
    long v = strtol(p, nullptr, 10);
    return (v >= 0 && v <= 0x7fffffff) ? (int)v : -1;
}

// Rewrite the readlink result if it contains a suspicious substring.
// `target_kind`: 0 = /proc/<pid>/exe (rewrite to the stock app_process
// path), 1 = /proc/<pid>/fd/<n> (rewrite to /dev/null).
static ssize_t rewrite_if_suspicious(char* buf, size_t bufsiz,
                                     ssize_t real_n, int target_kind) {
    if (real_n < 0) return real_n;
    // Clamp to the buffer (readlink may return exactly bufsiz when the
    // target is longer — the bytes in buf are valid up to bufsiz).
    size_t n = (size_t)real_n;
    if (n > bufsiz) n = bufsiz;

    int suspicious = 0;
    for (const char* s : kRewriteSubstrings) {
        size_t slen = __builtin_strlen(s);
        if (slen == 0 || slen > n) continue;
        if (memmem(buf, n, s, slen) != nullptr) {
            suspicious = 1;
            break;
        }
    }
    if (!suspicious) return real_n;

    const char* replacement =
        (target_kind == 0) ? stock_exe_path() : "/dev/null";
    size_t rlen = __builtin_strlen(replacement);
    // Round 15 (POSIX conformance): readlink() truncates to EXACTLY
    // bufsiz bytes and returns bufsiz — the old `bufsiz - 1` clamp
    // made the rewritten answer one byte short, and a caller checking
    // "return == bufsiz means truncated" could see a phantom NUL.
    if (rlen > bufsiz) rlen = bufsiz;
    memcpy(buf, replacement, rlen);
    return (ssize_t)rlen;
}

// ROUND 32 (found by cross-compiling against the NDK): aarch64's
// kernel UAPI has no __NR_readlink (only readlinkat, verified in the
// NDK sysroot's asm-generic/unistd.h) — the raw-syscall fallback now
// uses readlinkat(AT_FDCWD, ...) on such arches, which is the exact
// readlink semantic. This path only runs if the dlsym of libc's
// readlink failed, which does not happen on real Android.
static inline ssize_t zs_raw_readlink(const char* path, char* buf,
                                       size_t bufsiz) {
#if defined(SYS_readlink)
    return (ssize_t)syscall(SYS_readlink, path, buf, bufsiz);
#elif defined(SYS_readlinkat)
    return (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsiz);
#else
    errno = ENOSYS;
    return -1;
#endif
}

extern "C" ssize_t zygisk_study_hook_readlink(const char* path,
                                              char* buf, size_t bufsiz) {
    ssize_t n;
    if (ZS_UNLIKELY(!hide_advanced_is_active())) {
        n = g_real_readlink
            ? g_real_readlink(path, buf, bufsiz)
            : zs_raw_readlink(path, buf, bufsiz);
        return n;
    }
    n = g_real_readlink
        ? g_real_readlink(path, buf, bufsiz)
        : zs_raw_readlink(path, buf, bufsiz);
    if (n < 0) return n;
    // Round 23: a RELATIVE path with the cwd inside a tracked /proc
    // directory resolves to the same symlink the absolute path would
    // (chdir("/proc/self"); readlink("fd/3") — the pre-R23 hook
    // returned the raw "memfd:scudo (deleted)" target here, the exact
    // leak the absolute-path arm had already fixed).
    const char* eff_path = path;
    char* resolved = (path && path[0] != '/')
        ? hide_advanced_resolve_proc_relative(AT_FDCWD, path)
        : nullptr;
    if (resolved) eff_path = resolved;
    ssize_t out = n;
    if (path_is_proc_exe(eff_path)) {
        out = rewrite_if_suspicious(buf, bufsiz, n, 0);
    } else if (path_is_proc_fd(eff_path)) {
        // Round 15 (fd observable parity): one of OUR filtered memfds
        // answers "memfd:scudo" where a stock fd would answer the proc
        // path it was opened from. Rewrite it to exactly that before
        // the generic suspicious-substring rewrite gets a chance.
        int fd = proc_fd_path_number(eff_path);
        ssize_t spoofed = hide_advanced_spoof_memfd_readlink(
            fd, buf, (size_t)n, buf, bufsiz);
        if (spoofed > 0) {
            out = spoofed;
        } else {
            out = rewrite_if_suspicious(buf, bufsiz, n, 1);
        }
    }
    free(resolved);
    return out;
}

extern "C" ssize_t zygisk_study_hook_readlinkat(int dirfd,
                                                const char* path,
                                                char* buf, size_t bufsiz) {
    ssize_t n;
    if (ZS_UNLIKELY(!hide_advanced_is_active())) {
        return g_real_readlinkat
            ? g_real_readlinkat(dirfd, path, buf, bufsiz)
            : (ssize_t)syscall(SYS_readlinkat, dirfd, path, buf, bufsiz);
    }
    n = g_real_readlinkat
        ? g_real_readlinkat(dirfd, path, buf, bufsiz)
        : (ssize_t)syscall(SYS_readlinkat, dirfd, path, buf, bufsiz);
    if (n < 0) return n;
    if (!path) return n;
    // Round 23: relative path + tracked /proc dirfd resolves to the
    // same symlink the absolute path would:
    //     int dfd = open("/proc/self", O_DIRECTORY);
    //     readlinkat(dfd, "fd/3", buf, sz);
    // leaked the raw memfd target before this round. (Absolute paths
    // ignore dirfd per POSIX — unchanged behavior.)
    const char* eff_path = path;
    char* resolved = (path[0] != '/')
        ? hide_advanced_resolve_proc_relative(dirfd, path)
        : nullptr;
    if (resolved) eff_path = resolved;
    ssize_t out = n;
    if (path_is_proc_exe(eff_path)) {
        out = rewrite_if_suspicious(buf, bufsiz, n, 0);
    } else if (path_is_proc_fd(eff_path)) {
        // Round 15: same memfd-origin spoof as readlink().
        int fd = proc_fd_path_number(eff_path);
        ssize_t spoofed = hide_advanced_spoof_memfd_readlink(
            fd, buf, (size_t)n, buf, bufsiz);
        if (spoofed > 0) {
            out = spoofed;
        } else {
            out = rewrite_if_suspicious(buf, bufsiz, n, 1);
        }
    }
    free(resolved);
    return out;
}

// ----------------------------------------------------------------------------
// 10.-13. One-shot prctl helpers.
//
// These remain available (unit tests call them directly) but are NOT
// part of the post-fork pipeline anymore — see the file header for
// why each removal makes the process MORE stock-looking, not less.
// ----------------------------------------------------------------------------

void set_pdeathsig_if_safe() {
    (void)prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0);
}

void set_dumpable_zero() {
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

void set_no_new_privs() {
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

static void set_neutral_comm_name() {
    // "main" is the transient comm the zygote's forks report before
    // the runtime sets the package name — the expected value in the
    // post-fork window.
    const char n[] = "main";
    char buf[16] = {};
    memcpy(buf, n, sizeof(n) - 1);
    (void)prctl(PR_SET_NAME, buf, 0, 0, 0);
}

void disable_core_dumps() {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    (void)setrlimit(RLIMIT_CORE, &rl);
}

// Re-pin cwd to "/" — if the hide unmounts disconnected the old cwd,
// getcwd() would fail and /proc/self/cwd would read "<path> (deleted)",
// neither of which ever happens in a stock app process.
static void ensure_cwd_is_root() {
    if (chdir("/") != 0) {
        ZS_LOGW("hide_stealth: chdir(/) failed: %s", strerror(errno));
    }
}

// ----------------------------------------------------------------------------
// Public surface (see hide_stealth.h)
// ----------------------------------------------------------------------------


static std::atomic<int> g_stealth_initialized{0};

void hide_stealth_init() {
    int expected = 0;
    if (!g_stealth_initialized.compare_exchange_strong(expected, 1)) {
        return;
    }
    // Resolve the real libc readlink functions (delegate targets).
    g_real_readlink   = (ReadlinkFn)zs_resolve_libc("readlink");
    g_real_readlinkat = (ReadlinkAtFn)zs_resolve_libc("readlinkat");
    // Register through the shared DEFERRED registry (promoted and
    // walked only when a hide lands on Tier B).
    hide_advanced_register_tier_b_hook("readlink",
        (void*)&zygisk_study_hook_readlink);
    hide_advanced_register_tier_b_hook("readlinkat",
        (void*)&zygisk_study_hook_readlinkat);
}

void hide_stealth_apply_post_fork(const char* /*package_name*/) {
    // Only the stock-compatible actions remain:
    //   - comm "main" during the transition window
    //   - RLIMIT_CORE 0 (already the zygote default; idempotent)
    //   - cwd pinned to "/"
    set_neutral_comm_name();
    disable_core_dumps();
    ensure_cwd_is_root();
}

} // namespace zygisk_study
