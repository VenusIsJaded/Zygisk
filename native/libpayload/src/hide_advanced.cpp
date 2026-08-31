// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide_advanced.cpp
//
// Advanced runtime stealth layer. See hide_advanced.h for the public
// surface and the Round 7 two-tier architecture note.
//
// Important design notes:
//
//   - Every technique here is ORIGINAL source written for this
//     repository. None of it is copied from any other project.
//     The techniques themselves are publicly documented in the
//     Magisk / Shamiko / LSPosed docs and in public Android
//     security research; the implementation is mine.
//
//   - The Tier B hooks are installed at HIDE TIME in the target
//     child, never in the zygote. A pre-Round-7 version patched the
//     GOTs of every process forked from the zygote — including
//     system_server — and filtered /proc files for every app on the
//     device. That was both a system-wide performance regression and
//     a behavioral anomaly. Now a non-hidden process never executes
//     a single hooked call.
//
//   - The property-area clone is CONTENT-PRESERVING. The pre-Round-7
//     version mmap'd MAP_FIXED|MAP_ANONYMOUS over the property area
//     and returned — leaving a zero-filled mapping where the property
//     trie used to be. Every __system_property_get in the app then
//     walked garbage. mmap does not copy; the clone must save the
//     bytes first.

#include "hide_advanced.h"
#include "log.h"
#include "resolve_libc.h"

#include <cctype>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

// ----------------------------------------------------------------------------
// Branch-prediction hints for hot paths (mirrors hide.cpp).
// ----------------------------------------------------------------------------
#define ZS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ZS_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace zygisk_study {

// ------------------------------------------------------------------------
// Per-process activation gate (Tier B) + tracked fds
// ------------------------------------------------------------------------

static std::atomic<int> g_hide_active{0};

void hide_advanced_set_active(int active) {
    g_hide_active.store(active ? 1 : 0, std::memory_order_release);
}
int  hide_advanced_is_active() {
    return g_hide_active.load(std::memory_order_relaxed);
}

// Fds we opened ourselves. The hide pipeline closes exactly these.
static int   g_tracked_fds[16];
static size_t g_tracked_fd_count;

void hide_advanced_track_fd(int fd) {
    if (fd < 0) return;
    for (size_t i = 0; i < g_tracked_fd_count; ++i) {
        if (g_tracked_fds[i] == fd) return;
    }
    if (g_tracked_fd_count < sizeof(g_tracked_fds) / sizeof(g_tracked_fds[0])) {
        g_tracked_fds[g_tracked_fd_count++] = fd;
    }
}

// Close exactly the fds we tracked. NEVER the runtime's: the
// pre-Round-7 close_unknown_fds() closed every fd >= 3, which killed
// the GPU driver / gralloc / ashmem descriptors every app process
// inherits from the zygote — black screens and renderer crashes on
// real devices, invisible in host tests (the host child only had
// stdio + a pipe).
static void close_tracked_fds() {
    for (size_t i = 0; i < g_tracked_fd_count; ++i) {
        close(g_tracked_fds[i]);
    }
    g_tracked_fd_count = 0;
}

// ------------------------------------------------------------------------
// 4. Property-area cloning (content-preserving) + value spoofing
// ------------------------------------------------------------------------

// Spoof values: what a STOCK, LOCKED device reports. Empty values are
// never used for boot-state keys — a probe that sees
// verifiedbootstate == "" knows something is wrong, because stock
// Android always reports green/orange/red/yellow. Keys with nullptr
// are magisk/kernelSU-specific: on a stock device they do not exist.
// Tier B additionally hooks __system_property_find/get so they truly
// report "absent"; Tier A leaves them present-but-empty (Java's
// SystemProperties.get() returns "" for both cases, which covers the
// overwhelming majority of real-world probes).
static const ZsPropSpoof kPropSpoofTable[] = {
    {"ro.boot.verifiedbootstate",   "green"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.veritymode",          "enforcing"},
    {"ro.bootmanager.veritymode",   "enforcing"},
    {"ro.boot.flash.locked",        "1"},
    {"ro.boot.warrantybit",         "0"},
    {"ro.warranty.bits",            "0"},
    {"ro.boot.vbmeta.hash_algo",    ""},
    {"ro.boot.vbmeta.digest",       ""},
    // Magisk / KernelSU / our own keys: no stock device has them.
    {"init.svc.magisk",             ""},
    {"init.svc.magisk_pfsd",        ""},
    {"ro.magisk.version",           ""},
    {"ro.magisk.versioncode",       ""},
    {"persist.sys.magisk_denylist", ""},
    {"persist.magisk.hide",         ""},
    {"service.magisk.rootdir",      ""},
    {"persist.sys.rootdir",         ""},
    {"ro.kernelsu.version",         ""},
    {"ro.kernelsu.exposed",         ""},
    {"ro.zygisk_study.version",     ""},
    // init.svc.adbd is deliberately NOT spoofed: adbd exists on stock
    // devices and "running"/"stopped" are both normal values.
};

const ZsPropSpoof* zs_prop_spoof_table(size_t* count) {
    if (count) *count = sizeof(kPropSpoofTable) / sizeof(kPropSpoofTable[0]);
    return kPropSpoofTable;
}

static std::atomic<int> g_props_cloned{0};

using FindPropFn = const void* (*)(const char*);
static FindPropFn g_find_prop = nullptr;

// Bionic prop_info layout (stable Android 5 → 15+):
//   offset 0:  atomic_uint_least32_t serial   (4 bytes)
//   offset 4:  char value[92]                 (PROP_VALUE_MAX)
//   offset 96: uint32_t namelen
//   offset 100:char name[]
constexpr size_t kPropSerialOffset = 0;
constexpr size_t kPropValueOffset  = 4;
constexpr size_t kPropValueSize    = 92;  // PROP_VALUE_MAX

// Update one prop_info value using bionic's serial protocol so
// concurrent readers in other threads of THIS process never observe
// a torn value. The mapping must be writable when this is called.
static void patch_prop_value(const void* pi, const char* value) {
    if (!pi || !value) return;
    auto* serial_atomic =
        reinterpret_cast<std::atomic<uint32_t>*>(
            reinterpret_cast<uintptr_t>(pi) + kPropSerialOffset);
    char* value_field =
        reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(pi)
                                + kPropValueOffset);

    uint32_t serial = serial_atomic->load(std::memory_order_relaxed);
    // Don't touch an entry mid-update by another writer.
    if (serial & 1u) return;
    serial_atomic->store(serial | 1u, std::memory_order_release);
    memset(value_field, 0, kPropValueSize);
    size_t len = strnlen(value, kPropValueSize - 1);
    memcpy(value_field, value, len);
    serial_atomic->store((serial + 2) & ~1u, std::memory_order_release);
}

// Find /dev/__properties__/ mappings in a maps buffer. Pure function
// (no I/O) so host tests can feed synthetic maps content. Writes up
// to cap {lo, hi} spans and returns how many were found.
struct PropMapping { uintptr_t lo, hi; };
static size_t find_prop_mappings(const char* buf, size_t total,
                                 PropMapping* out, size_t cap) {
    static const char kPropPath[] = "/dev/__properties__/";
    const size_t kPropPathLen = sizeof(kPropPath) - 1;
    size_t n = 0;
    const char* p = buf;
    const char* end = buf + total;
    while (p < end && n < cap) {
        const char* nl = (const char*)memchr(p, '\n', end - p);
        const char* line_end = nl ? nl : end;
        // Path field = after the 5th whitespace run.
        const char* fp = p;
        const char* path_field = nullptr;
        int col = 0;
        while (fp < line_end) {
            char c = *fp;
            if (c == ' ' || c == '\t') {
                while (fp < line_end && (*fp == ' ' || *fp == '\t')) ++fp;
                ++col;
                if (col == 5) { path_field = fp; break; }
            } else {
                ++fp;
            }
        }
        if (path_field && path_field + kPropPathLen <= line_end &&
            memcmp(path_field, kPropPath, kPropPathLen) == 0) {
            uintptr_t lo = 0, hi = 0;
            char perms[8] = {};
            char linebuf[512];
            size_t copy = (size_t)(line_end - p);
            if (copy >= sizeof linebuf) copy = sizeof linebuf - 1;
            memcpy(linebuf, p, copy);
            linebuf[copy] = '\0';
            int k = sscanf(linebuf, "%lx-%lx %7s", &lo, &hi, perms);
            if (k >= 3 && perms[0] == 'r' && perms[1] == '-' && hi > lo) {
                out[n].lo = lo;
                out[n].hi = hi;
                ++n;
            }
        }
        p = line_end + (nl ? 1 : 0);
    }
    return n;
}

// Replace ONE property mapping with a private, content-identical,
// writable copy; returns 1 on success. The steps:
//
//   1. mmap a scratch region and memcpy the original bytes out.
//   2. mmap MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE over the original
//      range (this is the step the old code did WITHOUT step 1 —
//      which zeroed the trie and broke every property read).
//   3. memcpy the saved bytes back in.
//
// After step 3 the range holds a byte-identical private copy. The
// page is left writable so patch_prop_value() can fix values; the
// caller mprotects it back to PROT_READ after patching.
static int remap_prop_mapping_private(uintptr_t lo, uintptr_t hi) {
    size_t size = hi - lo;
    void* addr = reinterpret_cast<void*>(lo);

    void* scratch = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) return 0;
    memcpy(scratch, addr, size);  // save original content

    void* remapped = mmap(addr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                          -1, 0);
    if (remapped == MAP_FAILED) {
        munmap(scratch, size);
        return 0;
    }
    memcpy(addr, scratch, size);  // restore content into the copy
    munmap(scratch, size);
    return 1;
}

static void clone_property_area_private() {
    if (g_props_cloned.exchange(1)) return;

    // Resolve bionic's property lookup once. On the host there is no
    // __system_property_find; the clone is skipped (host tests assert
    // the pure helpers instead).
    if (!g_find_prop) {
        g_find_prop = (FindPropFn)zs_resolve_libc("__system_property_find");
    }

    constexpr size_t kMapsCap = 96 * 1024;
    static char maps_buf[kMapsCap];   // static: runs once, keep it off the stack
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t total = 0;
    while ((size_t)total < kMapsCap) {
        ssize_t n = read(fd, maps_buf + total, kMapsCap - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    if (total <= 0) return;

    PropMapping mappings[32];
    size_t n_mappings = find_prop_mappings(maps_buf, (size_t)total,
                                           mappings, 32);
    int n_remapped = 0;
    for (size_t i = 0; i < n_mappings; ++i) {
        if (remap_prop_mapping_private(mappings[i].lo,
                                       mappings[i].hi)) {
            ++n_remapped;
        } else {
            ZS_LOGW("hide_advanced: property remap %lx-%lx failed: %s",
                    (unsigned long)mappings[i].lo,
                    (unsigned long)mappings[i].hi, strerror(errno));
        }
    }
    if (n_remapped == 0) {
        g_props_cloned.store(0);  // allow a retry on a later fork
        return;
    }

    // Patch spoof values through bionic's own lookup. The cached trie
    // pointers still resolve (the MAP_FIXED replacement keeps every
    // address identical), so find() now walks OUR private copy.
    if (g_find_prop) {
        size_t n_spoof = 0;
        for (const ZsPropSpoof& s : kPropSpoofTable) {
            const void* pi = g_find_prop(s.key);
            if (pi) {
                patch_prop_value(pi, s.value ? s.value : "");
                ++n_spoof;
            }
        }
        ZS_LOGD("hide_advanced: spoofed %zu property value(s)", n_spoof);
    }

    // Restore read-only protection on every remapped range — the
    // original property mappings are PROT_READ, and leaving pages
    // writable is both an anomaly and a corruption risk.
    for (size_t i = 0; i < n_mappings; ++i) {
        void* addr = reinterpret_cast<void*>(mappings[i].lo);
        size_t size = mappings[i].hi - mappings[i].lo;
        if (mprotect(addr, size, PROT_READ) != 0) {
            ZS_LOGW("hide_advanced: mprotect(R) on property clone "
                    "failed: %s", strerror(errno));
        }
        // STEALTH: rename the new anon mapping so /proc/self/maps
        // shows a benign "[anon:linker_alloc]" style label instead
        // of a bare anonymous mapping at the property-area address.
        // No-op on kernels without the vendor PR_SET_VMA extension.
        constexpr int kPrSetVma = 0x53564d41;          // "AVMS"
        constexpr int kPrSetVmaAnonName = 0;
        const char kAnonName[] = "linker_alloc";
        (void)prctl(kPrSetVma, kPrSetVmaAnonName,
                    reinterpret_cast<unsigned long>(addr),
                    (unsigned long)size,
                    reinterpret_cast<unsigned long>(kAnonName));
    }
    ZS_LOGD("hide_advanced: property area cloned (%d mapping(s))",
            n_remapped);
}

// ------------------------------------------------------------------------
// 5. /proc file filtering (Tier B)
// ------------------------------------------------------------------------

// The /proc files whose contents would reveal us. Matched by base
// name; see zs_path_is_filtered for the /proc/self, /proc/thread-self
// and /proc/<pid> prefix handling.
static const char* const kFilteredBaseNames[] = {
    "maps",
    "mounts",
    "mountinfo",
    "mountstats",
    // status carries TracerPid (rewritten to 0 in the filtered copy).
    "status",
    "smaps",
    "smaps_rollup",
};

// Tier B also filters these in the maps/mounts content:
struct HiddenSubstring {
    const char* data;
    size_t      len;
    constexpr HiddenSubstring(const char* s)
        : data(s), len(__builtin_strlen(s)) {}
};

static constexpr HiddenSubstring kHiddenSubstrings[] = {
    // Our own .so files
    "libzygisk.so",
    "libpayload.so",
    "libzn_loader.so",
    // Standard Magisk paths
    "/data/adb/",
    "/sbin/",
    "/debug_ramdisk/",
    // KernelSU paths
    "/data/adb/ksu/",
    "/data/adb/modules",
    // Zygisk Study's own working dir
    "/data/system/zygisk_study",
};

// True if `rest` (the part after "/proc/<id>/") names a file we
// filter.
static int basename_is_filtered(const char* rest) {
    for (const char* b : kFilteredBaseNames) {
        if (strcmp(rest, b) == 0) return 1;
    }
    return 0;
}

int zs_path_is_filtered(const char* path) {
    if (ZS_UNLIKELY(!path)) return 0;
    if (memcmp(path, "/proc/", 6) != 0) return 0;
    const char* rest = path + 6;

    if (strncmp(rest, "thread-self/", 12) == 0) {
        rest += 12;
    } else if (strncmp(rest, "self/", 5) == 0) {
        rest += 5;
    } else {
        // Numeric pid form: /proc/<pid>/<file>. Only OUR pid counts —
        // /proc/1/mounts from an app fails with EACCES anyway.
        const char* p = rest;
        while (*p >= '0' && *p <= '9') ++p;
        if (ZS_UNLIKELY(p == rest || *p != '/')) return 0;
        // Verify the pid is ours. getpid() is a raw syscall on
        // bionic (~0.5 µs); this path only runs for /proc/<digits>
        // opens in hidden apps, so no caching is worth the
        // stale-across-fork risk.
        long v = 0;
        for (const char* q = rest; q < p; ++q) v = v * 10 + (*q - '0');
        if (v != (long)getpid()) return 0;
        rest = p + 1;
    }
    return basename_is_filtered(rest);
}

// We hold the original libc open/openat addresses so our hook can
// delegate to them when the path is not one we filter.
using OpenFn   = int (*)(const char*, int, ...);
using OpenAtFn = int (*)(int, const char*, int, ...);
static OpenFn   g_real_open   = nullptr;
static OpenAtFn g_real_openat = nullptr;

// Forward decls.
extern "C" int   zygisk_study_hook_open(const char* path, int flags, ...);
extern "C" int   zygisk_study_hook_openat(int dirfd, const char* path,
                                          int flags, ...);
extern "C" FILE* zygisk_study_hook_fopen(const char* path, const char* mode);

// sys_memfd_create — call the memfd_create syscall directly so we do
// not depend on the libc wrapper (older bionic lacks it) and never
// recurse through our own hooks.
static int syscall_memfd_create(const char* name, unsigned int flags) {
#ifdef __NR_memfd_create
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    (void)name; (void)flags;
    return -1;
#endif
}

// Rewrite the TracerPid line of /proc/self/status to "TracerPid:\t0".
static ssize_t rewrite_status_line(char* dst, size_t dst_cap,
                                    const char* line_start,
                                    size_t line_len) {
    static const char kPrefix[] = "TracerPid:";
    constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
    if (line_len < kPrefixLen) return 0;
    if (memcmp(line_start, kPrefix, kPrefixLen) != 0) return 0;

    static const char kReplacement[] = "TracerPid:\t0\n";
    constexpr size_t kReplacementLen = sizeof(kReplacement) - 1;
    if (dst_cap < kReplacementLen) return 0;
    memcpy(dst, kReplacement, kReplacementLen);
    return (ssize_t)kReplacementLen;
}

// True if `path` is a filtered /proc path whose base name is `base`.
static int filtered_path_basename_is(const char* path, const char* base) {
    if (!path) return 0;
    size_t plen = strlen(path);
    size_t blen = strlen(base);
    if (plen <= blen + 1) return 0;
    if (path[plen - blen - 1] != '/') return 0;
    return strcmp(path + plen - blen, base) == 0;
}

// Produce a filtered copy of the given file's contents in a memfd.
// Returns the memfd fd, or -1 on error.
//
// PERF/SAFETY NOTE (Round 7): the pre-Round-7 version used a 256 KB
// STACK array. This runs inside an open() hook on whatever app thread
// performed the open — including deep ART call stacks on threads with
// 1 MB stacks. 256 KB of stack there is a silent stack-overflow bomb
// that only fires on device. The scratch buffer is now an anonymous
// mmap: two extra syscalls (~4 µs) against a ~200 µs filtering pass,
// and zero stack pressure on any thread.
static int make_filtered_memfd(int orig_fd, const char* target_path) {
    int memfd = syscall_memfd_create("scudo", 0);
    if (memfd < 0) return -1;

    constexpr size_t kReadCap = 256 * 1024;
    char* buf = (char*)mmap(nullptr, kReadCap, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        close(memfd);
        return -1;
    }
    ssize_t total = 0;
    while ((size_t)total < kReadCap) {
        ssize_t n = pread(orig_fd, buf + total, kReadCap - total,
                          (off_t)total);
        if (n <= 0) break;
        total += n;
    }
    if (total < 0) {
        munmap(buf, kReadCap);
        close(memfd);
        return -1;
    }

    // In-place compaction: kept lines move to the front, then ONE
    // write() pushes the whole result into the memfd (P1.18 history:
    // this replaced one write() per line, ~490 syscalls per read).
    char* write_ptr = buf;
    const char* line_start = buf;
    const char* end = buf + total;
    int is_status = zs_path_is_filtered(target_path ? target_path : "") &&
                    filtered_path_basename_is(target_path, "status");
    while (line_start < end) {
        const char* line_end = (const char*)memchr(line_start, '\n',
                                                   end - line_start);
        if (!line_end) line_end = end;
        size_t line_len = line_end - line_start;
        size_t nl_len   = (line_end < end && *line_end == '\n') ? 1 : 0;
        size_t full_len = line_len + nl_len;

        if (is_status) {
            char rewrite_buf[64];
            ssize_t rewritten = rewrite_status_line(
                rewrite_buf, sizeof rewrite_buf, line_start, full_len);
            if (rewritten > 0) {
                size_t rlen = (size_t)rewritten;
                if (write_ptr + rlen <= buf + kReadCap) {
                    memcpy(write_ptr, rewrite_buf, rlen);
                    write_ptr += rlen;
                }
                line_start = line_end + nl_len;
                continue;
            }
        }

        // Find the path field (after the 5th whitespace run) and
        // search the hidden substrings only within it (P1.39/P1.40
        // history: compile-time lengths + branch hints).
        const char* p = line_start;
        const char* path_field = nullptr;
        int col = 0;
        while (p < line_end) {
            char c = *p;
            if (c == ' ' || c == '\t') {
                while (p < line_end && (*p == ' ' || *p == '\t')) ++p;
                ++col;
                if (col == 5) { path_field = p; break; }
            } else {
                ++p;
            }
        }

        int skip = 0;
        if (path_field && path_field < line_end) {
            size_t path_len = line_end - path_field;
            for (const HiddenSubstring& sub : kHiddenSubstrings) {
                if (sub.len == 0 || sub.len > path_len) continue;
                if (memmem(path_field, path_len, sub.data, sub.len)) {
                    skip = 1;
                    break;
                }
            }
        }

        if (ZS_LIKELY(!skip)) {
            if (write_ptr != line_start) {
                memmove(write_ptr, line_start, full_len);
            }
            write_ptr += full_len;
        }
        line_start = line_end + nl_len;
    }

    size_t kept_total = (size_t)(write_ptr - buf);
    if (kept_total > 0) {
        ssize_t w = write(memfd, buf, kept_total);
        (void)w;
    }
    munmap(buf, kReadCap);
    lseek(memfd, 0, SEEK_SET);
    return memfd;
}

// Wrap the original open so the caller gets back either the original
// fd (for non-filtered paths) or a filtered memfd (for filtered
// paths).
static int wrapped_open(const char* path, int flags, mode_t mode) {
    int real_fd = g_real_open
        ? g_real_open(path, flags, mode)
        : (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
    if (real_fd < 0) return real_fd;

    if (!zs_path_is_filtered(path)) return real_fd;

    int memfd = make_filtered_memfd(real_fd, path);
    close(real_fd);
    if (memfd >= 0) return memfd;
    // B2 history: never return the closed fd.
    errno = EBADF;
    return -1;
}

static int wrapped_openat(int dirfd, const char* path, int flags,
                          mode_t mode) {
    // Only absolute paths can name a /proc file; relative paths pass
    // through untouched (we lack the context to resolve them).
    if (ZS_UNLIKELY(!path || path[0] != '/' || dirfd != AT_FDCWD)) {
        return g_real_openat
            ? g_real_openat(dirfd, path, flags, mode)
            : (int)syscall(SYS_openat, dirfd, path, flags, mode);
    }
    int real_fd = g_real_openat
        ? g_real_openat(dirfd, path, flags, mode)
        : (int)syscall(SYS_openat, dirfd, path, flags, mode);
    if (real_fd < 0) return real_fd;

    if (!zs_path_is_filtered(path)) return real_fd;

    int memfd = make_filtered_memfd(real_fd, path);
    close(real_fd);
    if (memfd >= 0) return memfd;
    errno = EBADF;
    return -1;
}

extern "C" int zygisk_study_hook_open(const char* path, int flags, ...) {
    // Tier B gate: one relaxed atomic load when inactive. Every
    // non-hidden process pays exactly that.
    if (ZS_UNLIKELY(!hide_advanced_is_active())) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            mode = va_arg(ap, int); va_end(ap);
        }
        return g_real_open
            ? g_real_open(path, flags, mode)
            : (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int); va_end(ap);
    }
    return wrapped_open(path, flags, mode);
}

extern "C" int zygisk_study_hook_openat(int dirfd, const char* path,
                                        int flags, ...) {
    if (ZS_UNLIKELY(!hide_advanced_is_active())) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            mode = va_arg(ap, int); va_end(ap);
        }
        return g_real_openat
            ? g_real_openat(dirfd, path, flags, mode)
            : (int)syscall(SYS_openat, dirfd, path, flags, mode);
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int); va_end(ap);
    }
    return wrapped_openat(dirfd, path, flags, mode);
}

// Round 7 (S2): fopen() bypass. libc's fopen calls openat
// *internally* (hidden alias — NOT via the caller's PLT), so a
// stdio-based detector reading /proc/self/maps sailed past the
// open/openat GOT hooks. std::ifstream and plain C detectors using
// fopen are extremely common, so we hook fopen itself and serve the
// filtered memfd through fdopen().
using FopenFn = FILE* (*)(const char*, const char*);
static FopenFn g_real_fopen = nullptr;

extern "C" FILE* zygisk_study_hook_fopen(const char* path,
                                         const char* mode) {
    if (ZS_UNLIKELY(!hide_advanced_is_active()) || !path || !mode) {
        return g_real_fopen ? g_real_fopen(path, mode) : nullptr;
    }
    // Never intercept write/append modes (and path_is_filtered only
    // ever matches /proc reads anyway).
    if (strchr(mode, 'w') || strchr(mode, 'a') ||
        !zs_path_is_filtered(path)) {
        return g_real_fopen ? g_real_fopen(path, mode) : nullptr;
    }
    FILE* f = g_real_fopen ? g_real_fopen(path, mode) : nullptr;
    if (!f) return f;
    int fd = fileno(f);
    int memfd = make_filtered_memfd(fd, path);
    fclose(f);
    if (memfd < 0) { errno = EBADF; return nullptr; }
    FILE* rf = fdopen(memfd, "r");
    if (!rf) close(memfd);
    return rf;
}

// Round 7 (S2): FORTIFY variants. Code compiled with
// _FORTIFY_SOURCE (the NDK default) calls __open_2/__openat_2
// instead of open/openat. These bypass the plain-name hooks.
extern "C" int zygisk_study_hook___open_2(const char* path, int flags);
extern "C" int zygisk_study_hook___openat_2(int dirfd, const char* path,
                                            int flags);

extern "C" int zygisk_study_hook___open_2(const char* path, int flags) {
    if (ZS_UNLIKELY(!hide_advanced_is_active()) || !path) {
        return g_real_open ? g_real_open(path, flags, 0)
                           : (int)syscall(SYS_openat, AT_FDCWD, path,
                                          flags, 0);
    }
    return wrapped_open(path, flags, 0);
}

extern "C" int zygisk_study_hook___openat_2(int dirfd, const char* path,
                                            int flags) {
    if (ZS_UNLIKELY(!hide_advanced_is_active()) || !path) {
        return g_real_openat
            ? g_real_openat(dirfd, path, flags, 0)
            : (int)syscall(SYS_openat, dirfd, path, flags, 0);
    }
    if (path[0] != '/' || dirfd != AT_FDCWD) {
        return g_real_openat
            ? g_real_openat(dirfd, path, flags, 0)
            : (int)syscall(SYS_openat, dirfd, path, flags, 0);
    }
    return wrapped_openat(dirfd, path, flags, 0);
}

// ------------------------------------------------------------------------
// 5b. stat / access family hooks (Tier B)
// ------------------------------------------------------------------------

using StatFn      = int (*)(const char*, struct stat*);
using LstatFn     = int (*)(const char*, struct stat*);
using AccessFn    = int (*)(const char*, int);
using FAccessAtFn = int (*)(int, const char*, int, int);
using FAccessAt2Fn = int (*)(int, const char*, int, int);
using FStatAtFn   = int (*)(int, const char*, struct stat*, int);
using StatxFn     = int (*)(int, const char*, int, unsigned int,
                            struct statx*);

static StatFn       g_real_stat        = nullptr;
static LstatFn      g_real_lstat       = nullptr;
static AccessFn     g_real_access      = nullptr;
static FAccessAtFn  g_real_faccessat   = nullptr;
static FAccessAt2Fn g_real_faccessat2  = nullptr;
static FStatAtFn    g_real_fstatat     = nullptr;
static StatxFn      g_real_statx       = nullptr;

extern "C" int zygisk_study_hook_stat(const char* path, struct stat* st);
extern "C" int zygisk_study_hook_lstat(const char* path, struct stat* st);
extern "C" int zygisk_study_hook_access(const char* path, int mode);
extern "C" int zygisk_study_hook_faccessat(int dirfd, const char* path,
                                           int mode, int flags);
extern "C" int zygisk_study_hook_faccessat2(int dirfd, const char* path,
                                            int mode, int flags);
extern "C" int zygisk_study_hook_fstatat(int dirfd, const char* path,
                                         struct stat* st, int flags);
extern "C" int zygisk_study_hook_statx(int dirfd, const char* path,
                                       int flags, unsigned int mask,
                                       struct statx* stx);

// Paths whose existence would reveal a root framework. We return
// ENOENT for these.
//
// On a real device /data/adb is mode 0700 root:root, so an
// untrusted_app probe already gets EACCES there — the hooks are
// defense-in-depth for ROMs with looser permissions and for the
// /system overlay paths some frameworks use.
static const char* const kHiddenStatPaths[] = {
    "/data/adb/magisk",
    "/data/adb/modules",
    "/data/adb/modules_update",
    "/data/adb/ksu",
    "/data/adb/zygisk_study",
    "/sbin/magisk",
    "/sbin/zygisk_study",
    "/system/bin/magisk",
    "/debug_ramdisk",
    "/data/system/zygisk_study",
};

static int path_is_hidden(const char* path) {
    if (ZS_UNLIKELY(!path || path[0] != '/')) return 0;
    // Fast gate (P1.62 history): all hidden paths start with one of
    // these prefixes.
    if (strncmp(path, "/data",          5) != 0 &&
        strncmp(path, "/sbin",          5) != 0 &&
        strncmp(path, "/system",        7) != 0 &&
        strncmp(path, "/debug_ramdisk", 14) != 0) {
        return 0;
    }
    for (const char* h : kHiddenStatPaths) {
        if (strcmp(path, h) == 0) return 1;
    }
    // Prefix match (hidden path + '/' + anything), with the B1
    // bounds check fixed in Round 6.
    size_t plen = strlen(path);
    for (const char* h : kHiddenStatPaths) {
        size_t hlen = __builtin_strlen(h);
        if (hlen > 0 && h[hlen-1] == '/') hlen--;
        if (hlen < plen && path[hlen] == '/' &&
            strncmp(path, h, hlen) == 0) return 1;
    }
    return 0;
}

extern "C" int zygisk_study_hook_stat(const char* path, struct stat* st) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !path_is_hidden(path)) {
        return g_real_stat
            ? g_real_stat(path, st)
            : (int)syscall(SYS_stat, path, st);
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_lstat(const char* path, struct stat* st) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !path_is_hidden(path)) {
        return g_real_lstat
            ? g_real_lstat(path, st)
            : (int)syscall(SYS_lstat, path, st);
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_access(const char* path, int mode) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !path_is_hidden(path)) {
        return g_real_access
            ? g_real_access(path, mode)
            : (int)syscall(SYS_access, path, mode);
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_faccessat(int dirfd, const char* path,
                                           int mode, int flags) {
    if (ZS_LIKELY(!hide_advanced_is_active()) ||
        !(path && path[0] == '/' && path_is_hidden(path))) {
        return g_real_faccessat
            ? g_real_faccessat(dirfd, path, mode, flags)
            : (int)syscall(SYS_faccessat, dirfd, path, mode, flags);
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_faccessat2(int dirfd, const char* path,
                                            int mode, int flags) {
    if (ZS_LIKELY(!hide_advanced_is_active()) ||
        !(path && path[0] == '/' && path_is_hidden(path))) {
        if (g_real_faccessat2) return g_real_faccessat2(dirfd, path, mode, flags);
        if (g_real_faccessat)  return g_real_faccessat(dirfd, path, mode, flags);
#ifdef SYS_faccessat2
        return (int)syscall(SYS_faccessat2, dirfd, path, mode, flags);
#else
        return (int)syscall(SYS_faccessat, dirfd, path, mode, flags);
#endif
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_fstatat(int dirfd, const char* path,
                                         struct stat* st, int flags) {
    if (ZS_LIKELY(!hide_advanced_is_active()) ||
        !(path && path[0] == '/' && path_is_hidden(path))) {
        if (g_real_fstatat) return g_real_fstatat(dirfd, path, st, flags);
#if defined(SYS_fstatat)
        return (int)syscall(SYS_fstatat, dirfd, path, st, flags);
#elif defined(SYS_newfstatat)
        return (int)syscall(SYS_newfstatat, dirfd, path, st, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_statx(int dirfd, const char* path,
                                       int flags, unsigned int mask,
                                       struct statx* stx) {
    if (ZS_LIKELY(!hide_advanced_is_active()) ||
        !(path && path[0] == '/' && path_is_hidden(path))) {
        if (g_real_statx) return g_real_statx(dirfd, path, flags, mask, stx);
#ifdef SYS_statx
        return (int)syscall(SYS_statx, dirfd, path, flags, mask, stx);
#else
        errno = ENOSYS;
        return -1;
#endif
    }
    errno = ENOENT;
    return -1;
}

// ------------------------------------------------------------------------
// 5c. Property READ hooks (Tier B)
// ------------------------------------------------------------------------

// For keys whose stock behavior is "does not exist", find()/get()
// must report absence. The clone alone can only empty the VALUE —
// the key still enumerates and find() still returns non-NULL.
// Hooking the two read entry points closes that residual.
//
// libandroid_runtime (SystemProperties JNI) calls both of these
// through its PLT, so the GOT patch covers every Java-level
// SystemProperties.get() call.
using PropFindFn = const void* (*)(const char*);
using PropGetFn  = int (*)(const char*, char*);
static PropFindFn g_real_prop_find = nullptr;
static PropGetFn  g_real_prop_get  = nullptr;

static int prop_key_is_absent(const char* key) {
    if (!key) return 0;
    for (const ZsPropSpoof& s : kPropSpoofTable) {
        if (s.value == nullptr || s.value[0] == '\0') {
            if (strcmp(key, s.key) == 0) return 1;
        }
    }
    return 0;
}

extern "C" const void* zygisk_study_hook_prop_find(const char* key) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !prop_key_is_absent(key)) {
        return g_real_prop_find ? g_real_prop_find(key) : nullptr;
    }
    return nullptr;  // property "does not exist"
}

extern "C" int zygisk_study_hook_prop_get(const char* key, char* value) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !prop_key_is_absent(key)) {
        return g_real_prop_get ? g_real_prop_get(key, value) : 0;
    }
    if (value) value[0] = '\0';
    return 0;  // length 0 = not found
}

// ------------------------------------------------------------------------
// 5d. Raw syscall() hook (Tier B)
// ------------------------------------------------------------------------

// Detectors that bypass libc wrappers call syscall(SYS_openat, ...)
// directly. The libc syscall() wrapper itself goes through the PLT,
// so hooking it catches every such probe that does not hand-roll
// inline asm. The fast path (not active / not an interesting syscall
// number) costs one atomic load plus one switch.
using SyscallFn = long (*)(long, ...);
static SyscallFn g_real_syscall = nullptr;

extern "C" long zygisk_study_hook_syscall(long number, ...) {
    if (ZS_UNLIKELY(!hide_advanced_is_active())) {
        // Pass the varargs straight through.
        va_list ap;
        va_start(ap, number);
        long a[6];
        for (int i = 0; i < 6; ++i) a[i] = va_arg(ap, long);
        va_end(ap);
        return g_real_syscall
            ? g_real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5])
            : -ENOSYS;
    }
    // Extract the first four arguments (the most any of our handled
    // syscalls use) and dispatch.
    va_list ap;
    va_start(ap, number);
    long a0 = va_arg(ap, long);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    va_end(ap);

#ifdef SYS_openat
    if (number == (long)SYS_openat) {
        const char* path = (const char*)a1;
        if (path && path[0] == '/' && (int)a0 == AT_FDCWD &&
            zs_path_is_filtered(path)) {
            int flags = (int)a2;
            mode_t mode = (flags & O_CREAT) ? (mode_t)a3 : 0;
            return wrapped_openat((int)a0, path, flags, mode);
        }
    }
#endif
#ifdef SYS_open
    if (number == (long)SYS_open) {
        const char* path = (const char*)a0;
        if (path && zs_path_is_filtered(path)) {
            int flags = (int)a1;
            mode_t mode = (flags & O_CREAT) ? (mode_t)a2 : 0;
            return wrapped_open(path, flags, mode);
        }
    }
#endif
    if (
#ifdef SYS_statx
        number == (long)SYS_statx ||
#endif
#ifdef SYS_faccessat2
        number == (long)SYS_faccessat2 ||
#endif
        false) {
        const char* path = (const char*)a1;
        if (path && path[0] == '/' && path_is_hidden(path)) {
            errno = ENOENT;
            return -1;
        }
    }
#if defined(SYS_newfstatat)
    if (number == (long)SYS_newfstatat) {
        const char* path = (const char*)a1;
        if (path && path[0] == '/' && path_is_hidden(path)) {
            errno = ENOENT;
            return -1;
        }
    }
#endif
    // Not ours — pass all four extracted args through. (Handled
    // syscalls never use more than four; callers passing fewer are
    // harmless — extra register args are ignored by the kernel.)
    return g_real_syscall
        ? g_real_syscall(number, a0, a1, a2, a3)
        : -ENOSYS;
}

// ------------------------------------------------------------------------
// GOT hook registry + the single walker
// ------------------------------------------------------------------------

constexpr size_t kMaxGotHooks = 48;
struct GotHookEntry {
    const char* name;
    void*       fn;
};
// Immediate registry: walked by hide_advanced_install_got_hooks()
// (payload init installs ONLY the fork/privilege-drop hooks here).
static GotHookEntry g_got_hooks[kMaxGotHooks];
static size_t       g_got_hook_count = 0;
// Deferred (Tier B) registry: promoted into the main registry by
// hide_advanced_install_tier_b() — i.e. only in a child we are
// actually hiding. Installing these in the zygote would hook every
// process on the device (system_server included) for zero benefit.
static GotHookEntry g_tier_b_hooks[kMaxGotHooks];
static size_t       g_tier_b_hook_count = 0;

int hide_advanced_register_got_hook(const char* name, void* fn) {
    if (!name || !fn) return 0;
    if (g_got_hook_count >= kMaxGotHooks) {
        ZS_LOGW("hide_advanced: GOT hook registry full (%zu)",
                kMaxGotHooks);
        return 0;
    }
    for (size_t i = 0; i < g_got_hook_count; ++i) {
        if (strcmp(g_got_hooks[i].name, name) == 0) return 1; // dup
    }
    g_got_hooks[g_got_hook_count].name = name;
    g_got_hooks[g_got_hook_count].fn   = fn;
    ++g_got_hook_count;
    return 1;
}

int hide_advanced_register_tier_b_hook(const char* name, void* fn) {
    if (!name || !fn) return 0;
    if (g_tier_b_hook_count >= kMaxGotHooks) {
        ZS_LOGW("hide_advanced: Tier B hook registry full (%zu)",
                kMaxGotHooks);
        return 0;
    }
    for (size_t i = 0; i < g_tier_b_hook_count; ++i) {
        if (strcmp(g_tier_b_hooks[i].name, name) == 0) return 1;
    }
    g_tier_b_hooks[g_tier_b_hook_count].name = name;
    g_tier_b_hooks[g_tier_b_hook_count].fn   = fn;
    ++g_tier_b_hook_count;
    return 1;
}

// Every slot we patched, with its original value, so we can restore
// the process to a byte-stock state before the self-unmap.
constexpr size_t kMaxPatchedSlots = 1024;
struct PatchedSlot {
    void** slot;
    void*  original;
};
static PatchedSlot g_patched_slots[kMaxPatchedSlots];
static size_t      g_patched_slot_count = 0;

static long got_pagesize() {
    static long ps = sysconf(_SC_PAGESIZE);
    return ps > 0 ? ps : 4096;
}

// Resolve a registered hook by symbol name; first-char gate then
// strcmp (P1.60 history: one byte compare rejects most names).
// Only the LIVE registry is consulted: deferred Tier B entries are
// invisible until hide_advanced_install_tier_b() promotes them,
// which happens before the walk runs — so the walker never misses
// anything and non-hidden processes provably carry no Tier B hooks.
static void* match_registered_hook(const char* name) {
    const char c = name[0];
    for (size_t i = 0; i < g_got_hook_count; ++i) {
        const char* h = g_got_hooks[i].name;
        if (h[0] == c && strcmp(name, h) == 0) {
            return g_got_hooks[i].fn;
        }
    }
    return nullptr;
}

// Portable relocation-symbol extraction. Bionic's <link.h> defines
// ELF_R_SYM for both classes; glibc's does not, so pick explicitly.
// (Round 7 / P5: the old ELF64_R_SYM broke armeabi-v7a builds, where
// the symbol index lives in the UPPER 24 bits of r_info, not 32.)
#ifdef __LP64__
#  define ZS_ELF_R_SYM(info) ELF64_R_SYM(info)
#else
#  define ZS_ELF_R_SYM(info) ELF32_R_SYM(info)
#endif

static int patch_got_all_for_phdr(struct dl_phdr_info* info,
                                  size_t /*size*/, void* /*data*/) {
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

    // Skip our own .so files — never patch ourselves (our internal
    // calls must keep resolving to the real libc functions, or the
    // hooks would recurse).
    if (strstr(info->dlpi_name, "libpayload.so")   != nullptr ||
        strstr(info->dlpi_name, "libzygisk.so")    != nullptr ||
        strstr(info->dlpi_name, "libzn_loader.so") != nullptr) {
        return 0;
    }

    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(
                reinterpret_cast<const char*>(info->dlpi_addr) + ph.p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    const ElfW(Sym)*  symtab   = nullptr;
    const char*       strtab   = nullptr;
    const ElfW(Rela)* jmprel   = nullptr;
    size_t            pltrelsz = 0;

    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab   = reinterpret_cast<const ElfW(Sym)*>(d->d_un.d_ptr); break;
            case DT_STRTAB:   strtab   = reinterpret_cast<const char*>(d->d_un.d_ptr);      break;
            case DT_JMPREL:   jmprel   = reinterpret_cast<const ElfW(Rela)*>(d->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val;                                    break;
            default: break;
        }
    }
    if (!symtab || !strtab || !jmprel || pltrelsz == 0) return 0;

    size_t n = pltrelsz / sizeof(ElfW(Rela));
    long pagesize = got_pagesize();

    for (size_t i = 0; i < n; i++) {
        const ElfW(Rela)& r = jmprel[i];
        // Round 7 (P5): ELF_R_SYM (not ELF64_R_SYM) so 32-bit ELF
        // relocations parse correctly on armeabi-v7a builds.
        size_t sym_idx = ZS_ELF_R_SYM(r.r_info);
        const ElfW(Sym)& sym = symtab[sym_idx];
        const char* name = strtab + sym.st_name;

        void* hook = match_registered_hook(name);
        if (!hook) continue;

        void** slot = reinterpret_cast<void**>(
            reinterpret_cast<char*>(info->dlpi_addr) + r.r_offset);
        void* current = *slot;
        if (current == hook) continue;  // already patched (re-walk)

        uintptr_t page = reinterpret_cast<uintptr_t>(slot)
                         & ~((uintptr_t)pagesize - 1);
        void* pageptr = reinterpret_cast<void*>(page);
        if (mprotect(pageptr, (size_t)pagesize,
                     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            // Record the original so the uninstall pass can restore
            // it before we unmap ourselves.
            if (g_patched_slot_count < kMaxPatchedSlots) {
                g_patched_slots[g_patched_slot_count].slot     = slot;
                g_patched_slots[g_patched_slot_count].original = current;
                ++g_patched_slot_count;
            } else if (g_patched_slot_count == kMaxPatchedSlots) {
                ZS_LOGW("hide_advanced: patched-slot table full; "
                        "uninstall will be partial");
                ++g_patched_slot_count;  // log once
            }
            *slot = hook;
            mprotect(pageptr, (size_t)pagesize, PROT_READ | PROT_EXEC);
        }
    }
    return 0;
}

void hide_advanced_install_got_hooks() {
    dl_iterate_phdr(patch_got_all_for_phdr, nullptr);
    ZS_LOGD("hide_advanced: GOT walk done (%zu hook(s), %zu slot(s))",
            g_got_hook_count, g_patched_slot_count);
}

void hide_advanced_uninstall_got_hooks() {
    long pagesize = got_pagesize();
    for (size_t i = 0; i < g_patched_slot_count &&
                       i < kMaxPatchedSlots; ++i) {
        void** slot = g_patched_slots[i].slot;
        uintptr_t page = reinterpret_cast<uintptr_t>(slot)
                         & ~((uintptr_t)pagesize - 1);
        void* pageptr = reinterpret_cast<void*>(page);
        if (mprotect(pageptr, (size_t)pagesize,
                     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            *slot = g_patched_slots[i].original;
            mprotect(pageptr, (size_t)pagesize, PROT_READ | PROT_EXEC);
        }
    }
    g_patched_slot_count = 0;
}

// ------------------------------------------------------------------------
// dlopen hook (Tier B): patch libs the app loads later
// ------------------------------------------------------------------------

// In Tier B the payload stays resident, and apps load their detector
// .so files via System.loadLibrary AFTER our hide-time walk. The
// freshly loaded library's GOT is pristine, so its open()/stat()
// calls bypass every hook. Hooking dlopen/android_dlopen_ext and
// re-running the walk after each load closes that window.
using DlopenFn = void* (*)(const char*, int);
static DlopenFn g_real_dlopen = nullptr;

extern "C" void* zygisk_study_hook_dlopen(const char* path, int flags) {
    void* h = g_real_dlopen ? g_real_dlopen(path, flags) : nullptr;
    if (h && hide_advanced_is_active()) {
        // Re-walk: patches the newly loaded module's GOT (and is
        // idempotent for everything already patched).
        dl_iterate_phdr(patch_got_all_for_phdr, nullptr);
    }
    return h;
}

// android_dlopen_ext is the variant actually used by
// System.loadLibrary / libart on Android.
struct android_dlopen_ext_t;  // opaque
using AndroidDlopenExtFn =
    void* (*)(const char*, int, const struct android_dlopen_ext_t*);
static AndroidDlopenExtFn g_real_android_dlopen_ext = nullptr;

extern "C" void* zygisk_study_hook_android_dlopen_ext(
        const char* path, int flags,
        const struct android_dlopen_ext_t* extinfo) {
    void* h = g_real_android_dlopen_ext
        ? g_real_android_dlopen_ext(path, flags, extinfo) : nullptr;
    if (h && hide_advanced_is_active()) {
        dl_iterate_phdr(patch_got_all_for_phdr, nullptr);
    }
    return h;
}

// ------------------------------------------------------------------------
// Env scrub
// ------------------------------------------------------------------------

static const char* const kOurEnvVars[] = {
    "ZYGISK_STUDY_DEBUG",
    "ZYGISK_STUDY_LOG_TAG",
    "ZYGISK_STUDY_WORKDIR",
};

static void scrub_env() {
    for (const char* v : kOurEnvVars) {
        unsetenv(v);
    }
}

// ------------------------------------------------------------------------
// Public surface
// ------------------------------------------------------------------------


static std::atomic<int> g_advanced_initialized{0};

void hide_advanced_init() {
    int expected = 0;
    if (!g_advanced_initialized.compare_exchange_strong(expected, 1)) {
        return;
    }
    // Resolve the real libc symbols every hook delegates to. Using
    // dlsym on libc.so directly (not RTLD_NEXT) because our library
    // is loaded with RTLD_LOCAL and is not in the global search order.
    g_real_open     = (OpenFn)zs_resolve_libc("open");
    g_real_openat   = (OpenAtFn)zs_resolve_libc("openat");
    g_real_fopen    = (FopenFn)zs_resolve_libc("fopen");
    g_real_stat     = (StatFn)zs_resolve_libc("stat");
    g_real_lstat    = (LstatFn)zs_resolve_libc("lstat");
    g_real_access   = (AccessFn)zs_resolve_libc("access");
    g_real_faccessat  = (FAccessAtFn)zs_resolve_libc("faccessat");
    g_real_faccessat2 = (FAccessAt2Fn)zs_resolve_libc("faccessat2");
    g_real_fstatat    = (FStatAtFn)zs_resolve_libc("fstatat");
    g_real_statx      = (StatxFn)zs_resolve_libc("statx");
    g_real_prop_find  = (PropFindFn)zs_resolve_libc("__system_property_find");
    g_real_prop_get   = (PropGetFn)zs_resolve_libc("__system_property_get");
    g_real_syscall    = (SyscallFn)zs_resolve_libc("syscall");
    g_real_dlopen     = (DlopenFn)zs_resolve_libc("dlopen");
    g_real_android_dlopen_ext = (AndroidDlopenExtFn)zs_resolve_libc(
        "android_dlopen_ext");

    // Register the Tier B hooks into the DEFERRED registry. They are
    // promoted and walked only when a hide actually lands on the
    // fallback tier (hide_advanced_install_tier_b).
    hide_advanced_register_tier_b_hook("open",
        (void*)&zygisk_study_hook_open);
    hide_advanced_register_tier_b_hook("openat",
        (void*)&zygisk_study_hook_openat);
    hide_advanced_register_tier_b_hook("__open_2",
        (void*)&zygisk_study_hook___open_2);
    hide_advanced_register_tier_b_hook("__openat_2",
        (void*)&zygisk_study_hook___openat_2);
    hide_advanced_register_tier_b_hook("fopen",
        (void*)&zygisk_study_hook_fopen);
    hide_advanced_register_tier_b_hook("stat",
        (void*)&zygisk_study_hook_stat);
    hide_advanced_register_tier_b_hook("lstat",
        (void*)&zygisk_study_hook_lstat);
    hide_advanced_register_tier_b_hook("access",
        (void*)&zygisk_study_hook_access);
    hide_advanced_register_tier_b_hook("faccessat",
        (void*)&zygisk_study_hook_faccessat);
    hide_advanced_register_tier_b_hook("faccessat2",
        (void*)&zygisk_study_hook_faccessat2);
    hide_advanced_register_tier_b_hook("fstatat",
        (void*)&zygisk_study_hook_fstatat);
    hide_advanced_register_tier_b_hook("fstatat64",
        (void*)&zygisk_study_hook_fstatat);
    hide_advanced_register_tier_b_hook("__fstatat",
        (void*)&zygisk_study_hook_fstatat);
    hide_advanced_register_tier_b_hook("statx",
        (void*)&zygisk_study_hook_statx);
    hide_advanced_register_tier_b_hook("__system_property_find",
        (void*)&zygisk_study_hook_prop_find);
    hide_advanced_register_tier_b_hook("__system_property_get",
        (void*)&zygisk_study_hook_prop_get);
    hide_advanced_register_tier_b_hook("syscall",
        (void*)&zygisk_study_hook_syscall);
    hide_advanced_register_tier_b_hook("dlopen",
        (void*)&zygisk_study_hook_dlopen);
    hide_advanced_register_tier_b_hook("android_dlopen_ext",
        (void*)&zygisk_study_hook_android_dlopen_ext);
}

void hide_advanced_install_tier_b() {
    // Promote every deferred hook into the live registry, flip the
    // per-process gate, then run the single walk. This runs in the
    // forked child we are hiding — no other process is affected.
    for (size_t i = 0; i < g_tier_b_hook_count; ++i) {
        hide_advanced_register_got_hook(g_tier_b_hooks[i].name,
                                        g_tier_b_hooks[i].fn);
    }
    hide_advanced_set_active(1);
    hide_advanced_install_got_hooks();
}

void hide_advanced_apply_post_fork(const char* /*package_name*/) {
    // Order (both tiers):
    //   1. Property clone + spoof — see clone_property_area_private
    //      for why this must preserve content.
    //   2. Close OUR fds (tracked) — never the runtime's.
    //   3. Env scrub.
    //
    // REMOVED in Round 7:
    //   - reset_signals(): ART installs the SIGSEGV/SIGBUS handlers for
    //     implicit null checks and stack-overflow detection in the
    //     zygote BEFORE forking. Resetting to SIG_DFL in the child
    //     turned every NullPointerException and every deep recursion
    //     into a hard crash. Nothing we install ever sets handlers,
    //     so there is nothing to reset anyway.
    //   - close_unknown_fds(): see close_tracked_fds().
    clone_property_area_private();
    close_tracked_fds();
    scrub_env();
}

} // namespace zygisk_study
