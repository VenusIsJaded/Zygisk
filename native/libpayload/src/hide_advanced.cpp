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
    // Round 8 (B10): ro.dalvik.vm.native.bridge IS "libzygisk.so" on
    // every process while we are loaded (post-fs-data.sh swaps it —
    // that is the injection mechanism). It is also the single most
    // greppable property in the entire design: every root-detection
    // writeup checks it. We are only ever loaded when the original
    // value was EMPTY (the swap is guarded), so a stock arm64 device
    // reports this property as absent — spoof it to empty + report
    // absence in the find()/get() hooks below, which is what the
    // property looked like before we touched the device.
    {"ro.dalvik.vm.native.bridge",   ""},
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
// Round 8 (B5): /proc/self/maps of the zygote can exceed the 96 KB
// static buffer on real devices (a zygote with the full preloaded
// class list carries ~1500 mappings ~= 110 KB). The single-read scan
// then silently missed property mappings past the cap and property
// spoofing quietly did NOTHING — a detection, not a failure. This
// chunked scan (8 KB chunk + carry) finds every mapping at any file
// size with bounded stack use.
static size_t find_prop_mappings_from_fd(int fd, PropMapping* out,
                                         size_t cap) {
    constexpr size_t kChunk = 8 * 1024;
    char buf[kChunk + 1024];
    size_t carry = 0;
    size_t n = 0;
    off_t off = 0;
    for (;;) {
        ssize_t r = pread(fd, buf + carry, kChunk, off);
        if (r <= 0) break;
        off += r;
        size_t have = carry + (size_t)r;

        // Only complete lines are scanned in this pass.
        size_t last_nl = 0;
        for (size_t i = have; i > 0; --i) {
            if (buf[i - 1] == '\n') { last_nl = i; break; }
        }
        if (last_nl == 0) {
            // No complete line in this chunk. Maps lines are < 512 B;
            // if a hostile "line" overflows the carry region, give up
            // gracefully with what we have.
            if (have >= sizeof buf) return n;
            carry = have;
            continue;
        }
        if (n < cap) {
            n += find_prop_mappings(buf, last_nl, out + n, cap - n);
        }
        memmove(buf, buf + last_nl, have - last_nl);
        carry = have - last_nl;
    }
    // Final unterminated line.
    if (carry > 0 && n < cap) {
        n += find_prop_mappings(buf, carry, out + n, cap - n);
    }
    return n;
}

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

// Defined with the property READ hooks in section 5c below; forward
// declaration because clone_property_area_private() calls it.
static void collect_absent_prop_infos();

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
    int truncated = 0;
    while ((size_t)total < kMapsCap) {
        ssize_t n = read(fd, maps_buf + total, kMapsCap - total);
        if (n <= 0) break;
        total += n;
    }
    if ((size_t)total == kMapsCap) {
        char probe;
        if (read(fd, &probe, 1) > 0) truncated = 1;
    }

    PropMapping mappings[32];
    size_t n_mappings;
    if (truncated) {
        // Round 8 (B5): maps larger than the static buffer. Rewind
        // and scan in chunks so property mappings past the cap are
        // still found (see find_prop_mappings_from_fd).
        if (lseek(fd, 0, SEEK_SET) != (off_t)-1) {
            n_mappings = find_prop_mappings_from_fd(fd, mappings, 32);
        } else {
            n_mappings = 0;
        }
    } else {
        n_mappings = total > 0
            ? find_prop_mappings(maps_buf, (size_t)total, mappings, 32)
            : 0;
    }
    close(fd);
    if (n_mappings == 0) return;
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
        // Round 9 (B2): record the clone addresses of every key we
        // spoof as absent so the read_callback/read/foreach hooks can
        // make them vanish even for callers that never call find().
        collect_absent_prop_infos();
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
// name; see zs_filter_kind_for_path for the /proc/self,
// /proc/thread-self, /proc/<pid>, /proc/<pid>/task/<tid>/ and
// /proc/net prefix handling.
static const char* const kFilteredBaseNames[] = {
    "maps",
    "mounts",
    "mountinfo",
    "mountstats",
    // status carries TracerPid (rewritten to 0 in the filtered copy).
    "status",
    "smaps",
    "smaps_rollup",
    // Round 8 (S2): the process environment. unsetenv() rewrites the
    // environ ARRAY, but /proc/self/environ is a window onto the
    // ORIGINAL stack env block — scrub_env() alone never cleaned it,
    // so our ZYGISK_STUDY_* variables stayed readable there forever.
    "environ",
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

// Round 13 — runtime hidden substrings for the unix-socket filter:
// the daemon's randomized per-boot socket directory. Registered at
// payload init (module_dispatch.cpp reads the session file).
static char g_rt_unix_subs[4][96];
static size_t g_rt_unix_sub_lens[4];
static int g_rt_unix_sub_count = 0;

void hide_advanced_register_unix_hidden_substring(const char* s) {
    if (!s || !*s) return;
    size_t n = strlen(s);
    if (n >= sizeof g_rt_unix_subs[0]) return;
    if (g_rt_unix_sub_count >= 4) return;
    memcpy(g_rt_unix_subs[g_rt_unix_sub_count], s, n + 1);
    g_rt_unix_sub_lens[g_rt_unix_sub_count] = n;
    ++g_rt_unix_sub_count;
}

// Round 8 (S1): /proc/net/unix is a GLOBAL socket table — every
// filesystem-path unix socket on the device appears there, including
// our daemon's socket (an app can read the file; perms do not help).
// We drop lines naming root-framework sockets. Bare "magisk"/
// "zygisk" matter here because socket names (abstract or path) are
// the actual thing detectors grep for.
static const HiddenSubstring kUnixHiddenSubstrings[] = {
    "/data/system/zygisk_study",
    "/data/adb/",
    "magisk",
    "zygisk",
    "riru",
};

// Environment entries we strip from /proc/self/environ (and scrub
// via unsetenv — see scrub_env()). Defined here, before the filter
// engine, because zs_filter_record() needs them.
static const char* const kOurEnvVars[] = {
    "ZYGISK_STUDY_DEBUG",
    "ZYGISK_STUDY_LOG_TAG",
    "ZYGISK_STUDY_WORKDIR",
};

// True if `rest` (the part after "/proc/") names a file we filter.
static int basename_is_filtered(const char* rest) {
    for (const char* b : kFilteredBaseNames) {
        if (strcmp(rest, b) == 0) return 1;
    }
    return 0;
}

// Parse the per-process / net / task prefix that may sit between
// "/proc/" and the base file name. On success sets *base to the base
// name and *is_net for /proc/net and /proc/<pid>/net forms, and
// returns 1. Returns 0 when the path does not name a per-process
// file at all (or names ANOTHER process — we never touch those).
//
// Round 8 fixes handled here:
//   B2: "/proc/mounts" (the classic alias of /proc/self/mounts) used
//       to fall through the old matcher — a detector could simply
//       read the mount table through it, unfiltered.
//   B3: "/proc/<pid>/task/<tid>/maps" and friends — per-thread
//       variants of every filtered file — bypassed the old matcher.
//   S1: "/proc/net/unix" and its /proc/self/net + /proc/<pid>/net
//       aliases (the daemon socket leak — see kUnixHiddenSubstrings).
static int parse_proc_prefix(const char* rest, const char** base,
                             int* is_net) {
    *is_net = 0;
    if (strncmp(rest, "thread-self/", 12) == 0) {
        rest += 12;
    } else if (strncmp(rest, "self/", 5) == 0) {
        rest += 5;
    } else if (strncmp(rest, "net/", 4) == 0) {
        rest += 4;
        *is_net = 1;               // the global /proc/net form
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
    // Second-level net/: /proc/self/net/<f>, /proc/<pid>/net/<f>.
    if (!*is_net && strncmp(rest, "net/", 4) == 0) {
        rest += 4;
        *is_net = 1;
    }
    // Optional per-thread component: task/<tid>/.
    if (strncmp(rest, "task/", 5) == 0) {
        rest += 5;
        const char* p = rest;
        while (*p >= '0' && *p <= '9') ++p;
        if (ZS_UNLIKELY(p == rest || *p != '/')) return 0;
        rest = p + 1;
    }
    *base = rest;
    return 1;
}

ZsFilterKind zs_filter_kind_for_path(const char* path) {
    if (ZS_UNLIKELY(!path)) return ZS_FILTER_NONE;
    // Round 10 (ASan): strncmp, NOT memcmp. A caller can hand us a
    // path SHORTER than 6 bytes ("" from a miscomputed buffer, "/" ,
    // ...); memcmp(path, "/proc/", 6) then reads past the caller's
    // buffer — harmless 99.999% of the time and a SIGSEGV in the
    // open() hot path the day a short path lands at the end of a
    // page. strncmp stops at either string's NUL, so a 1-byte path
    // reads exactly 1 byte. (Found by the ASan run, reproduced by
    // the documented-paths test feeding "" through the matcher.)
    if (strncmp(path, "/proc/", 6) != 0) return ZS_FILTER_NONE;
    const char* rest = path + 6;

    const char* base = nullptr;
    int is_net = 0;
    if (!parse_proc_prefix(rest, &base, &is_net)) {
        // "/proc/mounts" — the historical alias for
        // /proc/self/mounts and the single most common way code reads
        // the mount table. It names OUR process by definition.
        if (strcmp(path, "/proc/mounts") == 0) {
            return ZS_FILTER_PROC_LINE;
        }
        return ZS_FILTER_NONE;
    }
    if (is_net) {
        // Only the unix socket table is filtered; /proc/net/tcp etc.
        // carry no path information about us.
        return strcmp(base, "unix") == 0 ? ZS_FILTER_NET_UNIX
                                          : ZS_FILTER_NONE;
    }
    if (strcmp(base, "status") == 0)   return ZS_FILTER_STATUS;
    if (strcmp(base, "environ") == 0)  return ZS_FILTER_ENVIRON;
    if (basename_is_filtered(base))     return ZS_FILTER_PROC_LINE;
    return ZS_FILTER_NONE;
}

int zs_path_is_filtered(const char* path) {
    return zs_filter_kind_for_path(path) != ZS_FILTER_NONE;
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

// Round 8: the record filter. One record = one line (newline-
// separated kinds) or one env entry (NUL-separated environ). Pure,
// allocation-free, and unit-tested directly (host tests).
//
// Returns the kept length written to dst (dst may alias rec — the
// streaming loop compacts in place), or -1 to drop the record.
ssize_t zs_filter_record(char* dst, size_t dst_cap,
                         const char* rec, size_t rec_len,
                         ZsFilterKind kind) {
    if (ZS_UNLIKELY(!rec && rec_len > 0)) return -1;

    switch (kind) {
    case ZS_FILTER_STATUS: {
        // Rewrite the TracerPid line to 0; pass everything else
        // through byte-for-byte.
        static const char kPrefix[] = "TracerPid:";
        constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
        static const char kReplacement[] = "TracerPid:\t0";
        constexpr size_t kReplacementLen = sizeof(kReplacement) - 1;
        if (rec_len >= kPrefixLen &&
            memcmp(rec, kPrefix, kPrefixLen) == 0) {
            // Only rewrite in place when the replacement provably fits
            // (real TracerPid lines are >= 13 bytes; a hand-crafted
            // shorter one is passed through unchanged).
            if (kReplacementLen > rec_len || dst_cap < kReplacementLen) {
                break;   // keep the original record
            }
            memcpy(dst, kReplacement, kReplacementLen);
            return (ssize_t)kReplacementLen;
        }
        break;
    }
    case ZS_FILTER_ENVIRON: {
        // Drop entries that belong to us. unsetenv() only rewrites
        // the environ ARRAY — /proc/self/environ keeps serving the
        // ORIGINAL stack block, so this is the only place the
        // ZYGISK_STUDY_* variables actually disappear from.
        for (const char* v : kOurEnvVars) {
            size_t n = __builtin_strlen(v);
            if (rec_len > n && memcmp(rec, v, n) == 0 && rec[n] == '=') {
                return -1;
            }
        }
        break;
    }
    case ZS_FILTER_NET_UNIX: {
        // Whole-line scan: socket names, not path fields, are what
        // carries the signal here.
        for (const HiddenSubstring& sub : kUnixHiddenSubstrings) {
            if (sub.len == 0 || sub.len > rec_len) continue;
            if (memmem(rec, rec_len, sub.data, sub.len)) return -1;
        }
        for (int i = 0; i < g_rt_unix_sub_count; ++i) {
            if (g_rt_unix_sub_lens[i] == 0 ||
                g_rt_unix_sub_lens[i] > rec_len) continue;
            if (memmem(rec, rec_len, g_rt_unix_subs[i],
                       g_rt_unix_sub_lens[i])) return -1;
        }
        break;
    }
    case ZS_FILTER_PROC_LINE:
    default: {
        // Find the path field (after the 5th whitespace run) and
        // search the hidden substrings only within it (P1.39/P1.40
        // history: compile-time lengths + branch hints).
        const char* p = rec;
        const char* rec_end = rec + rec_len;
        const char* path_field = nullptr;
        int col = 0;
        while (p < rec_end) {
            char c = *p;
            if (c == ' ' || c == '\t') {
                while (p < rec_end && (*p == ' ' || *p == '\t')) ++p;
                ++col;
                if (col == 5) { path_field = p; break; }
            } else {
                ++p;
            }
        }
        if (path_field && path_field < rec_end) {
            size_t path_len = (size_t)(rec_end - path_field);
            for (const HiddenSubstring& sub : kHiddenSubstrings) {
                if (sub.len == 0 || sub.len > path_len) continue;
                if (memmem(path_field, path_len, sub.data, sub.len)) {
                    return -1;
                }
            }
        }
        break;
    }
    }

    if (dst != rec) {
        if (dst_cap < rec_len) return -1;
        memmove(dst, rec, rec_len);
    }
    return (ssize_t)rec_len;
}

// Produce a filtered copy of the given file's contents in a memfd.
// Returns the memfd fd, or -1 on error.
//
// Round 8 (B4): this is now a STREAMING filter. The Round 7 version
// read up to 256 KB and silently DROPPED everything beyond — and
// /proc/self/smaps of a real app process runs 1-3 MB (about 30 lines
// per mapping x thousands of mappings). A truncated smaps meant
// missing mappings in the output AND, for maps, potentially our own
// .so entries sitting in the dropped tail. We now filter in 64 KB
// chunks with a carry buffer, so the output is correct at any size
// with bounded memory.
//
// PERF/SAFETY: the scratch is a heap mmap, never a stack array —
// this runs inside an open() hook on whatever app thread performed
// the open, including deep ART call stacks on threads with 1 MB
// stacks. See the TLS scratch notes below for why it is allocated
// once per thread rather than per call.
// Round 9 (P1): the 64 KB scratch is now a lazily-allocated
// THREAD-LOCAL buffer instead of a per-call mmap/munmap pair. Every
// filtered /proc read used to pay two syscalls PLUS the cost of
// zeroing 16 fresh anonymous pages (mmap always zeroes) — in a
// hidden app, every open() of maps/smaps/mounts/status/environ paid
// it, on every thread that touched one. The TLS buffer is allocated
// once per filtering thread and reused for the process lifetime.
//
// Memory bound: 64 KB x (threads that filter /proc files) — a few
// dozen at worst, and the alternative (per-call 64 KB zeroing) cost
// more in raw page-touch time than this costs in RSS.
//
// Unloading: Tier A unmaps only exec/writable SELF segments and no
// hook of ours can run afterwards, so nothing ever dereferences this
// pointer post-unmap; Tier B keeps the payload mapped. The buffer
// itself is a plain libc mmap, not part of our image.
static thread_local char* tls_filter_scratch = nullptr;
static std::atomic<int> g_filter_scratch_allocs{0};

static char* zs_filter_scratch_acquire(size_t size) {
    if (ZS_LIKELY(tls_filter_scratch != nullptr)) return tls_filter_scratch;
    char* p = (char*)mmap(nullptr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return nullptr;
    tls_filter_scratch = p;
    g_filter_scratch_allocs.fetch_add(1, std::memory_order_relaxed);
    return p;
}

static int make_filtered_memfd(int orig_fd, const char* target_path) {
    ZsFilterKind kind = zs_filter_kind_for_path(target_path ? target_path
                                                            : "");
    if (kind == ZS_FILTER_NONE) kind = ZS_FILTER_PROC_LINE;

    int memfd = syscall_memfd_create("scudo", 0);
    if (memfd < 0) return -1;

    constexpr size_t kChunk = 64 * 1024;
    char* buf = zs_filter_scratch_acquire(kChunk);
    if (!buf) {
        close(memfd);
        return -1;
    }

    const char sep = (kind == ZS_FILTER_ENVIRON) ? '\0' : '\n';
    size_t carry = 0;      // unterminated record bytes at buf[0..carry)
    size_t file_off = 0;   // pread offset into orig_fd
    int ok = 1;

    for (;;) {
        ssize_t n = pread(orig_fd, buf + carry, kChunk - carry,
                          (off_t)file_off);
        if (n <= 0) break;
        file_off += (size_t)n;
        size_t have = carry + (size_t)n;

        // Locate the LAST separator in the buffer; everything after
        // it is a partial record carried into the next iteration.
        size_t last_sep = (size_t)-1;
        for (size_t i = have; i > 0; --i) {
            if (buf[i - 1] == sep) { last_sep = i - 1; break; }
        }
        if (last_sep == (size_t)-1) {
            // No complete record in this chunk (a >64 KB single line
            // does not occur in any filtered /proc file; if a hostile
            // source produces one, drop it rather than stall).
            if (have >= kChunk - 1) {
                ZS_LOGW("hide_advanced: oversized record (%zu B) in "
                        "filtered /proc file; dropping it", have);
                carry = 0;
            } else {
                carry = have;
            }
            continue;
        }

        // In-place compaction of complete records. The record that
        // ENDS at the last separator is included: memchr's range must
        // reach last_sep itself, and the loop must run while
        // rec_start <= last_sep (an empty final record is a blank
        // line — preserved, like the Round 7 filter did).
        size_t write_ptr = 0;
        size_t rec_start = 0;
        while (rec_start <= last_sep) {
            char* sep_pos = (char*)memchr(buf + rec_start, sep,
                                          last_sep - rec_start + 1);
            if (!sep_pos) break;   // cannot happen; paranoia
            size_t rec_len = (size_t)(sep_pos - (buf + rec_start));
            ssize_t kept = zs_filter_record(buf + write_ptr,
                                            kChunk - write_ptr,
                                            buf + rec_start, rec_len,
                                            kind);
            if (kept >= 0) {
                write_ptr += (size_t)kept;
                buf[write_ptr++] = sep;   // re-emit the separator
            }
            rec_start = (size_t)(sep_pos - buf) + 1;
        }
        if (write_ptr > 0) {
            if (write(memfd, buf, write_ptr) != (ssize_t)write_ptr) {
                ok = 0;
                break;
            }
        }
        // Carry the trailing partial record to the front.
        size_t consumed = last_sep + 1;
        memmove(buf, buf + consumed, have - consumed);
        carry = have - consumed;
    }

    // Final record without a trailing separator (EOF mid-record).
    if (ok && carry > 0) {
        ssize_t kept = zs_filter_record(buf, carry, buf, carry, kind);
        if (kept > 0 && write(memfd, buf, (size_t)kept) != kept) {
            ok = 0;
        }
    }

    // Round 9 (P1): no munmap — the scratch is thread-local and
    // reused by this thread's next filtered /proc read.
    if (!ok) {
        close(memfd);
        return -1;
    }
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
    // Round 11: an ABSOLUTE path ignores dirfd (POSIX), so the filter
    // decision must not depend on dirfd either — the old
    // `dirfd != AT_FDCWD` passthrough let a detector bypass the
    // filter by passing any arbitrary fd with an absolute /proc
    // path. Relative paths still pass through untouched (we lack
    // the context to resolve them). The real openat below receives
    // the caller's dirfd unchanged, which preserves exact semantics.
    if (ZS_UNLIKELY(!path || path[0] != '/')) {
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

// Round 8 (B8): call the REAL fopen, with an open()+fdopen() fallback
// for the (unusual) case where dlsym could not resolve fopen — the
// old code returned nullptr for EVERY file in that situation, which
// breaks far more than it hides.
static FILE* zs_real_fopen(const char* path, const char* mode) {
    if (g_real_fopen) return g_real_fopen(path, mode);
    if (!path || !mode) { errno = EINVAL; return nullptr; }
    int flags = O_RDONLY;
    if (strchr(mode, 'w'))      flags = O_WRONLY | O_CREAT | O_TRUNC;
    else if (strchr(mode, 'a')) flags = O_WRONLY | O_CREAT | O_APPEND;
    else if (strchr(mode, '+')) flags = O_RDWR;
    int fd = g_real_open
        ? g_real_open(path, flags | O_CLOEXEC, 0666)
        : (int)syscall(SYS_openat, AT_FDCWD, path, flags | O_CLOEXEC,
                       0666);
    if (fd < 0) return nullptr;
    FILE* f = fdopen(fd, mode);
    if (!f) close(fd);
    return f;
}

extern "C" FILE* zygisk_study_hook_fopen(const char* path,
                                         const char* mode) {
    if (ZS_UNLIKELY(!hide_advanced_is_active()) || !path || !mode) {
        return zs_real_fopen(path, mode);
    }
    // Never intercept write/append modes (and path_is_filtered only
    // ever matches /proc reads anyway).
    if (strchr(mode, 'w') || strchr(mode, 'a') ||
        !zs_path_is_filtered(path)) {
        return zs_real_fopen(path, mode);
    }
    FILE* f = zs_real_fopen(path, mode);
    if (!f) return f;
    int fd = fileno(f);
    int memfd = make_filtered_memfd(fd, path);
    fclose(f);
    if (memfd < 0) { errno = EBADF; return nullptr; }
    FILE* rf = fdopen(memfd, "r");
    if (!rf) close(memfd);
    return rf;
}

// Round 11 (S3): freopen(). The one stdio entry point that still
// bypassed every filter — freopen("/proc/self/maps", "r", stdout)
// rebinds an EXISTING FILE to the raw procfs file with no open()/
// fopen() call ever happening through the GOT. Implementation uses
// the same wrapped_open (which returns the filtered memfd), then
// rebinds the caller's stream to the memfd via its /proc/self/fd
// link — which our own hooks deliberately do NOT filter (only
// /proc/{self,<pid>}/{maps,mounts,...} basename files match). Our
// scratch fd is closed after the rebind: real freopen opened its
// OWN descriptor for the memfd, and fclose(stream) will close that
// one, never ours.
using FreopenFn = FILE* (*)(const char*, const char*, FILE*);
static FreopenFn g_real_freopen = nullptr;

extern "C" FILE* zygisk_study_hook_freopen(const char* path,
                                           const char* mode, FILE* stream) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !path || !mode ||
        strchr(mode, 'w') || strchr(mode, 'a') ||
        path[0] != '/' || !zs_path_is_filtered(path)) {
        return g_real_freopen ? g_real_freopen(path, mode, stream)
                              : nullptr;
    }
    int fd = wrapped_open(path, O_RDONLY, 0);
    if (fd < 0) {
        // Fall back to the unfiltered real call — a failed filter
        // must never break the caller's semantics.
        return g_real_freopen ? g_real_freopen(path, mode, stream)
                              : nullptr;
    }
    char fdpath[64];
    int n = snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
    FILE* out = nullptr;
    if (n > 0 && (size_t)n < sizeof fdpath && g_real_freopen) {
        out = g_real_freopen(fdpath, mode, stream);
    }
    close(fd);
    return out;
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
    // Round 11: absolute path → dirfd is irrelevant (POSIX) → the
    // filter applies. (Was: `dirfd != AT_FDCWD` bypass.)
    if (path[0] != '/') {
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
//
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
// Round 9 (B2): the enumeration path. __system_property_foreach()
// hands the caller a prop_info* for EVERY key in the area; the
// modern read API is __system_property_read_callback (get() is
// implemented on top of it since Android O), and __system_property_read
// is the legacy variant. Without hooks here, a detector could
// enumerate all properties and read each one directly from the
// (patched-value) clone — seeing every absent-spoofed key EXIST with
// an empty value, which no stock device shows.
using PropReadCbFn = void (*)(const void*,
                              void (*)(void*, const char*, const char*,
                                       uint32_t),
                              void*);
using PropReadFn    = int (*)(const void*, char*);
using PropForeachFn = int (*)(void (*)(const void*, void*), void*);
static PropReadCbFn g_real_prop_read_cb = nullptr;
static PropReadFn   g_real_prop_read    = nullptr;
static PropForeachFn g_real_prop_foreach = nullptr;

static PropFindFn g_real_prop_find = nullptr;
static PropGetFn  g_real_prop_get  = nullptr;

// prop_info addresses (inside our private clone) of every key we
// spoof as ABSENT. Collected by clone_property_area_private() right
// after the values are patched — the trie walk finds the addresses
// in the clone, which is what any later read sees. Bounded at the
// spoof table size; if the table grows past this, extras fall back
// to the clone-only behavior (documented residual, tested).
static const void* g_absent_prop_infos[32];
static size_t      g_absent_prop_count = 0;

static int prop_key_is_absent(const char* key) {
    if (!key) return 0;
    for (const ZsPropSpoof& s : kPropSpoofTable) {
        if (s.value == nullptr || s.value[0] == '\0') {
            if (strcmp(key, s.key) == 0) return 1;
        }
    }
    return 0;
}

// Is this prop_info one of the absent-spoof keys? Address identity
// is the only portable test: the public prop_info struct layout
// varies per Android release, but the pointer values are what
// foreach/read_callback hand the caller.
static int prop_pi_is_absent(const void* pi) {
    if (!pi) return 0;
    for (size_t i = 0; i < g_absent_prop_count; ++i) {
        if (g_absent_prop_infos[i] == pi) return 1;
    }
    return 0;
}

// collect_absent_prop_infos() is called from
// clone_property_area_private() once the clone (with patched values)
// is live at the original addresses.
static void collect_absent_prop_infos() {
    if (!g_find_prop) return;
    g_absent_prop_count = 0;
    for (const ZsPropSpoof& s : kPropSpoofTable) {
        if (s.value != nullptr && s.value[0] != '\0') continue;
        const void* pi = g_find_prop(s.key);
        if (pi && g_absent_prop_count <
                      sizeof(g_absent_prop_infos) / sizeof(void*)) {
            g_absent_prop_infos[g_absent_prop_count++] = pi;
        }
    }
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

// Round 9 (B2): read_callback for an absent key must not invoke the
// caller's callback at all — calling it with an empty value is
// exactly the "present but empty" anomaly only hiding creates. This
// matters even for callers that never touched find(): any prop_info
// pointer obtained from foreach() or cached before we hid resolves
// into the clone, so the address test still sees the spoof.
extern "C" void zygisk_study_hook_prop_read_callback(
    const void* pi, void (*cb)(void*, const char*, const char*, uint32_t),
    void* cookie) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !prop_pi_is_absent(pi)) {
        if (g_real_prop_read_cb) g_real_prop_read_cb(pi, cb, cookie);
        return;  // no real symbol on host: no-op
    }
    // Absent key: swallow the read entirely.
}

// Legacy __system_property_read (same treatment as read_callback).
extern "C" int zygisk_study_hook_prop_read(const void* pi, char* value) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !prop_pi_is_absent(pi)) {
        return g_real_prop_read ? g_real_prop_read(pi, value) : 0;
    }
    if (value) value[0] = '\0';
    return 0;
}

// __system_property_foreach: run the REAL enumeration with a
// trampoline callback that drops absent keys before the caller ever
// sees them. Value-spoofed keys pass through: the clone already
// holds the patched values, which is what the caller's own
// read_callback will read.
namespace {
struct ForeachCtx {
    void (*user_cb)(const void*, void*);
    void* user_cookie;
};
} // namespace
static void zs_foreach_trampoline(const void* pi, void* cookie) {
    ForeachCtx* ctx = static_cast<ForeachCtx*>(cookie);
    if (prop_pi_is_absent(pi)) return;  // key vanishes from enumeration
    ctx->user_cb(pi, ctx->user_cookie);
}

extern "C" int zygisk_study_hook_prop_foreach(
    void (*cb)(const void*, void*), void* cookie) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !cb) {
        return g_real_prop_foreach ? g_real_prop_foreach(cb, cookie) : -1;
    }
    ForeachCtx ctx{cb, cookie};
    return g_real_prop_foreach ? g_real_prop_foreach(&zs_foreach_trampoline,
                                                     &ctx)
                               : -1;
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
    // Extract ALL SIX syscall arguments up front. The Round 7 version
    // forwarded only four: any caller invoking a 5- or 6-argument
    // syscall through the libc wrapper (pselect6, epoll_pwait2,
    // clone, splice, sync_file_range, ...) had arguments 5 and 6
    // silently replaced with garbage. In a hidden app that meant
    // sporadic, impossible-to-debug breakage in exactly the kind of
    // low-level code that also uses raw syscalls to probe us.
    va_list ap;
    va_start(ap, number);
    long a[6];
    for (int i = 0; i < 6; ++i) a[i] = va_arg(ap, long);
    va_end(ap);

    if (ZS_UNLIKELY(!hide_advanced_is_active())) {
        return g_real_syscall
            ? g_real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5])
            : -ENOSYS;
    }

#ifdef SYS_openat
    if (number == (long)SYS_openat) {
        const char* path = (const char*)a[1];
        // Round 11: an ABSOLUTE path ignores dirfd (POSIX), so the
        // filter must apply regardless of what the caller passed in
        // a[0]. The old AT_FDCWD requirement meant a detector could
        // bypass the filter entirely by handing any arbitrary fd to
        // openat() with an absolute /proc path. Relative paths still
        // pass through untouched (we cannot cheaply resolve them).
        if (path && path[0] == '/' && zs_path_is_filtered(path)) {
            int flags = (int)a[2];
            mode_t mode = (flags & O_CREAT) ? (mode_t)a[3] : 0;
            return wrapped_openat((int)a[0], path, flags, mode);
        }
    }
#endif
#ifdef SYS_open
    if (number == (long)SYS_open) {
        const char* path = (const char*)a[0];
        if (path && zs_path_is_filtered(path)) {
            int flags = (int)a[1];
            mode_t mode = (flags & O_CREAT) ? (mode_t)a[2] : 0;
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
        const char* path = (const char*)a[1];
        if (path && path[0] == '/' && path_is_hidden(path)) {
            errno = ENOENT;
            return -1;
        }
    }
#if defined(SYS_newfstatat)
    if (number == (long)SYS_newfstatat) {
        const char* path = (const char*)a[1];
        if (path && path[0] == '/' && path_is_hidden(path)) {
            errno = ENOENT;
            return -1;
        }
    }
#endif
    // Not ours — pass every argument through untouched.
    return g_real_syscall
        ? g_real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5])
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

// ---- Round 8 (P1): hash index over the live registry ----
// The Round 7 matcher was a linear scan with a first-char gate. That
// is fine for the 5 zygote-time hooks, but Tier B promotes ~24 hooks
// and the walk then runs over every JMPREL entry of every loaded DSO
// (tens of thousands of entries in a real app) — per hidden app
// launch. The index below (FNV-1a, open addressing, names kept for
// verification) turns the per-entry cost into one hash + one strcmp.
constexpr size_t kHookIndexCap = 128;   // power of two > kMaxGotHooks
static uint32_t    g_hook_idx_hash[kHookIndexCap];
static void*       g_hook_idx_fn[kHookIndexCap];
static const char* g_hook_idx_name[kHookIndexCap];
static int         g_hook_idx_dirty = 1;

static uint32_t zs_fnv1a(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (uint32_t)(uint8_t)*s++; h *= 16777619u; }
    return h;
}

static void zs_rebuild_hook_index() {
    memset(g_hook_idx_hash, 0, sizeof g_hook_idx_hash);
    memset(g_hook_idx_fn,   0, sizeof g_hook_idx_fn);
    memset(g_hook_idx_name, 0, sizeof g_hook_idx_name);
    for (size_t i = 0; i < g_got_hook_count; ++i) {
        uint32_t h = zs_fnv1a(g_got_hooks[i].name);
        if (h == 0) h = 1;   // 0 marks an empty slot
        size_t idx = h & (kHookIndexCap - 1);
        while (g_hook_idx_fn[idx]) idx = (idx + 1) & (kHookIndexCap - 1);
        g_hook_idx_hash[idx] = h;
        g_hook_idx_fn[idx]   = g_got_hooks[i].fn;
        g_hook_idx_name[idx] = g_got_hooks[i].name;
    }
    g_hook_idx_dirty = 0;
}

// ---- Round 8 (P4): the walked-DSO mark set ----
// See the dlopen hook comment. Cleared whenever the registry changes
// (so the next install_got_hooks() is a full walk) and garbage-
// collected after every successful dlclose.
constexpr size_t kMaxWalkedDsos = 512;
static uintptr_t g_walked_dsos[kMaxWalkedDsos];
static size_t    g_walked_dso_count = 0;

static void clear_walked_dsos() { g_walked_dso_count = 0; }

static int dso_already_walked(uintptr_t addr) {
    for (size_t i = 0; i < g_walked_dso_count; ++i) {
        if (g_walked_dsos[i] == addr) return 1;
    }
    return 0;
}

static void mark_dso_walked(uintptr_t addr) {
    if (g_walked_dso_count < kMaxWalkedDsos) {
        g_walked_dsos[g_walked_dso_count++] = addr;
    }
    // Overflow (a process with > 512 DSOs): stop marking. Later
    // re-walks then re-examine everything — correct, just slower.
}

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
    // Registry mutation: the hash index and the walked-DSO set are
    // both stale now (a DSO marked "walked" under the OLD hook set
    // must be re-walked for the new hooks).
    g_hook_idx_dirty = 1;
    clear_walked_dsos();
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

// Resolve a registered hook by symbol name. Hash-indexed since
// Round 8 (P1); the name is still verified with strcmp so a hash
// collision can never patch the wrong function.
// Only the LIVE registry is consulted: deferred Tier B entries are
// invisible until hide_advanced_install_tier_b() promotes them,
// which happens before the walk runs — so the walker never misses
// anything and non-hidden processes provably carry no Tier B hooks.
static void* match_registered_hook(const char* name) {
    if (ZS_UNLIKELY(g_hook_idx_dirty)) zs_rebuild_hook_index();
    uint32_t h = zs_fnv1a(name);
    if (h == 0) h = 1;
    size_t idx = h & (kHookIndexCap - 1);
    while (g_hook_idx_fn[idx]) {
        if (g_hook_idx_hash[idx] == h &&
            strcmp(name, g_hook_idx_name[idx]) == 0) {
            return g_hook_idx_fn[idx];
        }
        idx = (idx + 1) & (kHookIndexCap - 1);
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

    // Round 8 (P4): skip DSOs this walk has already processed. The
    // set is cleared when the registry changes and garbage-collected
    // after a dlclose, so this can never skip a DSO that still needs
    // (re-)patching — see the dlopen hook comment.
    if (dso_already_walked(info->dlpi_addr)) return 0;
    mark_dso_walked(info->dlpi_addr);

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
    // Full walk: clear the mark set so every DSO is re-examined
    // (callers of this function just changed — or may have changed —
    // the live registry; incremental re-walks happen in the dlopen
    // hooks instead).
    clear_walked_dsos();
    g_hook_idx_dirty = 1;   // pick up registry mutations
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
// dlopen / dlclose hooks (Tier B): patch libs the app loads later
// ------------------------------------------------------------------------

// In Tier B the payload stays resident, and apps load their detector
// .so files via System.loadLibrary AFTER our hide-time walk. The
// freshly loaded library's GOT is pristine, so its open()/stat()
// calls bypass every hook. Hooking dlopen/android_dlopen_ext and
// re-running the walk after each load closes that window.
//
// Round 8 (P4): the re-walk is now INCREMENTAL. The walker marks every
// DSO it has processed (by load address); a re-walk after a dlopen
// only examines DSOs not seen before (the new library + any of its
// dependencies that were loaded with it). The mark set is cleared
// whenever the live registry changes (a re-walk is then a full walk)
// and garbage-collected after every successful dlclose — a library
// that is unloaded and later re-dlopen'd AT THE SAME ADDRESS must not
// be skipped as "already walked".
using DlopenFn = void* (*)(const char*, int);
static DlopenFn g_real_dlopen = nullptr;

extern "C" void* zygisk_study_hook_dlopen(const char* path, int flags) {
    void* h = g_real_dlopen ? g_real_dlopen(path, flags) : nullptr;
    if (h && hide_advanced_is_active()) {
        // Incremental re-walk: patches the newly loaded module's GOT
        // (and anything else loaded alongside it).
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

using DlcloseFn = int (*)(void*);
static DlcloseFn g_real_dlclose = nullptr;

// Collect the load addresses of every currently loaded DSO (used to
// garbage-collect the walked-DSO mark set after a dlclose).
static uintptr_t g_live_dso_addrs[512];
static size_t    g_live_dso_count = 0;
static int gc_collect_live_cb(struct dl_phdr_info* info, size_t,
                              void*) {
    if (info && g_live_dso_count <
                sizeof(g_live_dso_addrs) / sizeof(g_live_dso_addrs[0])) {
        g_live_dso_addrs[g_live_dso_count++] = info->dlpi_addr;
    }
    return 0;
}

static void gc_walked_dso_set() {
    g_live_dso_count = 0;
    dl_iterate_phdr(gc_collect_live_cb, nullptr);   // cheap: no GOT work
    size_t kept = 0;
    for (size_t i = 0; i < g_walked_dso_count; ++i) {
        uintptr_t addr = g_walked_dsos[i];
        int live = 0;
        for (size_t j = 0; j < g_live_dso_count; ++j) {
            if (g_live_dso_addrs[j] == addr) { live = 1; break; }
        }
        if (live) g_walked_dsos[kept++] = addr;
    }
    g_walked_dso_count = kept;
}

extern "C" int zygisk_study_hook_dlclose(void* handle) {
    if (!g_real_dlclose) {
        g_real_dlclose = (DlcloseFn)zs_resolve_libc("dlclose");
    }
    if (!g_real_dlclose) return -1;
    int rv = g_real_dlclose(handle);
    if (rv == 0 && hide_advanced_is_active()) {
        gc_walked_dso_set();
    }
    return rv;
}

// ------------------------------------------------------------------------
// opendir hook (Tier B) — Round 8 (S3)
// ------------------------------------------------------------------------

// stat()/access() report ENOENT for hidden paths, but a detector can
// simply opendir("/data/adb") and readdir() the entries — directory
// contents were never gated. Java's File.list() goes through
// libjavacore's opendir import, so the GOT patch covers it; native
// detectors calling opendir directly are covered too. (scandir()
// uses libc-internal opendir and is NOT covered — documented residual
// in docs/ANDROID-REALISM.md.)
using OpendirFn = DIR* (*)(const char*);
static OpendirFn g_real_opendir = nullptr;

extern "C" DIR* zygisk_study_hook_opendir(const char* name) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !name ||
        !(name[0] == '/' && path_is_hidden(name))) {
        if (g_real_opendir) return g_real_opendir(name);
        // Fallback when dlsym failed: openat + fdopendir.
        int fd = (int)syscall(SYS_openat, AT_FDCWD, name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) return nullptr;
        DIR* d = fdopendir(fd);
        if (!d) close(fd);
        return d;
    }
    errno = ENOENT;
    return nullptr;
}

// ------------------------------------------------------------------------
// scandir / scandirat hooks (Tier B) — Round 9 (S1)
// ------------------------------------------------------------------------
//
// scandir() walks the directory with libc-INTERNAL opendir/readdir
// calls, so the opendir GOT hook never sees it (documented Round 8
// residual — closed here). Detector-friendly directories ("/",
// "/data") are not themselves hidden, so the DIRECTORY-level ENOENT
// rewrite is not enough: the ENTRY list must drop every name that
// matches a root-framework artifact.
//
// Implementation: run the real scandir (with the caller's own filter
// and comparator), then compact the resulting list in place, freeing
// every hidden entry. No globals, so concurrent scandirs on different
// app threads are safe; entries that survive are untouched (and
// still owned by the caller to free as usual).
//
// The name list is deliberately TIGHT: entry-name filtering happens
// in directories that are NOT hidden themselves, so a false positive
// hides a legitimate app file. Exact matches of framework binaries
// and our own artifacts only; everything else stays visible.

static const char* const kHiddenDirentNames[] = {
    "magisk", "magisk32", "magisk64", "magiskinit", "magiskboot",
    ".magisk",
    "ksu", "zygiskd",
    "zygisk_study",
    "libzygisk.so", "libpayload.so", "libzn_loader.so",
};

static int zs_dirent_name_is_hidden(const char* name) {
    if (!name) return 0;
    for (const char* h : kHiddenDirentNames) {
        if (strcmp(name, h) == 0) return 1;
    }
    return 0;
}

using ScandirFn = int (*)(const char*, struct dirent***,
                          int (*)(const struct dirent*),
                          int (*)(const struct dirent**,
                                  const struct dirent**));
using ScandiratFn = int (*)(int, const char*, struct dirent***,
                            int (*)(const struct dirent*),
                            int (*)(const struct dirent**,
                                    const struct dirent**));
static ScandirFn   g_real_scandir = nullptr;
static ScandiratFn g_real_scandirat = nullptr;

// Shared post-filter for both scandir variants: compacts namelist in
// place and returns the new count. Frees the dropped entries exactly
// like a caller looping over the list would, so there is no leak and
// no double-free contract change.
static int zs_scandir_postfilter(struct dirent*** namelist, int n) {
    if (n <= 0 || !namelist || !*namelist) return n;
    struct dirent** list = *namelist;
    int w = 0;
    for (int i = 0; i < n; ++i) {
        if (zs_dirent_name_is_hidden(list[i]->d_name)) {
            free(list[i]);
            continue;
        }
        list[w++] = list[i];
    }
    return w;
}

extern "C" int zygisk_study_hook_scandir(
    const char* dir, struct dirent*** namelist,
    int (*filter)(const struct dirent*),
    int (*compar)(const struct dirent**, const struct dirent**)) {
    if (!g_real_scandir) {
        errno = ENOSYS;
        return -1;
    }
    int n = g_real_scandir(dir, namelist, filter, compar);
    if (n <= 0) return n;
    // Same rewrite opendir() applies: a hidden directory "does not
    // exist" rather than "permission denied".
    if (hide_advanced_is_active() && dir && dir[0] == '/' &&
        path_is_hidden(dir)) {
        for (int i = 0; i < n; ++i) free((*namelist)[i]);
        free(*namelist);
        *namelist = nullptr;
        errno = ENOENT;
        return -1;
    }
    if (hide_advanced_is_active()) {
        n = zs_scandir_postfilter(namelist, n);
    }
    return n;
}

extern "C" int zygisk_study_hook_scandirat(
    int dirfd, const char* dir, struct dirent*** namelist,
    int (*filter)(const struct dirent*),
    int (*compar)(const struct dirent**, const struct dirent**)) {
    if (!g_real_scandirat) {
        errno = ENOSYS;
        return -1;
    }
    int n = g_real_scandirat(dirfd, dir, namelist, filter, compar);
    if (n <= 0) return n;
    // Absolute paths get the full treatment; relative paths (relative
    // to an unknown dirfd) are only entry-filtered — resolving them
    // cheaply is not possible without /proc probing per call.
    if (hide_advanced_is_active() && dir && dir[0] == '/' &&
        path_is_hidden(dir)) {
        for (int i = 0; i < n; ++i) free((*namelist)[i]);
        free(*namelist);
        *namelist = nullptr;
        errno = ENOENT;
        return -1;
    }
    if (hide_advanced_is_active()) {
        n = zs_scandir_postfilter(namelist, n);
    }
    return n;
}

// ------------------------------------------------------------------------
// Leaked-fd closing by link target (Tier A + B) — Round 9 (S2)
// ------------------------------------------------------------------------
//
// close_tracked_fds() closes exactly the descriptors WE opened.
// But any OTHER descriptor whose /proc/self/fd/<n> link resolves
// into a root-framework path is equally a detection vector — and a
// better one than most, because readlink("/proc/self/fd/N") is a
// single cheap syscall that needs no directory listing. Sources of
// such fds: a Zygisk module that dlopen'd (open fd kept briefly),
// a module .so that leaked one at fork time, or a file under
// /data/adb opened before the child dropped privileges.
//
// The scan reads /proc/self/fd with raw getdents64 syscalls and
// resolves each link with the REAL readlink (resolved once, so it
// bypasses our own Tier B GOT rewrite of readlink — no recursion),
// then closes exactly the descriptors whose target is under a
// hidden prefix. GPU/graphics/ashmem fds point at /dev or memfd:
// names that never start with a root prefix, so they are untouched.
//
// ReZygisk solves the general case with an fd allow-list snapshot
// taken at pre-fork and closes everything else; we deliberately do
// NOT — closing descriptors the runtime owns (the exact bug Round 7
// fixed) is a crash class, while a /data/adb link target is purely
// ours to remove.

using ReadlinkFn = ssize_t (*)(const char*, char*, size_t);
static ReadlinkFn g_real_readlink_for_fd_scan = nullptr;

// Raw getdents64 layout (neither glibc nor bionic headers expose it
// for direct syscall use). d_reclen advances the walk; d_name is the
// fd number string.
#pragma pack(push, 1)
struct zs_linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[256];
};
#pragma pack(pop)

// Root-path prefixes for the fd-link scan. File-scope (not a local
// constant) so host tests can point the scanner at a directory they
// can actually create — the getdents64 walk and readlink resolution
// then run for real against the host kernel. Slots 4..7 are runtime
// registrations (Round 13: the randomized daemon socket dir).
struct FdRootPrefix { const char* p; size_t n; };
static char g_fd_rt_prefix_store[4][96];
static FdRootPrefix g_fd_root_prefixes[] = {
    {"/data/adb/",                 10},
    {"/sbin/",                      6},
    {"/debug_ramdisk/",            15},
    {"/data/system/zygisk_study/", 26},
    {nullptr, 0}, {nullptr, 0}, {nullptr, 0}, {nullptr, 0},
};

void hide_advanced_register_root_path_prefix(const char* prefix) {
    if (!prefix || !*prefix) return;
    size_t n = strlen(prefix);
    if (n >= sizeof g_fd_rt_prefix_store[0]) return;
    for (size_t i = 4; i < 8; ++i) {
        if (g_fd_root_prefixes[i].p == nullptr) {
            memcpy(g_fd_rt_prefix_store[i - 4], prefix, n + 1);
            g_fd_root_prefixes[i] =
                FdRootPrefix{g_fd_rt_prefix_store[i - 4], n};
            return;
        }
    }
}

static int fd_target_is_root_path(const char* t, size_t len) {
    for (const auto& pre : g_fd_root_prefixes) {
        if (pre.n == 0 || pre.p == nullptr) continue;
        if (len >= pre.n && memcmp(t, pre.p, pre.n) == 0) return 1;
    }
    return 0;
}

static void close_leaked_root_fds() {
    if (!g_real_syscall) return;   // cannot scan without raw syscalls

    int dirfd = (int)g_real_syscall(SYS_openat, AT_FDCWD, "/proc/self/fd",
                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dirfd < 0) return;

    // Bounded buffer: /proc/self/fd entries are tiny; 8 KB covers
    // ~200 descriptors per getdents64 round.
    char buf[8192];
    if (!g_real_readlink_for_fd_scan) {
        g_real_readlink_for_fd_scan =
            (ReadlinkFn)zs_resolve_libc("readlink");
    }
    int closed = 0;
    for (;;) {
        long n = g_real_syscall(SYS_getdents64, dirfd, buf, (long)sizeof buf);
        if (n <= 0) break;
        for (long off = 0; off < n;) {
            struct zs_linux_dirent64* de =
                (struct zs_linux_dirent64*)(buf + off);
            off += de->d_reclen;
            if (off > n) break;  // corrupt record; stop this round
            // d_name must be a pure fd number ("." / ".." excluded).
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            int fd = atoi(de->d_name);
            if (fd <= 0 || fd == dirfd) continue;
            char path[64];
            char target[PATH_MAX];
            int nw = snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
            if (nw <= 0 || (size_t)nw >= sizeof path) continue;
            ssize_t tl = g_real_readlink_for_fd_scan
                ? g_real_readlink_for_fd_scan(path, target, sizeof target - 1)
                : -1;
            if (tl <= 0) continue;
            target[tl] = '\0';
            if (fd_target_is_root_path(target, (size_t)tl)) {
                close(fd);
                ++closed;
            }
        }
    }
    close(dirfd);
    if (closed) {
        ZS_LOGD("hide_advanced: closed %d leaked root-path fd(s)", closed);
    }
}

// ------------------------------------------------------------------------
// Env scrub
// ------------------------------------------------------------------------

// kOurEnvVars is defined next to the /proc filter engine (it is
// shared with zs_filter_record's ZS_FILTER_ENVIRON handling).

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
    g_real_freopen  = (FreopenFn)zs_resolve_libc("freopen");  // Round 11
    g_real_stat     = (StatFn)zs_resolve_libc("stat");
    g_real_lstat    = (LstatFn)zs_resolve_libc("lstat");
    g_real_access   = (AccessFn)zs_resolve_libc("access");
    g_real_faccessat  = (FAccessAtFn)zs_resolve_libc("faccessat");
    g_real_faccessat2 = (FAccessAt2Fn)zs_resolve_libc("faccessat2");
    g_real_fstatat    = (FStatAtFn)zs_resolve_libc("fstatat");
    g_real_statx      = (StatxFn)zs_resolve_libc("statx");
    g_real_prop_find  = (PropFindFn)zs_resolve_libc("__system_property_find");
    g_real_prop_get   = (PropGetFn)zs_resolve_libc("__system_property_get");
    // Round 9 (B2): the enumeration/read path.
    g_real_prop_read_cb = (PropReadCbFn)zs_resolve_libc(
        "__system_property_read_callback");
    g_real_prop_read  = (PropReadFn)zs_resolve_libc(
        "__system_property_read");
    g_real_prop_foreach = (PropForeachFn)zs_resolve_libc(
        "__system_property_foreach");
    g_real_scandir    = (ScandirFn)zs_resolve_libc("scandir");
    g_real_scandirat  = (ScandiratFn)zs_resolve_libc("scandirat");
    g_real_readlink_for_fd_scan = (ReadlinkFn)zs_resolve_libc("readlink");
    g_real_syscall    = (SyscallFn)zs_resolve_libc("syscall");
    g_real_dlopen     = (DlopenFn)zs_resolve_libc("dlopen");
    g_real_android_dlopen_ext = (AndroidDlopenExtFn)zs_resolve_libc(
        "android_dlopen_ext");
    g_real_dlclose    = (DlcloseFn)zs_resolve_libc("dlclose");
    g_real_opendir    = (OpendirFn)zs_resolve_libc("opendir");

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
    // Round 11 (S3): the last stdio entry point that bypassed the
    // filter (rebinds an existing FILE without open/fopen).
    hide_advanced_register_tier_b_hook("freopen",
        (void*)&zygisk_study_hook_freopen);
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
    // Round 9 (B2): the enumeration path — read_callback, the legacy
    // read, and foreach itself.
    hide_advanced_register_tier_b_hook("__system_property_read_callback",
        (void*)&zygisk_study_hook_prop_read_callback);
    hide_advanced_register_tier_b_hook("__system_property_read",
        (void*)&zygisk_study_hook_prop_read);
    hide_advanced_register_tier_b_hook("__system_property_foreach",
        (void*)&zygisk_study_hook_prop_foreach);
    hide_advanced_register_tier_b_hook("syscall",
        (void*)&zygisk_study_hook_syscall);
    hide_advanced_register_tier_b_hook("dlopen",
        (void*)&zygisk_study_hook_dlopen);
    hide_advanced_register_tier_b_hook("android_dlopen_ext",
        (void*)&zygisk_study_hook_android_dlopen_ext);
    hide_advanced_register_tier_b_hook("dlclose",
        (void*)&zygisk_study_hook_dlclose);
    // Round 8 (S3): directory enumeration of hidden paths.
    hide_advanced_register_tier_b_hook("opendir",
        (void*)&zygisk_study_hook_opendir);
    // Round 9 (S1): scandir()/scandirat() build their dirent list
    // through libc-internal opendir/readdir, so the opendir GOT hook
    // does not see them. Post-filtering the result list here covers
    // the "simple API" detectors reach for first.
    hide_advanced_register_tier_b_hook("scandir",
        (void*)&zygisk_study_hook_scandir);
    hide_advanced_register_tier_b_hook("scandirat",
        (void*)&zygisk_study_hook_scandirat);
}

#ifdef ZS_HOST_TEST
// Test-only: the live-registry matcher behind the hash index.
void* zs_test_match_registered_hook(const char* name) {
    return match_registered_hook(name);
}

// Round 9 (B2): drive the property enumeration hooks with synthetic
// prop_info pointers and a fake real-foreach, exactly like the
// denylist path seam drives the reload logic.
void zs_test_set_absent_prop_infos(const void** arr, size_t n) {
    g_absent_prop_count = 0;
    for (size_t i = 0; i < n && i < 32; ++i) {
        g_absent_prop_infos[g_absent_prop_count++] = arr[i];
    }
}

void zs_test_set_real_prop_foreach(int (*fn)(void (*)(const void*, void*),
                                              void*)) {
    g_real_prop_foreach = (PropForeachFn)fn;
}

// Round 9 (S1): scandir — replace the real scandir so tests can
// supply a synthetic dirent list.
void zs_test_set_real_scandir(void* fn) {
    g_real_scandir = (ScandirFn)fn;
}

// Round 9 (P1): the number of TLS scratch allocations the filter
// engine has performed (should be <= 1 per thread, ever).
int zs_test_filter_scratch_allocs() {
    return g_filter_scratch_allocs.load(std::memory_order_relaxed);
}

// Round 9 (S2): point the fd-link scan at a host-creatable directory
// so the getdents64 walk + readlink resolution run for real.
void zs_test_set_fd_root_prefix(const char* prefix) {
    g_fd_root_prefixes[0] = FdRootPrefix{prefix, strlen(prefix)};
}
#endif

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
    //   3. Round 9 (S2): close ANY fd whose /proc/self/fd link target
    //      is under a root-framework path (leaked module fds are a
    //      readlink-away detection vector that tracking alone cannot
    //      catch).
    //   4. Env scrub.
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
    close_leaked_root_fds();
    scrub_env();
}

} // namespace zygisk_study
