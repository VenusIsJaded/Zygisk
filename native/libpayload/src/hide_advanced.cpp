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
#include "hide.h"
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

// Bionic property-area layout, VERIFIED this round from AOSP
// bionic sources (libc/system_properties/include/system_properties/
// {prop_area.h, prop_info.h} + prop_area.cpp, fetched at refs/heads/main
// AND android-9.0.0_r1 — byte-identical across the whole range):
//
//   prop_area file header (128 bytes):
//     [0]  uint32 bytes_used_        (writer-only bookkeeping)
//     [4]  uint32 serial_            (area serial; bumped by init on update)
//     [8]  uint32 magic_     0x504f5250
//     [12] uint32 version_   0xfc6ed0ab
//     [16] uint32 reserved_[28]
//     [128] data_[]
//   data_[0]    = root prop_trie_node (20 bytes):
//     [0] namelen u32  [4] prop u32  [8] left u32  [12] right u32
//     [16] children u32  [20] name[namelen] + NUL  (4-aligned allocs)
//   data_[20..112) = the "dirty backup area" (A10+; A9 starts allocs
//     at 20 — irrelevant to readers, offsets are explicit)
//   prop_info (96 bytes + name):
//     [0]  uint32 serial      — top byte = value length (READERS USE
//                               IT: ReadMutablePropertyValue memcpy's
//                               SERIAL_VALUE_LEN(serial)+1 bytes)
//     [4]  char value[92]    (union: long_property = {err[56], u32 offset})
//     [96] char name[] + NUL (the FULL dotted name — no namelen field;
//     the pre-Round-22 comment claiming one at offset 96 was wrong)
//   All trie offsets are uint32 relative to data_.
constexpr size_t kPropSerialOffset = 0;
constexpr size_t kPropValueOffset  = 4;
constexpr size_t kPropValueSize    = 92;  // PROP_VALUE_MAX
constexpr uint32_t kPropAreaMagic   = 0x504f5250u;
constexpr uint32_t kPropAreaVersion = 0xfc6ed0abu;
constexpr uint32_t kPropLongFlag    = 1u << 16;
constexpr size_t kPropAreaHeaderSize = 128;
constexpr size_t kPropInfoSize       = 96;
constexpr size_t kTrieNodeSize       = 20;
// SERIAL_VALUE_LEN(serial) = serial >> 24 — bionic's own reader macro
// (system_properties.cpp). A patch that changes the value's length
// MUST rewrite that byte, or __system_property_get returns a
// truncated, possibly non-NUL-terminated value (the Round 22 bug).

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
    size_t len = strnlen(value, kPropValueSize - 1);
    serial_atomic->store(serial | 1u, std::memory_order_release);
    memset(value_field, 0, kPropValueSize);
    memcpy(value_field, value, len);
    // Round 22 REAL BUG FIX: bionic's reader takes the value LENGTH
    // from the serial's top byte (SERIAL_VALUE_LEN(serial) = >> 24,
    // memcpy of len+1 bytes in ReadMutablePropertyValue). The old
    // code bumped only the low counter, so a spoof LONGER than the
    // device original made __system_property_get hand back a
    // truncated, potentially non-NUL-terminated value ("enforcing"
    // patched over "logging" returned "enforcin" + no NUL — a buffer
    // over-read in the hidden app). Rewrite the length byte, keep
    // the low counter bump, and clear kLongFlag (patched values are
    // short by construction; a long entry must not keep the union
    // interpreted as an error message + offset).
    uint32_t low = ((serial + 2) & 0x00FFFFFFu) & ~1u;
    low &= ~kPropLongFlag;
    serial_atomic->store(((uint32_t)len << 24) | low,
                         std::memory_order_release);
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

// Forward declaration — the validated-header check lives with the
// Round 22 trie utilities below; remap_prop_mapping_private uses it
// to decide the live-prefix copy size.
static int pa_header_valid(const uint8_t* base, size_t size);
static int pa_trie_delete_key(uint8_t* base, size_t size,
                              const char* key);
// Forward declaration — the real readlink used by the fd scan and
// the fdopendir hook (declared with the Tier B reals below).
using ReadlinkFn = ssize_t (*)(const char*, char*, size_t);
static ReadlinkFn g_real_readlink_for_fd_scan = nullptr;

static int remap_prop_mapping_private(uintptr_t lo, uintptr_t hi) {
    size_t size = hi - lo;
    void* addr = reinterpret_cast<void*>(lo);

    // Round 22 PERF: when the range is a well-formed property area,
    // only 128 + bytes_used_ bytes are live — the tail past the last
    // allocation is never reachable through the trie. Copy just the
    // live prefix; the MAP_FIXED replacement pages are already zero,
    // which is strictly MORE conservative than copying the real
    // area's dead entries (stale values init left behind). ~35-50%
    // less memcpy on the hide critical path. Non-areas (the contexts
    // trie, or a mapping not at file offset 0) keep the full copy —
    // the header check is the gate.
    size_t copy_size = size;
    if (pa_header_valid((const uint8_t*)addr, size)) {
        uint32_t bytes_used = 0;
        memcpy(&bytes_used, addr, 4);
        size_t live = kPropAreaHeaderSize + (size_t)bytes_used;
        if (live > 0 && live <= size) copy_size = live;
    }

    void* scratch = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) return 0;
    memcpy(scratch, addr, copy_size);  // save live content

    void* remapped = mmap(addr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                          -1, 0);
    if (remapped == MAP_FAILED) {
        munmap(scratch, size);
        return 0;
    }
    memcpy(addr, scratch, copy_size);  // restore content into the copy
    munmap(scratch, size);
    return 1;
}

// Defined with the property READ hooks in section 5c below; forward
// declaration because clone_property_area_private() calls it.
static void collect_absent_prop_infos();

// ------------------------------------------------------------------------
// Round 23 — stock-line restoration for the property mappings.
//
// The private clone replaces the /dev/__properties__ file mappings
// with ANONYMOUS ones at the same addresses (the mechanism that makes
// Tier A's hook-free property spoofing work). Side effect: every
// stock Android process carries exactly two /dev/__properties__ lines
// in /proc/self/maps, and the hidden process's RAW maps show blank
// anon lines there instead. Tier B reads (the filtered memfd) now
// restore the captured stock line for any cloned range — same
// addresses, same perms, same size, and the real file's dev/ino and
// path. (Tier A children read unfiltered maps: the deviation there is
// documented in ANDROID-REALISM Round 23 — the address/perms/size all
// match stock; only the path column is blank.)
// ------------------------------------------------------------------------
struct PropLineRestore {
    uintptr_t lo, hi;
    size_t    prefix_len;   // strlen("lo-hi ") — precomputed matcher
    char      prefix[40];   // "lo-hi " (hex, lowercase, as maps shows)
    size_t    len;          // without the trailing newline
    char      line[152];
};
static PropLineRestore g_prop_line_restore[8];
static size_t          g_prop_line_restore_count;

// Parse a maps line's leading "hexlo-hexhi" range. Manual — no
// sscanf on the hot path (~5 ns vs ~300 ns per line).
static int zs_parse_maps_range(const char* rec, size_t rec_len,
                               uintptr_t* lo, uintptr_t* hi) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    uintptr_t a = 0, b = 0;
    size_t i = 0;
    int n1 = 0, n2 = 0;
    while (i < rec_len) {
        int v = hexval(rec[i]);
        if (v < 0) break;
        a = (a << 4) | (uintptr_t)v;
        ++i; ++n1;
    }
    if (n1 == 0 || n1 > 16 || i >= rec_len || rec[i] != '-') return 0;
    ++i;
    while (i < rec_len) {
        int v = hexval(rec[i]);
        if (v < 0) break;
        b = (b << 4) | (uintptr_t)v;
        ++i; ++n2;
    }
    if (n2 == 0 || n2 > 16) return 0;
    *lo = a;
    *hi = b;
    return 1;
}

// How many registered stock lines does this record's address range
// COVER? The two property mappings sit at adjacent addresses on a
// real device, and after the clone both are anonymous with identical
// protection — the kernel MERGES them into a single VMA, so the raw
// maps line we must answer for is the UNION range, not the exact
// per-mapping range. (Verified from the ANON_VMA_NAME Kconfig help
// text this round: named/unnamed VMAs merge when the name matches.
// The exact-prefix prototype silently skipped restoration for the
// merged case — the classic host-test-green, device-different trap.)
// Emits the stock lines in table (ascending address) order.
static size_t prop_line_restore_covered(const char* rec, size_t rec_len,
                                        const PropLineRestore* out[8]) {
    if (g_prop_line_restore_count == 0 || !rec || rec_len < 16) return 0;
    uintptr_t lo = 0, hi = 0;
    if (!zs_parse_maps_range(rec, rec_len, &lo, &hi) || hi <= lo) return 0;
    size_t n = 0;
    for (size_t i = 0; i < g_prop_line_restore_count && n < 8; ++i) {
        const PropLineRestore* r = &g_prop_line_restore[i];
        if (r->lo >= lo && r->hi <= hi) out[n++] = r;
    }
    return n;
}

// Match a record's leading "lo-hi " address range against the restore
// table (EXACT form — for zs_filter_record's direct-call path with a
// separate destination buffer).
// PERF: a precomputed "lo-hi " prefix + memcmp — an early sscanf
// prototype cost ~100-250 us per 500-line maps read (one libc sscanf
// per line); the memcmp fails on the first differing byte (~5 ns per
// line, the same order as the record token scan itself).
static const PropLineRestore* prop_line_restore_for(const char* rec,
                                                    size_t rec_len) {
    if (g_prop_line_restore_count == 0 || !rec || rec_len < 16) {
        return nullptr;
    }
    for (size_t i = 0; i < g_prop_line_restore_count; ++i) {
        const PropLineRestore* r = &g_prop_line_restore[i];
        if (rec_len > r->prefix_len &&
            memcmp(rec, r->prefix, r->prefix_len) == 0) {
            return r;
        }
    }
    return nullptr;
}

// Capture the stock text of every /dev/__properties__ maps line.
// Same 5th-whitespace path-field discipline as find_prop_mappings.
// Pure function over the maps buffer (host-testable directly).
static void capture_prop_line_restores(const char* buf, size_t total) {
    g_prop_line_restore_count = 0;
    static const char kPropPath[] = "/dev/__properties__/";
    constexpr size_t kPropPathLen = sizeof(kPropPath) - 1;
    const char* p = buf;
    const char* end = buf + total;
    while (p < end && g_prop_line_restore_count < 8) {
        const char* nl = (const char*)memchr(p, '\n', end - p);
        const char* line_end = nl ? nl : end;
        // Locate the path field (5th whitespace run — maps layout).
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
            unsigned long lo = 0, hi = 0;
            char head[48];
            size_t copy = (size_t)(line_end - p);
            if (copy >= sizeof head) copy = sizeof head - 1;
            memcpy(head, p, copy);
            head[copy] = '\0';
            if (sscanf(head, "%lx-%lx", &lo, &hi) == 2 && hi > lo) {
                PropLineRestore* r =
                    &g_prop_line_restore[g_prop_line_restore_count];
                size_t len = (size_t)(line_end - p);
                if (len >= sizeof r->line) len = sizeof r->line - 1;
                memcpy(r->line, p, len);
                r->line[len] = '\0';
                r->lo = (uintptr_t)lo;
                r->hi = (uintptr_t)hi;
                r->len = len;
                int pn = snprintf(r->prefix, sizeof r->prefix,
                                  "%lx-%lx ", lo, hi);
                r->prefix_len = pn > 0 && (size_t)pn < sizeof r->prefix
                    ? (size_t)pn : 0;
                if (r->prefix_len == 0) continue;   // unreachable lengths
                ++g_prop_line_restore_count;
            }
        }
        p = line_end + (nl ? 1 : 0);
    }
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
    // Round 23: capture the stock text of every property line BEFORE
    // the remap replaces the mappings — the filter restores these
    // lines for Tier B maps/smaps reads (see PropLineRestore above).
    if (!truncated) {
        capture_prop_line_restores(maps_buf, (size_t)total);
    }
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
        // MUST run before the unlink below: after it, find() no
        // longer resolves these keys — but any pointer the app cached
        // earlier still needs the hook-layer swallow.
        collect_absent_prop_infos();

        // Round 22 — delete the absent-spoofed keys from the clone's
        // TRIE (this is the writable window: before the mprotect(R)
        // loop below). Native absence: the REAL bionic find() returns
        // nullptr and foreach() skips the entry with no hook involved
        // — the find/get/foreach/read hooks above stay installed as
        // the SECOND layer (they also cover cached prop_info pointers
        // and any format drift that makes this walk fail-closed).
        // The scrubbed entries additionally remove the in-process
        // string-forensics signal (a raw memory scan for
        // "ro.magisk.version" no longer finds the name in the clone).
        size_t n_unlinked = 0;
        for (size_t i = 0; i < n_mappings; ++i) {
            uint8_t* base = reinterpret_cast<uint8_t*>(mappings[i].lo);
            size_t msize = (size_t)(mappings[i].hi - mappings[i].lo);
            if (!pa_header_valid(base, msize)) continue;  // contexts area etc.
            for (const ZsPropSpoof& s : kPropSpoofTable) {
                if (s.value && s.value[0] != '\0') continue;
                if (pa_trie_delete_key(base, msize, s.key)) ++n_unlinked;
            }
        }
        ZS_LOGD("hide_advanced: unlinked %zu absent key(s) from the "
                "clone trie", n_unlinked);
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
// 4b. Round 19 — the spoofed properties_serial FILE
//
// Execve-proof property spoofing. The in-process clone (above) plus
// the find/get/foreach hooks cover every read the hidden app itself
// makes. But a fork+exec'd helper (Runtime.exec("getprop ..."))
// starts with a fresh libc: it re-maps properties_serial BY PATH,
// sees the REAL trie, and prints the REAL root-indicating values.
// That was the single largest documented residual class since
// Round 8 ("exec'd helpers see real property values").
//
// The closure: the child's mount namespace is inherited across
// execve. At hide time (still root, still in the zygote SELinux
// domain — AOSP's own Zygote.cpp bind-mounts over /dev/__properties__
// from exactly this point via BindMountSyspropOverride, so the
// platform itself sanctions both the mount and the label story), we
// bind-mount a FILE copy of the property area — with every spoof
// value already patched in — over /dev/__properties__/properties_serial.
//
//   payload (zygote, root): builds the spoofed bytes. Only the
//     payload can do this: it lets bionic's own __system_property_find
//     walk the real trie, so we never hard-code the trie format
//     (which has changed across Android versions). The prop_info
//     ADDRESS gives us the byte offset in the file via the mapping
//     table — no format assumptions, version-proof by construction.
//
//   daemon (root, privileged domain): writes the bytes into the
//     randomized session directory and chcons the file to
//     u:object_r:properties_serial:s0 — the label bionic's readers
//     (apps and their exec'd helpers) are already allowed to read.
//     The zygote domain cannot write there itself, so the daemon
//     does the file I/O over the existing socket protocol (verb 'P').
//
//   payload (hidden child, mount phase): bind-mounts the file over
//     /dev/__properties__/properties_serial, then self-checks by
//     opening the mounted path and comparing the area magic; on any
//     failure it umounts immediately (fail-closed back to the exact
//     pre-Round-19 behavior).
//
// Cost accounting: the build+send happens ONCE at payload init;
// each hidden child pays one mount(2) + one open(2) at hide time.
// Non-hidden processes pay nothing (no hook, no mount).
// ------------------------------------------------------------------------

// Pure helper: patch one prop_info VALUE inside a raw byte buffer,
// at a caller-computed byte offset of the prop_info header. Same
// serial protocol as patch_prop_value (odd serial while writing,
// +2 at the end) so readers of the FILE see a consistent value.
// Round 22: also rewrites the serial's value-length byte (see the
// patch_prop_value comment — the file image's exec'd readers use the
// same SERIAL_VALUE_LEN memcpy). Returns 1 when patched, 0 on
// bounds failure.
static int patch_prop_value_in_buffer(char* buf, size_t size,
                                       size_t pi_off, const char* value) {
    if (pi_off > size || size - pi_off < kPropValueOffset + kPropValueSize) {
        return 0;
    }
    char* pi = buf + pi_off;
    auto* serial_atomic =
        reinterpret_cast<std::atomic<uint32_t>*>(pi + kPropSerialOffset);
    char* value_field = pi + kPropValueOffset;
    uint32_t serial = serial_atomic->load(std::memory_order_relaxed);
    if (serial & 1u) return 0;   // mid-update entry: leave it alone
    size_t len = value ? strnlen(value, kPropValueSize - 1) : 0;
    serial_atomic->store(serial | 1u, std::memory_order_release);
    memset(value_field, 0, kPropValueSize);
    if (len) memcpy(value_field, value, len);
    uint32_t low = ((serial + 2) & 0x00FFFFFFu) & ~1u;
    low &= ~kPropLongFlag;
    serial_atomic->store(((uint32_t)len << 24) | low,
                         std::memory_order_release);
    return 1;
}

// ------------------------------------------------------------------------
// Round 22 — the property-trie utilities (validated walk + deletion).
//
// THE INSIGHT THIS SECTION IS BUILT ON: a trie node with prop == 0 is
// a perfectly legal "fragment without a property" — every INTERMEDIATE
// node of every stock area is one. Zeroing a terminal node's `prop`
// offset is therefore a reader-transparent DELETION: find() walks to
// the node, sees prop == 0 and returns nullptr; foreach skips the
// entry. The pre-Round-22 docs claimed "the trie format cannot
// express deletion without a full re-serialization" — that claim was
// WRONG (corrected in the docs this round), and it was the only reason
// absent-spoofed keys stayed present-but-empty in the R19 file image
// and hook-gated-only in the in-process clone.
//
// Everything below is validated against the byte layout verified from
// AOSP bionic this round (see the format-facts comment above the
// patch_prop_value constants). ANY anomaly (bad magic/version, wild
// offset, unterminated name) makes the walk report "not found" —
// fail-closed to the pre-Round-22 behavior, never a crash.
// ------------------------------------------------------------------------

// Read a little-endian uint32 from base+off with bounds validation.
// Returns 0 (and sets *ok=0) when out of range.
static uint32_t pa_read32(const uint8_t* base, size_t size, size_t off,
                          int* ok) {
    if (off > size || size - off < 4) { if (ok) *ok = 0; return 0; }
    uint32_t v;
    memcpy(&v, base + off, 4);
    return v;
}

// Is the buffer a well-formed property area (header at base)?
// Used to gate the trie code to real properties_serial mappings only
// (the property_info contexts area has a different magic and is
// skipped; the hooks still cover its keys).
static int pa_header_valid(const uint8_t* base, size_t size) {
    if (!base || size < kPropAreaHeaderSize + kTrieNodeSize) return 0;
    int ok = 1;
    uint32_t magic = pa_read32(base, size, 8, &ok);
    uint32_t version = pa_read32(base, size, 12, &ok);
    if (!ok || magic != kPropAreaMagic || version != kPropAreaVersion) {
        return 0;
    }
    uint32_t bytes_used = pa_read32(base, size, 0, &ok);
    if (!ok || bytes_used == 0 || bytes_used > size - kPropAreaHeaderSize) {
        return 0;   // corrupt writer field — refuse to walk
    }
    return 1;
}

// bionic's cmp_prop_name, verbatim (prop_area.cpp).
static int pa_cmp_name(const char* one, uint32_t one_len,
                       const char* two, uint32_t two_len) {
    if (one_len < two_len) return -1;
    if (one_len > two_len) return 1;
    return strncmp(one, two, one_len);
}

// Fetch a validated trie node pointer. data base = base+128. Returns
// 0 on any anomaly.
static int pa_node_at(const uint8_t* base, size_t size, uint32_t off,
                      /*out*/ const uint8_t** node) {
    if (off == 0 || (off & 3u) != 0) return 0;
    if ((size_t)off + kTrieNodeSize > size - kPropAreaHeaderSize) return 0;
    const uint8_t* n = base + kPropAreaHeaderSize + off;
    uint32_t namelen = 0;
    memcpy(&namelen, n, 4);
    if (namelen == 0 || (size_t)namelen > 128) return 0;
    if ((size_t)off + kTrieNodeSize + (size_t)namelen + 1 >
        size - kPropAreaHeaderSize) {
        return 0;
    }
    if (n[kTrieNodeSize + namelen] != '\0') return 0;  // bionic NUL-terminates
    if (node) *node = n;
    return 1;
}

static uint32_t pa_node_u32(const uint8_t* n, size_t field) {
    uint32_t v;
    memcpy(&v, n + field, 4);
    return v;
}

// Walk to the trie node that terminates `name` (bionic's
// find_property + find_prop_trie_node with alloc_if_needed=false,
// with validation at every hop). `data` = base+128 is computed by the
// caller. Writes the node's data_-relative offset and returns 1, or
// returns 0 (not found / anomaly — never a crash).
static int pa_trie_find_node(const uint8_t* base, size_t size,
                             const char* name, uint32_t* node_off) {
    if (!base || !name || !node_off) return 0;
    const uint8_t* root = base + kPropAreaHeaderSize;  // node at offset 0
    const char* remaining = name;
    uint32_t current = 0;   // root (special: namelen 0, never compared)
    while (1) {
        const char* sep = strchr(remaining, '.');
        size_t frag_len = sep ? (size_t)(sep - remaining)
                              : strlen(remaining);
        if (frag_len == 0) return 0;
        // Children of `current` (root's fields are read directly; it
        // has no validated allocation of its own).
        uint32_t children = 0;
        if (current == 0) {
            children = pa_node_u32(root, 16);
        } else {
            const uint8_t* cur_node = nullptr;
            if (!pa_node_at(base, size, current, &cur_node)) return 0;
            children = pa_node_u32(cur_node, 16);
        }
        if (children == 0) return 0;
        // BST walk among siblings.
        uint32_t node = children;
        int found = 0;
        while (1) {
            const uint8_t* n = nullptr;
            if (!pa_node_at(base, size, node, &n)) return 0;
            uint32_t n_namelen = pa_node_u32(n, 0);
            int cmp = pa_cmp_name(remaining, (uint32_t)frag_len,
                                  (const char*)(n + kTrieNodeSize),
                                  n_namelen);
            if (cmp == 0) { found = 1; break; }
            uint32_t next = cmp < 0 ? pa_node_u32(n, 8)   // left
                                    : pa_node_u32(n, 12); // right
            if (next == 0) break;
            node = next;
        }
        if (!found) return 0;
        if (!sep) {
            *node_off = node;
            return 1;
        }
        remaining = sep + 1;
        current = node;
    }
}

// Validate a prop_info at data_-relative offset `pi_off`; write the
// total allocation size (96 + namelen + 1, rounded up to 4) so the
// caller can scrub the whole entry. Returns 0 on anomaly.
static int pa_prop_info_at(const uint8_t* base, size_t size,
                           uint32_t pi_off, size_t* alloc_size) {
    size_t data_size = size - kPropAreaHeaderSize;
    if ((pi_off & 3u) != 0) return 0;
    if ((size_t)pi_off + kPropInfoSize > data_size) return 0;
    const uint8_t* pi = base + kPropAreaHeaderSize + pi_off;
    // The name must be NUL-terminated within the area.
    const char* name = (const char*)(pi + kPropInfoSize);
    size_t max_name = data_size - (size_t)pi_off - kPropInfoSize;
    size_t namelen = strnlen(name, max_name);
    if (namelen == max_name) return 0;   // no NUL — refuse
    if (namelen > 128) return 0;         // sanity (PROP_NAME_MAX-ish)
    size_t total = kPropInfoSize + namelen + 1;
    total = (total + 3u) & ~(size_t)3u;  // bionic's 4-byte align
    if ((size_t)pi_off + total > data_size) return 0;
    if (alloc_size) *alloc_size = total;
    return 1;
}

// Delete `key` from a property-area image (in memory):
//   1. zero the terminal node's `prop` offset — find()/foreach() now
//      report the key as absent, exactly like any intermediate node;
//   2. scrub the orphaned prop_info bytes (name AND value) — the entry
//      is unreachable by any correct reader (an exec'd helper maps the
//      file fresh and only ever walks the trie), and scrubbing kills
//      the raw-forensics signal of e.g. "ro.magisk.version" surviving
//      as a dead record;
//   3. scrub a long value block too, bounded by its NUL.
// Returns 1 when the key was deleted, 0 when not found / anomaly
// (fail-closed: the entry keeps its pre-Round-22 hook treatment).
static int pa_trie_delete_key(uint8_t* base, size_t size,
                              const char* key) {
    if (!pa_header_valid(base, size)) return 0;
    uint32_t node_off = 0;
    if (!pa_trie_find_node(base, size, key, &node_off)) return 0;
    uint8_t* node = base + kPropAreaHeaderSize + node_off;
    uint32_t pi_off = pa_node_u32(node, 4);
    if (pi_off == 0) return 0;   // already absent
    size_t alloc = 0;
    if (!pa_prop_info_at(base, size, pi_off, &alloc)) return 0;
    uint8_t* pi = base + kPropAreaHeaderSize + pi_off;
    // Long-value block? (union at pi+4: err[56] then u32 offset)
    uint32_t serial = 0;
    memcpy(&serial, pi, 4);
    if (serial & kPropLongFlag) {
        uint32_t long_rel = 0;
        memcpy(&long_rel, pi + 4 + 56, 4);
        // long_value() = pi + long_rel; bounded NUL-scrub.
        if ((uint64_t)pi_off + kPropInfoSize + (uint64_t)long_rel <
            size - kPropAreaHeaderSize) {
            uint8_t* lv = pi + long_rel;
            size_t max = size - kPropAreaHeaderSize -
                         ((size_t)pi_off + kPropInfoSize + long_rel);
            for (size_t i = 0; i < max && lv[i] != 0; ++i) lv[i] = 0;
        }
    }
    memset(pi, 0, alloc);          // name, value, serial — all gone
    uint32_t zero = 0;
    memcpy(node + 4, &zero, 4);    // node->prop = 0: deleted
    return 1;
}

// A mapping of a SPECIFIC property file, with its file offset (maps
// lines carry the offset column; the serial area is normally one
// offset-0 mapping, but the math stays correct if it ever is not).
struct PropFileMapping { uintptr_t lo, hi; uintptr_t file_off; };

// Pure function: find mappings whose maps-line path field equals
// `want_path` exactly. Same line-parsing discipline as
// find_prop_mappings (5th-whitespace path field, length-guarded).
static size_t find_file_mappings(const char* buf, size_t total,
                                 const char* want_path,
                                 PropFileMapping* out, size_t cap) {
    const size_t want_len = strlen(want_path);
    size_t n = 0;
    const char* p = buf;
    const char* end = buf + total;
    while (p < end && n < cap) {
        const char* nl = (const char*)memchr(p, '\n', end - p);
        const char* line_end = nl ? nl : end;
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
        if (path_field) {
            size_t path_len = (size_t)(line_end - path_field);
            if (path_len == want_len &&
                memcmp(path_field, want_path, want_len) == 0) {
                char linebuf[512];
                size_t copy = (size_t)(line_end - p);
                if (copy >= sizeof linebuf) copy = sizeof linebuf - 1;
                memcpy(linebuf, p, copy);
                linebuf[copy] = '\0';
                unsigned long lo = 0, hi = 0, off = 0;
                char perms[8] = {};
                int k = sscanf(linebuf, "%lx-%lx %7s %lx",
                               &lo, &hi, perms, &off);
                if (k >= 4 && perms[0] == 'r' && hi > lo) {
                    out[n].lo = (uintptr_t)lo;
                    out[n].hi = (uintptr_t)hi;
                    out[n].file_off = (uintptr_t)off;
                    ++n;
                }
            }
        }
        p = line_end + (nl ? 1 : 0);
    }
    return n;
}

// Read the whole file at `path` into a malloc'd buffer. Returns null
// on failure. (Root-only callers: the property area file is 0444
// root-owned; the zygote domain is allowed to read it — bionic maps
// it at process start.)
static char* read_whole_file(const char* path, size_t* out_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return nullptr;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (size_t)st.st_size > 8 * 1024 * 1024) {
        close(fd);
        return nullptr;
    }
    size_t size = (size_t)st.st_size;
    char* buf = (char*)malloc(size);
    if (!buf) { close(fd); return nullptr; }
    size_t got = 0;
    while (got < size) {
        ssize_t r = read(fd, buf + got, size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != size) { free(buf); return nullptr; }
    *out_size = size;
    return buf;
}

// Which mapping (if any) contains the address `addr`?
static const PropFileMapping* containing_mapping(
        const PropFileMapping* maps, size_t n, uintptr_t addr) {
    for (size_t i = 0; i < n; ++i) {
        if (addr >= maps[i].lo && addr < maps[i].hi) return &maps[i];
    }
    return nullptr;
}

// Pure core (unit-tested on host with a synthetic area): given the
// file bytes, the mapping table that produced them and a find()
// function over the LIVE mapping, patch every spoof value into the
// byte buffer at the computed file offsets. Returns the number of
// values patched.
static size_t zs_patch_spoofed_area_bytes(
        char* buf, size_t size,
        const PropFileMapping* maps, size_t n_maps,
        const char* (*find)(const char*)) {
    size_t patched = 0;
    for (const ZsPropSpoof& s : kPropSpoofTable) {
        const void* pi = find(s.key);
        if (!pi) continue;
        const PropFileMapping* m =
            containing_mapping(maps, n_maps, (uintptr_t)pi);
        if (!m) continue;
        size_t pi_off = (size_t)(((uintptr_t)pi - m->lo) + m->file_off);
        patched += (size_t)patch_prop_value_in_buffer(
            buf, size, pi_off, s.value ? s.value : "");
    }
    return patched;
}

// Round 19 public entry (production path): build the spoofed
// properties_serial image. Parameterized by the file path so host
// tests can drive the REAL code against a synthetic area; production
// passes "/dev/__properties__/properties_serial". Returns a malloc'd
// buffer the caller owns, or null (feature disabled — callers must
// treat null as "no file, no mount" and proceed unchanged).
char* zs_build_spoofed_serial_area(const char* prop_file_path,
                                   size_t* out_size) {
    if (!prop_file_path) return nullptr;
    if (!g_find_prop) {
        g_find_prop = (FindPropFn)zs_resolve_libc(
            "__system_property_find");
        if (!g_find_prop) return nullptr;   // host/no bionic
    }
    // 1. The live mapping table (offsets must come from the mapping
    //    the CURRENT find() walks, i.e. the real area — call this
    //    before the in-process clone ever runs, or at init).
    constexpr size_t kMapsCap = 96 * 1024;
    static char maps_buf[kMapsCap];   // once per process; off-stack
    int mfd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (mfd < 0) return nullptr;
    ssize_t total = 0;
    while ((size_t)total < kMapsCap) {
        ssize_t n = read(mfd, maps_buf + total, kMapsCap - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    PropFileMapping maps[8];
    size_t n_maps = total > 0
        ? find_file_mappings(maps_buf, (size_t)total, prop_file_path,
                             maps, 8)
        : 0;
    close(mfd);
    if (n_maps == 0) return nullptr;

    // 2. The file bytes.
    size_t size = 0;
    char* buf = read_whole_file(prop_file_path, &size);
    if (!buf) return nullptr;

    // 3. Patch every spoof value at its computed file offset.
    size_t patched = zs_patch_spoofed_area_bytes(
        buf, size, maps, n_maps,
        (const char* (*)(const char*))g_find_prop);

    // 4. Round 22 — delete every absent-spoofed key FROM THE TRIE.
    //    The live find() above located each prop_info; the trie walk
    //    in the FILE buffer does the rest (node->prop = 0 + scrubbed
    //    entry). Exec'd helpers now see these keys as ABSENT via the
    //    file itself — no hook involved — closing the R19 residual
    //    ("absent keys present-but-empty in the file image").
    //    Fail-closed: a malformed area keeps the patch-only image.
    size_t deleted = 0;
    if (pa_header_valid((const uint8_t*)buf, size)) {
        for (const ZsPropSpoof& s : kPropSpoofTable) {
            if (s.value && s.value[0] != '\0') continue;  // value spoof
            if (pa_trie_delete_key((uint8_t*)buf, size, s.key)) {
                ++deleted;
            }
        }
    }

    ZS_LOGD("hide_advanced: spoofed serial area built "
            "(%zu value(s) patched, %zu key(s) deleted, %zu bytes)",
            patched, deleted, size);
    if (patched == 0 && deleted == 0) {
        // Zero hits almost certainly means the offset math is wrong
        // for this device — a file with no patches is the real trie
        // verbatim; serving it gains nothing, so fail closed.
        free(buf);
        return nullptr;
    }
    if (out_size) *out_size = size;
    return buf;
}

#ifdef ZS_HOST_TEST
// Test seam: supply a fake __system_property_find (the host has no
// bionic property area). The production builder resolves the real
// one via zs_resolve_libc.
void zs_test_set_prop_find(const void* (*find)(const char*)) {
    g_find_prop = (FindPropFn)find;
}
void zs_test_reset_prop_find() { g_find_prop = nullptr; }
#endif

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

// Round 19 — the PROC_LINE record matcher was REWRITTEN after an
// adversarial audit found it only understood the MAPS line format.
//
// The old matcher located "the path field" as "whatever follows the
// 5th whitespace run" — correct for maps/smaps (addr perms offset
// dev inode path), but every OTHER filtered file has its paths in
// different columns:
//
//   /proc/self/mounts:      source target fstype opts 0 0
//   /proc/self/mountinfo:   id parent maj:min root mountpoint opts
//                           ... - fstype source super_opts
//   /proc/self/mountstats:  device target fstype opts / per-field lines
//
// The 5th-field logic landed on "0" (mounts) or the options column
// (mountinfo) — so a mounts line whose SOURCE was /data/adb/... or a
// mountinfo line whose mountpoint/root carried a module path was
// NEVER dropped. The existing content tests only ever fed
// maps-format lines, so 85 host tests stayed green while the mounts
// backstop (the safety net for the fail-closed unmount path, where a
// failed unshare leaves module mounts in the table) leaked every
// root path to the app. (Reproduced empirically before the fix —
// see test "filter_record_drops_hidden_paths_in_every_line_format".)
//
// The new matcher is format-agnostic: it tokenizes the line on
// whitespace and tests EVERY token with the same rule the fd-scanner
// uses (fd_target_is_root_path: anchored prefix against the static +
// runtime root-path table), plus two additions the line formats
// need:
//   - exact-path match for the magic-mounted bridge libraries
//     (/system/lib[64]/libzygisk.so|libpayload.so — these come from
//     the systemless overlay, so no /data prefix identifies them);
//   - the mountinfo "root" column of a /data bind mount shows the
//     path INSIDE the source filesystem ("/adb/modules/..."), so
//     tokens are also matched against that form.
//
// Token-anchored matching also FIXES a false-positive class the old
// substring scan had: an app that ships its own libpayload.so in
// /data/data/<pkg>/lib/ had that maps line dropped (substring
// "libpayload.so" matched mid-path). Anchored prefixes and exact
// /system/lib[64]/ paths never match an app's own data-dir library.

// Exact full paths of the systemless (magic-mounted) copies of our
// libraries. The module installs them under $MODPATH/system/lib[64]
// so ART's native-bridge dlopen finds them; in maps they appear at
// these paths, and no /data/... prefix distinguishes them.
static const char* const kHiddenExactPaths[] = {
    "/system/lib64/libzygisk.so",
    "/system/lib64/libpayload.so",
    "/system/lib64/libzn_loader.so",
    "/system/lib/libzygisk.so",
    "/system/lib/libpayload.so",
    "/system/lib/libzn_loader.so",
};

// mountinfo "root" fields (the path INSIDE the source filesystem —
// always slash-form) for bind mounts whose source lives under our
// root paths: a bind of /data/adb/modules reports root
// "/adb/modules/...", which no /data-anchored prefix can match.
// Stock mountinfo root fields are "/", "/system", "/vendor",
// "/product", "/data", ... — none of these forms, so the anchored
// prefixes cannot false-positive on stock lines.
static const char* const kHiddenRootFieldPrefixes[] = {
    "/adb/modules",
    "/adb/.zygisk_study",
    "/system/zygisk_study",
};

// Substring helper for the unix-socket line filter (whole-line
// memmem semantics — socket names are not path-shaped, so anchored
// prefix matching does not apply there).
struct HiddenSubstring {
    const char* data;
    size_t      len;
    constexpr HiddenSubstring(const char* s)
        : data(s), len(__builtin_strlen(s)) {}
};

// Defined with the fd scanner in section 6; forward declaration so
// the Round 19 line matcher can share the SAME root-path table
// (single source of truth: everything registered via
// hide_advanced_register_root_path_prefix applies to both the fd
// scanner and the /proc line filter).
static int fd_target_is_root_path(const char* t, size_t len);

// Round 19: does this whitespace-delimited TOKEN identify one of our
// paths? Token-anchored (the match must start at the token's first
// byte — never mid-path), which is what makes app-owned files named
// libpayload.so survive while the module's own lines drop.
static int proc_line_token_is_hidden(const char* tok, size_t len) {
    if (len == 0) return 0;
    if (tok[0] != '/') return 0;   // mountinfo root fields are slash-form
    // Anchored prefix against the shared root-path table
    // (static set + runtime session prefixes).
    if (fd_target_is_root_path(tok, len)) return 1;
    // Exact paths of the magic-mounted bridge libraries.
    for (const char* p : kHiddenExactPaths) {
        size_t n = __builtin_strlen(p);
        if (n == len && memcmp(tok, p, n) == 0) return 1;
    }
    // mountinfo root-column forms (path inside the source fs).
    for (const char* p : kHiddenRootFieldPrefixes) {
        size_t n = __builtin_strlen(p);
        if (len >= n && memcmp(tok, p, n) == 0) return 1;
    }
    return 0;
}

// Round 19: walk every whitespace-delimited token of the line and
// apply proc_line_token_is_hidden. Format-agnostic — works for maps,
// smaps, mounts, mountinfo and mountstats without knowing which
// column carries a path (paths can appear as source, target, root
// and mapped-file columns across those formats).
static int proc_line_has_hidden_token(const char* rec, size_t rec_len) {
    const char* p   = rec;
    const char* end = rec + rec_len;
    while (p < end) {
        // Skip leading whitespace.
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        const char* tok = p;
        while (p < end && *p != ' ' && *p != '\t') ++p;
        if (p > tok &&
            proc_line_token_is_hidden(tok, (size_t)(p - tok))) {
            return 1;
        }
    }
    return 0;
}

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
        // Round 23: the property-area clone replaced the stock
        // file-backed /dev/__properties__ mappings with anonymous
        // ones at the same addresses. Restore the captured stock
        // line for any cloned range BEFORE the hidden-token scan (the
        // stock line is not ours to drop, and the blank anon line is
        // not what a stock process would show).
        //
        // ONLY when dst is a SEPARATE buffer: the streaming loop
        // compacts in place (dst may alias rec) and a restored line
        // can be LONGER than the record — the loop handles restores
        // itself BEFORE calling here, so this path is for direct
        // callers with their own destination. smaps detail lines
        // ("Size:", "Rss:", ...) never parse as "lo-hi" and pass
        // through, keeping the entry's sizes coherent.
        if (g_prop_line_restore_count && dst != rec) {
            const PropLineRestore* r = prop_line_restore_for(rec, rec_len);
            if (r && dst_cap >= r->len) {
                memcpy(dst, r->line, r->len);
                return (ssize_t)r->len;
            }
        }
        // Round 19: format-agnostic token matching (see the long
        // comment above the kHiddenExactPaths table). The old
        // "path field = after 5th whitespace run" logic only fit the
        // maps format — mounts/mountinfo/mountstats lines carry
        // their paths in other columns and leaked. Every token is
        // now tested, anchored at token start, against the shared
        // root-path prefix table, the bridge-library exact paths and
        // the mountinfo root-column forms.
        if (proc_line_has_hidden_token(rec, rec_len)) {
            return -1;
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
    // Round 17: when a record larger than the whole scratch chunk
    // appears (hostile input only — every real filtered /proc file
    // has < 4 KB lines), the old code dropped the FIRST chunk and
    // then happily emitted the record's TAIL as a fresh record. The
    // dropping flag now skips everything up to and including the next
    // separator before filtering resumes.
    int dropping = 0;

    for (;;) {
        ssize_t n = pread(orig_fd, buf + carry, kChunk - carry,
                          (off_t)file_off);
        if (n <= 0) break;
        file_off += (size_t)n;
        size_t have = carry + (size_t)n;

        if (dropping) {
            char* sep_pos = (char*)memchr(buf, sep, have);
            if (!sep_pos) {
                // The whole chunk belongs to the oversized record.
                carry = 0;
                continue;
            }
            size_t consumed = (size_t)(sep_pos - buf) + 1;
            memmove(buf, buf + consumed, have - consumed);
            have -= consumed;
            carry = have;
            dropping = 0;
            if (have == 0) continue;
        }

        // Locate the LAST separator in the buffer; everything after
        // it is a partial record carried into the next iteration.
        size_t last_sep = (size_t)-1;
        for (size_t i = have; i > 0; --i) {
            if (buf[i - 1] == sep) { last_sep = i - 1; break; }
        }
        if (last_sep == (size_t)-1) {
            // No complete record in this chunk (a >64 KB single line
            // does not occur in any filtered /proc file; if a hostile
            // source produces one, drop it rather than stall — and
            // keep dropping until its separator arrives).
            if (have >= kChunk - 1) {
                ZS_LOGW("hide_advanced: oversized record (%zu B) in "
                        "filtered /proc file; dropping it", have);
                dropping = 1;
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
        //
        // Round 23: records whose address range matches a captured
        // stock property line are REPLACED by it — and the stock line
        // can be LONGER than the anon record it replaces, which
        // in-place compaction cannot express (the write would clobber
        // input records that are not processed yet — the sanitizer
        // suite's maps test caught exactly that). Restored records
        // are flushed straight to the memfd instead: flush whatever
        // is pending in the compaction buffer, write the stock line,
        // shift the remaining input to the front, and restart the
        // scan. At most two hits per stream (the two property
        // mappings), so the extra memmove is bounded and rare.
        size_t write_ptr = 0;
        size_t rec_start = 0;
        while (rec_start <= last_sep) {
            char* sep_pos = (char*)memchr(buf + rec_start, sep,
                                          last_sep - rec_start + 1);
            if (!sep_pos) break;   // cannot happen; paranoia
            size_t rec_len = (size_t)(sep_pos - (buf + rec_start));
            if (kind == ZS_FILTER_PROC_LINE && g_prop_line_restore_count) {
                const PropLineRestore* hits[8];
                size_t nhits = prop_line_restore_covered(buf + rec_start,
                                                         rec_len, hits);
                if (nhits > 0) {
                    if (write_ptr > 0) {
                        if (write(memfd, buf, write_ptr) !=
                            (ssize_t)write_ptr) {
                            ok = 0;
                            break;
                        }
                    }
                    // One input (possibly MERGED) anon line becomes
                    // every stock line it covers — the exact byte
                    // content a stock process shows for the region.
                    int write_ok = 1;
                    for (size_t h = 0; h < nhits && write_ok; ++h) {
                        write_ok =
                            write(memfd, hits[h]->line, hits[h]->len) ==
                                (ssize_t)hits[h]->len &&
                            write(memfd, &sep, 1) == 1;
                    }
                    if (!write_ok) {
                        ok = 0;
                        break;
                    }
                    // Shift the remaining input to the front and
                    // restart the record scan on the shifted buffer.
                    size_t after = (size_t)(sep_pos - buf) + 1;
                    memmove(buf, buf + after, have - after);
                    have -= after;
                    last_sep = (size_t)-1;
                    for (size_t i = have; i > 0; --i) {
                        if (buf[i - 1] == sep) { last_sep = i - 1; break; }
                    }
                    write_ptr = 0;
                    rec_start = 0;
                    if (last_sep == (size_t)-1) break;
                    continue;
                }
            }
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

// ------------------------------------------------------------------------
// 5a. The fd shadow table (Round 15) — procfs observable parity
// ------------------------------------------------------------------------
//
// Every filtered /proc read hands the caller a memfd instead of the
// real procfs file. The CONTENT is right, but an fd is more than its
// content: a suspicious app can turn the descriptor around and ask
// questions a stock procfs fd answers differently:
//
//   readlink("/proc/self/fd/N")   real: "/proc/self/maps"
//                                 ours (pre-R15): "memfd:scudo"
//   fstat(N).st_size              real: 0      (procfs always reports 0)
//                                 ours: filtered byte count
//   fstat(N).st_mode              real: S_IFREG|0444
//                                 ours: S_IFREG|0777 (shmem files)
//   mmap(..., N, ...)             real: ENODEV (procfs has no .mmap)
//                                 ours: works — a memfd is mmap-able
//
// Each mismatch is a quiet "I am being filtered" signal. This table
// records, for every memfd we hand out, the identity (dev/ino/size —
// captured at creation) plus the ORIGINAL path the caller asked for.
// The fstat/statx/mmap/readlink hooks then reproduce the stock procfs
// answer for exactly those descriptors.
//
// Validation without a close() hook: entries can go stale (the app
// closes our memfd; the fd number is reused for something else). Every
// consumer first re-stats the fd and compares dev/ino/size against the
// record; a mismatch means the entry is stale — it is dropped and the
// real libc behavior passes through untouched. fd reuse to a NEW file
// cannot produce all three matches (dev+ino identify the file).
//
// dup()/fcntl(F_DUPFD)/pidfd_getfd() create new fd numbers pointing at
// the SAME file: the number lookup misses, but a dev/ino scan finds
// the record — readlink spoofing therefore covers duplicated
// descriptors too (the fstat-size rewrite only covers the original
// number; documented residual, both paths tested).
//
// Verified against Linux/Android behavior, stable across every
// supported release: procfs regular files report st_size 0 and reject
// mmap with ENODEV; memfd files are mode-0777 shmem files whose
// readlink target is "memfd:<name>". (Android version research for
// this round is in docs/ANDROID-REALISM.md.)

struct FdShadow {
    int      fd;            // -1 = free slot
    int      kind;          // FD_SHADOW_* below
    uint64_t dev;
    uint64_t ino;
    uint64_t size;          // exact st_size at creation (memfd only)
    char     orig_path[96]; // MEMFD: path the caller opened (the
                            // readlink spoof answer). PROC_DIR: the
                            // directory prefix (relative-path
                            // reconstruction).
};
enum {
    FD_SHADOW_MEMFD    = 0, // a filtered memfd we handed to the caller
    FD_SHADOW_PROC_DIR = 1, // a directory fd under /proc of OUR process
};
static FdShadow g_fd_shadow[32];
static size_t   g_fd_shadow_count;   // high-water mark, scan bounded

// Is `path` a /proc DIRECTORY whose relative opens we must filter?
// Covers /proc, /proc/net, /proc/self, /proc/thread-self, /proc/<pid>
// (ours only), and each of those plus /net, /task, /task/<tid>.
// openat(dirfd, "maps") with such a dirfd, or open("maps") after
// chdir into one, must resolve to the same filtered file as the
// absolute path would — Round 16 closes exactly that bypass.
static int zs_is_proc_dir_prefix(const char* path) {
    if (ZS_UNLIKELY(!path)) return 0;
    if (strncmp(path, "/proc", 5) != 0) return 0;
    if (path[5] == '\0') return 1;                 // "/proc"
    if (path[5] != '/') return 0;
    const char* rest = path + 6;
    if (strcmp(rest, "net") == 0) return 1;        // "/proc/net"
    if (strncmp(rest, "self", 4) == 0) {
        rest += 4;
    } else if (strncmp(rest, "thread-self", 11) == 0) {
        rest += 11;
    } else {
        const char* p = rest;
        while (*p >= '0' && *p <= '9') ++p;
        if (p == rest || (*p != '/' && *p != '\0')) return 0;
        long v = 0;
        for (const char* q = rest; q < p; ++q) v = v * 10 + (*q - '0');
        if (v != (long)getpid()) return 0;         // another process
        rest = p;
    }
    if (*rest == '\0') return 1;
    if (*rest != '/') return 0;
    ++rest;
    if (strcmp(rest, "net") == 0)  return 1;
    if (strcmp(rest, "task") == 0) return 1;
    if (strncmp(rest, "task/", 5) == 0) {
        const char* p = rest + 5;
        while (*p >= '0' && *p <= '9') ++p;
        if (p == rest + 5 || *p != '\0') return 0;
        return 1;
    }
    return 0;
}

// st_dev of the procfs mount — sampled once (lazily) from a real
// unfiltered /proc file so our spoofed stats report a believable
// device instead of the shmem one.
static uint64_t g_procfs_dev = 0;
static int      g_procfs_dev_done = 0;

static uint64_t zs_procfs_dev() {
    if (ZS_UNLIKELY(!g_procfs_dev_done)) {
        g_procfs_dev_done = 1;
        struct stat st;
        // /proc/self/cmdline is real procfs and NOT a filtered file —
        // its stat passes through every hook untouched. Calling the
        // libc symbol directly is safe from inside our own hooks: our
        // own DSO's GOT is never patched (the walker skips our libs).
        if (stat("/proc/self/cmdline", &st) == 0) {
            g_procfs_dev = (uint64_t)st.st_dev;
        }
    }
    return g_procfs_dev;
}

// Record the memfd we are about to hand to the caller.
static FdShadow* fd_shadow_alloc_slot(int want_fd);
static void      fd_shadow_set_path(FdShadow* slot, const char* path);

static void fd_shadow_register(int memfd, const char* orig_path) {
    struct stat st;
    // g_real_fstat may not be resolved yet on the first call; use the
    // libc fstat directly — it cannot recurse into our hooks because
    // fstat is not intercepted at libc-internal call sites.
    if (fstat(memfd, &st) != 0) return;
    FdShadow* slot = fd_shadow_alloc_slot(memfd);
    if (!slot) return;   // table full: plain memfd behavior (documented)
    slot->fd   = memfd;
    slot->kind = FD_SHADOW_MEMFD;
    slot->dev  = (uint64_t)st.st_dev;
    slot->ino  = (uint64_t)st.st_ino;
    slot->size = (uint64_t)st.st_size;
    fd_shadow_set_path(slot, orig_path);
}

// Round 16: record a /proc directory fd the app opened — relative
// opens against it (openat(dirfd, "maps")) are resolved through the
// stored prefix so the filter applies exactly like the absolute path.
static void fd_shadow_register_proc_dir(int dirfd, const char* path) {
    if (dirfd < 0) return;
    struct stat st;
    if (fstat(dirfd, &st) != 0) return;
    if (!S_ISDIR(st.st_mode)) return;
    FdShadow* slot = fd_shadow_alloc_slot(dirfd);
    if (!slot) return;
    slot->fd   = dirfd;
    slot->kind = FD_SHADOW_PROC_DIR;
    slot->dev  = (uint64_t)st.st_dev;
    slot->ino  = (uint64_t)st.st_ino;
    slot->size = 0;          // dir sizes change; identity is dev+ino
    fd_shadow_set_path(slot, path);
}

// Shared slot allocator for both register flavors.
static FdShadow* fd_shadow_alloc_slot(int want_fd) {
    for (size_t i = 0; i < g_fd_shadow_count; ++i) {
        if (g_fd_shadow[i].fd == want_fd) return &g_fd_shadow[i];
    }
    for (size_t i = 0; i < g_fd_shadow_count; ++i) {
        if (g_fd_shadow[i].fd < 0) return &g_fd_shadow[i];
    }
    if (g_fd_shadow_count < sizeof(g_fd_shadow) / sizeof(g_fd_shadow[0])) {
        return &g_fd_shadow[g_fd_shadow_count++];
    }
    return nullptr;
}

static void fd_shadow_set_path(FdShadow* slot, const char* orig_path) {
    size_t n = strlen(orig_path);
    if (n >= sizeof slot->orig_path) n = sizeof slot->orig_path - 1;
    memcpy(slot->orig_path, orig_path, n);
    slot->orig_path[n] = '\0';
}

// Find the shadow record whose fd matches AND whose identity still
// matches the live descriptor (memfd: dev/ino/size; proc dir: dev/ino
// — directory st_size can legitimately change). Returns nullptr for
// "not one of ours" (stale entries are invalidated here).
static FdShadow* fd_shadow_lookup(int fd, int kind) {
    for (size_t i = 0; i < g_fd_shadow_count; ++i) {
        if (g_fd_shadow[i].fd != fd || g_fd_shadow[i].kind != kind) continue;
        struct stat st;
        if (fstat(fd, &st) != 0) { g_fd_shadow[i].fd = -1; return nullptr; }
        if ((uint64_t)st.st_dev == g_fd_shadow[i].dev &&
            (uint64_t)st.st_ino == g_fd_shadow[i].ino &&
            (kind == FD_SHADOW_PROC_DIR ||
             (uint64_t)st.st_size == g_fd_shadow[i].size)) {
            return &g_fd_shadow[i];
        }
        // fd number reused for a different file — entry is dead.
        g_fd_shadow[i].fd = -1;
        return nullptr;
    }
    return nullptr;
}

// Find the shadow record by FILE IDENTITY (dup'd descriptors have new
// fd numbers but the same dev/ino). Caller has already fstat'd.
// memfd flavor only — readlink dups of directories answer the real
// directory path anyway (nothing to hide there).
static FdShadow* fd_shadow_scan_by_identity(uint64_t dev, uint64_t ino) {
    for (size_t i = 0; i < g_fd_shadow_count; ++i) {
        if (g_fd_shadow[i].fd >= 0 &&
            g_fd_shadow[i].kind == FD_SHADOW_MEMFD &&
            g_fd_shadow[i].dev == dev &&
            g_fd_shadow[i].ino == ino) {
            return &g_fd_shadow[i];
        }
    }
    return nullptr;
}

// Rewrite a filled-in `struct stat` to look like real procfs.
static void stat_rewrite_as_procfs(struct stat* st) {
    st->st_mode  = S_IFREG | 0444;
    st->st_size  = 0;
    st->st_blocks = 0;
    st->st_rdev  = 0;
    uint64_t pdev = zs_procfs_dev();
    if (pdev) st->st_dev = (dev_t)pdev;
    // st_ino: procfs inode numbers are dynamic per boot; any stable
    // non-zero value is indistinguishable from a real one.
    if (st->st_ino == 0) st->st_ino = 0x1000;
}

// Public helper used by the readlink hooks (hide_stealth.cpp).
// The REAL readlink result for one of our memfds is
// "/memfd:scudo (deleted)" — the kernel prefixes memfd targets with
// '/' (verified on Linux host; the same format since memfd_create
// was introduced). Accept the prefixed and bare forms. `fd` is
// parsed from the /proc/<pid>/fd/<n> path.
// Returns the spoofed length (>0), or 0 when no spoof applies.
ssize_t hide_advanced_spoof_memfd_readlink(int fd, const char* real_target,
                                           size_t real_len, char* buf,
                                           size_t bufsiz) {
    if (fd < 0 || !buf || bufsiz == 0) return 0;
    static const char kMemfdMark[] = "memfd:scudo";
    constexpr size_t kMemfdMarkLen = sizeof(kMemfdMark) - 1;
    const char* t = real_target;
    size_t tl = real_len;
    if (tl > 0 && t[0] == '/') { ++t; --tl; }
    if (tl < kMemfdMarkLen ||
        memcmp(t, kMemfdMark, kMemfdMarkLen) != 0) {
        return 0;   // not one of ours (or a genuinely other memfd)
    }
    // Direct hit by fd number, else identity scan for dups.
    FdShadow* rec = fd_shadow_lookup(fd, FD_SHADOW_MEMFD);
    if (!rec) {
        struct stat st;
        if (fstat(fd, &st) != 0) return 0;
        rec = fd_shadow_scan_by_identity((uint64_t)st.st_dev,
                                         (uint64_t)st.st_ino);
        if (!rec) return 0;
    }
    size_t n = strlen(rec->orig_path);
    if (n > bufsiz) n = bufsiz;          // readlink truncation semantics
    memcpy(buf, rec->orig_path, n);
    return (ssize_t)n;
}

// Round 16: relative-path /proc resolution. A detector that cannot
// use an absolute /proc path (both arms of the R11 fix) can still get
// there relatively:
//     chdir("/proc/self");   open("maps", ...)
//     dirfd = open("/proc/self", O_RDONLY|O_DIRECTORY);
//     openat(dirfd, "maps", ...)
// Both resolve to /proc/self/maps in the kernel; both must resolve
// to the same FILTERED file with us. State:
//   - g_cwd_proc_prefix: set by the chdir/fchdir hooks (and the
//     SYS_chdir/SYS_fchdir arms of the syscall hook) whenever the
//     process cwd is a /proc directory of ours; cleared on any other
//     successful chdir.
//   - FD_SHADOW_PROC_DIR records: any successful open of a /proc
//     directory fd (registered in wrapped_open/openat) lets a later
//     relative openat against that fd resolve through the prefix.
// The real syscall still receives the caller's ORIGINAL relative
// path and dirfd — kernel resolution semantics are unchanged; only
// the filter decision uses the reconstructed absolute path (and the
// memfd's readlink answer, which must match).
static char   g_cwd_proc_prefix[80];
static size_t g_cwd_proc_prefix_len = 0;

static void zs_set_cwd_proc_prefix(const char* dir) {
    if (dir && zs_is_proc_dir_prefix(dir)) {
        size_t n = strlen(dir);
        if (n >= sizeof g_cwd_proc_prefix) n = sizeof g_cwd_proc_prefix - 1;
        memcpy(g_cwd_proc_prefix, dir, n);
        g_cwd_proc_prefix[n] = '\0';
        g_cwd_proc_prefix_len = n;
        return;
    }
    g_cwd_proc_prefix[0] = '\0';
    g_cwd_proc_prefix_len = 0;
}

// Lexically normalize an absolute path: resolve "." and ".."
// textually (the kernel resolves them too — a relative
// "task/../maps" from a proc dirfd lands on the filtered file, so
// the reconstruction must classify it). Bounded; returns the length
// written (with NUL), or 0 when it does not fit / is not absolute.
static size_t zs_normalize_path(const char* in, char* out, size_t cap) {
    if (!in || in[0] != '/' || cap < 2) return 0;
    size_t w = 0;
    const char* p = in;
    while (*p) {
        while (*p == '/') ++p;
        if (!*p) break;
        const char* comp = p;
        size_t clen = 0;
        while (*p && *p != '/') { ++p; ++clen; }
        if (clen == 1 && comp[0] == '.') continue;
        if (clen == 2 && comp[0] == '.' && comp[1] == '.') {
            while (w > 0 && out[w - 1] != '/') --w;
            if (w > 0) --w;              // drop the '/' as well
            continue;
        }
        if (w + 1 + clen + 1 > cap) return 0;
        out[w++] = '/';
        // memmove, not memcpy: the Round 22 heap twin calls this with
        // in == out (in-place normalization). The write cursor never
        // passes the read cursor (w <= p-comp), so ranges only ever
        // overlap forward — but overlapping memcpy is formally UB and
        // the sanitizer's interceptor would flag it.
        memmove(out + w, comp, clen);
        w += clen;
    }
    if (w == 0) out[w++] = '/';
    out[w] = '\0';
    return w + 1;
}

// prefix + "/" + rel, lexically normalized, into out. Returns 0 when
// it cannot fit the stack cap (callers fall back to the heap variant
// below — Round 22 closed the old "fall through UNFILTERED" residual,
// which a detector could reach with any traversal string over ~380
// bytes: openat(proc_dirfd, "task/../" * 64 + "maps")).
static int zs_join_proc_dir(const char* prefix, const char* rel,
                             char* out, size_t cap) {
    if (!prefix || !rel || prefix[0] != '/' || !rel[0]) return 0;
    constexpr size_t kMaxJoined = 384;
    size_t plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') --plen;
    size_t rlen = strlen(rel);
    if (plen + 1 + rlen + 1 > kMaxJoined) return 0;
    char joined[kMaxJoined];
    memcpy(joined, prefix, plen);
    joined[plen] = '/';
    memcpy(joined + plen + 1, rel, rlen + 1);
    return zs_normalize_path(joined, out, cap) > 0;
}

// Heap twin for the overflow case (cold path: only when the joined
// string exceeds 383 bytes). Returns a malloc'd normalized absolute
// path the caller owns, or null. Normalization never grows the
// string, so the joined buffer is reused in place — the w<=p write
// cursor invariant of zs_normalize_path makes the aliasing safe.
static char* zs_join_proc_dir_heap(const char* prefix, const char* rel) {
    if (!prefix || !rel || prefix[0] != '/' || !rel[0]) return nullptr;
    size_t plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') --plen;
    size_t rlen = strnlen(rel, 4096);
    if (rel[rlen] != '\0') return nullptr;   // unreasonably long
    if (plen + 1 + rlen + 2 > 4096 + 128) return nullptr;
    char* joined = (char*)malloc(plen + 1 + rlen + 2);
    if (!joined) return nullptr;
    memcpy(joined, prefix, plen);
    joined[plen] = '/';
    memcpy(joined + plen + 1, rel, rlen + 1);
    size_t n = zs_normalize_path(joined, joined, plen + 1 + rlen + 2);
    if (n == 0) { free(joined); return nullptr; }
    return joined;
}

// Public helper used by the readlink hooks (hide_stealth.cpp).
// Round 23: resolve a RELATIVE path against a tracked /proc dirfd (or
// the tracked /proc cwd) into a malloc'd, lexically-normalized
// ABSOLUTE path (caller frees). Returns null when nothing tracked
// matches — callers must then treat the path as unresolvable and
// pass through, exactly as before this round. The readlink/readlinkat
// hooks used to skip ALL of their matchers for relative paths:
//     int dfd = open("/proc/self", O_DIRECTORY);
//     readlinkat(dfd, "fd/3", buf, sz);      // leaked "memfd:scudo"
//     chdir("/proc/self"); readlink("exe", buf, sz);
// — the same bypass class the Round 16 openat closure fixed for open.
char* hide_advanced_resolve_proc_relative(int dirfd, const char* rel) {
    if (!rel || rel[0] == '/') return nullptr;
    if (!hide_advanced_is_active()) return nullptr;
    const char* prefix = nullptr;
    if (dirfd != AT_FDCWD) {
        FdShadow* rec = fd_shadow_lookup(dirfd, FD_SHADOW_PROC_DIR);
        if (!rec) return nullptr;
        prefix = rec->orig_path;
    } else {
        if (g_cwd_proc_prefix_len == 0) return nullptr;
        prefix = g_cwd_proc_prefix;
    }
    if (!prefix || prefix[0] != '/') return nullptr;
    char full[160];
    if (zs_join_proc_dir(prefix, rel, full, sizeof full)) {
        return strdup(full);
    }
    // Cold path: >383-byte joined traversals (same discipline as the
    // open wrappers — never fall through unfiltered for size reasons).
    return zs_join_proc_dir_heap(prefix, rel);
}

// Wrap the original open so the caller gets back either the original
// fd (for non-filtered paths) or a filtered memfd (for filtered
// paths).
static int wrapped_open(const char* path, int flags, mode_t mode) {
    // Round 16: a relative open with a /proc cwd names the same file
    // the absolute path would — decide the filter on that path.
    // Round 22: overlong relative paths (>383 bytes joined) fall back
    // to a HEAP reconstruction instead of skipping the filter (the
    // old fall-through was a documented bypass).
    char full[160];
    char* heap_full = nullptr;
    const char* filter_path = path;
    if (path && path[0] != '/' && g_cwd_proc_prefix_len > 0) {
        if (zs_join_proc_dir(g_cwd_proc_prefix, path, full, sizeof full)) {
            filter_path = full;
        } else {
            heap_full = zs_join_proc_dir_heap(g_cwd_proc_prefix, path);
            if (heap_full) filter_path = heap_full;
        }
    }
    int real_fd = g_real_open
        ? g_real_open(path, flags, mode)
        : (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
    if (real_fd < 0) { free(heap_full); return real_fd; }

    if (filter_path && filter_path[0] == '/' &&
        zs_is_proc_dir_prefix(filter_path)) {
        fd_shadow_register_proc_dir(real_fd, filter_path);
    }
    int keep = !zs_path_is_filtered(filter_path);
    if (keep) { free(heap_full); return real_fd; }

    int memfd = make_filtered_memfd(real_fd, filter_path);
    close(real_fd);
    if (memfd >= 0) {
        // NOTE: register BEFORE free — fd_shadow_set_path strdups the
        // path, and the heap twin is freed right after (the sanitizer
        // suite caught the reversed order as a use-after-free).
        fd_shadow_register(memfd, filter_path);
        free(heap_full);
        return memfd;
    }
    // Round 15: fail-open. memfd_create exists since Linux 3.17 —
    // every Android 8+ device kernel (3.18 floor) has it, so this
    // branch is only reachable under ENOMEM-class pressure. The old
    // behavior (EBADF after closing the real fd) made every /proc read
    // fail bizarrely in exactly that situation — a louder anomaly
    // than serving the unfiltered file. Log and hand back the real fd.
    ZS_LOGW("hide_advanced: filter memfd unavailable; passing the real "
            "fd for %s through unfiltered", filter_path);
    free(heap_full);
    // B2 history: never return the closed fd — re-open instead.
    return g_real_open
        ? g_real_open(path, flags & ~O_TRUNC, mode)
        : (int)syscall(SYS_openat, AT_FDCWD, path, flags & ~O_TRUNC, mode);
}

static int wrapped_openat(int dirfd, const char* path, int flags,
                          mode_t mode) {
    // Round 16: relative path + tracked /proc dirfd (or a /proc cwd
    // with AT_FDCWD) resolves through the reconstructed absolute
    // path, exactly like wrapped_open above. Round 22: the heap
    // fallback covers traversal strings too long for the stack path.
    char full[160];
    char* heap_full = nullptr;
    const char* filter_path = path;
    if (path && path[0] != '/' && hide_advanced_is_active()) {
        FdShadow* rec = (dirfd != AT_FDCWD)
            ? fd_shadow_lookup(dirfd, FD_SHADOW_PROC_DIR)
            : nullptr;
        if (rec) {
            if (zs_join_proc_dir(rec->orig_path, path, full,
                                 sizeof full)) {
                filter_path = full;
            } else {
                heap_full = zs_join_proc_dir_heap(rec->orig_path, path);
                if (heap_full) filter_path = heap_full;
            }
        } else if (dirfd == AT_FDCWD && g_cwd_proc_prefix_len > 0) {
            if (zs_join_proc_dir(g_cwd_proc_prefix, path, full,
                                 sizeof full)) {
                filter_path = full;
            } else {
                heap_full = zs_join_proc_dir_heap(g_cwd_proc_prefix, path);
                if (heap_full) filter_path = heap_full;
            }
        }
    }
    // Round 11: an ABSOLUTE path ignores dirfd (POSIX), so the filter
    // decision must not depend on dirfd either — the old
    // `dirfd != AT_FDCWD` passthrough let a detector bypass the
    // filter by passing any arbitrary fd with an absolute /proc
    // path. Relative paths still pass through untouched (we lack
    // the context to resolve them). The real openat below receives
    // the caller's dirfd unchanged, which preserves exact semantics.
    int real_fd = g_real_openat
        ? g_real_openat(dirfd, path, flags, mode)
        : (int)syscall(SYS_openat, dirfd, path, flags, mode);
    if (real_fd < 0) { free(heap_full); return real_fd; }

    if (filter_path && filter_path[0] == '/' &&
        zs_is_proc_dir_prefix(filter_path)) {
        fd_shadow_register_proc_dir(real_fd, filter_path);
    }
    int keep = !zs_path_is_filtered(filter_path);
    if (keep) { free(heap_full); return real_fd; }

    int memfd = make_filtered_memfd(real_fd, filter_path);
    close(real_fd);
    if (memfd >= 0) {
        fd_shadow_register(memfd, filter_path);   // before free (see open)
        free(heap_full);
        return memfd;
    }
    // Round 15 fail-open — see wrapped_open.
    ZS_LOGW("hide_advanced: filter memfd unavailable; passing the real "
            "fd for %s through unfiltered", filter_path);
    free(heap_full);
    return g_real_openat
        ? g_real_openat(dirfd, path, flags & ~O_TRUNC, mode)
        : (int)syscall(SYS_openat, dirfd, path, flags & ~O_TRUNC, mode);
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
    else if (strchr(mode, 'r') && strchr(mode, '+')) flags = O_RDWR;
    // Round 15: real fopen() adds O_CLOEXEC ONLY for mode strings
    // containing 'e' (the glibc/bionic "e" extension). The old
    // fallback added it unconditionally — an exec'd helper would
    // silently lose the fd it should have inherited.
    if (strchr(mode, 'e')) flags |= O_CLOEXEC;
    int fd = g_real_open
        ? g_real_open(path, flags, 0666)
        : (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0666);
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
    if (memfd < 0) {
        // Round 15 fail-open: serve the real stream rather than a
        // broken FILE* (see wrapped_open).
        ZS_LOGW("hide_advanced: filter memfd unavailable; fopen passthru");
        return zs_real_fopen(path, mode);
    }
    fd_shadow_register(memfd, path);
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
// Round 15 (section 5e, defined below the stat family): fill `st`
// with procfs fiction when `fd` is one of our tracked memfds.
static int fd_stat_as_procfs(int fd, struct stat* st);

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
    // Round 20: the mounted properties file answers the REAL file's
    // identity (stock st_dev/st_ino), never the session file's.
    if (hide_advanced_is_active() && path && st &&
        strcmp(path, hide_props_serial_target_path()) == 0 &&
        hide_props_stat_fiction(st)) {
        return 0;
    }
    if (ZS_LIKELY(!hide_advanced_is_active()) || !path_is_hidden(path)) {
        return g_real_stat
            ? g_real_stat(path, st)
            : (int)syscall(SYS_stat, path, st);
    }
    errno = ENOENT;
    return -1;
}

extern "C" int zygisk_study_hook_lstat(const char* path, struct stat* st) {
    // Round 20: same fiction as stat() — the target is a plain file,
    // so lstat and stat must agree on its identity.
    if (hide_advanced_is_active() && path && st &&
        strcmp(path, hide_props_serial_target_path()) == 0 &&
        hide_props_stat_fiction(st)) {
        return 0;
    }
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
    // Round 15: statx(dirfd, "", AT_EMPTY_PATH, ...) stats the FD
    // itself — and on aarch64 bionic's fstat() is IMPLEMENTED as
    // exactly this call, so this arm runs for every fstat() on
    // 64-bit ARM even when the app never names the empty path.
    if ((flags & AT_EMPTY_PATH) && (!path || path[0] == '\0') &&
        hide_advanced_is_active()) {
        struct stat st;
        if (fd_stat_as_procfs(dirfd, &st)) {
            if (!stx) { errno = EFAULT; return -1; }
            int rv = g_real_statx
                ? g_real_statx(dirfd, path, flags, mask, stx)
#ifdef SYS_statx
                : (int)syscall(SYS_statx, dirfd, path, flags, mask, stx);
#else
                : -1;
#endif
            if (rv != 0) return rv;
            // Overlay the procfs fiction onto the real statx result.
            stx->stx_mode  = (uint16_t)(S_IFREG | 0444);
            stx->stx_size  = 0;
            // NOTE: the mounted-properties fd fiction is handled
            // BELOW (after this block) so both arms share it.
#ifdef STATX_BLOCKS
            if (stx->stx_mask & STATX_BLOCKS) stx->stx_blocks = 0;
#else
            stx->__stx_padding0[0] = 0;   // bionic w/o STATX_BLOCKS
#endif
            uint64_t pdev = zs_procfs_dev();
            if (pdev) {
                stx->stx_dev_major = (uint16_t)(pdev >> 8);
                stx->stx_dev_minor = (uint16_t)(pdev & 0xff);
            }
            return 0;
        }
        // Round 20: statx(fd) of the MOUNTED properties file answers
        // the REAL file's identity (aarch64 bionic implements fstat()
        // as exactly this call, so the fd-keyed fiction must live
        // here too).
        struct stat raw;
        if (fstat(dirfd, &raw) == 0) {
            if (hide_props_stat_is_mounted_identity(&raw)) {
                struct stat fiction;
                if (hide_props_stat_fiction(&fiction)) {
                    if (!stx) { errno = EFAULT; return -1; }
                    stx->stx_mode = (uint16_t)fiction.st_mode;
                    stx->stx_size = (uint64_t)fiction.st_size;
                    stx->stx_ino  = fiction.st_ino;
                    stx->stx_dev_major = (uint16_t)(fiction.st_dev >> 8);
                    stx->stx_dev_minor = (uint16_t)(fiction.st_dev & 0xff);
                    return 0;
                }
            }
        }
    }
    // Round 20: statx(path) of the mounted properties file answers
    // the real file's identity fields.
    if (hide_advanced_is_active() && path && path[0] == '/' &&
        strcmp(path, hide_props_serial_target_path()) == 0) {
        int rv = g_real_statx
            ? g_real_statx(dirfd, path, flags, mask, stx)
#ifdef SYS_statx
            : (int)syscall(SYS_statx, dirfd, path, flags, mask, stx);
#else
            : -1;
#endif
        if (rv == 0 && stx) {
            struct stat fiction;
            if (hide_props_stat_fiction(&fiction)) {
                stx->stx_mode = (uint16_t)fiction.st_mode;
                stx->stx_size = (uint64_t)fiction.st_size;
                stx->stx_ino  = fiction.st_ino;
                stx->stx_dev_major = (uint16_t)(fiction.st_dev >> 8);
                stx->stx_dev_minor = (uint16_t)(fiction.st_dev & 0xff);
                return 0;
            }
        }
        return rv;
    }
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
// 5e. fstat / mmap hooks (Tier B) — Round 15, fd observable parity
// ------------------------------------------------------------------------
//
// The fd shadow table (section 5a) knows which descriptors are our
// filtered memfds. These hooks make those descriptors ANSWER like
// procfs files:
//   fstat(N)   -> mode 0444, size 0, blocks 0, the procfs st_dev
//   mmap(N)    -> MAP_FAILED / ENODEV (procfs files cannot be mapped)
//
// fstat matters doubly on aarch64: bionic implements fstat() as
// fstatat(AT_FDCWD, "", AT_EMPTY_PATH) — but apps calling fstat()
// directly through their PLT hit the fstat symbol, so hooking the
// symbol covers both call styles on both architectures.
using FstatFn = int (*)(int, struct stat*);
static FstatFn g_real_fstat = nullptr;

// Shared body: if `fd` is one of our tracked memfds, fill `st` with
// the procfs fiction and return 1. Returns 0 (st untouched) otherwise.
static int fd_stat_as_procfs(int fd, struct stat* st) {
    if (fd < 0 || !st) return 0;
    FdShadow* rec = fd_shadow_lookup(fd, FD_SHADOW_MEMFD);
    if (!rec) return 0;
    struct stat raw;
    if (fstat(fd, &raw) != 0) return 0;
    *st = raw;
    stat_rewrite_as_procfs(st);
    return 1;
}

extern "C" int zygisk_study_hook_fstat(int fd, struct stat* st) {
    if (ZS_LIKELY(!hide_advanced_is_active())) {
        return g_real_fstat ? g_real_fstat(fd, st)
                            : fstat(fd, st);
    }
    if (fd_stat_as_procfs(fd, st)) return 0;
    // Round 20: an fd of the MOUNTED properties file must answer the
    // REAL file's identity, not the session file's.
    int rv = g_real_fstat ? g_real_fstat(fd, st) : fstat(fd, st);
    if (rv == 0 && st && hide_props_stat_is_mounted_identity(st)) {
        if (hide_props_stat_fiction(st)) return 0;
    }
    return rv;
}

using MmapFn = void* (*)(void*, size_t, int, int, int, off_t);
static MmapFn g_real_mmap = nullptr;

// Real procfs files have no mmap handler: mapping an fd opened from
// /proc/self/maps fails with ENODEV. A memfd maps fine — so an mmap()
// that SUCCEEDS on a descriptor the app believes is /proc/self/maps is
// a hook detector with zero false positives. Reject mappings of our
// tracked fds exactly like procfs would.
extern "C" void* zygisk_study_hook_mmap(void* addr, size_t len, int prot,
                                        int flags, int fd, off_t off) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || fd < 0 || len == 0) {
        return g_real_mmap ? g_real_mmap(addr, len, prot, flags, fd, off)
                           : mmap(addr, len, prot, flags, fd, off);
    }
    if (fd_shadow_lookup(fd, FD_SHADOW_MEMFD)) {
        errno = ENODEV;             // exactly what procfs answers
        return MAP_FAILED;
    }
    return g_real_mmap ? g_real_mmap(addr, len, prot, flags, fd, off)
                       : mmap(addr, len, prot, flags, fd, off);
}

// ------------------------------------------------------------------------
// 5f. dl_iterate_phdr / dladdr hooks (Tier B) — Round 15, linker
//     enumeration closure
// ------------------------------------------------------------------------
//
// Tier A unmaps the exec/writable segments of our .so files and
// re-maps the read-only ones as anonymous "linker_alloc" pages, but
// the dynamic linker's internal soinfo entry SURVIVES (removing it
// safely is the crash class Round 8 (B6) stepped back from — solist
// surgery on the wrong Android linker version hard-crashes dlopen).
// The surviving soinfo is observable through TWO public libc entry
// points neither of which we hooked:
//
//   dl_iterate_phdr(cb, data)  hands cb every loaded DSO, ours
//                              included, with dlpi_name =
//                              "/data/adb/modules/<id>/libpayload.so"
//   dladdr(addr, &info)        for any address inside our (anonymous!)
//                              pages returns 1 and fills dli_fname
//                              with the same path — on a stock device
//                              an anonymous mapping answers 0.
//
// Hooking the enumeration instead of the solist keeps the crash
// safety: the linker state is untouched, only its REPORTED output is
// filtered.
//
// Version note (researched from AOSP bionic): dl_iterate_phdr and
// dladdr have been exported since API 21; the dlpi_adds/dlpi_subs
// counters exist in bionic's link.h across every supported release.
// A detector that compares dlpi_adds against the number of callback
// invocations would see the mismatch — so the trampoline passes each
// entry through a COPY of dl_phdr_info with dlpi_adds decremented by
// the number of hidden entries already skipped.
using DlIterateFn = int (*)(int (*)(struct dl_phdr_info*, size_t, void*),
                            void*);
static DlIterateFn g_real_dl_iterate_phdr = nullptr;

using DladdrFn = int (*)(const void*, Dl_info*);
static DladdrFn g_real_dladdr = nullptr;
using Dladdr1Fn = int (*)(const void*, Dl_info*, void**, int);
static Dladdr1Fn g_real_dladdr1 = nullptr;

// Is this dlpi_name / dli_fname one of ours (or a generic root
// framework path)? Empty names are the main executable / vdso — a
// stock process emits them and so do we.
static int dl_name_is_ours(const char* name) {
    if (!name || !name[0]) return 0;
    if (strstr(name, "/data/adb/") != nullptr) return 1;
    if (strstr(name, "zygisk_study") != nullptr) return 1;
    static const char* const kOurSoNames[] = {
        "libpayload.so", "libzygisk.so", "libzn_loader.so",
    };
    for (const char* s : kOurSoNames) {
        size_t n = __builtin_strlen(s);
        size_t l = strlen(name);
        if (l >= n && strcmp(name + (l - n), s) == 0) return 1;
    }
    return 0;
}

struct DlIterateEntry {
    struct dl_phdr_info info;   // copied — the callback may write to it
    size_t size;
    std::string name;           // copied: the linker may free the
                                // original string (concurrent dlclose)
                                // once the real walk ends
};

static int dl_iterate_collect_cb(struct dl_phdr_info* info, size_t size,
                                 void* data) {
    auto* out = (std::vector<DlIterateEntry>*)data;
    DlIterateEntry e;
    e.size = size;
    if (info) {
        e.info = *info;
        if (info->dlpi_name) e.name = info->dlpi_name;
    } else {
        memset(&e.info, 0, sizeof e.info);
    }
    out->push_back(std::move(e));
    return 0;   // collect everything; filtering happens at emission
}

extern "C" int zygisk_study_hook_dl_iterate_phdr(
        int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !cb) {
        return g_real_dl_iterate_phdr
            ? g_real_dl_iterate_phdr(cb, data)
            : dl_iterate_phdr(cb, data);
    }
    // Round 15 (revised after the first test run): the streaming
    // trampoline could not fix dlpi_adds for entries that came
    // BEFORE our (usually last-loaded) library, and emitting the
    // caller's callback after releasing the linker lock raced a
    // concurrent dlclose freeing dlpi_name. Collect-and-emit closes
    // both: one walk, one consistent snapshot, names copied out, and
    // every emitted entry carries the SAME uniformly adjusted
    // dlpi_adds — so the caller's "iterations == adds - subs"
    // arithmetic stays exact (verified by the host test that first
    // exposed this).
    try {
        std::vector<DlIterateEntry> entries;
        entries.reserve(16);
        int rv = g_real_dl_iterate_phdr
            ? g_real_dl_iterate_phdr(dl_iterate_collect_cb, &entries)
            : dl_iterate_phdr(dl_iterate_collect_cb, &entries);
        if (rv != 0) return rv;

        size_t hidden = 0;
        for (const DlIterateEntry& e : entries) {
            if (dl_name_is_ours(e.name.c_str())) ++hidden;
        }

        for (DlIterateEntry& e : entries) {
            if (dl_name_is_ours(e.name.c_str())) continue;
            e.info.dlpi_name = e.name.c_str();
            if (e.info.dlpi_adds >= hidden) {
                e.info.dlpi_adds -= hidden;
            }
            int r = cb(&e.info, e.size, data);
            if (r != 0) return r;   // early termination, same as the
                                    // real iterator's contract
        }
        return 0;
    } catch (...) {
        // OOM inside the copy buffers: fall back to the unfiltered
        // real iterator rather than unwinding through a C boundary.
        // (Stealth loss under memory exhaustion is acceptable; a
        // terminate() inside dl_iterate_phdr is not.)
        return g_real_dl_iterate_phdr
            ? g_real_dl_iterate_phdr(cb, data)
            : dl_iterate_phdr(cb, data);
    }
}

// dladdr: an address inside our anonymous remap answers "not found"
// (0) on a stock process; return exactly that. The Dl_info is zeroed
// first because a spec-conforming caller may check fields even when
// the return is 0.
extern "C" int zygisk_study_hook_dladdr(const void* addr, Dl_info* info) {
    int rv = g_real_dladdr ? g_real_dladdr(addr, info)
                           : dladdr(addr, info);
    if (rv == 0 || !hide_advanced_is_active() || !info) return rv;
    if (dl_name_is_ours(info->dli_fname)) {
        memset(info, 0, sizeof *info);
        return 0;
    }
    return rv;
}

extern "C" int zygisk_study_hook_dladdr1(const void* addr, Dl_info* info,
                                         void** extra, int flags) {
    int rv = g_real_dladdr1
        ? g_real_dladdr1(addr, info, extra, flags)
        : dladdr1(addr, info, extra, flags);
    if (rv == 0 || !hide_advanced_is_active() || !info) return rv;
    if (dl_name_is_ours(info->dli_fname)) {
        memset(info, 0, sizeof *info);
        return 0;
    }
    return rv;
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

// Round 22 — the SET-side round-trip. __system_property_set sends the
// write to init's property service over the socket; init updates the
// REAL area — which the hidden process no longer maps (the clone
// replaced it at the same addresses). Every subsequent read walks the
// clone and sees the OLD value: an app that sets a property and reads
// it back observes its own write FAILING. That is both a functional
// bug and a textbook detection vector (setprop X && getprop X != X).
// SEPolicy makes untrusted_app's writable namespace small, but the
// pattern still fires for the keys apps may write.
//
// Fix: after a SUCCESSFUL real set(), reflect the value into the
// clone's entry (bionic's own odd/even serial protocol, so concurrent
// reader threads are safe). The clone is PROT_READ at this point —
// mprotect the span RW for the patch and restore. Entries that would
// become long (>= 92 chars) are left alone: the clone cannot
// allocate, and app-settable long values are vanishingly rare
// (documented residual).
using PropSetFn = int (*)(const char*, const char*);
static PropSetFn g_real_prop_set = nullptr;
// The protection the clone pages end up with (PROT_READ in
// production; a host-test seam relaxes it for malloc'd fakes).
static int g_props_clone_prot = PROT_READ;

extern "C" int zygisk_study_hook_prop_set(const char* key,
                                          const char* value) {
    int rc = g_real_prop_set ? g_real_prop_set(key, value) : -1;
    if (rc != 0 || !hide_advanced_is_active() || !g_props_cloned ||
        !key || !value) {
        return rc;
    }
    if (strnlen(value, kPropValueSize) >= kPropValueSize) {
        return rc;   // long value: cannot reflect (documented residual)
    }
    // Only existing clone entries can be patched; a genuinely NEW key
    // would need trie allocation in the clone (left as the residual —
    // a new-key set-then-read is not a round-trip any stock behavior
    // would contradict, since the reader sees "absent", the same as a
    // set that failed SEPolicy).
    const void* pi = g_find_prop ? g_find_prop(key) : nullptr;
    if (!pi) return rc;
    // Page span of the 96 bytes we may touch (value + serial can
    // straddle a page boundary).
    static long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uintptr_t start = (uintptr_t)pi & ~(uintptr_t)(page_size - 1);
    uintptr_t end = ((uintptr_t)pi + kPropValueOffset + kPropValueSize +
                     (uintptr_t)(page_size - 1)) & ~(uintptr_t)(page_size - 1);
    size_t span = (size_t)(end - start);
    int restored = 0;
    if (mprotect((void*)start, span, PROT_READ | PROT_WRITE) == 0) {
        patch_prop_value(pi, value);
        // g_props_clone_prot is what the clone finalized with (R in
        // production). Restoring to it keeps the anomaly surface flat.
        if (mprotect((void*)start, span,
                     g_props_clone_prot) != 0) {
            restored = 0;
        } else {
            restored = 1;
        }
    }
    if (!restored) {
        ZS_LOGW("hide_advanced: prop set reflect failed for %s "
                "(mprotect)", key);
    }
    return rc;
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

// Raw getdents64 layout (neither glibc nor bionic headers expose it
// for direct syscall use). d_reclen advances the walk; d_name is the
// file name. Defined here (rather than at the fd scan below, which
// also uses it) because the SYS_getdents64 arm of the syscall hook
// needs it first.
#pragma pack(push, 1)
struct zs_linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[256];
};
#pragma pack(pop)

static int zs_dirent_name_is_hidden(const char* name);   // scandir sect.

// Round 16: in-place compaction of a getdents64 buffer that drops
// every entry naming a root-framework artifact. Applied to the
// RESULT of a raw syscall(SYS_getdents64) call (the only way to read
// a directory without libc readdir). Each kept record keeps its own
// d_off cookie — seekdir/telldir semantics survive entry removal.
//
// NOTE: d_name in zs_linux_dirent64 is a max-size template; real
// records are variable-length (d_reclen = 19-byte header + name +
// NUL, padded). The bounds checks validate the HEADER before the
// reclen is trusted, then the reclen before anything else is read —
// the first version of this function demanded a full 275-byte struct
// per record and "filtered" every directory to empty (caught by its
// own test).
static size_t zs_filter_getdents64(char* buf, size_t len) {
    constexpr size_t kHdr = 19;   // d_ino(8)+d_off(8)+d_reclen(2)+d_type(1)
    size_t off = 0, write = 0;
    while (off < len) {
        if (len - off < kHdr) break;             // truncated header
        struct zs_linux_dirent64* de =
            (struct zs_linux_dirent64*)(buf + off);
        if (de->d_reclen < kHdr + 2 ||           // name + NUL minimum
            off + de->d_reclen > len) {
            break;                               // corrupt record
        }
        size_t reclen = de->d_reclen;
        // Bounded name check: the kernel NUL-terminates names within
        // the record, but a garbage/hostile buffer might not — strcmp
        // would then walk past the buffer. strnlen bounds it first.
        size_t name_max = reclen - kHdr;
        size_t name_len = strnlen(de->d_name, name_max);
        if (name_len == name_max) {
            // No terminator inside the record: not a valid kernel
            // record — keep it verbatim (kernel never produces this).
            if (write != off) {
                memmove(buf + write, buf + off, reclen);
            }
            write += reclen;
        } else if (!zs_dirent_name_is_hidden(de->d_name)) {
            if (write != off) {
                memmove(buf + write, buf + off, reclen);
            }
            write += reclen;
        }
        off += reclen;
    }
    return write;
}

// openat2's argument struct (Linux >= 5.6). Defined locally because
// no bionic release ships <linux/openat2.h> (verified against
// main-branch bionic libc/include/fcntl.h) and NDK sysroot headers
// only gained it recently.
struct zs_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
#ifndef SYS_openat2
#define SYS_openat2 437   // unified syscall number on all supported arches
#endif

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
#ifdef SYS_openat2
    if (number == (long)SYS_openat2) {
        // Round 15: openat2 (Linux 5.6+, i.e. Android 13+ kernels)
        // has NO bionic wrapper in ANY release (verified against
        // main-branch bionic libc/include/fcntl.h) — the only way an
        // app reaches it is exactly this raw syscall() call, which
        // used to sail past the open/openat arms above. open_how has
        // carried {flags, mode, resolve} since the syscall was added.
        const struct zs_open_how* how = (const struct zs_open_how*)a[2];
        const char* path = (const char*)a[1];
        if (path && path[0] == '/' && how &&
            a[3] >= (long)sizeof(*how) && zs_path_is_filtered(path)) {
            int flags = (int)how->flags;
            mode_t mode = (flags & O_CREAT) ? (mode_t)how->mode : 0;
            return wrapped_openat((int)a[0], path, flags, mode);
        }
    }
#endif
#ifdef SYS_fstat
    if (number == (long)SYS_fstat && hide_advanced_is_active()) {
        // x86_64-only raw path (aarch64 has no SYS_fstat — its fstat
        // is fstatat AT_EMPTY_PATH, covered by the statx hook).
        struct stat* st = (struct stat*)a[1];
        if (fd_stat_as_procfs((int)a[0], st)) return 0;
    }
#endif
#ifdef SYS_getdents64
    if (number == (long)SYS_getdents64 && hide_advanced_is_active()) {
        // Round 16: raw getdents64 (bypassing libc readdir) on any
        // directory drops entries naming root-framework artifacts.
        long rv = g_real_syscall
            ? g_real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5])
            : -ENOSYS;
        if (rv > 0) {
            rv = (long)zs_filter_getdents64((char*)a[1], (size_t)rv);
        }
        return rv;
    }
#endif
#ifdef SYS_chdir
    if (number == (long)SYS_chdir && hide_advanced_is_active()) {
        long rv = g_real_syscall
            ? g_real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5])
            : -ENOSYS;
        if (rv == 0) zs_set_cwd_proc_prefix((const char*)a[0]);
        return rv;
    }
#endif
#ifdef SYS_fchdir
    if (number == (long)SYS_fchdir && hide_advanced_is_active()) {
        long rv = g_real_syscall
            ? g_real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5])
            : -ENOSYS;
        if (rv == 0) {
            FdShadow* rec = fd_shadow_lookup((int)a[0], FD_SHADOW_PROC_DIR);
            zs_set_cwd_proc_prefix(rec ? rec->orig_path : nullptr);
        }
        return rv;
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

constexpr size_t kMaxGotHooks = 64;
// Round 17: the live registry hit 47/48 entries after Rounds 15-16 —
// one more hook and register_got_hook() would have SILENTLY refused
// (log warning only), leaving a stealth hole with zero test signal.
// Capacity is now 64, and the tier-B promotion test pins the exact
// live count so this can never drift unnoticed again.
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
    int    orig_prot;   // Round 17: the page protection the linker
                        // left the page with (see zs_page_prot_below).
};
static PatchedSlot g_patched_slots[kMaxPatchedSlots];
static size_t      g_patched_slot_count = 0;

// Round 17 (REAL BUG, found by the registry pin test): the patch and
// uninstall passes used to leave every touched GOT page as
// PROT_READ|PROT_EXEC. Two consequences:
//
//   1. LAZY BINDING CRASH: for any DSO whose .got.plt still resolves
//      lazily (third-party dlopen'd libs — exactly what the Tier B
//      dlopen re-walk patches), the dynamic linker WRITES the resolved
//      address into the slot at the first call. Writing to an RX page
//      faults. The host test binary hit this at process exit; an app
//      would hit it on the first call of any not-yet-resolved import
//      in a patched DSO.
//
//   2. PROT_EXEC on data pages is both wrong (GOT is data) and an
//      SELinux execmem-class check on Android that RW does not
//      trigger.
//
// The original protection is now COMPUTED from the ELF headers we
// are already iterating: pages inside PT_GNU_RELRO are what the
// linker made read-only; pages in a writable PT_LOAD are RW; the
// conservative fallback is RW (a writable page can never fault the
// lazy resolver).
static int zs_page_original_prot(const struct dl_phdr_info* info,
                                  uintptr_t page, size_t pagesize) {
    if (!info) return PROT_READ | PROT_WRITE;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_GNU_RELRO) continue;
        uintptr_t lo = base + ph.p_vaddr;
        uintptr_t hi = lo + ph.p_memsz;
        hi = (hi + pagesize - 1) & ~((uintptr_t)pagesize - 1);
        if (page >= lo && page < hi) return PROT_READ;
    }
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        uintptr_t lo = base + ph.p_vaddr;
        uintptr_t hi = lo + ph.p_memsz;
        if (page >= lo && page < hi) {
            return (ph.p_flags & PF_W) ? (PROT_READ | PROT_WRITE)
                                       : PROT_READ;
        }
    }
    return PROT_READ | PROT_WRITE;   // not in any segment: safe default
}

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
        int orig_prot = zs_page_original_prot(info, page,
                                              (size_t)pagesize);
        // Round 17: RW for the write window (no PROT_EXEC — data
        // pages must not gain execute permission, and SELinux
        // execmem checks on Android make that a real failure mode).
        if (mprotect(pageptr, (size_t)pagesize,
                     PROT_READ | PROT_WRITE) == 0) {
            // Record the original so the uninstall pass can restore
            // it before we unmap ourselves.
            if (g_patched_slot_count < kMaxPatchedSlots) {
                g_patched_slots[g_patched_slot_count].slot     = slot;
                g_patched_slots[g_patched_slot_count].original = current;
                g_patched_slots[g_patched_slot_count].orig_prot =
                    orig_prot;
                ++g_patched_slot_count;
            } else if (g_patched_slot_count == kMaxPatchedSlots) {
                ZS_LOGW("hide_advanced: patched-slot table full; "
                        "uninstall will be partial");
                ++g_patched_slot_count;  // log once
            }
            *slot = hook;
            // Restore the protection the linker left (RELRO pages R,
            // lazy .got.plt pages RW — leaving RW keeps the lazy
            // resolver working; leaving RX crashed it).
            mprotect(pageptr, (size_t)pagesize, orig_prot);
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
        // Round 17: RW window, then the RECORDED original protection
        // (the old hard-coded RX broke lazy binding — see
        // zs_page_original_prot).
        if (mprotect(pageptr, (size_t)pagesize,
                     PROT_READ | PROT_WRITE) == 0) {
            *slot = g_patched_slots[i].original;
            mprotect(pageptr, (size_t)pagesize,
                     g_patched_slots[i].orig_prot);
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
    if (!name) {
        errno = ENOENT;
        return nullptr;
    }
    // Hidden paths: answer ENOENT without touching the filesystem
    // (unchanged from Round 8).
    if (hide_advanced_is_active() && name[0] == '/' &&
        path_is_hidden(name)) {
        errno = ENOENT;
        return nullptr;
    }
    // Round 20: even for NON-hidden paths we must register a /proc
    // directory fd. opendir()'s internal open is a libc-INTERNAL
    // openat — it never crosses the GOT, so the open-family hooks
    // never see it, so no FD_SHADOW_PROC_DIR record exists for the
    // dirfd libc hands back. A detector doing
    //     DIR* d = opendir("/proc/self");
    //     openat(dirfd(d), "maps", O_RDONLY);
    // then read the REAL, unfiltered maps through the Round 16
    // relative-open path (the openat hook found no proc-dir record
    // and fell through to the kernel). Registering here closes the
    // last R16 residual: every subsequent openat/fchdir against
    // that fd resolves through the stored prefix and filters.
    DIR* d = g_real_opendir ? g_real_opendir(name) : nullptr;
    if (!d && !g_real_opendir) {
        // Fallback when dlsym failed: openat + fdopendir.
        int fd = (int)syscall(SYS_openat, AT_FDCWD, name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) return nullptr;
        d = fdopendir(fd);
        if (!d) { close(fd); return nullptr; }
    }
    if (d && hide_advanced_is_active() && name[0] == '/' &&
        zs_is_proc_dir_prefix(name)) {
        fd_shadow_register_proc_dir(dirfd(d), name);
    }
    return d;
}

// Round 22 — fdopendir(): the R15-17 residual. A DIR* can be built
// from ANY fd:  fd = open("/proc/self", O_RDONLY|O_DIRECTORY);
// d = fdopendir(fd);  openat(dirfd(d), "maps", ...). When the fd
// came through a hooked entry point it already carries a
// FD_SHADOW_PROC_DIR record (the openat hook registers every /proc
// dir it hands out), and the R20 opendir hook covers opendir(). The
// gap was an fd that NEVER crossed a hooked call — opened pre-hide
// or through a libc-internal path. The hook resolves the fd's link
// target with the REAL readlink (never our own readlink hook — no
// recursion) and registers the prefix. readdir() entry filtering is
// unchanged (it keys off names, not records).
using FdopendirFn = DIR* (*)(int);
static FdopendirFn g_real_fdopendir = nullptr;

extern "C" DIR* zygisk_study_hook_fdopendir(int fd) {
    DIR* d = g_real_fdopendir
        ? g_real_fdopendir(fd)
        : fdopendir(fd);
    if (d && fd >= 0 && hide_advanced_is_active() &&
        !fd_shadow_lookup(fd, FD_SHADOW_PROC_DIR)) {
        // Classify by link target: readlink("/proc/self/fd/<fd>")
        // answers the directory path the kernel has open.
        char link_path[48];
        snprintf(link_path, sizeof link_path, "/proc/self/fd/%d", fd);
        char target[128];
        ssize_t n = g_real_readlink_for_fd_scan
            ? g_real_readlink_for_fd_scan(link_path, target,
                                          sizeof target - 1)
            : -1;
        if (n > 0) {
            target[n] = '\0';
            if (zs_is_proc_dir_prefix(target)) {
                fd_shadow_register_proc_dir(fd, target);
            }
        }
    }
    return d;
}

// ------------------------------------------------------------------------
// chdir / fchdir hooks (Tier B) — Round 16
// ------------------------------------------------------------------------
//
// These exist ONLY to maintain g_cwd_proc_prefix: after
// chdir("/proc/self"), a relative open("maps") must resolve through
// the filter (see wrapped_open). Every other chdir is a pure
// passthrough that clears the state.
using ChdirFn  = int (*)(const char*);
using FchdirFn = int (*)(int);
static ChdirFn  g_real_chdir  = nullptr;
static FchdirFn g_real_fchdir = nullptr;

extern "C" int zygisk_study_hook_chdir(const char* path) {
    int rv = g_real_chdir ? g_real_chdir(path) : chdir(path);
    if (rv == 0 && hide_advanced_is_active()) {
        zs_set_cwd_proc_prefix(path);
    }
    return rv;
}

extern "C" int zygisk_study_hook_fchdir(int fd) {
    int rv = g_real_fchdir ? g_real_fchdir(fd) : fchdir(fd);
    if (rv == 0 && hide_advanced_is_active()) {
        FdShadow* rec = fd_shadow_lookup(fd, FD_SHADOW_PROC_DIR);
        zs_set_cwd_proc_prefix(rec ? rec->orig_path : nullptr);
    }
    return rv;
}

// ------------------------------------------------------------------------
// readdir / readdir_r hooks (Tier B) — Round 16
// ------------------------------------------------------------------------
//
// opendir()/scandir() gate HIDDEN directories, but the entries
// INSIDE a visible directory are the actual leak: listing "/" shows
// "debug_ramdisk", listing "/data" shows "adb" (stock non-root
// devices have no /data/adb — RootBeer and a decade of bank-app
// checkers look exactly there). The scandir hooks post-filter the
// namelist; plain opendir+readdir loops (Java File.list() included)
// go through the readdir symbol and were uncovered.
//
// The hook loops the real readdir until it yields a non-hidden entry
// or end-of-directory. Cost when active: a first-char gate plus at
// most ~14 exact strcmps per entry (kHiddenDirentNames is shared
// with the scandir filter — one source of truth). readdir_r is the
// same loop with its entry/result contract.
using ReaddirFn   = struct dirent* (*)(DIR*);
using ReaddirRFn = int (*)(DIR*, struct dirent*, struct dirent**);
static ReaddirFn   g_real_readdir   = nullptr;
static ReaddirRFn g_real_readdir_r = nullptr;

extern "C" struct dirent* zygisk_study_hook_readdir(DIR* dirp) {
    if (ZS_LIKELY(!hide_advanced_is_active())) {
        return g_real_readdir ? g_real_readdir(dirp) : readdir(dirp);
    }
    for (;;) {
        struct dirent* e =
            g_real_readdir ? g_real_readdir(dirp) : readdir(dirp);
        if (!e) return nullptr;
        if (!zs_dirent_name_is_hidden(e->d_name)) return e;
        // hidden entry — silently advance to the next one
    }
}

// readdir_r is deprecated on glibc AND in new bionic headers, but it
// remains exported from every bionic release (verified against
// main-branch bionic dirent.h) and 32-bit-era app code still calls
// it — hooking it is exactly as necessary as readdir.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
extern "C" int zygisk_study_hook_readdir_r(DIR* dirp,
                                           struct dirent* entry,
                                           struct dirent** result) {
    if (ZS_LIKELY(!hide_advanced_is_active()) || !entry || !result) {
        return g_real_readdir_r
            ? g_real_readdir_r(dirp, entry, result)
            : readdir_r(dirp, entry, result);
    }
    for (;;) {
        int rv = g_real_readdir_r
            ? g_real_readdir_r(dirp, entry, result)
            : readdir_r(dirp, entry, result);
        if (rv != 0) return rv;
        if (!*result) return 0;                    // end of directory
        if (!zs_dirent_name_is_hidden(entry->d_name)) return 0;
    }
}
#pragma GCC diagnostic pop

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
    // First-char gate: readdir filters EVERY directory entry of a
    // hidden app, so this runs millions of times; only names starting
    // with one of the hidden set's first chars reach the strcmp loop.
    switch (name[0]) {
        case 'm':   // magisk, magisk32, magisk64, magiskinit, magiskboot
        case '.':   // .magisk
        case 'k':   // ksu
        case 'z':   // zygiskd, zygisk_study
        case 'l':   // libzygisk.so, libpayload.so, libzn_loader.so
            break;
        default:
            return 0;
    }
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
// (ReadlinkFn / g_real_readlink_for_fd_scan are forward-declared near
// the top of the file — the fdopendir hook needs them too.)

// Raw getdents64 walk for this scan uses zs_linux_dirent64, defined
// at the syscall hook section (5d) where the getdents64 filter also
// lives. d_name is the fd number string.

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
    // Round 22: the set-side round-trip reflect.
    g_real_prop_set = (PropSetFn)zs_resolve_libc(
        "__system_property_set");
    g_real_scandir    = (ScandirFn)zs_resolve_libc("scandir");
    g_real_scandirat  = (ScandiratFn)zs_resolve_libc("scandirat");
    g_real_readlink_for_fd_scan = (ReadlinkFn)zs_resolve_libc("readlink");
    g_real_syscall    = (SyscallFn)zs_resolve_libc("syscall");
    g_real_dlopen     = (DlopenFn)zs_resolve_libc("dlopen");
    g_real_android_dlopen_ext = (AndroidDlopenExtFn)zs_resolve_libc(
        "android_dlopen_ext");
    g_real_dlclose    = (DlcloseFn)zs_resolve_libc("dlclose");
    g_real_opendir    = (OpendirFn)zs_resolve_libc("opendir");
    g_real_fdopendir  = (FdopendirFn)zs_resolve_libc("fdopendir");
    // Round 16 — relative-path resolution and directory-entry filtering.
    g_real_chdir      = (ChdirFn)zs_resolve_libc("chdir");
    g_real_fchdir     = (FchdirFn)zs_resolve_libc("fchdir");
    g_real_readdir    = (ReaddirFn)zs_resolve_libc("readdir");
    g_real_readdir_r  = (ReaddirRFn)zs_resolve_libc("readdir_r");
    // Round 15 — the fd-observable and linker-enumeration layers.
    g_real_fstat      = (FstatFn)zs_resolve_libc("fstat");
    g_real_mmap       = (MmapFn)zs_resolve_libc("mmap");
    g_real_dl_iterate_phdr =
        (DlIterateFn)zs_resolve_libc("dl_iterate_phdr");
    g_real_dladdr     = (DladdrFn)zs_resolve_libc("dladdr");
    g_real_dladdr1    = (Dladdr1Fn)zs_resolve_libc("dladdr1");

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
    // Round 22 — the set-side round-trip.
    hide_advanced_register_tier_b_hook("__system_property_set",
        (void*)&zygisk_study_hook_prop_set);
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
    // Round 22 — DIR* built from a bare fd (the R15-17 residual).
    hide_advanced_register_tier_b_hook("fdopendir",
        (void*)&zygisk_study_hook_fdopendir);
    // Round 9 (S1): scandir()/scandirat() build their dirent list
    // through libc-internal opendir/readdir, so the opendir GOT hook
    // does not see them. Post-filtering the result list here covers
    // the "simple API" detectors reach for first.
    hide_advanced_register_tier_b_hook("scandir",
        (void*)&zygisk_study_hook_scandir);
    hide_advanced_register_tier_b_hook("scandirat",
        (void*)&zygisk_study_hook_scandirat);
    // Round 15 — fd observable parity (fstat/fstat64 are one symbol
    // on LP64; registering both names is free where one is absent).
    hide_advanced_register_tier_b_hook("fstat",
        (void*)&zygisk_study_hook_fstat);
    hide_advanced_register_tier_b_hook("fstat64",
        (void*)&zygisk_study_hook_fstat);
    hide_advanced_register_tier_b_hook("mmap",
        (void*)&zygisk_study_hook_mmap);
    hide_advanced_register_tier_b_hook("mmap64",
        (void*)&zygisk_study_hook_mmap);
    // Round 15 — linker enumeration closure.
    hide_advanced_register_tier_b_hook("dl_iterate_phdr",
        (void*)&zygisk_study_hook_dl_iterate_phdr);
    hide_advanced_register_tier_b_hook("dladdr",
        (void*)&zygisk_study_hook_dladdr);
    hide_advanced_register_tier_b_hook("dladdr1",
        (void*)&zygisk_study_hook_dladdr1);
    // Round 16 — chdir tracking + readdir entry filtering. stat64/
    // lstat64 are 32-bit-ABI twins of already-hooked symbols (one
    // symbol on LP64); registering the names is free where absent.
    hide_advanced_register_tier_b_hook("chdir",
        (void*)&zygisk_study_hook_chdir);
    hide_advanced_register_tier_b_hook("fchdir",
        (void*)&zygisk_study_hook_fchdir);
    hide_advanced_register_tier_b_hook("readdir",
        (void*)&zygisk_study_hook_readdir);
    hide_advanced_register_tier_b_hook("readdir_r",
        (void*)&zygisk_study_hook_readdir_r);
    hide_advanced_register_tier_b_hook("stat64",
        (void*)&zygisk_study_hook_stat);
    hide_advanced_register_tier_b_hook("lstat64",
        (void*)&zygisk_study_hook_lstat);
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

// Round 22: the protection the prop-set reflect restores after
// patching (PROT_READ in production; tests relax it for heap fakes).
void zs_test_set_props_clone_prot(int prot) {
    g_props_clone_prot = prot;
}

// Round 22: drive the set hook with a fake real-set + fake find.
void zs_test_set_real_prop_set(int (*fn)(const char*, const char*)) {
    g_real_prop_set = (PropSetFn)fn;
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
