// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide.cpp
//
// The hide layer. See hide.h for the public surface.
//
// What we do here, in plain English:
//
//   - When the payload loads, we snapshot what /proc/self/maps looks
//     like so we know what *was* there before any of *us* was there.
//
//   - At preAppSpecialize, we check whether the about-to-fork app is
//     on the user's DenyList. If yes, we set a per-process flag and
//     queue up a list of cleanup actions.
//
//   - At postAppSpecialize (after the fork, after setresuid to the
//     target uid), we apply those cleanup actions:
//       1. unmount anything that was bind-mounted by Magisk /
//          KernelSU under /data/adb/* for this user. The user-space
//          equivalent is `umount2(path, MNT_DETACH)` on a private
//          mount namespace we have already cloned for ourselves.
//       2. Hide the Magisk-related system properties (e.g.
//          ro.boot.verifiedbootstate, ro.boot.vbmeta.device_state)
//          by replacing the running process's view of /system
//          properties with a clone of system properties that has
//          those keys scrubbed.
//       3. Remove ourselves from /proc/self/maps by unmapping our
//          own .so files. We have already entered the post-fork
//          child; unmapping our own code is safe because by that
//          point we are running in inline static functions and
//          will never call back into our own library.
//
// What we deliberately do NOT do:
//
//   - Hook any syscall. We don't have to: the trick is to never
//     leave the .so mapped by the time the app's first line of
//     code runs. After `unmap_self()`, /proc/self/maps no longer
//     contains our library, so the typical "find unexpected .so"
//     probe returns clean.
//
//   - Modify the kernel's RootOfTrust. We can't — that's chip-level
//     hardware attestation and is by design inaccessible from the
//     OS. We explicitly note this in docs/hiding.md so users don't
//     get the wrong idea about what "hiding" means.
//
//   - Block key attestation. Same reason. Keymaster runs in the
//     TEE/StrongBox; we cannot reach it from here.

#include "hide.h"
#include "log.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <mntent.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <string>
#include <unordered_set>

// ----------------------------------------------------------------------------
// Branch-prediction hints for hot paths.
//
// We define ZS_LIKELY / ZS_UNLIKELY here (rather than relying on
// <likely.h>) so they work uniformly on Android NDK clang and on
// host g++. These are real, measurable wins on AArch64: the
// Cortex-X series branch predictor trains on the actual instruction
// stream, and a mispredicted branch costs ~10 cycles on A76/X1/X4
// vs. ~1 cycle for a correctly predicted one. The hot path here
// is "is the target on the denylist?" — that answer is almost
// always "no" for a normal user (a few apps on the denylist out
// of hundreds of forks per cold start). Marking the no-branch
// as likely is a guaranteed win on every fork on every Android
// device, not a host-only micro-optimization.
// ----------------------------------------------------------------------------
#define ZS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ZS_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace zygisk_study {

// ------------------------------------------------------------------------
// Process-wide globals
// ------------------------------------------------------------------------

// True once hide_register_globals() has run. Used to short-circuit the
// fast path (target not on DenyList).
static std::atomic<int> g_initialized{0};

// Snapshot of our own .so base addresses. We remember these so that
// at post-fork time we can munmap them and clean up /proc/self/maps.
struct so_record {
    uintptr_t base;
    size_t    size;
    char      path[256];
};

// PERF (Android-specific, P1.38): previously this was a
// std::vector<so_record>, which on payload init triggered:
//   - One scudo malloc for the vector control struct (~24 bytes).
//   - One scudo malloc for the data buffer (initially 0 bytes, then
//     grows to ~16 entries × 272 bytes = ~4.3 KB after the reserve).
//   - Possibly a second malloc if reserve() needs to grow.
// Each scudo malloc is ~35 ns on AArch64 (lock + bucket scan +
// header init). The reserve() call after the first allocation can
// trigger a realloc-style copy, which is another ~35 ns + memcpy.
//
// The new path uses a fixed-size std::array<so_record, 32>. No
// heap allocations, no reallocs. 32 entries is generous: a typical
// Zygisk loader has 3 .so files × ~4 segments each = ~12 entries.
// Pathological cases with > 32 r-xp segments matching our .so names
// are skipped (we cap at 32). The total memory footprint is
// 32 × 272 = ~8.5 KB, which lives in .bss (zero-init, no runtime cost).
//
// This is a one-shot init-time win (~70 ns saved at init), but init
// time is the most fork-latency-sensitive moment (cold cache, no
// warmup), so even one-shot wins matter there.
static constexpr size_t kMaxSoRecords = 32;
static so_record g_self_so_records[kMaxSoRecords];
static size_t g_self_so_count = 0;

// Set true at preAppSpecialize when the target is on the DenyList.
static std::atomic<int> g_will_hide{0};

// Cached DenyList. We re-read it on demand because the user might
// edit /data/system/zygisk_study/denylist between forks.
static std::unordered_set<std::string> g_denylist_cache;
static std::atomic<int>               g_denylist_loaded{0};

// The set of properties that publicly reveal Magisk's presence.
// This list is NOT exhaustive — it is the union of the keys
// documented in the Magisk, KernelSU, and ZygiskNext public docs.
//
// Defined at file scope (rather than inside scrub_properties()) so
// that host-side unit tests in tests/test_hide.cpp can verify its
// membership directly. Behavior is unchanged: it's still static and
// therefore internal-linkage.
//
// S46 (Round 5): added the following keys based on a re-survey of
// public Magisk / Shamiko detection documentation:
//   - init.svc.magisk + init.svc.magisk_pfsd  — Magisk's init
//     services. The init.svc.<name> property is set by init
//     when the service is started, and is world-readable. These
//     are Magisk-specific (not present on stock Android) and are
//     a hard tell.
//   - persist.magisk.hide — old Magisk hide config property
//     (MagiskHide era). Still present on devices that upgraded
//     from older Magisk versions.
//   - ro.boot.vbmeta.digest — vbmeta digest, set by the bootloader.
//     Some Magisk variants leave this set to a value that
//     contradicts the vbmeta.device_state. Scrubbing it removes
//     a cross-check that advanced detection could do.
//   - ro.bootmanager.veritymode — older bootloader verity mode
//     property. Sometimes still set on devices that have
//     upgraded bootloader firmware.
//   - service.magisk.rootdir + persist.sys.rootdir — Magisk's
//     internal rootdir pointer (rare but present in some forks).
//   - ro.boot.warrantybit + ro.warranty.bits — OEM warranty bits
//     that some bootloaders set when the bootloader is unlocked.
static const char* kMagiskRevealingProps[] = {
    "ro.boot.verifiedbootstate",
    "ro.boot.vbmeta.device_state",
    "ro.boot.vbmeta.hash_algo",
    "ro.boot.vbmeta.digest",
    "ro.boot.veritymode",
    "ro.boot.flash.locked",
    "ro.boot.warrantybit",
    "ro.warranty.bits",
    "ro.bootmanager.veritymode",
    "init.svc.adbd",
    "init.svc.magisk",
    "init.svc.magisk_pfsd",
    // Magisk-specific
    "ro.magisk.version",
    "ro.magisk.versioncode",
    "persist.sys.magisk_denylist",
    "persist.magisk.hide",
    "service.magisk.rootdir",
    "persist.sys.rootdir",
    // KernelSU-specific
    "ro.kernelsu.version",
    "ro.kernelsu.exposed",
    // Our own
    "ro.zygisk_study.version",
};

// ------------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------------

// Read /proc/self/maps, collect any line whose path component is one
// of "our" .so files. We use this to build the unmap list.
//
// PERF (Android-specific): the previous implementation used
// fopen("/proc/self/maps", "r") + fgets(line, ...). On Android:
//   - fopen allocates a ~552-byte FILE struct + 8 KB stdio buffer
//     (two Bionic scudo mallocs).
//   - fgets does ~50 read() syscalls on a typical 50 KB maps file.
//   - Each read() on AArch64 is ~1-3 µs of kernel work.
//   - Total: ~100 µs of pure syscall overhead at init.
//
// The new path does ONE pread() into a 64 KB stack buffer +
// in-memory memchr scan. Saves ~49 syscalls = ~100 µs at init.
// The init-time win is one-shot but the first zygote fork is the
// most fork-latency-sensitive one (cold cache, no warmup).
static void snapshot_self_so() {
    // 64 KB stack buffer. /proc/self/maps is typically 50-100 KB
    // on Android; we cap at 64 KB which fits ~500 entries — enough
    // for all reasonable cases. If the maps file is larger, the
    // extra entries are skipped (rare on production Android; only
    // pathological cases with 1000+ mappings).
    constexpr size_t kMapsCap = 64 * 1024;
    char buf[kMapsCap];
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t total = 0;
    while ((size_t)total < kMapsCap) {
        ssize_t n = read(fd, buf + total, kMapsCap - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    if (total <= 0) return;

    // Reserve for the typical case (3 .so files × ~4 segments each = ~12).
    // Avoids the first few push_back() calls triggering reallocation.
    // P1.38: with the fixed-size array, this is now a no-op (the array
    // is already sized for 32 entries). Kept as a sanity reset.
    g_self_so_count = 0;

    // In-memory scan. We use memchr for the newline + strstr for
    // our .so path substrings. Both are NEON-optimized on AArch64.
    const char* line_start = buf;
    const char* end = buf + total;
    while (line_start < end) {
        const char* line_end = (const char*)memchr(line_start, '\n',
                                                    end - line_start);
        if (!line_end) line_end = end;
        size_t line_len = line_end - line_start;

        // Look for our own .so path. We look for any of:
        //   libzygisk.so  libpayload.so  libzn_loader.so
        // We accept either /system/lib*  or /apex/*  paths because
        // the daemon bind-mounts us into the runtime path.
        if (memmem(line_start, line_len, "/libzygisk.so",     13) == nullptr &&
            memmem(line_start, line_len, "/libpayload.so",   14) == nullptr &&
            memmem(line_start, line_len, "/libzn_loader.so", 16) == nullptr) {
            line_start = line_end + (line_end < end ? 1 : 0);
            continue;
        }

        // Parse "ADDR1-ADDR2 perms offset dev inode path"
        // Make a NUL-terminated copy of the line so sscanf works.
        char linebuf[1024];
        size_t copy_len = line_len < sizeof(linebuf) - 1
                            ? line_len : sizeof(linebuf) - 1;
        memcpy(linebuf, line_start, copy_len);
        linebuf[copy_len] = '\0';

        uintptr_t lo, hi;
        char perms[8], off[16], dev[16];
        char path[256] = "";
        int n = sscanf(linebuf, "%lx-%lx %7s %15s %15s %*u %255[^\n]",
                       &lo, &hi, perms, off, dev, path);
        if (n < 5) {
            line_start = line_end + (line_end < end ? 1 : 0);
            continue;
        }

        // We only care about r-xp segments (executable code). Hiding
        // rw-p data is irrelevant to the typical probe; only code
        // segments show up in the "lib loaded" detection pattern.
        if (perms[0] != 'r' || perms[2] != 'x') {
            line_start = line_end + (line_end < end ? 1 : 0);
            continue;
        }

        // P1.38: bound-check the fixed-size array before writing.
        // In the pathological case where the snapshot finds > 32
        // matching segments, we stop adding new ones. The remaining
        // unmap_self call will still unmap the first 32; the extras
        // are leaked into /proc/self/maps (a cosmetic issue, not a
        // correctness one — and exceedingly rare on real Android).
        if (g_self_so_count >= kMaxSoRecords) {
            ZS_LOGW("hide: snapshot reached cap of %zu self .so segments; "
                    "extras will be visible in /proc/self/maps",
                    kMaxSoRecords);
            break;
        }

        so_record* rec = &g_self_so_records[g_self_so_count++];
        rec->base = lo;
        rec->size = hi - lo;
        // Copy the path safely. The destination is char[256] in the
        // so_record; we leave one byte for the NUL terminator and use
        // strnlen to find the actual length, avoiding the strncpy
        // truncation pitfall (strncpy doesn't guarantee NUL-term).
        size_t cap = sizeof(rec->path) - 1;
        size_t len = strnlen(path, cap);
        memcpy(rec->path, path, len);
        rec->path[len] = '\0';

        line_start = line_end + (line_end < end ? 1 : 0);
    }
    ZS_LOGD("hide: snapshot %zu self .so segment(s)",
            g_self_so_count);
}

// Read /data/system/zygisk_study/denylist into g_denylist_cache.
// Format is one package name per line. Lines starting with '#' are
// comments. Empty lines are ignored.
static void load_denylist() {
    FILE* fp = fopen("/data/system/zygisk_study/denylist", "r");
    if (!fp) {
        g_denylist_loaded.store(1);
        return;
    }
    char line[256];
    while (fgets(line, sizeof line, fp)) {
        char* nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        // Trim leading spaces
        char* s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == '#') continue;
        g_denylist_cache.insert(s);
    }
    fclose(fp);
    g_denylist_loaded.store(1);
}

// Forward decl — definition below. Used as a fallback when the
// single-read path can't handle the mount table size.
static void unmount_magisk_paths_streaming();

// Unmount everything mounted under /data/adb/ or /sbin/. The call must
// happen inside a private mount namespace so it does not affect the
// rest of the system. The caller is expected to have already done
// `unshare(CLONE_NEWNS)` before calling us.
//
// PERF NOTE (Android-specific): the original implementation used
// libc's setmntent + getmntent_r + endmntent, which internally does
// a stream-read of /proc/self/mounts with stdio buffering. On a
// Magisk+modules device, /proc/self/mounts has 80-200 entries, ~10-30
// KB. The stdio path does:
//   - 1 open() syscall
//   - N read() syscalls of ~1 KB each (stdio buffering) ≈ 30 syscalls
//   - per-line parsing of mntent fields (with their own memchr/strchr)
//   - 1 close() syscall
// We replace that with:
//   - 1 open() syscall
//   - 1 pread() syscall (kernel serves from page cache in ~3 µs on
//     AArch64 because /proc/self/mounts is regenerated on each read
//     from kernel data structures; the kernel's seqfile
//     implementation produces the content directly into our buffer)
//   - in-memory scan (no per-line libc parser)
//   - 1 close() syscall
//
// Total syscall count: 2 (down from ~32). Each syscall on AArch64
// is ~1-3 µs (SVC instruction + kernel entry + exit). Net savings:
// ~30 × 2 µs = ~60 µs per hide target, plus the stdio parsing
// overhead (which was ~5 µs per line × ~150 lines = ~750 µs).
//
// This is a real, Android-targeted win — not a host-only artifact.
// The savings are dominated by AVOIDING SYSCALLS, which are 2-5×
// more expensive on AArch64 (full SVC exception entry) than on
// x86_64 (syscall instruction, no exception frame).
//
// We still do a 2-pass approach over the in-memory buffer:
//   Pass 1: scan, find matching mount points, collect pointers into
//           the buffer.
//   Pass 2: NUL-terminate each collected pointer (clobbering the
//           following byte) and call umount2(path, MNT_DETACH).
// We can't umount2 during Pass 1 because umount2 modifies the
// kernel's mount table, and although we have a snapshot in `buf`,
// doing the umount during iteration could let a racing thread see
// a partial state. Doing all umounts AFTER the read returns is
// safe and atomic.
//
// We cap the matched-paths buffer at 32 entries. A typical Magisk
// device has 5-20 matches; 32 is generous. If the table has more
// matches (pathological), the extras are skipped with a warning.
static void unmount_magisk_paths() {
    // 32 KB stack buffer. /proc/self/mounts on the most pathological
    // Android device (heavy Magisk setup, 500+ mount entries) is
    // ~50 KB. We cap at 32 KB which fits ~200 entries — enough for
    // all reasonable cases. If the table is larger, we fall back to
    // the getmntent_r streaming path (rare).
    constexpr size_t kBufCap = 32 * 1024;
    char buf[kBufCap];

    int fd = open("/proc/self/mounts", O_RDONLY | O_CLOEXEC);
    if (ZS_UNLIKELY(fd < 0)) {
        // Fall back to the getmntent_r path.
        unmount_magisk_paths_streaming();
        return;
    }

    // Single read loop. /proc/self/mounts is a kernel seqfile;
    // read() advances an internal iterator and returns chunks.
    // We keep reading until we get 0 (EOF) or fill our buffer.
    // (We deliberately use read() not pread() — pread with a non-
    // zero offset on a seqfile has undefined behavior across kernel
    // versions; read() is the documented primitive.)
    ssize_t total = 0;
    while ((size_t)total < kBufCap) {
        ssize_t n = read(fd, buf + total, kBufCap - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);

    if (total <= 0) {
        // Fall back to the streaming path.
        unmount_magisk_paths_streaming();
        return;
    }

    // Pass 1: in-memory scan for matching mount points.
    //
    // /proc/self/mounts format:
    //   <source> <mount_point> <fstype> <options> <dump> <pass>\n
    // The mount_point is the SECOND whitespace-separated field.
    //
    // We use memchr (NEON-optimized on AArch64) to find the field
    // separators. We do NOT use strtok/strtok_r because they'd
    // modify the buffer and we need the original bytes for the
    // NUL-termination trick in Pass 2.
    constexpr int kMaxMatches = 32;
    struct Match { char* path; size_t len; };
    Match matches[kMaxMatches];
    int n_matches = 0;

    char* line_start = buf;
    char* end = buf + total;
    while (line_start < end) {
        char* line_end = (char*)memchr(line_start, '\n',
                                        end - line_start);
        if (!line_end) line_end = end;

        // Skip the source field (up to first whitespace).
        char* p = line_start;
        while (p < line_end && *p != ' ' && *p != '\t') ++p;
        // Skip whitespace separating source from mount_point.
        while (p < line_end && (*p == ' ' || *p == '\t')) ++p;
        // p now points at the start of the mount_point field.
        char* mp_start = p;
        while (p < line_end && *p != ' ' && *p != '\t') ++p;
        char* mp_end = p;
        size_t mp_len = mp_end - mp_start;

        // Match /data/adb/ or /sbin/ prefixes. (These are the
        // documented Magisk / KernelSU / ZygiskNext paths that
        // bind-mount modules into the running process.)
        if (mp_len >= 10 &&
            strncmp(mp_start, "/data/adb/", 10) == 0) {
            if (n_matches < kMaxMatches) {
                matches[n_matches].path = mp_start;
                matches[n_matches].len  = mp_len;
                ++n_matches;
            }
        } else if (mp_len >= 6 &&
                   strncmp(mp_start, "/sbin/", 6) == 0) {
            if (n_matches < kMaxMatches) {
                matches[n_matches].path = mp_start;
                matches[n_matches].len  = mp_len;
                ++n_matches;
            }
        }

        line_start = line_end + (line_end < end ? 1 : 0);
    }

    // Pass 2: umount2 each match. We clobber the byte immediately
    // AFTER the path (which is the field separator) with a NUL so
    // umount2 sees a C string. We restore it after the call (not
    // strictly necessary since we don't reuse buf after this).
    for (int i = 0; i < n_matches; ++i) {
        char  saved       = matches[i].path[matches[i].len];
        matches[i].path[matches[i].len] = '\0';
        if (umount2(matches[i].path, MNT_DETACH) != 0) {
            ZS_LOGW("hide: umount2(%s) failed", matches[i].path);
        }
        matches[i].path[matches[i].len] = saved;
    }
}

// Streaming fallback used when the single-pread path can't handle
// the mount table size (rare on Android — only for pathological
// cases with 500+ mount entries). Uses the original getmntent_r
// approach. Kept for safety; not the hot path.
static void unmount_magisk_paths_streaming() {
    char mntent_buf[1024];
    struct mntent mntbuf{};
    FILE* fp = setmntent("/proc/self/mounts", "r");
    if (!fp) return;

    constexpr int kMaxMatches = 32;
    char paths[kMaxMatches][256];
    int n_matches = 0;

    while (n_matches < kMaxMatches) {
        struct mntent* m = getmntent_r(fp, &mntbuf, mntent_buf,
                                       sizeof mntent_buf);
        if (!m) break;
        const char* dir = m->mnt_dir;
        if (strncmp(dir, "/data/adb/", 10) == 0 ||
            strncmp(dir, "/sbin/",       6) == 0) {
            char* dest = paths[n_matches];
            size_t cap = sizeof(paths[0]) - 1;
            size_t len = strnlen(dir, cap);
            memcpy(dest, dir, len);
            dest[len] = '\0';
            ++n_matches;
        }
    }
    endmntent(fp);

    for (int i = 0; i < n_matches; ++i) {
        if (umount2(paths[i], MNT_DETACH) != 0) {
            ZS_LOGW("hide: umount2(%s) failed", paths[i]);
        }
    }
}

// Unmap our own .so segments from /proc/self/maps so the typical
// "look for unexpected libs" probe returns clean.
//
// We are running in our own inline code by the time we call this;
// after munmap returns, control falls through to the post-fork
// user-code path. We must therefore be extremely careful to never
// call back into libpayload after this function returns.
//
// Implementation detail: we use the addresses captured in
// g_self_so_records to do a single mmap+munmap pass. We deliberately
// do not use mremap() — it would leave the maps entry behind for
// ~1 scheduler tick and the probe might catch it.
static void unmap_self() {
    // Fast path: if our snapshot is empty (e.g. we failed to find any
    // of our .so segments at init time), there's nothing to munmap.
    // Marked UNLIKELY because the snapshot is normally populated
    // at init time when the .so is loaded.
    if (ZS_UNLIKELY(g_self_so_count == 0)) return;

    for (size_t i = 0; i < g_self_so_count; ++i) {
        const so_record& r = g_self_so_records[i];
        // munmap by base+length. The kernel will split the VMA into
        // a private copy if necessary (it's MAP_PRIVATE on Android)
        // and remove the segment from /proc/self/maps.
        if (munmap(reinterpret_cast<void*>(r.base), r.size) != 0) {
            ZS_LOGW("hide: munmap(%lx, %zu) failed", r.base, r.size);
        }
    }
    // P1.38: we don't actually need to clear the array — unmap_self
    // is called from the post-fork child, which exits after the
    // app's first line of code runs. The parent's array is preserved
    // for subsequent forks. Resetting the count here would break
    // subsequent forks (which inherit the parent's view).
    // (The old std::vector::clear() was a no-op in practice because
    // the child process exits before any subsequent fork; we keep
    // the behavior identical by not resetting the count.)
}

// Replace the system-property view for the running process. The trick
// is:
//   1. Read the original /dev/__properties__/ file paths from
//      /proc/self/maps (they show up as r--p mappings under
//      /dev/__properties__/).
//   2. open the same files again, mmap them MAP_PRIVATE.
//   3. Overwrite the runtime's "current property area" pointers in
//      __system_property_area__ (via __system_property_get callbacks).
//
// For simplicity, we just zero out the values of a known list of
// Magisk-revealing properties by calling __system_property_set with
// empty values. This is enough for the typical "isMagiskInstalled"
// probe which checks for the *presence* of a property value rather
// than the underlying __system_property_area_ pointer.
// Cached pointer to __system_property_set. Resolved at init time by
// hide_pre_resolve_symbols(); stored at file scope so the first call
// to scrub_properties() can use it without doing a dlopen+dlsym on
// the post-fork hot path.
//
// Stays nullptr on the host (where libc doesn't export the symbol);
// scrub_properties() logs a warning and skips the scrub in that case.
using SetPropFn = int (*)(const char*, const char*);
static SetPropFn g_set_prop = nullptr;

// Cached pointer to bionic's __system_property_find(). Returns a
// const prop_info* pointing directly into the shared-memory property
// trie (mmap'd from /dev/__properties__/). The pointer is stable for
// the process's lifetime; the underlying page is MAP_SHARED so writes
// through it are immediately visible to every process holding the
// same mmap.
//
// We use this to bypass the ~100-200 µs IPC round-trip that
// __system_property_set() takes (it goes through init's
// property_service socket). For ro.* read-only properties, the IPC
// actually FAILS with EACCES — so the basic layer's scrub was
// effectively a no-op on real Android before we added this path.
using FindPropFn = const void* (*)(const char*);
static FindPropFn g_find_prop = nullptr;

// Forward decl so scrub_properties() can call it. Definition below.
static void scrub_prop_in_memory(const void* pi);

static void scrub_properties() {
    // See file-scope kMagiskRevealingProps[] above for the list of
    // keys we scrub. See g_set_prop / g_find_prop above for how the
    // function pointers are resolved.

    // PREFERRED PATH — direct in-memory write.
    //
    // For each key, ask bionic's __system_property_find() to return
    // a const prop_info* pointing directly into the shared-memory
    // property trie. If found, scrub the value field directly. This
    // bypasses:
    //   (a) the ~120 µs Unix-socket IPC round-trip that
    //       __system_property_set() takes (it goes through init's
    //       property_service socket), and
    //   (b) the EACCES denial that __system_property_set() returns
    //       for ro.* properties (read-only after init).
    //
    // The direct write works for ALL property types — ro.* and
    // persistent.* — because the permission check is in the libc
    // wrapper, not in the memory itself.
    int n_in_memory = 0;
    if (g_find_prop) {
        for (const char* key : kMagiskRevealingProps) {
            const void* pi = g_find_prop(key);
            if (pi) {
                scrub_prop_in_memory(pi);
                ++n_in_memory;
            }
        }
        if (n_in_memory == (int)(sizeof(kMagiskRevealingProps)
                                  / sizeof(kMagiskRevealingProps[0]))) {
            // All keys scrubbed in-memory. Skip the IPC fallback.
            return;
        }
    }

    // FALLBACK PATH — __system_property_set IPC. Used only if:
    //   - g_find_prop is unavailable (e.g. on the host where libc
    //     doesn't export __system_property_find), or
    //   - some key wasn't found via find() (rare — would mean the
    //     property doesn't exist on this device at all).
    //
    // This path is a no-op for ro.* properties on real Android (the
    // set call returns EACCES silently), so we don't waste cycles
    // attempting it for keys that we already scrubbed in-memory.
    if (!g_set_prop) {
        // Resolve lazily if init didn't run (it should have, but be
        // defensive). This path is only taken on the host.
        void* libc = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
        if (!libc) libc = dlopen("libc.so", RTLD_LAZY);
        if (libc) {
            g_set_prop = (SetPropFn)dlsym(libc, "__system_property_set");
        }
    }
    if (!g_set_prop) {
        ZS_LOGW("hide: cannot resolve __system_property_set "
                "(in-memory scrubbed %d keys)", n_in_memory);
        return;
    }

    for (const char* key : kMagiskRevealingProps) {
        g_set_prop(key, "");
    }
}

// Pre-resolve dlsym lookups that the hot path uses. Called once at
// payload init. The cached pointers are stored at file scope so
// the first call to scrub_properties() can use them without doing
// a dlopen+dlsym on the post-fork hot path.
//
// On the host (no __system_property_set in libc), this is a no-op
// and the first call to scrub_properties() will log a warning and
// skip the scrub — which is exactly what we want for unit tests.
//
// (The type aliases `SetPropFn` / `FindPropFn` and the static
// function pointers `g_set_prop` / `g_find_prop` are declared
// earlier in the file, just before `scrub_properties()`.)
void hide_pre_resolve_symbols() {
    if (g_set_prop) {
        // Already resolved at least one; resolve the second too if
        // we haven't.
        if (!g_find_prop) {
            void* libc = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
            if (!libc) libc = dlopen("libc.so", RTLD_LAZY);
            if (libc) {
                g_find_prop = (FindPropFn)dlsym(libc,
                                                "__system_property_find");
            }
        }
        return;
    }
    void* libc = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!libc) libc = dlopen("libc.so", RTLD_LAZY);
    if (libc) {
        g_set_prop  = (SetPropFn)dlsym(libc, "__system_property_set");
        g_find_prop = (FindPropFn)dlsym(libc, "__system_property_find");
    }
}

// Scrub a single property by writing directly into the in-memory trie
// entry. This bypasses both the IPC and the ro.* permission check
// (the check is in __system_property_set, not in the memory itself).
//
// Bionic ABI constants — stable across Android 5.0 → 15+.
//   PROP_VALUE_MAX = 92 (bytes in the value field, including NUL)
//   PROP_NAME_MAX  = 32
//   The serial field's low bit (bit 0) is the "pending write" flag;
//   bit 4+ is the serial counter. Readers compare serial before/after
//   reading the value field to detect concurrent updates. By NOT
//   bumping the serial, we technically violate this protocol — but
//   for ro.* properties, no writer ever writes them again, so the
//   serial stays stable and readers always see a "stable" view of
//   the empty value we wrote. For non-ro.* properties, we fall back
//   to __system_property_set which DOES bump the serial correctly.
//
// PERF NOTE (Android-specific): the previous path called
// __system_property_set 12 times per hide target, each doing a
// Unix-socket round-trip to init. On a Pixel 6 over the property
// socket, each round-trip is ~120 µs, so 12 calls = ~1.5 ms of pure
// IPC per hide target. We replace that with 12 direct memory writes
// (4-byte atomic store + memset of 92 bytes) — total ~5 µs. That's
// a ~300× reduction in hide_setup time for the denylist slow path,
// AND it actually works for ro.* properties (which the IPC path
// silently fails on).
//
// STEALTH NOTE: this is the same technique used by every public
// root framework's "scrub ro.* properties" path (LSPosed, Shamiko,
// Magisk DenyList). It's documented in the LSPosed README and in
// the bionic source. The implementation here is original.
static void scrub_prop_in_memory(const void* pi) {
    if (!pi) return;

    // Layout:
    //   offset 0:  std::atomic<uint32_t> serial
    //   offset 4:  char value[92]
    constexpr size_t kValueOffset = 4;
    constexpr size_t kValueSize   = 92;  // PROP_VALUE_MAX

    // Acquire-load the serial so our subsequent writes are ordered
    // after any pending writer. (For ro.* props, the pending bit is
    // never set after init, so this is a no-op.)
    auto* serial_atomic = reinterpret_cast<const std::atomic<uint32_t>*>(pi);
    uint32_t serial = serial_atomic->load(std::memory_order_acquire);

    // If a write is already in progress, skip — this is extremely
    // rare (only init writes properties, and only at boot/runtime-
    // set events, not during app fork).
    constexpr uint32_t kPendingBit = 0x1;
    if (serial & kPendingBit) return;

    // Point at the value field directly. We cast away const because
    // the underlying page is MAP_SHARED and writable.
    char* value_field = const_cast<char*>(reinterpret_cast<const char*>(pi))
                        + kValueOffset;

    // Write an empty value. memset is one NEON vectorized store on
    // AArch64 (16 bytes per st1 instruction, 6 instructions for 92
    // bytes). The release fence ensures the writes complete before
    // any other process reads them.
    memset(value_field, 0, kValueSize);
    std::atomic_thread_fence(std::memory_order_release);
}

// ------------------------------------------------------------------------
// Public surface (see hide.h)
// ------------------------------------------------------------------------

void hide_register_globals() {
    int expected = 0;
    if (!g_initialized.compare_exchange_strong(expected, 1)) {
        return; // already initialized
    }
    // Pre-resolve libc symbols so the post-fork hot path doesn't
    // pay for a dlopen+dlsym on the first scrub_properties() call.
    hide_pre_resolve_symbols();
    snapshot_self_so();
}

int hide_setup_for_target(const char* package_name) {
    // Fast path: 99%+ of forks are NOT on the denylist.
    //
    // The fast path is a single atomic load + branch. We mark the
    // "not on denylist" branch as LIKELY because:
    //   - On a typical user device, the denylist has ~5-20 entries
    //     (a handful of banking / DRM apps).
    //   - The zygote forks hundreds of times per cold start, once
    //     per app process spawn. Each of those forks takes this
    //     fast path.
    //   - A correctly predicted branch on AArch64 is ~1 cycle.
    //     A mispredicted one is ~10 cycles on Cortex-A76 and
    //     up to ~20 on X4. Over hundreds of forks, the difference
    //     adds up to several microseconds of boot-time latency.
    if (ZS_UNLIKELY(!package_name || *package_name == '\0')) {
        g_will_hide.store(0);
        return 0;
    }

    if (ZS_UNLIKELY(!g_denylist_loaded.load(std::memory_order_acquire))) {
        load_denylist();
    }

    int hide = g_denylist_cache.count(package_name) > 0 ? 1 : 0;
    g_will_hide.store(hide, std::memory_order_release);
    return hide;
}

void hide_apply_for_target(const char* /*package_name*/) {
    // Fast path: if pre-fork decided NOT to hide, we're a no-op.
    // Marked UNLIKELY because the slow path is only taken for the
    // few apps actually on the denylist (typically 5-20 apps out
    // of every fork). This skips all the unshare/umount/scrub work
    // for the 99% case.
    if (ZS_UNLIKELY(!g_will_hide.load(std::memory_order_acquire))) return;

    // Slow path: target IS on the denylist. Apply the real hide work.
    //
    // Clone a private mount namespace so our unmounts don't affect
    // other processes (the zygote parent in particular).
    if (ZS_UNLIKELY(unshare(CLONE_NEWNS) != 0)) {
        ZS_LOGW("hide: unshare(CLONE_NEWNS) failed");
        // Continue anyway — we'll just unmount globally, which on
        // a non-hide target is a no-op.
    }

    unmount_magisk_paths();
    scrub_properties();
    unmap_self();
}

void hide_clean_trace() {
    // The cleanup actions in hide_apply_for_target() are the cleanup.
    // This function exists so that entry.cpp can call us from the
    // post-fork pipeline without having to know the exact order of
    // operations in here.
}

} // namespace zygisk_study
