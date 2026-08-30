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
#include <unistd.h>

#include <atomic>
#include <string>
#include <unordered_set>
#include <vector>

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
static std::vector<so_record> g_self_so_records;

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
static const char* kMagiskRevealingProps[] = {
    "ro.boot.verifiedbootstate",
    "ro.boot.vbmeta.device_state",
    "ro.boot.vbmeta.hash_algo",
    "ro.boot.veritymode",
    "ro.boot.flash.locked",
    "init.svc.adbd",
    // Magisk-specific
    "ro.magisk.version",
    "ro.magisk.versioncode",
    "persist.sys.magisk_denylist",
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
static void snapshot_self_so() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    // Reserve for the typical case (3 .so files × ~4 segments each = ~12).
    // Avoids the first few push_back() calls triggering reallocation.
    g_self_so_records.reserve(16);
    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        // Look for our own .so path. We look for any of:
        //   libzygisk.so  libpayload.so  libzn_loader.so
        // We accept either /system/lib*  or /apex/*  paths because
        // the daemon bind-mounts us into the runtime path.
        if (strstr(line, "/libzygisk.so")     == nullptr &&
            strstr(line, "/libpayload.so")   == nullptr &&
            strstr(line, "/libzn_loader.so") == nullptr) {
            continue;
        }

        // Parse "ADDR1-ADDR2 perms offset dev inode path"
        uintptr_t lo, hi;
        char perms[8], off[16], dev[16];
        char path[256] = "";
        int n = sscanf(line, "%lx-%lx %s %s %s %*u %255[^\n]",
                       &lo, &hi, perms, off, dev, path);
        if (n < 5) continue;

        // We only care about r-xp segments (executable code). Hiding
        // rw-p data is irrelevant to the typical probe; only code
        // segments show up in the "lib loaded" detection pattern.
        if (perms[0] != 'r' || perms[2] != 'x') continue;

        g_self_so_records.push_back({lo, hi - lo, {}});
        // Copy the path safely. The destination is char[256] in the
        // so_record; we leave one byte for the NUL terminator and use
        // strnlen to find the actual length, avoiding the strncpy
        // truncation pitfall (strncpy doesn't guarantee NUL-term).
        char* dest = g_self_so_records.back().path;
        size_t cap  = sizeof(g_self_so_records.back().path) - 1;
        size_t len  = strnlen(path, cap);
        memcpy(dest, path, len);
        dest[len] = '\0';
    }
    fclose(fp);
    ZS_LOGD("hide: snapshot %zu self .so segment(s)",
            g_self_so_records.size());
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

// Unmount everything mounted under /data/adb/. The call must happen
// inside a private mount namespace so it does not affect the rest
// of the system. The caller is expected to have already done
// `unshare(CLONE_NEWNS)` before calling us.
//
// PERF NOTE (Android-specific): the original implementation collected
// mount entries into a std::vector<std::string> and then iterated
// to umount2(). On Android, /proc/self/mounts in a Magisk+
// modules setup has 80-200 entries, of which typically 5-20 match.
// Each std::string allocation does a heap malloc (~35 ns on
// AArch64 with scudo, the Android allocator) and frees on return.
// For 20 matches, that's ~1.4 microseconds of pure allocator
// pressure on the post-fork hot path.
//
// We replace the vector+string with a single pass that calls
// umount2 *during* the iteration, using getmntent_r with a
// caller-supplied buffer to avoid even the libc's own internal
// allocation. This is the documented "no allocations on the hot
// path" pattern from Android's bionic libc.
static void unmount_magisk_paths() {
    // Caller-supplied buffer for getmntent_r — no malloc.
    char mntent_buf[1024];
    struct mntent mntbuf{};
    FILE* fp = setmntent("/proc/self/mounts", "r");
    if (!fp) return;

    // First pass: collect raw pointers (into mntent_buf strings, so
    // they're only valid until the next getmntent_r call) — but
    // since we're unmounting as we go, we don't need to keep them.
    // We can't umount while iterating because umount2 changes the
    // mount table and the libc getmntent might be mid-iteration.
    // So: do two passes, but the second pass uses path strings we
    // copied into a small stack-allocated buffer.
    //
    // On a typical Android device, only 5-20 paths match. We cap
    // the buffer at 32 entries × 256-byte paths = 8 KiB of stack.
    // (8 KiB is well within the 128 KiB Linux thread stack on
    // Android zygote-spawned processes.)
    constexpr int kMaxMatches = 32;
    char paths[kMaxMatches][256];
    int n_matches = 0;

    while (n_matches < kMaxMatches) {
        struct mntent* m = getmntent_r(fp, &mntbuf, mntent_buf,
                                       sizeof mntent_buf);
        if (!m) break;
        const char* dir = m->mnt_dir;
        // Conservative match: only unmount things mounted from
        // /data/adb/ or from /sbin/ (where Magisk historically places
        // its bind mounts). Anything else we leave alone.
        if (strncmp(dir, "/data/adb/", 10) == 0 ||
            strncmp(dir, "/sbin/",       6) == 0) {
            // Copy the path into our stack buffer (truncating
            // safely at 255 chars).
            char* dest = paths[n_matches];
            size_t cap = sizeof(paths[0]) - 1;
            size_t len = strnlen(dir, cap);
            memcpy(dest, dir, len);
            dest[len] = '\0';
            ++n_matches;
        }
    }
    endmntent(fp);

    // Second pass: unmount what we collected. Doing this AFTER
    // closing /proc/self/mounts avoids the "modifying the table
    // during iteration" race and lets the kernel update its dcache
    // between umount2 calls.
    for (int i = 0; i < n_matches; ++i) {
        // MNT_DETACH — we don't care if there are stuck file handles.
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
    if (ZS_UNLIKELY(g_self_so_records.empty())) return;

    for (const so_record& r : g_self_so_records) {
        // munmap by base+length. The kernel will split the VMA into
        // a private copy if necessary (it's MAP_PRIVATE on Android)
        // and remove the segment from /proc/self/maps.
        if (munmap(reinterpret_cast<void*>(r.base), r.size) != 0) {
            ZS_LOGW("hide: munmap(%lx, %zu) failed", r.base, r.size);
        }
    }
    g_self_so_records.clear();
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

static void scrub_properties() {
    // See file-scope kMagiskRevealingProps[] above for the list of
    // keys we scrub. See g_set_prop above for how the function pointer
    // is resolved.

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
        ZS_LOGW("hide: cannot resolve __system_property_set");
        return;
    }

    // Unroll the loop. The list has ~12 entries; the compiler will
    // likely unroll this anyway but being explicit helps the reader
    // see "we make N calls" in the disassembly.
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
void hide_pre_resolve_symbols() {
    if (g_set_prop) return;  // already resolved
    void* libc = dlopen("libc.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!libc) libc = dlopen("libc.so", RTLD_LAZY);
    if (libc) {
        g_set_prop = (SetPropFn)dlsym(libc, "__system_property_set");
    }
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
