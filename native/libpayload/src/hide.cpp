// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide.cpp
//
// The hide layer. See hide.h for the public surface.
//
// What we do here, in plain English:
//
//   - When the payload loads, we snapshot what /proc/self/maps looks
//     like so we know what *was* there before any of *us* was there.
//     We record EVERY segment of our own .so files (read-only,
//     executable, and writable alike — hiding only the r-xp segments
//     leaves "libpayload.so" greppable in the data segment lines).
//
//   - When a fork targets a DenyList entry (matched by package name
//     or by uid/appId), we set a per-process flag and queue up a
//     list of cleanup actions.
//
//   - In the child, while it is STILL ROOT (before the runtime's
//     setresuid drops privileges — see entry.cpp's setresgid/
//     setresuid GOT hooks):
//       1. unshare(CLONE_NEWNS) + umount2(MNT_DETACH) everything
//          that Magisk / KernelSU bind-mounted. We match BOTH the
//          mount-point field and the source field of
//          /proc/self/mounts — magic mounts have their source under
//          /data/adb/modules/... and their mount point at the
//          /system/... path they overlay.
//       2. Per-process property spoofing is done by hide_advanced
//          (a content-preserving MAP_PRIVATE clone + value patch).
//          This layer only owns the key list. (The old direct write
//          into the shared /dev/__properties__ pages was removed:
//          it wrote to a read-only MAP_SHARED mapping — a crash and
//          a system-wide visible change, the opposite of stealthy.)
//       3. The self-unmap of our own .so segments is NOT done here;
//          entry.cpp defers it to the asm trampoline so no
//          libpayload code executes after the munmaps. Doing it
//          from C is a guaranteed SIGSEGV once the loop munmaps the
//          page the loop itself runs from.
//
// What we deliberately do NOT do:
//
//   - Hook any syscall from this file. The GOT hooks live in
//     hide_advanced.cpp / entry.cpp.
//
//   - Modify the kernel's RootOfTrust. We can't — that's chip-level
//     hardware attestation and is by design inaccessible from the
//     OS. We explicitly note this in docs/hiding.md so users don't
//     get the wrong idea about what "hiding" means.

#include "hide.h"
#include "log.h"
#include "obfstr.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ----------------------------------------------------------------------------
// Branch-prediction hints for hot paths.
// ----------------------------------------------------------------------------
#define ZS_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ZS_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace zygisk_study {

// ------------------------------------------------------------------------
// Process-wide globals
// ------------------------------------------------------------------------

// True once hide_register_globals() has run.
static std::atomic<int> g_initialized{0};

// Snapshot of the .so segments we must remove from denylisted
// children. Fixed-size (no heap) — see the P1.38 history note: the
// array lives in .bss, so a forked child inherits it via plain
// memory and there is no allocator activity on the fork path.
//
// P1.38 history: this was a std::vector<so_record>; the fixed array
// removed two scudo mallocs + a potential realloc at init.
//
// Round 7: entries now cover ALL segment permissions (was: r-xp
// only) and carry a flags word so the trampoline can distinguish
// "our own text/data" (defer to asm) from "other .so" (plain C
// munmap is fine).
static constexpr size_t kMaxSoRecords = 64;
static so_record g_self_so_records[kMaxSoRecords];
static size_t g_self_so_count = 0;

// Set true at setup time when the target is on the DenyList.
static std::atomic<int> g_will_hide{0};

// Cached DenyList (package names) + the uid family map.
static std::unordered_set<std::string> g_denylist_cache;
static std::atomic<int>                g_denylist_loaded{0};
// Round 29 — 1 while the LAST load_denylist() could not open one of
// the two tracked files. The refresh path retries the load every
// throttle interval while this is set (a permanently-failing open
// costs one fopen attempt per 2 s — nothing), so a transient EACCES
// at zygote start no longer freezes an empty deny/uid map for the
// entire boot.
static std::atomic<int>                g_last_load_open_fail{0};
static std::unordered_set<uid_t>       g_deny_app_ids;   // uid % 100000
static std::atomic<int>                g_uid_map_loaded{0};
// Round 12 — appId -> package name for EVERY package (not just
// denylisted ones). Filled in the same packages.list pass; used by
// the module dispatch layer to source the real specialize args.
// First entry wins for shared-appId packages (rare, deprecated).
static std::unordered_map<uid_t, std::string> g_pkg_map;
// Round 14 — bumped on every packages.list/DenyList (re)parse. The
// module dispatch layer's single-entry args cache keys on it, so a
// reload invalidates the cache in the same breath as the map.
static std::atomic<uint32_t> g_pkg_map_gen{1};
// Round 14 — the uid/gid key the LAST hide_setup_for_target_uid
// call decided on in this process. The uid-drop hook re-checks the
// DenyList only when its key differs (the standard child has the
// gid hook decide first with the same key — one hash lookup saved
// per fork; the uid!=gid corner still re-checks and stays correct).
static std::atomic<uint32_t> g_deny_decided_key{0};

// DenyList refresh: forked children inherit the zygote's loaded copy
// AND its load timestamp, so a wall-clock throttle would make every
// fork after boot re-read both files (~150 µs each) forever. Instead
// we stat() the denylist file (~1 µs) and reload only when its mtime
// actually changed — user edits still show up, the steady-state cost
// per fork is one stat.
static std::atomic<time_t> g_denylist_mtime{-1};
// Round 13 — packages.list mtime for the module-args staleness fix
// (see maybe_refresh_denylist).
static std::atomic<time_t> g_pkg_list_mtime{-1};

// Round 8 (P2): the mtime check itself is throttled. The pre-Round-8
// code stat()ed the denylist on EVERY fork of EVERY app (~1 µs of
// syscall per app launch, system-wide, forever). Children inherit
// the zygote's loaded copy AND its load timestamp, so a wall-clock
// throttle would degenerate to a per-fork re-read. Instead: a vDSO
// clock read (CLOCK_MONOTONIC_COARSE, ~20 ns, no context switch)
// gates the stat(); the stat() only runs at most once per interval.
// User edits still land within 2 seconds.
static constexpr time_t kDenylistRefreshIntervalSec = 2;
static std::atomic<time_t> g_next_refresh_check{0};
static int g_denylist_reload_count = 0;   // test observable

// DenyList file path. Overridable by host tests (the real path needs
// a root-owned /data/system tree that does not exist on the host).
static const char* g_denylist_path = nullptr;   // test override or lazy
ZS_OBFS_PATH(kDenylistPathDefault, "/data/system/zygisk_study/denylist")
static const char* denylist_path() {
    return g_denylist_path ? g_denylist_path : kDenylistPathDefault();
}

// The set of properties that publicly reveal Magisk's presence.
// This list is NOT exhaustive — it is the union of the keys
// documented in the Magisk, KernelSU, and ZygiskNext public docs.
//
// Round 7 note: these keys are no longer *emptied* in the shared
// property area (an empty value for ro.boot.verifiedbootstate is
// itself an anomaly — stock devices say "green"). They are either
// SPOOFED to stock values in the per-process clone (see
// hide_advanced.cpp) or made to look absent via the
// __system_property_find/get GOT hooks.
// ROUND 33 (stealth): the key list is a decode-once obfuscated table.
// Plaintext "ro.magisk.version" / "persist.sys.magisk_denylist" /
// "ro.zygisk_study.version" inside the world-readable libpayload.so
// is a direct root-management fingerprint for any file scanner.
// (The SPOOF VALUES for these keys live in hide_advanced.cpp.)
static const zsst::StrTable magisk_revealing_props_g = [] {
        zsst::StrTable b;
        b.add(ZS_OBFS("ro.boot.verifiedbootstate"));
        b.add(ZS_OBFS("ro.boot.vbmeta.device_state"));
        b.add(ZS_OBFS("ro.boot.vbmeta.hash_algo"));
        b.add(ZS_OBFS("ro.boot.vbmeta.digest"));
        b.add(ZS_OBFS("ro.boot.veritymode"));
        b.add(ZS_OBFS("ro.boot.flash.locked"));
        b.add(ZS_OBFS("ro.boot.warrantybit"));
        b.add(ZS_OBFS("ro.warranty.bits"));
        b.add(ZS_OBFS("ro.bootmanager.veritymode"));
        b.add(ZS_OBFS("init.svc.adbd"));
        b.add(ZS_OBFS("init.svc.magisk"));
        b.add(ZS_OBFS("init.svc.magisk_pfsd"));
        // Magisk-specific
        b.add(ZS_OBFS("ro.magisk.version"));
        b.add(ZS_OBFS("ro.magisk.versioncode"));
        b.add(ZS_OBFS("persist.sys.magisk_denylist"));
        b.add(ZS_OBFS("persist.magisk.hide"));
        b.add(ZS_OBFS("service.magisk.rootdir"));
        b.add(ZS_OBFS("persist.sys.rootdir"));
        // KernelSU-specific
        b.add(ZS_OBFS("ro.kernelsu.version"));
        b.add(ZS_OBFS("ro.kernelsu.exposed"));
        // Our own
        b.add(ZS_OBFS("ro.zygisk_study.version"));
        return b;
    }();;
static const zsst::StrTable& magisk_revealing_props() { return magisk_revealing_props_g; }

// Public read-only accessor so host tests can verify the key list
// without befriending the static. (ptrs[] is the compact stride-8
// char* view over the decoded entries.)
const char* const* hide_revealing_props(size_t* count) {
    const zsst::StrTable& t = magisk_revealing_props();
    if (count) *count = t.count;
    return t.ptrs;
}

// ------------------------------------------------------------------------
// /proc/self/maps snapshot
// ------------------------------------------------------------------------

// Read a /proc file fully into a heap-free fixed buffer. Returns the
// total bytes read (>=0), or -1 on failure. Sets *truncated to 1 if
// the file did not fit (the caller decides on a fallback strategy —
// Round 7 fix: the old code silently dropped the tail of large maps
// and mounts files, which both missed unmounts and left .so records
// unregistered; callers now handle truncation explicitly).
static ssize_t read_proc_file(const char* path, char* buf, size_t cap,
                              int* truncated) {
    if (truncated) *truncated = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while ((size_t)total < cap) {
        ssize_t n = read(fd, buf + total, cap - total);
        if (n <= 0) break;
        total += n;
    }
    // If the buffer filled and there is more data pending, the read
    // above exited via the cap condition while more content exists.
    if ((size_t)total == cap) {
        char probe;
        ssize_t more = read(fd, &probe, 1);
        if (more > 0 && truncated) *truncated = 1;
    }
    close(fd);
    return total;
}

// One line of a maps file, split into the fields we care about.
struct MapsLine {
    uintptr_t lo, hi;
    char      perms[8];
    char      path[256];
    int       has_path;
};

// Parse a single maps line (NUL-terminated copy in `line`).
// Returns 1 on success. `prot_out` receives the ZS_SEG_X/ZS_SEG_W
// bits for the segment (Round 8: Tier A needs to know HOW each
// segment disappears).
static int parse_maps_line(const char* line, MapsLine* out,
                           uint32_t* prot_out = nullptr) {
    char perms[8], off[32], dev[32];
    char path[256] = "";
    uintptr_t lo = 0, hi = 0;
    int n = sscanf(line, "%lx-%lx %7s %31s %31s %*u %255[^\n]",
                   &lo, &hi, perms, off, dev, path);
    if (n < 5) return 0;
    out->lo = lo;
    out->hi = hi;
    memcpy(out->perms, perms, sizeof out->perms);
    size_t len = strnlen(path, sizeof(out->path) - 1);
    memcpy(out->path, path, len);
    out->path[len] = '\0';
    out->has_path = (n >= 6) && len > 0;
    if (prot_out) {
        *prot_out = (uint32_t)
            ((strchr(perms, 'x') ? ZS_SEG_X : 0u) |
             (strchr(perms, 'w') ? ZS_SEG_W : 0u));
    }
    return 1;
}

// Extra path fragments registered for unmap (module .so files).
// Mutated only at init time in the zygote (single-threaded), read
// after fork in the child — no locking needed.
static std::vector<std::string> g_extra_so_fragments;

// Add a record if there is room and it is not already present.
static void add_so_record(uintptr_t lo, uintptr_t hi, uint32_t flags,
                          uint32_t prot) {
    if (lo >= hi) return;
    for (size_t i = 0; i < g_self_so_count; ++i) {
        if (g_self_so_records[i].base == lo) return; // dedupe
    }
    if (g_self_so_count >= kMaxSoRecords) {
        ZS_LOGW("hide: unmap record set full (%zu); extra segments "
                "will remain visible", kMaxSoRecords);
        return;
    }
    so_record* rec = &g_self_so_records[g_self_so_count++];
    rec->base  = lo;
    rec->size  = hi - lo;
    rec->flags = flags;
    rec->prot  = prot;
    rec->_pad  = 0;
}

// Round 8 (B9): app library directories. A mapping whose path lives
// under one of these belongs to the APP (its own bundled .so files),
// not to us — even when the file name collides with ours (an app is
// free to ship its own "libpayload.so"). Unmapping or anonymizing an
// app library would crash the app; the pre-Round-8 scanner matched on
// the bare file NAME, so a name collision was enough to do exactly
// that.
static const char* const kAppLibPathPrefixes[] = {
    "/data/app/",
    "/data/data/",
    "/data/user/",
    "/data/user_de/",
    "/mnt/expand/",
    "/storage/",
    "/sdcard/",
};

static int path_is_under_app_dirs(const char* path, size_t len) {
    for (const char* pre : kAppLibPathPrefixes) {
        size_t n = __builtin_strlen(pre);
        if (len >= n && memcmp(path, pre, n) == 0) return 1;
    }
    return 0;
}

// Should a maps path be treated as "one of ours"?
// self_hit -> ZS_SO_SELF (libpayload itself), otherwise ZS_SO_OTHER.
// Round 7: ALL permission bits are recorded (the old code only kept
// r-xp segments, which left the r--p/rw-p segment lines containing
// "libpayload.so" in /proc/self/maps after the unmap — the most
// basic `grep libpayload /proc/self/maps` probe still hit).
// Round 8 (B9): the file-name match now excludes app library
// directories (see kAppLibPathPrefixes).
// Round 30 — randomized-soname support. When customize.sh installs
// us as /system/lib[64]/lib<8-hex>-p.so with the bridge as
// lib<8-hex>.so, the fixed-name literals below would never match
// and the unmap record set would be EMPTY (Tier A silently dead).
// The REAL paths are discovered once at init: our own via dladdr
// (the linker's resolved path for THIS library) and the bridge's by
// the same "-p" coupling libzygisk uses. The fixed literals are
// kept as fallbacks — manual installs and host tests use them, and
// a literal match outside app directories is still correct there.
static char g_own_path[512];
static char g_bridge_path[512];
static int  g_paths_discovered = 0;

static void discover_own_paths() {
    if (g_paths_discovered) return;
    g_paths_discovered = 1;
    Dl_info info{};
    // Any function guaranteed to live in this library.
    if (dladdr((const void*)&hide_register_globals, &info) == 0 ||
        !info.dli_fname) {
        return;
    }
    snprintf(g_own_path, sizeof g_own_path, "%s", info.dli_fname);
    // Payload ".../lib<stem>-p.so" -> bridge ".../lib<stem>.so" (the
    // same coupling libzygisk's derive_payload_path uses). Anything
    // else: same directory + the legacy bridge name.
    size_t len = strlen(g_own_path);
    if (len > 6 && strcmp(g_own_path + len - 6, "-p.so") == 0) {
        // bridge = own path minus the "-p" (2 bytes before ".so")
        memcpy(g_bridge_path, g_own_path, len - 2);
        memcpy(g_bridge_path + len - 6, ".so", 4);
    } else {
        const char* slash = strrchr(g_own_path, '/');
        if (slash) {
            snprintf(g_bridge_path, sizeof g_bridge_path,
                     ZS_OBFS("%.*s/libzygisk.so"),
                     (int)(slash - g_own_path), g_own_path);
        }
    }
}

static void scan_maps_into_records(const char* buf, size_t total) {
    discover_own_paths();
    char linebuf[512];
    const char* line_start = buf;
    const char* end = buf + total;
    while (line_start < end) {
        const char* line_end =
            (const char*)memchr(line_start, '\n', end - line_start);
        if (!line_end) line_end = end;
        size_t copy_len = (size_t)(line_end - line_start);
        if (copy_len >= sizeof(linebuf)) copy_len = sizeof(linebuf) - 1;
        memcpy(linebuf, line_start, copy_len);
        linebuf[copy_len] = '\0';

        MapsLine ml{};
        uint32_t prot = 0;
        if (parse_maps_line(linebuf, &ml, &prot) && ml.has_path) {
            const size_t plen = strnlen(ml.path, sizeof(ml.path));
            int in_app_dir = path_is_under_app_dirs(ml.path, plen);
            // Round 30: the discovered (randomized) paths are
            // matched as exact full-path substrings; the legacy
            // literals remain for fixed-name layouts.
            int is_self = !in_app_dir &&
                          (strstr(ml.path, ZS_OBFS("libpayload.so")) != nullptr ||
                           (g_own_path[0] != 0 &&
                            strstr(ml.path, g_own_path) != nullptr));
            int is_ours =
                is_self ||
                (!in_app_dir &&
                 (strstr(ml.path, ZS_OBFS("libzygisk.so"))    != nullptr ||
                  strstr(ml.path, ZS_OBFS("libzn_loader.so")) != nullptr ||
                  (g_bridge_path[0] != 0 &&
                   strstr(ml.path, g_bridge_path) != nullptr)));
            if (is_ours) {
                add_so_record(ml.lo, ml.hi,
                              is_self ? ZS_SO_SELF : ZS_SO_OTHER, prot);
            } else if (!in_app_dir) {
                // Registered module .so paths (hide_register_extra_so).
                for (const std::string& frag : g_extra_so_fragments) {
                    if (strstr(ml.path, frag.c_str()) != nullptr) {
                        add_so_record(ml.lo, ml.hi, ZS_SO_OTHER, prot);
                        break;
                    }
                }
            }
        }
        line_start = line_end + (line_end < end ? 1 : 0);
    }
    ZS_LOGD("hide: snapshot %zu unmap record(s)", g_self_so_count);
}

void hide_rescan_records();

static void snapshot_self_so();

void hide_register_extra_so(const char* path_fragment) {
    if (!path_fragment || !*path_fragment) return;
    for (const std::string& frag : g_extra_so_fragments) {
        if (frag == path_fragment) return; // idempotent
    }
    g_extra_so_fragments.emplace_back(path_fragment);
    // No rescan here — callers batch their registrations and finish
    // with one hide_rescan_records() (a maps read per registration
    // was wasted work at init).
}

// Re-snapshot /proc/self/maps against the current fragment set.
// Called once after module loading completes.
void hide_rescan_records() {
    snapshot_self_so();
}

// Snapshot /proc/self/maps and record every segment of our .so files.
// (zygote preloads a lot). If truncated we log loudly — the missing
// records mean less complete hiding, not a crash.
static void snapshot_self_so() {
    g_self_so_count = 0;
    constexpr size_t kMapsCap = 96 * 1024;
    static char maps_buf[kMapsCap];
    int truncated = 0;
    ssize_t total = read_proc_file("/proc/self/maps", maps_buf,
                                   kMapsCap, &truncated);
    if (total <= 0) return;
    if (truncated) {
        ZS_LOGW("hide: /proc/self/maps exceeded %zu KB; some unmap "
                "records may be missing", kMapsCap / 1024);
    }
    scan_maps_into_records(maps_buf, (size_t)total);
}

// ------------------------------------------------------------------------
// DenyList loading (package names + uid map)
// ------------------------------------------------------------------------

// /data/system/packages.list maps package -> uid. One line:
//   <package> <uid> <debugFlag> <dataDir> <seInfo> <targetSdk> ...
// We only need the first two fields. Read as root in the zygote.
//
// The uid we store is the *appId family* (uid % 100000) so user 0,
// user 10 (work profile), and secondary users all match the same
// package.
ZS_OBFS_PATH(kPackagesListPathDefault, "/data/system/packages.list")
static const char* g_packages_list_path = nullptr;  // test override or lazy
static const char* packages_list_path() {
    return g_packages_list_path ? g_packages_list_path
                                : kPackagesListPathDefault();
}

// Round 29: returns a bitmask of the files that actually OPENED
// (bit 0 = denylist, bit 1 = packages.list; 3 = both), plus bits for
// files that EXIST but refused the open (bit 2 = denylist, bit 3 =
// packages.list — the EACCES/path-block case worth retrying). A file
// that is simply MISSING (ENOENT — host tests, first boot before PMS
// writes packages.list) is NOT a failure: the mtime path already
// picks the file up when it appears.
static int load_denylist_locked_state() {
    // Round 8 (caught by the new reload tests): the cache must be
    // rebuilt from scratch. The old code merged every reload into the
    // existing set — once a package was denylisted, REMOVING it from
    // the denylist file never took effect until the next zygote
    // restart.
    g_denylist_cache.clear();
    ++g_pkg_map_gen;
    FILE* fp = fopen(denylist_path(), "r");
    int opened = 0;   // opened bits; blocked bits computed below
    int blocked = 0;
    if (fp) {
        opened |= 1;
        char line[256];
        while (fgets(line, sizeof line, fp)) {
            char* nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            char* s = line;
            while (*s == ' ' || *s == '\t') s++;
            if (*s == '\0' || *s == '#') continue;
            g_denylist_cache.insert(s);
        }
        fclose(fp);
    }
    g_denylist_loaded.store(1);
    ++g_denylist_reload_count;
    if (!fp) {
        struct stat probe{};
        if (stat(denylist_path(), &probe) == 0) blocked |= 4;
    }

    // uid map: denylist package names -> appIds.
    g_deny_app_ids.clear();
    // Round 12: full appId -> package map (module dispatch args).
    g_pkg_map.clear();
    fp = fopen(packages_list_path(), "r");
    if (fp) {
        opened |= 2;
        char line[1024];
        while (fgets(line, sizeof line, fp)) {
            char pkg[256] = "";
            unsigned long uid = 0;
            if (sscanf(line, "%255s %lu", pkg, &uid) == 2) {
                if (g_denylist_cache.count(pkg) > 0) {
                    g_deny_app_ids.insert((uid_t)(uid % 100000));
                }
                // The packages.list uid column is the user-0 uid; the
                // appId family key makes the map usable from children
                // of any profile/user.
                g_pkg_map.emplace((uid_t)(uid % 100000), pkg);
            }
        }
        fclose(fp);
    }
    g_uid_map_loaded.store(1);
    if (!fp) {
        struct stat probe{};
        if (stat(packages_list_path(), &probe) == 0) blocked |= 8;
    }
    return opened | blocked;
}

static void load_denylist() {
    int opens_ok = load_denylist_locked_state();
    // Round 29: latch the EXISTS-BUT-UNREADABLE case (blocked bits
    // 4/8). The old code latched g_*_loaded=1 no matter what, and the
    // refresh path only reloaded on an mtime CHANGE — so a load whose
    // fopen() was DENIED while the file existed (SELinux denial, a
    // kernel-side path block on the zygote's exe — the exact class
    // ReZygisk issue #380 documents on Samsung, or any other
    // transient EACCES) stored the CURRENT mtime and then never
    // reloaded: the empty deny map and the empty uid map stayed for
    // the whole boot, silently. A merely-missing file is NOT latched
    // (the mtime path picks it up when it appears; latching it would
    // burn one pointless fopen() per interval on hosts/early boot).
    g_last_load_open_fail.store((opens_ok & 0b1100) != 0,
                                std::memory_order_relaxed);
    struct stat st{};
    if (stat(denylist_path(), &st) == 0) {
        g_denylist_mtime.store(st.st_mtime, std::memory_order_relaxed);
    }
    struct stat pst{};
    if (stat(packages_list_path(), &pst) == 0) {
        g_pkg_list_mtime.store(pst.st_mtime, std::memory_order_relaxed);
    }
}

// Reload only when a tracked file's mtime moved, and only check the
// mtimes when the throttle interval has elapsed. Steady-state per-fork
// cost: one vDSO clock read.
//
// Round 13: packages.list is tracked TOO. The Round 12 module-args
// map is filled by the same parse as the DenyList uid map, but the
// reload used to trigger only on DENYLIST mtime changes — an app
// installed after zygote start had no package_name/app_data_dir in
// its specialize args until the next denylist edit. Now either
// file's change reloads both (one extra stat() per throttle
// interval, i.e. per 2 s at most, zero per-fork cost change).
static void maybe_refresh_denylist() {
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC_COARSE, &now);   // vDSO, ~20 ns
    if (now.tv_sec < g_next_refresh_check.load(std::memory_order_relaxed)) {
        return;
    }
    g_next_refresh_check.store(now.tv_sec + kDenylistRefreshIntervalSec,
                               std::memory_order_relaxed);
    // Round 13: each tracked file is checked INDEPENDENTLY. The
    // first version of this fix returned early when the denylist
    // stat() failed — which meant a device (or host) without a
    // denylist file never checked packages.list at all, restoring
    // the staleness the fix was for. Caught by the new test.
    int changed = 0;
    // Round 29: a load that failed to OPEN one of the files (they
    // existed but fopen() was denied) stored their CURRENT mtimes —
    // the mtime comparison below then sees "unchanged" and never
    // retries. While the failure latch is set, retry every interval:
    // a permanently failing open costs one fopen() per 2 s, a
    // transient one heals within 2 s instead of never.
    if (g_last_load_open_fail.load(std::memory_order_relaxed)) {
        changed = 1;
    }
    struct stat st{};
    if (stat(denylist_path(), &st) == 0 &&
        st.st_mtime != g_denylist_mtime.load(std::memory_order_relaxed)) {
        changed = 1;
    }
    struct stat pst{};
    if (stat(packages_list_path(), &pst) == 0 &&
        pst.st_mtime != g_pkg_list_mtime.load(std::memory_order_relaxed)) {
        changed = 1;
    }
    if (changed) load_denylist();
}

// ROUND 34 — the zygote-side refresh tick. Called from zs_impl_fork
// PRE-fork (see entry.cpp): running maybe_refresh_denylist in the
// long-lived zygote is what makes the throttle and the mtime
// bookkeeping actually advance — the pre-R34 call sites all ran in
// forked children, where copy-on-write gave every child a fresh
// g_next_refresh_check == 0 (the 2 s throttle elided nothing: every
// fork paid 2 stat() calls) and the zygote's stored mtimes never
// moved (after ANY packages.list change, every subsequent fork
// re-parsed both files in the child until the next zygote restart).
// From the zygote: the first fork after the interval stats both
// files ONCE and every later child inherits the fresh map and the
// future-dated throttle for free. The child-side calls stay as a
// belt-and-suspenders path (host tests, the R29 blocked-open retry).
void hide_refresh_tick() { maybe_refresh_denylist(); }

// ------------------------------------------------------------------------
// Mount table unmounting
// ------------------------------------------------------------------------

// Forward decl — fallback when the single-read path can't handle the
// mount table size.
static void unmount_magisk_paths_streaming();

// Parse one /proc/self/mounts line into (source, mount_point) spans
// inside the shared buffer. Returns 1 on success. Exposed for tests.
struct MountFields {
    char* source;    size_t source_len;
    char* mnt_point; size_t mnt_point_len;
};

int hide_parse_mounts_line(char* line_start, char* line_end,
                           MountFields* out) {
    char* p = line_start;
    // source field
    out->source = p;
    while (p < line_end && *p != ' ' && *p != '\t') ++p;
    out->source_len = p - out->source;
    while (p < line_end && (*p == ' ' || *p == '\t')) ++p;
    // mount point field
    out->mnt_point = p;
    while (p < line_end && *p != ' ' && *p != '\t') ++p;
    out->mnt_point_len = p - out->mnt_point;
    return out->source_len > 0 && out->mnt_point_len > 0;
}

// Round 13 — runtime root-path prefixes. The daemon's socket moved
// to a randomized per-boot directory (see module_dispatch.cpp's
// session-file reader); its path must be matched by the unmount/fd
// filters but cannot be a compile-time constant. Registered once at
// payload init, before any fork.
static char g_rt_prefixes[4][96];
static size_t g_rt_prefix_lens[4];
static int g_rt_prefix_count = 0;

void hide_register_root_path_prefix(const char* prefix) {
    if (!prefix || !*prefix) return;
    size_t n = strlen(prefix);
    if (n >= sizeof g_rt_prefixes[0]) return;
    if (g_rt_prefix_count >= 4) return;
    memcpy(g_rt_prefixes[g_rt_prefix_count], prefix, n + 1);
    g_rt_prefix_lens[g_rt_prefix_count] = n;
    ++g_rt_prefix_count;
}

// Does this field reference a root-framework path we should detach?
// Round 7 (S6): we match BOTH the mount point AND the source field.
// Magisk "magic mounts" bind-mount module files at their *target*
// paths (e.g. mount point /system/app/Foo.apk) with the *source*
// being /data/adb/modules/.../system/app/Foo.apk. Matching only the
// mount point (the old behavior) missed every magic mount, leaving
// the module-overlaid /system layout visible to the app.
// ROUND 33: the /sbin/.magisk mirror-mount marker, decode-once
// obfuscated (file scope: field_is_root_path below uses it).
ZS_OBFS_PATH(kMagiskMirror, "/sbin/.magisk")

// ROUND 33b: the prefix table is a file-scope init_array global (no
// guard variable — see obfstr.h's libc++abi rationale); the loop
// keeps its {ptr,len} memcmp shape.
static const zsst::StrTable kRootPathPrefixes_g = [] {
    zsst::StrTable b;
    b.add(ZS_OBFS("/data/adb/"));
    b.add(ZS_OBFS("/sbin/"));
    b.add(ZS_OBFS("/debug_ramdisk/"));
    b.add(ZS_OBFS("/data/system/zygisk_study/"));
    return b;
}();

static int field_is_root_path(const char* f, size_t len) {
    const zsst::StrTable& kPrefixes = kRootPathPrefixes_g;
    for (std::size_t i = 0; i < kPrefixes.count; ++i) {
        if (len >= kPrefixes.len(i) &&
            memcmp(f, kPrefixes.at(i), kPrefixes.len(i)) == 0) return 1;
    }
    for (int i = 0; i < g_rt_prefix_count; ++i) {
        if (len >= g_rt_prefix_lens[i] &&
            memcmp(f, g_rt_prefixes[i], g_rt_prefix_lens[i]) == 0) return 1;
    }
    // /sbin/.magisk mirror mount (source "magisk" style entries name
    // the block device; the mount point carries the marker instead).
    size_t mlen = strlen(kMagiskMirror());
    if (len >= mlen && memcmp(f, kMagiskMirror(), mlen) == 0) return 1;
    return 0;
}

// ------------------------------------------------------------------------
// Round 9 (B1) — mount-namespace syscall seam
// ------------------------------------------------------------------------
//
// unshare(CLONE_NEWNS) alone does NOT give a namespace that is
// private in the propagation sense. Android mounts / (and much of the
// tree) as SHARED: the new namespace's copies stay members of the
// same peer group as the originals. Two consequences, both severe:
//
//   1. Our umount2()s on shared mounts PROPAGATE BACK to the init
//      namespace — every other process on the device would lose its
//      module mounts (a system-wide breakage triggered by an app
//      fork).
//   2. Any mount event in the init namespace after our unshare
//      PROPAGATES INTO the child, re-introducing root mounts after
//      we unmounted them (a hide leak).
//
// The fix is the same one Magisk's DenyList and ReZygisk's clean-
// namespace switch rely on: after unshare(), remount / as
// MS_SLAVE|MS_REC. A slave mount receives nothing from the peer group
// and propagates nothing back — the child is fully detached while
// keeping a *copy* of the mount tree to unmount from.
//
// These three indirections exist so host tests can verify the ORDER
// and the fail-closed gating without root (mount(2) needs
// CAP_SYS_ADMIN). Production cost: three cold-path indirect calls.

typedef int (*ZsUnshareFn)(int);
typedef int (*ZsMountSlaveFn)();
typedef int (*ZsUmount2Fn)(const char*, int);

static int zs_do_mount_slave() {
    // mount(2) with MS_SLAVE|MS_REC: source, target, filesystem type
    // and data are all NULL for a propagation-type change.
    return mount(nullptr, "/", nullptr, MS_SLAVE | MS_REC, nullptr);
}

// Call-order log (bounded, cold path). 'u' = unshare, 's' = slave
// remount, 'm' = umount2. Written by the production defaults too, so
// a future reorder of the pipeline is caught by the existing tests.
static char  g_mount_log[96];
static size_t g_mount_log_n;

static inline void zs_mount_log(char op) {
    if (g_mount_log_n < sizeof(g_mount_log)) g_mount_log[g_mount_log_n++] = op;
}

static int zs_prod_unshare(int flags) {
    int rv = unshare(flags);
    zs_mount_log(rv == 0 ? 'u' : 'U');
    return rv;
}
static int zs_prod_mount_slave() {
    int rv = zs_do_mount_slave();
    zs_mount_log(rv == 0 ? 's' : 'S');
    return rv;
}
static int zs_prod_umount2(const char* target, int flags) {
    int rv = umount2(target, flags);
    zs_mount_log(rv == 0 ? 'm' : 'M');
    return rv;
}
static int zs_prod_bind_mount(const char* src, const char* dst) {
    int rv = mount(src, dst, nullptr, MS_BIND, nullptr);
    zs_mount_log(rv == 0 ? 'b' : 'B');
    return rv;
}
static ZsUnshareFn    g_fn_unshare = zs_prod_unshare;
static ZsMountSlaveFn g_fn_mount_slave = zs_prod_mount_slave;
static ZsUmount2Fn    g_fn_umount2 = zs_prod_umount2;
typedef int (*ZsBindMountFn)(const char*, const char*);
static ZsBindMountFn g_fn_bind_mount = zs_prod_bind_mount;

// ------------------------------------------------------------------------
// Round 19 — the spoofed property-area bind mount.
//
// State set at payload init by module_dispatch (zs_module_send_props):
//   g_props_src:  the file the daemon materialized (session dir/p).
//                 Empty = feature unavailable this boot.
//   g_props_magic: the AREA magic of the image we built (the uint32
//                 at file offset 8 — bytes_used@0, serial@4, magic@8;
//                 the self-check compares it against what the mount
//                 serves). Round 26: was the first 4 bytes (= the
//                 bytes_used_ field — self-consistent but weaker and
//                 mislabeled as "magic").
// ------------------------------------------------------------------------
static char    g_props_src[112];
static uint32_t g_props_magic = 0;
static std::atomic<int> g_props_file_ready{0};

void hide_props_file_set_source(const char* src, uint32_t magic) {
    if (!src || !*src) return;
    strncpy(g_props_src, src, sizeof g_props_src - 1);
    g_props_src[sizeof g_props_src - 1] = '\0';
    g_props_magic = magic;
    g_props_file_ready.store(1, std::memory_order_release);
}

int hide_props_file_ready() {
    return g_props_file_ready.load(std::memory_order_acquire);
}

static const char kPropSerialTarget[] =
    "/dev/__properties__/properties_serial";
// Round 26 — the 6.x single-file form: the whole property area is
// ONE regular file at /dev/__properties__ (no directory, no
// properties_serial — verified from AOSP bionic at
// android-6.0.0_r1). The bind target must follow the platform: on
// 6.x we cover the FILE ITSELF, so a fresh libc's open+map of
// /dev/__properties__ lands on our spoofed image.
static const char kPropLegacyTarget[] = "/dev/__properties__";

// Test override for the bind target (host tests point this at a
// temp file so the self-check's open() can succeed without root).
static const char* g_props_target_override = nullptr;

#ifdef ZS_HOST_TEST
void zs_test_set_prop_serial_target(const char* target) {
    g_props_target_override = target;
}
// Round 26: drive the pure target-selection core against any probe
// path (a regular file selects the 6.x single-file target; a
// directory or missing path selects the 7.0+ serial target).
// Defined below props_target_for_probe (forward-declared here).
static const char* props_target_for_probe(const char* probe);
const char* zs_test_props_target_for_probe(const char* probe);
#endif

// Round 26: which target does THIS platform use? stat() of
// /dev/__properties__ (regular file = the 6.x form, anything else =
// the 7.0+ directory form); the answer is cached. The test override,
// when set, wins — host tests have no /dev/__properties__ to probe.
// Pure core (props_target_for_probe) so tests can drive the
// selection against temp files/dirs.
static const char* props_target_for_probe(const char* probe) {
    struct stat st{};
    if (probe && stat(probe, &st) == 0 && S_ISREG(st.st_mode)) {
        return kPropLegacyTarget;
    }
    return kPropSerialTarget;
}

static const char* props_mount_target() {
    if (g_props_target_override) return g_props_target_override;
    static const char* target = nullptr;
    if (!target) {
        target = props_target_for_probe("/dev/__properties__");
    }
    return target;
}

#ifdef ZS_HOST_TEST
const char* zs_test_props_target_for_probe(const char* probe) {
    return props_target_for_probe(probe);
}
#endif

// Round 20 — stat parity for the mounted properties file. Through
// the bind mount, stat() of /dev/__properties__/properties_serial
// (and fstat() of an fd the app opened on it) reports the SESSION
// file's st_dev/st_ino — while a stock device reports the /dev
// tmpfs file's identity. A detector cross-checking the property
// file's device id against another /dev file would see the
// difference. The fiction below answers the REAL file's identity,
// captured in the mount phase BEFORE the bind covers it.
static struct {
    int         active;
    struct stat real;     // identity of the real properties_serial
    struct stat mounted;  // identity of the session file we serve
} g_props_stat_fiction{};

// Capture both identities around the bind mount. Call order matters:
// capture_real() BEFORE the mount, capture_mounted() AFTER.
static void props_fiction_capture_real() {
    int fd = open(props_mount_target(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    if (fstat(fd, &g_props_stat_fiction.real) == 0) {
        g_props_stat_fiction.active = 1;
    }
    close(fd);
}

// The mounted identity is simply the SOURCE file we serve (the bind
// makes the path resolve to it) — fstat it directly, which also works
// on host tests where the bind is only recorded.
static void props_fiction_capture_mounted() {
    if (!g_props_src[0]) return;
    int fd = open(g_props_src, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    (void)fstat(fd, &g_props_stat_fiction.mounted);
    close(fd);
}

// The path the stat hooks must answer with the fiction (the bind
// target; override-aware for host tests).
const char* hide_props_serial_target_path() {
    return props_mount_target();
}

int hide_props_stat_fiction(struct stat* out) {
    if (!g_props_stat_fiction.active || !out) return 0;
    *out = g_props_stat_fiction.real;
    return 1;
}

// Is this stat result the identity of our MOUNTED session file
// (i.e. what the kernel now answers for the properties path)?
int hide_props_stat_is_mounted_identity(const struct stat* st) {
    return g_props_stat_fiction.active && st &&
           (uint64_t)st->st_dev == (uint64_t)g_props_stat_fiction.mounted.st_dev &&
           (uint64_t)st->st_ino == (uint64_t)g_props_stat_fiction.mounted.st_ino;
}

void hide_props_stat_fiction_clear() {
    memset(&g_props_stat_fiction, 0, sizeof g_props_stat_fiction);
}

// Bind-mount the spoofed area over the real properties_serial, then
// VERIFY the mount serves our bytes (open + magic compare). Any
// failure umounts immediately — fail-closed back to the pre-Round-19
// behavior (exec'd helpers see the real trie, exactly as before;
// in-process reads were never affected by this mount either way).
//
// Runs AFTER unshare+slave, so the mount lives only in this child's
// namespace and cannot propagate anywhere. Runs BEFORE the real
// setresgid: still root, still in the zygote SELinux domain (the
// domain AOSP's own Zygote.cpp uses to bind-mount over
// /dev/__properties__ for appcompat overrides — verified from
// AOSP 15/main sources: BindMountSyspropOverride runs before
// setresgid too).
static void mount_spoofed_properties_file() {
    if (!hide_props_file_ready()) return;

    const char* target = props_mount_target();
    // Round 20: capture the real file's identity BEFORE the bind
    // covers it (the stat fiction needs it).
    hide_props_stat_fiction_clear();
    props_fiction_capture_real();
    props_fiction_capture_mounted();
    if (g_fn_bind_mount(g_props_src, target) != 0) {
        ZS_LOGW("hide: properties bind mount failed: %s — exec'd "
                "helpers will see real property values",
                strerror(errno));
        hide_props_stat_fiction_clear();
        return;
    }
    // Self-check: open the MOUNTED path and verify the AREA MAGIC,
    // which lives at byte offset 8 of the file (bytes_used@0,
    // serial@4, magic@8 — verified from AOSP bionic at 6.0/7.0/9.0;
    // Round 26 fixed the old first-4-bytes compare, which actually
    // compared bytes_used_). A mismatch means the mount is not
    // serving our file (or SELinux denied the open) — revert rather
    // than serve garbage.
    int fd = open(target, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ZS_LOGW("hide: properties mount self-check open failed: %s "
                "— reverting", strerror(errno));
        g_fn_umount2(target, MNT_DETACH);
        hide_props_stat_fiction_clear();
        return;
    }
    unsigned char head[12] = {};
    ssize_t n = read(fd, head, sizeof head);
    close(fd);
    uint32_t served = 0;
    if (n == (ssize_t)sizeof head) {
        memcpy(&served, head + 8, sizeof served);
    }
    if (n != (ssize_t)sizeof head || served != g_props_magic) {
        ZS_LOGW("hide: properties mount self-check mismatch "
                "(got %#x want %#x) — reverting",
                (unsigned)served, (unsigned)g_props_magic);
        g_fn_umount2(target, MNT_DETACH);
        hide_props_stat_fiction_clear();
        return;
    }
    ZS_LOGD("hide: spoofed property area mounted over %s "
            "(execve-proof)", target);
}

// Unmount everything the root framework mounted, inside our private
// mount namespace (caller did unshare(CLONE_NEWNS)).
//
// PERF NOTE (unchanged from previous rounds, still true): one
// open() + a few read()s into a stack buffer + in-memory scan beats
// setmntent/getmntent_r by ~30 syscalls. See the historical comment
// in the repo history; the structure is preserved.
static void unmount_magisk_paths() {
    constexpr size_t kBufCap = 48 * 1024;
    char buf[kBufCap];
    int truncated = 0;
    ssize_t total = read_proc_file("/proc/self/mounts", buf, kBufCap,
                                   &truncated);
    if (total <= 0 || truncated) {
        // Round 7 fix: the old code only fell back when total <= 0.
        // A full 32 KB buffer meant the tail of the mount table was
        // silently DROPPED — missed unmounts are exactly the kind of
        // "works in testing, leaks on a real Magisk device with many
        // modules" bug. Now any truncation goes to the streaming path.
        unmount_magisk_paths_streaming();
        return;
    }

    constexpr int kMaxMatches = 64;
    struct Match { char* path; size_t len; };
    Match matches[kMaxMatches];
    int n_matches = 0;

    char* line_start = buf;
    char* end = buf + total;
    while (line_start < end) {
        char* line_end = (char*)memchr(line_start, '\n', end - line_start);
        if (!line_end) line_end = end;

        MountFields mf{};
        if (hide_parse_mounts_line(line_start, line_end, &mf)) {
            char*  fields[2] = { mf.mnt_point, mf.source };
            size_t lens[2]   = { mf.mnt_point_len, mf.source_len };
            for (int k = 0; k < 2; ++k) {
                if (field_is_root_path(fields[k], lens[k])) {
                    if (n_matches < kMaxMatches) {
                        matches[n_matches].path = fields[k];
                        matches[n_matches].len  = lens[k];
                        ++n_matches;
                    }
                    break;
                }
            }
        }
        line_start = line_end + (line_end < end ? 1 : 0);
    }

    // Pass 2: umount2 each match. We NUL-terminate the field in
    // place (clobbering the separator byte) and restore it.
    //
    // Round 7 fix (P4): if a match ends exactly at buf[total] with
    // no separator byte following (last line, buffer completely
    // full), the old code wrote one byte past the buffer. Truncation
    // now routes to the streaming path above, and we keep a belt-
    // and-braces bounds check here as well.
    for (int i = 0; i < n_matches; ++i) {
        char* mpath = matches[i].path;
        size_t mlen = matches[i].len;
        if (mpath + mlen >= buf + kBufCap) continue; // paranoia
        char saved = mpath[mlen];
        mpath[mlen] = '\0';
        if (g_fn_umount2(mpath, MNT_DETACH) != 0) {
            ZS_LOGW("hide: umount2(%s) failed", mpath);
        }
        mpath[mlen] = saved;
    }
}

// Streaming fallback (getmntent_r) for pathological mount tables.
static void unmount_magisk_paths_streaming() {
    char mntent_buf[1024];
    struct mntent mntbuf{};
    FILE* fp = setmntent("/proc/self/mounts", "r");
    if (!fp) return;

    constexpr int kMaxMatches = 64;
    char paths[kMaxMatches][256];
    int n_matches = 0;

    while (n_matches < kMaxMatches) {
        struct mntent* m = getmntent_r(fp, &mntbuf, mntent_buf,
                                       sizeof mntent_buf);
        if (!m) break;
        // S6: match source as well as mount point.
        if ((m->mnt_dir  && field_is_root_path(m->mnt_dir,  strlen(m->mnt_dir))) ||
            (m->mnt_fsname && field_is_root_path(m->mnt_fsname, strlen(m->mnt_fsname)))) {
            char* dest = paths[n_matches];
            size_t cap = sizeof(paths[0]) - 1;
            size_t len = strnlen(m->mnt_dir, cap);
            memcpy(dest, m->mnt_dir, len);
            dest[len] = '\0';
            ++n_matches;
        }
    }
    endmntent(fp);

    for (int i = 0; i < n_matches; ++i) {
        if (g_fn_umount2(paths[i], MNT_DETACH) != 0) {
            ZS_LOGW("hide: umount2(%s) failed", paths[i]);
        }
    }
}

// ------------------------------------------------------------------------
// Property layer (basic tier)
// ------------------------------------------------------------------------
//
// Round 7: the basic layer no longer writes to the shared property
// area. scrub_properties() used to (a) call __system_property_set
// via a 12-round Unix-socket IPC that silently fails with EACCES for
// ro.* keys, then (b) memset the prop_info value field directly —
// in a MAP_SHARED, PROT_READ page. (b) was a crash on real Android
// (read-only page) AND a system-wide visible change (shared mapping)
// AND a detection tell (empty value where stock devices report
// "green"/"locked").
//
// The real per-process spoofing now lives in hide_advanced.cpp:
//   - a content-preserving MAP_PRIVATE clone of the property area,
//     patched with the kPropSpoofTable values, and
//   - GOT hooks on __system_property_find / _get / _read_callback
//     that report "absent" for the nullptr-valued keys.
// This function remains as the seam for tests and for the API.

void hide_pre_resolve_symbols() {
    // Kept for API compatibility; the advanced layer resolves the
    // property symbols it needs at its own init.
}

void hide_clean_trace() {
    // The cleanup actions in the post-fork pipeline are the cleanup.
}

// ------------------------------------------------------------------------
// Public surface (see hide.h)
// ------------------------------------------------------------------------

void hide_register_globals() {
    int expected = 0;
    if (!g_initialized.compare_exchange_strong(expected, 1)) {
        return; // already initialized
    }
    snapshot_self_so();
    load_denylist();
}

int hide_setup_for_target(const char* package_name) {
    // Fast path: 99%+ of forks are NOT on the denylist.
    if (ZS_UNLIKELY(!package_name || *package_name == '\0')) {
        g_will_hide.store(0);
        return 0;
    }
    if (ZS_UNLIKELY(!g_denylist_loaded.load(std::memory_order_acquire))) {
        load_denylist();
    } else {
        maybe_refresh_denylist();
    }
    int hide = g_denylist_cache.count(package_name) > 0 ? 1 : 0;
    g_will_hide.store(hide, std::memory_order_release);
    return hide;
}

int hide_setup_for_target_uid(uid_t uid) {
    // Record the decision key regardless of outcome: the uid-drop
    // hook uses it to skip its own identical re-check (Round 14).
    g_deny_decided_key.store((uint32_t)uid, std::memory_order_relaxed);
    // Fast path: not a full app uid range at all (zygote forks
    // system_server with uid 1000; native daemons keep uid 0).
    if (ZS_UNLIKELY(uid < 10000)) {
        g_will_hide.store(0);
        return 0;
    }
    if (ZS_UNLIKELY(!g_uid_map_loaded.load(std::memory_order_acquire))) {
        load_denylist();
    } else {
        maybe_refresh_denylist();
    }
    // appId family match covers multi-user profiles.
    uid_t app_id = (uid_t)(uid % 100000);
    int hide = g_deny_app_ids.count(app_id) > 0 ? 1 : 0;
    g_will_hide.store(hide, std::memory_order_release);
    return hide;
}

void hide_lookup_package_for_uid(uid_t uid, char* out, size_t cap) {
    if (ZS_UNLIKELY(!out || cap == 0)) return;
    out[0] = '\0';
    // uid < 10000 is never an app (system_server, root, daemons).
    if (uid < 10000) return;
    if (ZS_UNLIKELY(!g_uid_map_loaded.load(std::memory_order_acquire))) {
        load_denylist();
    }
    auto it = g_pkg_map.find((uid_t)(uid % 100000));
    if (it == g_pkg_map.end()) return;
    strncpy(out, it->second.c_str(), cap - 1);
    out[cap - 1] = '\0';
}

// Round 25 — the data dir of the package owning `uid` (the same
// derivation fill_app_args uses: /data/user/<userId>/<pkg>, the
// canonical per-user form). Returns 0 and fills `out` on success;
// -1 when the uid is not a mapped app package. This feeds the
// old-kernel filter fallback (hide_advanced's unlinked-scratch file):
// on Android 7.x devices with pre-3.17 kernels there is no
// memfd_create, and the only directory the (already dropped, app-uid)
// child is guaranteed to create files in is its own data dir.
int hide_data_dir_for_uid(uid_t uid, char* out, size_t cap) {
    if (ZS_UNLIKELY(!out || cap == 0)) return -1;
    out[0] = '\0';
    if (uid < 10000) return -1;
    char pkg[256];
    hide_lookup_package_for_uid(uid, pkg, sizeof pkg);
    if (pkg[0] == '\0') return -1;
    long user_id = (long)uid / 100000L;
    char dir[320];   // sized for the longest path + user id
    int n = snprintf(dir, sizeof dir, "/data/user/%ld/%s", user_id, pkg);
    if (n < 0 || (size_t)n >= sizeof dir) return -1;
    if ((size_t)n >= cap) {          // caller buffer too small
        return -1;
    }
    memcpy(out, dir, (size_t)n + 1);
    return 0;
}

uint32_t hide_pkg_map_generation() {
    return g_pkg_map_gen.load(std::memory_order_acquire);
}

int hide_deny_decided_for(uid_t uid) {
    // 0 is the "never decided" sentinel; uid 0 is also the fast-path
    // no-app key, so a uid-0 decision IS distinguishable from none
    // (both mean "no hide" to the caller, so the collision is
    // harmless by construction).
    return g_deny_decided_key.load(std::memory_order_acquire) ==
           (uint32_t)uid;
}

void hide_apply_for_target(const char* /*package_name*/) {
    // Fast path: if setup decided NOT to hide, we're a no-op.
    if (ZS_UNLIKELY(!g_will_hide.load(std::memory_order_acquire))) return;

    // Slow path: target IS on the denylist.
    //
    // The caller (entry.cpp's setresgid/setresuid hook) guarantees we
    // are still root here — unshare(CLONE_NEWNS) requires
    // CAP_SYS_ADMIN, which is gone the moment the real setresuid
    // runs. This is why the hide pipeline hooks the *privilege drop*
    // rather than postAppSpecialize.
    //
    // Round 9 (B1): this function is now FAIL-CLOSED around the
    // namespace dance. The old code had two system-breaking defects
    // that host tests could not see (no root, no shared mounts):
    //
    //   a) On unshare() failure it fell through to the umount loop,
    //      reasoning that "umount2 will fail without a private
    //      namespace". That is exactly backwards: after a FAILED
    //      unshare we are still in the INIT namespace and still root,
    //      so umount2() SUCCEEDS there — detaching module mounts for
    //      every process on the device. A denylisted app fork could
    //      break the whole system's module mounts.
    //   b) On unshare() SUCCESS, the copied namespace stays in the
    //      same SHARED propagation peer group as init's. Every
    //      umount2() on a shared mount propagates back to the init
    //      namespace (same global breakage), and any mount event in
    //      init after our unshare propagates INTO the child (a hide
    //      leak). The MS_SLAVE|MS_REC remount below detaches us from
    //      the peer group in both directions — the same guarantee
    //      Magisk's DenyList and ReZygisk's clean-namespace setns()
    //      rely on.
    //
    // Both failures now skip the unmount phase entirely: property
    // spoofing, fd closing and the self-unmap still apply, we just
    // leave the mount table alone rather than risk a global mutation.
    if (ZS_UNLIKELY(g_fn_unshare(CLONE_NEWNS) != 0)) {
        ZS_LOGW("hide: unshare(CLONE_NEWNS) failed: %s — skipping the "
                "unmount phase (never umount in the init namespace)",
                strerror(errno));
        return;
    }
    if (ZS_UNLIKELY(g_fn_mount_slave() != 0)) {
        ZS_LOGW("hide: MS_SLAVE|MS_REC remount of / failed: %s — "
                "skipping the unmount phase (shared propagation would "
                "leak our umounts system-wide)",
                strerror(errno));
        return;
    }
    unmount_magisk_paths();
    // Round 19: serve the spoofed property area to exec'd helpers
    // (bind mount + self-check; no-op when the feature is off).
    // After the unmounts, not before: for THIS child the mount lands
    // after the scanner's pass, so the scanner never sees it. For a
    // SECONDARY child (child-of-child, e.g. an app zygote's fork)
    // the INHERITED bind is visible to the scan and gets detached
    // like any other session-prefix mount — then re-mounted fresh
    // right here, in this child's own namespace. Either way each
    // hidden child ends up with exactly one mount of its own.
    mount_spoofed_properties_file();
    // NOTE: no scrub_properties() and no unmap_self() here anymore.
    // Property spoofing moved to hide_advanced (per-process clone +
    // read hooks); the self-unmap is deferred to the asm trampoline
    // as the last action of the post-fork pipeline (entry.cpp).
}

// ---- unmap record accessors ----

size_t hide_unmap_record_count() { return g_self_so_count; }

size_t hide_unmap_records(struct so_record* out, size_t cap) {
    size_t n = g_self_so_count < cap ? g_self_so_count : cap;
    for (size_t i = 0; i < n; ++i) out[i] = g_self_so_records[i];
    return n;
}

// ROUND 34: see hide.h. Address-based, name-agnostic — works under
// the Round 30 randomized install names.
int hide_is_self_load_addr(uintptr_t addr) {
    for (size_t i = 0; i < g_self_so_count; ++i) {
        const so_record& r = g_self_so_records[i];
        if (addr >= r.base && addr < r.base + r.size) return 1;
    }
    return 0;
}

int hide_trampoline_unmap_pending() {
    for (size_t i = 0; i < g_self_so_count; ++i) {
        if (g_self_so_records[i].flags & ZS_SO_SELF) return 1;
    }
    return 0;
}

// ------------------------------------------------------------------------
// Round 8 — Tier A record preprocessing (see hide.h for the contract)
// ------------------------------------------------------------------------

// Replace the mapping at [lo, lo+size) with a content-preserving
// ANONYMOUS copy: save the bytes, MAP_FIXED an anon mapping over the
// range, restore the bytes, then restore the original protection and
// (where the kernel supports it) name the region "linker_alloc" so
// /proc/self/maps shows a benign anon label instead of a file path.
//
// The read-only segments of our .so files carry the ELF program
// headers and .dynstr that the dynamic linker's soinfo nodes point
// at. munmap()ing them (the Round 7 behavior) left every later
// dlopen()/dl_iterate_phdr() solist walk one strcmp away from a
// SIGSEGV in app code. Keeping the bytes — while hiding the file
// path — keeps those walks safe AND removes the name from maps.
static int zs_anonymize_range(uintptr_t lo, size_t size, uint32_t prot) {
    if (!size || lo == 0) return 0;
    void* addr = reinterpret_cast<void*>(lo);

    void* scratch = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED) return 0;
    memcpy(scratch, addr, size);   // save the original bytes

    void* remapped = mmap(addr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                          -1, 0);
    if (remapped == MAP_FAILED) {
        munmap(scratch, size);
        return 0;
    }
    memcpy(addr, scratch, size);   // restore content into the copy
    munmap(scratch, size);

    int out_prot = ((prot & ZS_SEG_W) ? PROT_WRITE : 0) |
                   ((prot & ZS_SEG_X) ? PROT_EXEC : 0) |
                   PROT_READ;
    if (mprotect(addr, size, out_prot) != 0) {
        // Anonymized RW is safe content-wise; fall back to read-only.
        (void)mprotect(addr, size, PROT_READ);
    }
    // Best-effort label. PR_SET_VMA is an Android vendor extension;
    // no-op elsewhere. "linker_alloc" regions exist in every ART
    // process, so the label itself is not an anomaly.
    constexpr int kPrSetVma = 0x53564d41;          // "AVMS"
    constexpr int kPrSetVmaAnonName = 0;
    const char kAnonName[] = "linker_alloc";
    (void)prctl(kPrSetVma, kPrSetVmaAnonName, lo, size,
                (unsigned long)(uintptr_t)kAnonName);
    return 1;
}

size_t hide_prepare_tier_a_records(struct so_record* out, size_t cap) {
    size_t n_out = 0;

    // Pass 1: every read-only segment of every record becomes an
    // anonymous, content-identical copy. Executable/writable segments
    // of OTHER records are munmap'd now (their code never runs again);
    // SELF ones are deferred to the asm trampoline.
    for (size_t i = 0; i < g_self_so_count; ++i) {
        so_record* rec = &g_self_so_records[i];
        uint32_t dynamic_bits = rec->prot & (ZS_SEG_X | ZS_SEG_W);
        if (dynamic_bits == 0) {
            // Read-only metadata segment: keep the bytes, hide the path.
            if (!zs_anonymize_range(rec->base, rec->size, rec->prot)) {
                ZS_LOGW("hide: anonymize(%lx, %zu) failed; segment "
                        "stays file-backed",
                        (unsigned long)rec->base, rec->size);
            }
            continue;
        }
        if (rec->flags & ZS_SO_OTHER) {
            // Code/data of other libs: nothing of theirs executes
            // past this point, plain munmap is safe.
            if (munmap((void*)rec->base, rec->size) != 0) {
                ZS_LOGW("hide: munmap(%lx, %zu) failed",
                        (unsigned long)rec->base, rec->size);
            }
            continue;
        }
        // SELF + (exec|writable): the trampoline's job. Collected in
        // pass 2 (SELF first) below.
    }

    // Pass 2: SELF records that still need the trampoline. SELF
    // records go FIRST so the trampoline's fixed kTrampMaxRecords
    // (32) array can never cut them when many modules pushed the
    // record count past the cap (Round 8 / B7: the old code copied
    // records in scan order, so a payload segment could land past
    // index 32 and stay mapped — silently degrading Tier A).
    for (size_t i = 0; i < g_self_so_count && n_out < cap; ++i) {
        const so_record* rec = &g_self_so_records[i];
        if ((rec->flags & ZS_SO_SELF) &&
            (rec->prot & (ZS_SEG_X | ZS_SEG_W))) {
            out[n_out++] = *rec;
        }
    }
    // Then any OTHER exec/writable records that did not fit... there
    // are none — pass 1 munmap'd them all. Any overflow of SELF
    // records beyond `cap` is logged by the caller.
    if (n_out == cap) {
        size_t overflow = 0;
        for (size_t i = 0; i < g_self_so_count; ++i) {
            const so_record* rec = &g_self_so_records[i];
            if ((rec->flags & ZS_SO_SELF) &&
                (rec->prot & (ZS_SEG_X | ZS_SEG_W))) {
                ++overflow;
            }
        }
        if (overflow > cap) {
            ZS_LOGW("hide: %zu SELF segment(s) exceed the trampoline "
                    "record cap (%zu); they will remain mapped",
                    overflow - cap, cap);
        }
    }
    return n_out;
}

// ------------------------------------------------------------------------
// Round 30 — the atexit / pthread_atfork trace purge. See hide.h for
// the full design note (everything below was verified against
// bionic's libc/bionic/atexit.cpp and crtbegin_so.c this round, not
// assumed).
// ------------------------------------------------------------------------

// __cxa_finalize is resolved at first use (both bionic and glibc
// export it; a null resolution leaves the documented residual
// instead of crashing the hide pipeline).
typedef void (*ZsCxaFinalizeFn)(void*);
static ZsCxaFinalizeFn g_real_cxa_finalize = nullptr;
static int g_cxa_finalize_resolved = 0;

static ZsCxaFinalizeFn resolve_cxa_finalize() {
    if (!g_cxa_finalize_resolved) {
        g_cxa_finalize_resolved = 1;
        g_real_cxa_finalize =
            (ZsCxaFinalizeFn)dlsym(RTLD_DEFAULT, "__cxa_finalize");
        if (!g_real_cxa_finalize) {
            // RTLD_DEFAULT only searches the global scope; we are
            // RTLD_LOCAL. dlopen'ing libc by soname resolves through
            // the default namespace on both bionic and glibc hosts.
            void* libc = dlopen("libc.so", RTLD_LAZY | RTLD_NOLOAD);
            if (libc) {
                g_real_cxa_finalize =
                    (ZsCxaFinalizeFn)dlsym(libc, "__cxa_finalize");
                // NO dlclose: the NOLOAD handle only bumps a
                // refcount, and undoing it would be a wasted syscall
                // on the hide path.
            }
        }
        if (!g_real_cxa_finalize) {
            ZS_LOGW("hide: __cxa_finalize unavailable; atexit purge "
                    "disabled (documented residual)");
        }
    }
    return g_real_cxa_finalize;
}

size_t zs_collect_dso_handles(struct ZsDsoHandle* out, size_t cap) {
    if (ZS_UNLIKELY(!out || cap == 0)) return 0;
    size_t n = 0;
    for (size_t i = 0; i < g_self_so_count && n < cap; ++i) {
        const so_record* rec = &g_self_so_records[i];
        // __dso_handle lives in .data.rel.ro or .data — never in a
        // text page. Scanning the non-executable records only keeps
        // this linear walk tiny (a few pages per library).
        if (rec->prot & ZS_SEG_X) continue;
        // Guard against a zero/garbage record from tests.
        if (!rec->base || !rec->size) continue;
        const uintptr_t start = (rec->base + sizeof(uintptr_t) - 1) &
                                ~(uintptr_t)(sizeof(uintptr_t) - 1);
        const uintptr_t end = rec->base + rec->size;
        for (uintptr_t p = start;
             p + sizeof(uintptr_t) <= end && n < cap;
             p += sizeof(uintptr_t)) {
            uintptr_t w;
            memcpy(&w, (const void*)p, sizeof w);
            if (w == p) {
                // A self-pointing word: bionic's __dso_handle (and
                // glibc's, which uses the same crt trick). Deduped
                // (several records can map the same library); an
                // overlapping SELF classification upgrades an
                // existing OTHER entry (production never overlaps
                // them — one address is one library — but the
                // upgrade keeps the classification right if a
                // rescan ever produces odd records).
                int found = -1;
                for (size_t k = 0; k < n; ++k) {
                    if (out[k].handle == p) { found = (int)k; break; }
                }
                if (found < 0) {
                    out[n].handle = p;
                    out[n].self =
                        (rec->flags & ZS_SO_SELF) ? 1u : 0u;
                    ++n;
                } else if (rec->flags & ZS_SO_SELF) {
                    out[found].self = 1u;
                }
                // One record yields at most one handle (the alias
                // pair __dso_handle_const/__dso_handle shares the
                // address).
                break;
            }
        }
    }
    if (n == cap) {
        ZS_LOGW("hide: dso-handle scan hit the %zu cap; extra "
                "libraries keep their atexit entries (residual)",
                cap);
    }
    return n;
}

int zs_atexit_finalize(uintptr_t dso_handle) {
    ZsCxaFinalizeFn fn = resolve_cxa_finalize();
    if (!fn || !dso_handle) return 0;
    // The bionic/glibc contract: entries whose dso matches are
    // extracted (zeroed in the array), their destructors CALLED, the
    // array compacted, and bionic additionally unregisters the
    // library's pthread_atfork handlers. This is exactly what a
    // proper dlclose triggers via crtbegin_so's __on_dlclose.
    fn((void*)dso_handle);
    return 1;
}

#ifdef ZS_HOST_TEST
// Test-only: force a uid into the deny set so the e2e test can drive
// the uid-keyed pipeline without root access to packages.list.
void hide_test_force_deny_uid(uid_t uid) {
    g_deny_app_ids.insert((uid_t)(uid % 100000));
    g_uid_map_loaded.store(1);
}

void hide_test_set_records(const struct so_record* recs, size_t count) {
    g_self_so_count = count < kMaxSoRecords ? count : kMaxSoRecords;
    for (size_t i = 0; i < g_self_so_count; ++i) {
        g_self_so_records[i] = recs[i];
    }
}

extern "C" void hide_test_set_denylist_path(const char* path) {
    g_denylist_path = path;
    // Force a fresh load against the new path.
    g_denylist_loaded.store(0);
    g_uid_map_loaded.store(0);
    g_denylist_mtime.store(-1);
    g_denylist_cache.clear();
    g_deny_app_ids.clear();
}

// Round 12 — packages.list seam for the module-args lookup tests.
extern "C" void hide_test_set_packages_list_path(const char* path) {
    g_packages_list_path = path;   // null restores the obfuscated default
    g_uid_map_loaded.store(0);
    g_deny_app_ids.clear();
    g_pkg_map.clear();
}

extern "C" void hide_test_reset_refresh() {
    g_next_refresh_check.store(0);
}

extern "C" int hide_test_denylist_reload_count() {
    return g_denylist_reload_count;
}

void zs_scan_maps_into_records_test(const char* buf, size_t total) {
    g_self_so_count = 0;
    scan_maps_into_records(buf, total);
}

// ---- Round 9 (B1) mount-namespace seam ----
//
// hide_apply_for_target()'s ordering contract:
//   unshare('u') -> slave remount('s') -> umount2('m'...)
// and its fail-closed contract: 'U' (unshare failed) or 'S' (slave
// remount failed) must NEVER be followed by any 'm'. The tests
// replace the three syscalls with recorders that also seed the mount
// table, then assert the log shape.

void zs_test_set_mount_fns(ZsUnshareFn u, ZsMountSlaveFn s,
                           ZsUmount2Fn um) {
    g_fn_unshare    = u ? u : zs_prod_unshare;
    g_fn_mount_slave = s ? s : zs_prod_mount_slave;
    g_fn_umount2    = um ? um : zs_prod_umount2;
}

void zs_test_mount_log_reset() {
    g_mount_log_n = 0;
    g_mount_log[0] = '\0';   // clear stale bytes, not just the length
}

// Test recorders append their own markers so the ordering assertions
// work no matter which fn set is installed.
void zs_test_mount_log_append(char op) { zs_mount_log(op); }

const char* zs_test_mount_log() { return g_mount_log; }

// Round 19: the properties-file mount seams.
void zs_test_set_bind_mount_fn(int (*bind)(const char*, const char*)) {
    g_fn_bind_mount = bind ? bind : zs_prod_bind_mount;
}
void zs_test_props_source_clear() {
    g_props_src[0] = '\0';
    g_props_magic = 0;
    g_props_file_ready.store(0, std::memory_order_release);
    hide_props_stat_fiction_clear();
}
// extern "C" so the dlopen-based dispatch test can resolve it.
extern "C" void zs_test_props_source_clear_c() {
    zs_test_props_source_clear();
}
// Drive both fiction captures around a (recorded) bind mount so the
// hide_advanced hook tests can exercise the stat parody end to end.
extern "C" void zs_test_props_fiction_capture_both() {
    hide_props_stat_fiction_clear();
    props_fiction_capture_real();
    props_fiction_capture_mounted();
}
extern "C" int zs_test_props_ready_c() {
    return hide_props_file_ready();
}
#endif

} // namespace zygisk_study
