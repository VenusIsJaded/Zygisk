// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide.h
//
// The hide layer — public surface used by entry.cpp.
//
// The hiding mechanisms here are all PUBLIC, well-documented Android
// rooting techniques (Magisk DenyList, Shamiko, mount namespace
// isolation, props spoofing). Nothing here is novel; it's the
// minimum set of techniques needed to keep Magisk-flavored root
// signals out of an app's first observable callback.
//
// Entry points:
//
//   1. hide_register_globals()
//      Called once at payload init. Snapshots the *initial* state of
//      /proc/self/maps (every segment — r--p, r-xp, rw-p — of our own
//      .so files) and loads the DenyList.
//
//   2. hide_register_extra_so(const char* path)
//      Called for every Zygisk module .so we dlopen. Their segments
//      are added to the unmap set so denylisted children can remove
//      them too (a module path like /data/adb/modules/<id>/... is a
//      louder tell than our own .so names).
//
//   3. hide_setup_for_target(const char* package_name)
//      Called from pre-fork / early child. Decides whether the target
//      is on the DenyList and, if so, queues up the post-fork hide
//      actions.
//
//   4. hide_setup_for_target_uid(uid_t uid)
//      Same decision keyed by uid/appId instead of package name.
//      This is the path that actually fires on a real device: the
//      child's identity is available at setresgid/setresuid time
//      (the uid arguments), while the package name is not. appId
//      (uid % 100000) matching handles multi-user (work profiles)
//      automatically.
//
//   5. hide_apply_for_target(const char* package_name)
//      Applies the mount-namespace unmount + property spoof setup.
//      MUST still be running as root (before the real setresuid) so
//      unshare(CLONE_NEWNS) succeeds. The self-unmap is NOT done
//      here — see hide_unmap_records()/hide_trampoline_unmap();
//      it must be the very last action of the post-fork pipeline.
//
//   6. hide_unmap_records()/hide_trampoline_unmap_pending()
//      Access to the self-unmap record set. entry.cpp unmaps the
//      non-self records directly (safe: their pages are not
//      executing) and defers ONLY the self records to the asm
//      trampoline (see unmap_trampoline.h) which restores the
//      fork-wrapper's register frame and returns to the original
//      caller without executing another byte of libpayload code.

#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/stat.h>
#include <sys/types.h>

namespace zygisk_study {

// Initialize the hide layer (snapshot initial state, pre-resolve
// dlsym lookups so the post-fork hot path doesn't pay for them,
// load the DenyList and the uid map).
void hide_register_globals();

// Pre-resolve libc function pointers (e.g. __system_property_find)
// that the post-fork hide path uses. Idempotent. Called from
// hide_register_globals() at init time, but exposed separately so
// tests can call it in isolation.
void hide_pre_resolve_symbols();

// Add every maps segment whose path contains `path_fragment` to the
// unmap record set. Used for Zygisk module .so files. Idempotent per
// path. Callers batch registrations and finish with one
// hide_rescan_records().
void hide_register_extra_so(const char* path_fragment);

// Re-snapshot /proc/self/maps (records every segment matching our own
// .so names plus all registered extra fragments).
void hide_rescan_records();

// Decide whether to hide for this target (package-name key).
// Returns 1 if yes, 0 if no.
int  hide_setup_for_target(const char* package_name);

// Decide whether to hide for this target (uid key; matches on the
// appId family, uid % 100000, so user 0 / 10 / work profiles all
// match). Returns 1 if yes, 0 if no.
int  hide_setup_for_target_uid(uid_t uid);

// Round 12 — look up the package name that owns `uid` (appId family,
// first entry wins for shared-appId packages). Fills out[0..cap) with
// the package name or an empty string when unknown. Backed by the
// same packages.list parse the DenyList uid map uses (no extra file
// reads). Used by the module dispatch layer to fill the real
// specialize arguments.
void hide_lookup_package_for_uid(uid_t uid, char* out, size_t cap);
int hide_data_dir_for_uid(uid_t uid, char* out, size_t cap);

// Round 14 — generation counter bumped on every packages.list /
// DenyList (re)parse. Consumers (the module dispatch args cache) use
// it to invalidate in lockstep with the map.
uint32_t hide_pkg_map_generation();

// Round 14 — true when the last hide_setup_for_target_uid call in
// THIS process decided on exactly this uid/gid key. The uid-drop
// hook uses it to skip its redundant re-check (the gid-drop hook
// already decided with the same key in the standard specialization
// order).
int hide_deny_decided_for(uid_t uid);

// Round 13 — register a runtime root-path prefix (matched by the
// unmount table's source/mount-point filter in addition to the
// compile-time table). Used for the daemon's randomized per-boot
// socket directory; call once at payload init. Max 4 prefixes, each
// < 96 bytes; extras are ignored.
void hide_register_root_path_prefix(const char* prefix);

// Apply the mount unmount + property clone/spoof actions. Only
// meaningful if hide_setup_for_target*() returned 1. Must be called
// while the child is still root (before the real privilege drop).
void hide_apply_for_target(const char* package_name);

// ------------------------------------------------------------------------
// Round 19 — execve-proof property spoofing.
//
// The daemon materializes the spoofed properties_serial file at
// payload init (module_dispatch.cpp drives the 'P' protocol); this
// registers the file's path + expected area magic. The hide mount
// phase bind-mounts it over /dev/__properties__/properties_serial
// (self-checked, fail-closed) so fork+exec'd helpers — fresh libc,
// no hooks — re-map the SPOOFED area instead of the real one.
// ------------------------------------------------------------------------
void hide_props_file_set_source(const char* src, uint32_t magic);
int  hide_props_file_ready();

// Round 20 — stat parity for the mounted properties file. The mount
// phase captures the REAL file's identity (pre-bind) and the served
// file's identity; the stat hooks in hide_advanced answer the real
// identity for the properties path / any fd of the served file, so a
// st_dev/st_ino cross-check sees exactly what a stock device reports.
int  hide_props_stat_fiction(struct stat* out);
int  hide_props_stat_is_mounted_identity(const struct stat* st);
const char* hide_props_serial_target_path();
void hide_props_stat_fiction_clear();

// Clean up any traces we left behind after apply, before user code
// runs. The caller (entry.cpp) calls this from postAppSpecialize.
void hide_clean_trace();

// ---- self-unmap record access (used by entry.cpp + trampoline) ----
//
// One maps segment to be removed from the denylisted child.
// Kept in sync with the asm trampolines in
// unmap_trampoline_aarch64.S / unmap_trampoline_x86_64.S — the blob
// reads {base, size} pairs with the exact layout below. Do not
// reorder the leading fields.
struct so_record {
    uintptr_t base;    // segment start
    size_t    size;    // segment length
    uint32_t  flags;   // ZS_SO_* bits
    uint32_t  prot;    // ZS_SEG_* bits (from the maps perms field)
    uint32_t  _pad;    // keep the stride stable
};

// Segment protection bits (so_record.prot), straight from the rwxp
// chars of the maps line. Tier A uses them to decide HOW a segment
// disappears — see hide_prepare_tier_a_records().
#define ZS_SEG_X 0x1u   // executable (r-xp / rwxp)
#define ZS_SEG_W 0x2u   // writable (rw-p / rwxp)

// Records whose unmap must be deferred to the asm trampoline
// (segments of libpayload itself — unmapping them from C would
// execute unmapped code on return).
#define ZS_SO_SELF   0x1u
// Records that plain C code may munmap directly (libzygisk.so,
// libzn_loader.so, module .so files — none of their code runs
// anymore by the time we unmap).
#define ZS_SO_OTHER  0x2u

// Total number of records currently registered.
size_t hide_unmap_record_count();

// Copy up to cap records into out. Returns the number copied.
size_t hide_unmap_records(struct so_record* out, size_t cap);

// ROUND 34 — identity test used by the GOT walker (hide_advanced.cpp)
// to skip our own DSOs BY ADDRESS: true when `addr` falls inside any
// registered self record range. The Round 30 randomized install
// names (lib<8hex>-p.so) defeated the old name-needle skip, and the
// walker then patched libpayload's own GOT — the internal fstat()
// calls of the fd-shadow layer re-entered the fstat hook and
// recursed to a stack overflow in every Tier B child. The load bias
// dl_iterate_phdr reports (dlpi_addr) is the base of a DSO's first
// PT_LOAD; if that address lies inside one of OUR live mappings,
// the DSO IS us — no other library can have its load base mapped
// over our ranges.
int    hide_is_self_load_addr(uintptr_t addr);

// ROUND 34 — zygote-side (pre-fork) denylist/packages.list refresh
// tick. Call from the fork hook while still in the long-lived zygote
// so the throttle/mtime state advances there and children inherit
// fresh data through fork's copy-on-write. See hide.cpp.
void   hide_refresh_tick();

// True if any ZS_SO_SELF records are registered (i.e. the trampoline
// path should be used). On host test builds without a real
// libpayload.so mapping this is 0 and the whole thing is a no-op.
int    hide_trampoline_unmap_pending();

// Round 8 — Tier A record preprocessing. MUST run as the first step
// of the Tier A path, while libpayload code is still executing
// normally:
//
//   - Every READ-ONLY (r--p) segment of every record — ours, the
//     bridge, the loader, module .so files — is replaced by a
//     content-preserving ANONYMOUS copy (same address, same bytes,
//     named "linker_alloc" where PR_SET_VMA exists). Why not munmap:
//     the dynamic linker keeps a soinfo node for every dlopen'd lib,
//     and those nodes point into the r--p segment (program headers,
//     .dynstr with the soname). Unmapping it leaves every later
//     dlopen()/dl_iterate_phdr() walk reading unmapped memory — a
//     random crash in app code long after we left. Keeping the bytes
//     (but hiding the file path from maps) keeps those walks safe.
//   - Executable/writable segments of ZS_SO_OTHER records are
//     munmap'd right here (their code never runs again).
//   - Executable/writable segments of ZS_SO_SELF records are copied
//     into `out` (SELF records first, so the trampoline's fixed 32
//     record array can never cut them when many modules are loaded)
//     for the asm trampoline to unmap as its final act.
//
// Returns the number of records written to out.
size_t hide_prepare_tier_a_records(struct so_record* out, size_t cap);

// ------------------------------------------------------------------------
// Round 30 — atexit / pthread_atfork trace purge (the Tier A missing
// step, verified against bionic's own sources this round).
//
// WHAT BUG THIS FIXES (every Tier A child, since Round 8):
//
//   bionic keeps __cxa_atexit registrations in libc's AtexitArray
//   (libc/bionic/atexit.cpp: g_array; AtexitEntry {fn, arg, dso}).
//   Every .so built with bionic's crtbegin_so carries a destructor
//   (libc/arch-common/bionic/crtbegin_so.c: __on_dlclose) that calls
//   __cxa_finalize(&__dso_handle) — that is how a PROPER dlclose
//   purges its entries (and __unregister_atfork(dso) with them).
//   Our Tier A unmaps WITHOUT that step, so every hidden child keeps:
//
//     - atexit entries whose `fn` points into the now-unmapped text
//       of libpayload / the module .so's. bionic's exit() walks ALL
//       entries (__cxa_finalize(nullptr) calls every fn != null) —
//       the first exit() in a hidden app jumps to unmapped memory
//       and SIGSEGVs.
//     - pthread_atfork handlers registered by module code: bionic's
//       fork() runs them, so every later fork() in the hidden app
//       would crash the same way.
//     - a forensic trace: the entries' dso handles point at our
//       (unmapped or anonymized) segments — exactly what
//       public Zygisk detectors (lrhtony/ZygiskDetector, read this
//       round) enumerate by parsing libc's g_array.
//
// __dso_handle is a HIDDEN symbol (not dlsym-able), but bionic
// defines it as a SELF-POINTING pointer
// (__dso_handle_so.h: static const void* const __dso_handle_const =
// &__dso_handle_const; with __dso_handle as an alias) — so scanning
// each record's non-executable pages for a word W with *(void**)W ==
// W finds every library's handle with no symbol lookups.
//
// Entry points (called by entry.cpp's Tier A path, in this order):
//
//   zs_collect_dso_handles()  — BEFORE hide_prepare_tier_a_records()
//       (every record must still be mapped and file-backed for the
//       scan). Returns {handle, self} pairs: SELF records yield
//       libpayload's own handle, OTHER records (modules, bridge)
//       yield theirs.
//   zs_atexit_finalize(h)     — the purge for ONE library:
//       __cxa_finalize(h) — extracts the entries (zeroing them),
//       CALLS the destructors (so it must run while that library's
//       text is still mapped), compacts the array and unregisters
//       its atfork handlers: the exact protocol a proper dlclose
//       runs. Modules are finalized BEFORE the Tier A prep unmaps
//       their text; the payload's own handle is finalized only
//       after the trampoline page is prepared and immediately
//       before the jump (nothing libpayload-side may touch its C++
//       statics afterwards).
// ------------------------------------------------------------------------

struct ZsDsoHandle {
    uintptr_t handle;   // the __dso_handle address (self-pointing word)
    uint32_t  self;     // 1 = found in a ZS_SO_SELF record (libpayload)
};

// Maximum handles the Tier A path tracks (the payload + up to 15
// modules/bridge/loader records). Extras are logged and skipped.
#define ZS_MAX_DSO_HANDLES 16

size_t zs_collect_dso_handles(struct ZsDsoHandle* out, size_t cap);

// Purge one library's atexit + atfork registrations. Returns 1 when
// __cxa_finalize ran, 0 when it was unavailable/failed (logged; the
// device then carries the documented residual).
int zs_atexit_finalize(uintptr_t dso_handle);

#ifdef ZS_HOST_TEST
// Test-only: inject a uid into the deny set (no root access to
// packages.list on the host).
void hide_test_force_deny_uid(uid_t uid);

// Test-only: replace the record set (drives Tier A preprocessing
// against synthetic records without loading real .so files).
void hide_test_set_records(const struct so_record* recs, size_t count);

// Test-only: point the denylist at a writable file and drive the
// mtime-refresh + throttle logic deterministically. (extern "C" so
// the dlopen-based dispatch test can resolve them with dlsym.)
extern "C" {
void   hide_test_set_denylist_path(const char* path);
void   hide_test_reset_refresh();   // force the next mtime check to run
int    hide_test_denylist_reload_count();

// Test-only (Round 12): point the packages.list parse at a writable
// file so hide_lookup_package_for_uid is drivable on the host.
void   hide_test_set_packages_list_path(const char* path);
}

// Test-only: run the maps scanner over synthetic content.
void   zs_scan_maps_into_records_test(const char* buf, size_t total);

// Round 9 (B1) — mount-namespace seam. Replace the unshare /
// MS_SLAVE remount / umount2 syscalls with recorders to verify the
// ordering and fail-closed gating of hide_apply_for_target()
// without CAP_SYS_ADMIN. See hide.cpp for the log format.
typedef int (*ZsUnshareFn)(int);
typedef int (*ZsMountSlaveFn)();
typedef int (*ZsUmount2Fn)(const char*, int);
void        zs_test_set_mount_fns(ZsUnshareFn u, ZsMountSlaveFn s,
                                  ZsUmount2Fn um);
void        zs_test_mount_log_reset();
void        zs_test_mount_log_append(char op);
const char* zs_test_mount_log();

// Round 19 — the spoofed-properties bind-mount seams.
void zs_test_set_bind_mount_fn(int (*bind)(const char*, const char*));
void zs_test_props_source_clear();
void zs_test_set_prop_serial_target(const char* target);

// Round 26 — the mount-target selection core (probe = the path a
// production probe would stat): a regular file selects the 6.x
// single-file target, a directory/missing path the 7.0+ serial one.
const char* zs_test_props_target_for_probe(const char* probe);
#endif

} // namespace zygisk_study

#ifdef ZS_HOST_TEST
// Round 20: C-linkage test seam (defined in hide.cpp) so the
// dlopen-based and link-based tests can both resolve it.
extern "C" void zs_test_props_fiction_capture_both();
#endif
