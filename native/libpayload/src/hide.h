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

// Apply the mount unmount + property clone/spoof actions. Only
// meaningful if hide_setup_for_target*() returned 1. Must be called
// while the child is still root (before the real privilege drop).
void hide_apply_for_target(const char* package_name);

// Clean up any traces we left behind after apply, before user code
// runs. The caller (entry.cpp) calls this from postAppSpecialize.
void hide_clean_trace();

// ---- self-unmap record access (used by entry.cpp + trampoline) ----

// One maps segment to be unmapped from the denylisted child.
// Kept in sync with the asm trampolines in
// unmap_trampoline_aarch64.S / unmap_trampoline_x86_64.S — they read
// {base, size} pairs with the exact layout below. Do not reorder.
struct so_record {
    uintptr_t base;    // segment start
    size_t    size;    // segment length
    uint32_t  flags;   // ZS_SO_* bits
    uint32_t  _pad;    // keep 8-byte stride stable for the asm
};

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

// True if any ZS_SO_SELF records are registered (i.e. the trampoline
// path should be used). On host test builds without a real
// libpayload.so mapping this is 0 and the whole thing is a no-op.
int    hide_trampoline_unmap_pending();

#ifdef ZS_HOST_TEST
// Test-only: inject a uid into the deny set (no root access to
// packages.list on the host).
void hide_test_force_deny_uid(uid_t uid);
#endif

} // namespace zygisk_study
