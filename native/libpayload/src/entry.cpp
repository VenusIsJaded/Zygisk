// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/entry.cpp
//
// libpayload.so — the in-process trampoline + Zygisk module loader.
//
// Round 7 — how this actually runs on a device now:
//
//   The pre-Round-7 code claimed an "LD_PRELOAD-style override on
//   fork()" that was never implemented: `fork` was only *declared*,
//   nothing patched any PLT/GOT slot for it, and
//   zygisk_study_payload_fork_hook was dead code. The entire hide
//   pipeline could never execute on a real device.
//
//   The real mechanism now hooks the privilege-drop calls that every
//   zygote child makes during specialization (setresgid/setresuid —
//   with legacy setgid/setuid covered too) via the same GOT-walking
//   machinery the hide layers use. This is the right hook point for
//   three reasons:
//
//     1. It fires in the child while the child is STILL ROOT — the
//        only moment unshare(CLONE_NEWNS) can succeed. A
//        postAppSpecialize hook (the old design) runs after setresuid,
//        when the capability is gone and every umount would fail.
//
//     2. It carries the target identity: the uid argument maps to a
//        package via /data/system/packages.list, so the DenyList
//        decision needs no Java-side plumbing. Matching on the appId
//        family (uid % 100000) covers work profiles automatically.
//
//     3. It fires for USAP-forked apps too (the app-process pool does
//        not call fork() again, but it always specializes).
//
//   Each hook enters through a hand-written asm wrapper (see
//   unmap_trampoline_<arch>.S) that saves the caller's callee-saved
//   registers at a fixed frame layout. When the hide pipeline decides
//   to disappear completely (Tier A), the trampoline unmaps every
//   record and "returns" straight to libandroid_runtime's code with
//   the real call's return value — no libpayload instruction executes
//   afterwards.
//
// Public ABI (all explicitly exported with visibility=default):
//
//   zs_entry_init         — one-time setup
//   zs_entry_pre_fork     — module pre-fork dispatch
//   zs_entry_post_fork    — package-name-keyed hide pipeline
//   (test-only exports under ZS_HOST_TEST at the bottom)

#include "hide.h"
#include "hide_advanced.h"
#include "hide_stealth.h"
#include "log.h"
#include "module_dispatch.h"
#include "resolve_libc.h"
#include "unmap_trampoline.h"

// Branch-prediction hints (the payload's hot per-fork paths).
#ifndef ZS_LIKELY
#  define ZS_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define ZS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "zygisk.hpp"

namespace zygisk_study {

// ------------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------------

static std::atomic<int> g_initialized{0};

// The pid that loaded the payload (the zygote). Any process whose pid
// differs is a fork. This is the primary "are we in a child?" check —
// more robust than a fork-hook flag, because it also covers children
// forked through paths that do not call fork() through a patched GOT
// slot (the USAP pool).
static pid_t g_origin_pid = -1;

// Set once the hide pipeline has run in this process (guards against
// setresgid AND setresuid both triggering it).
static std::atomic<int> g_hide_done{0};

// Round 12: set once the module post-dispatch + forced-unmount phase
// has run (guards the setresuid hook against double-entry the same
// way g_hide_done guards the hide pipeline).
//
// ROUND 37 (Bug 4): the latch is now PID-AWARE. g_dispatch_done is
// copy-on-write INHERITED by children of a dispatched process — the
// app-zygote case: AOSP forks the app zygote from the system zygote
// (our uid-drop hook dispatches modules in IT), and the app zygote
// then forks isolated children (appId 90000-98999, verified from
// Process.java FIRST/LAST_APP_ZYGOTE_ISOLATED_UID, present since
// Android 10). Those children inherited done=1 and the guards below
// bounced them off — the isolated child of a NON-denylisted owner
// (payload resident, modules loaded) got neither the setcontext name
// check nor its own pre/post callbacks, while real Zygisk dispatches
// for every specialization. The pid field records WHICH process
// latched; an inherited latch (pid mismatch) re-arms the isolated
// coverage. A latch set in THIS process still short-circuits exactly
// as before. (A latch holder is always an ancestor of the current
// process, and a live process' pid differs from any ancestor's, so
// pid reuse cannot false-positive.)
static std::atomic<int> g_dispatch_done{0};
static pid_t            g_dispatch_pid = 0;   // R37: set BEFORE the
                                               // release store above

// ROUND 37 (Bug 4): is the dispatch latch set by THIS process?
// (acquire-loads pair with the pid store preceding the latch's
// release store: seeing done==1 implies the pid field is visible.)
static int dispatch_latched_in_this_process() {
    return g_dispatch_done.load(std::memory_order_acquire) &&
           g_dispatch_pid == getpid();
}

// Round 36: set when the selinux_android_setcontext GOT hook is
// actually REGISTERED (the real symbol resolved — it does on every
// studied release from 5.0.0_r1 to main; a hypothetical vendor build
// that hides it leaves this 0). While 0, the uid-drop hook keeps the
// pre-R36 behavior for isolated-range uids: dispatch at uid-drop
// time, no name-based isolated coverage (modules keep working —
// graceful degradation). While 1, the uid-drop hook DEFERS the
// decision for isolated-range uids (appId 90000-99999) to the
// setcontext hook, where the full nice_name arrives.
static std::atomic<int> g_setcontext_hook_live{0};

#ifdef ZS_HOST_TEST
// Round 30: test-only — when 1, the Tier A path skips the
// __cxa_finalize purge so the regression proof can demonstrate the
// dangling-entry crash it fixes. Unset = byte-identical production
// behavior.
static int g_disable_atexit_purge = 0;
#endif

// ------------------------------------------------------------------------
// The hide pipeline (shared by the uid hooks and the exported
// package-name API).
// ------------------------------------------------------------------------

// A no-op "real call" for pipeline invocations that have no libc
// function to relay (the exported package-name API).
static long priv_drop_nop(void*) { return 0; }

// Run the full hide pipeline for a target we have ALREADY decided to
// hide (hide_setup_for_target* returned 1). `wrapper_fp` is non-null
// when invoked from an asm wrapper (Tier A possible); null when
// invoked from the exported API (Tier B forced).
//
// Round 12: the pipeline is split into two phases because the
// FORCE_DENYLIST_UNMOUNT path needs the mount work while the child is
// still root (it runs BEFORE the module pre callbacks) but the
// spoof/unmap work only AFTER the post callbacks (they are the last
// module code that will ever execute).
//
// Phase 1 (requires euid 0 / CAP_SYS_ADMIN): unshare + unmounts.
static void hide_mount_phase() {
    hide_apply_for_target(nullptr);          // unshare + unmount
}

// Phase 2: per-process spoofing + cleanup, ending in the Tier A
// unmap (relaying the real call's return value to the runtime) or the
// Tier B hook install.
//
// `call_real`/`real_ctx` invoke the real libc function this hook
// replaced. In the Tier A path it MUST run before the trampoline
// jumps out — the runtime expects setresgid/setresuid to have
// actually executed, and skipping it would leave the app running as
// root (an instant detection and a security hole).
//
// `real_already_ran`/`rv_in`: the FORCE path already made the real
// call (module post callbacks needed the dropped privileges); the
// trampoline relays `rv_in` instead of calling again.
//
// Returns true if the trampoline jumped out (caller must return
// immediately — no libpayload instruction after it is safe).
static bool hide_process_phase(void* wrapper_fp,
                               long (*call_real)(void*), void* real_ctx,
                               bool real_already_ran, long rv_in) {
    // ---- per-process spoofing + cleanup (both tiers) ----
    hide_advanced_apply_post_fork(nullptr);  // props clone+spoof, fds, env
    hide_stealth_apply_post_fork(nullptr);   // comm, rlimit_core, cwd

    if (wrapper_fp && zs_trampoline_supported() &&
        hide_trampoline_unmap_pending()) {
        // ---------------- Tier A: vanish ----------------
        // 0. Round 30 — collect every library's __dso_handle (the
        //    self-pointing word in its data) while ALL records are
        //    still mapped, then purge the MODULE libraries' atexit /
        //    pthread_atfork registrations NOW, while their
        //    destructors can still execute (bionic's
        //    __cxa_finalize calls them; their text is unmapped by
        //    step 1 below). This is the exact protocol a proper
        //    dlclose runs (crtbegin_so's __on_dlclose); skipping it
        //    left dangling entries in libc's AtexitArray — the first
        //    exit() or fork() in the hidden app would SIGSEGV, and
        //    the entries are a detection surface (see hide.h's
        //    Round 30 note for the source-verified details).
        ZsDsoHandle dsoh[ZS_MAX_DSO_HANDLES];
        size_t nd = 0;
#ifdef ZS_HOST_TEST
        if (!g_disable_atexit_purge)
#endif
        {
            nd = zs_collect_dso_handles(dsoh, ZS_MAX_DSO_HANDLES);
            for (size_t i = 0; i < nd; ++i) {
                if (!dsoh[i].self) {
                    zs_atexit_finalize(dsoh[i].handle);
                }
            }
        }
        // 1. Preprocess the record set (hide.cpp):
        //      - every READ-ONLY segment of every record becomes a
        //        content-preserving anonymous copy (the linker's
        //        soinfo nodes point into those segments — unmapping
        //        them turned a later dlopen() solist walk into a
        //        crash; see hide.h),
        //      - exec/writable segments of OTHER records (modules,
        //        bridge, loader) are munmap'd right there,
        //      - the remaining SELF exec/writable segments come back
        //        for the trampoline, SELF records first so the fixed
        //        32-record array can never cut them.
        so_record prep_out[kTrampMaxRecords];
        size_t pn = hide_prepare_tier_a_records(prep_out,
                                                kTrampMaxRecords);
        // 2. Restore every GOT slot we ever patched. A slot pointing
        //    into soon-to-be-unmapped memory is a guaranteed crash on
        //    the app's next libc call.
        hide_advanced_uninstall_got_hooks();
        // 3. PREPARE the trampoline page (Round 30 split: every
        //    failing operation happens HERE). A failure falls back to
        //    Tier B with the payload's C++ statics still intact —
        //    the purge of OUR OWN handle (step 4) must only run when
        //    the only remaining exits are the real call and the jump.
        ZsTrampRecord tramp_recs[kTrampMaxRecords];
        size_t tn = 0;
        for (size_t i = 0; i < pn && tn < kTrampMaxRecords; ++i) {
            tramp_recs[tn].base = prep_out[i].base;
            tramp_recs[tn].size = prep_out[i].size;
            ++tn;
        }
        void* tramp_page = zs_trampoline_prepare(tramp_recs, tn,
                                                 wrapper_fp);
        if (tramp_page) {
            // 4. Round 30 — purge the payload's OWN registrations.
            //    From here on NO libpayload C++ static may be
            //    touched: the dtors just ran. The remaining steps
            //    (the real libc call and the trampoline jump) are
            //    static-free by design.
#ifdef ZS_HOST_TEST
            if (!g_disable_atexit_purge)
#endif
            {
                for (size_t i = 0; i < nd; ++i) {
                    if (dsoh[i].self) {
                        zs_atexit_finalize(dsoh[i].handle);
                    }
                }
            }
            // 5. Drop privileges for real — the specialization code
            //    that resumes after us assumes the call succeeded.
            long rv = real_already_ran ? rv_in : call_real(real_ctx);
            // 6. Hand everything left to the trampoline: it unmaps
            //    our own remaining segments (text/data — the
            //    read-only metadata survives as anonymous pages) and
            //    returns `rv` to the wrapper's caller without
            //    executing another libpayload instruction.
            if (zs_trampoline_jump(tramp_page, rv) == 0) {
                return true;  // never reached — jumped out
            }
            ZS_LOGW("payload: trampoline jump failed (impossible "
                    "state); falling back to Tier B");
            // Fall through: the real call already ran above; the
            // caller's second invocation of an idempotent
            // setres*/set* is harmless.
        } else {
            ZS_LOGW("payload: trampoline prepare failed; falling "
                    "back to hook-based hiding (Tier B)");
            // The real call has NOT run yet — the Tier B fallthrough
            // (or the FORCE path's already-relayed rv) handles it.
        }
    }

    // ---------------- Tier B: hook-based hiding ----------------
    // Payload stays resident; open/stat/fopen/readlink/property reads
    // get filtered. Installed HERE, in the hidden child only — every
    // other process on the system never executes a hooked call.
    hide_advanced_install_tier_b();
    return false;
}

// The classic denylisted path: both phases back to back, real call
// made from inside the Tier A branch as before.
static bool run_hide_pipeline(void* wrapper_fp,
                              long (*call_real)(void*), void* real_ctx) {
    hide_mount_phase();
    return hide_process_phase(wrapper_fp, call_real, real_ctx,
                              false, 0);
}

// Real-call thunks (resolved from libc at init). Under ZS_HOST_TEST a
// recorder seam can replace them so tests can assert what the hooks
// actually forwarded (module-rewritten uid/gid included).
static int (*g_real_setresgid)(gid_t, gid_t, gid_t) = nullptr;
static int (*g_real_setresuid)(uid_t, uid_t, uid_t) = nullptr;
static int (*g_real_setgid)(gid_t)                  = nullptr;
static int (*g_real_setuid)(uid_t)                  = nullptr;
static long (*g_real_fork)(void)                    = nullptr;
// Round 35 — the isolated-process coverage hook's real target:
// int selinux_android_setcontext(uid_t, int, const char*, const char*)
// from libselinux.so, called by AOSP's SpecializeCommon on every
// studied release (5.0.0_r1 .. refs/heads/main) AFTER the uid drop
// with the FULL, untruncated nice_name. Resolved at init; the GOT
// hook is only registered when this resolves (a vendor build with the
// symbol hidden leaves the coverage off rather than hooking blindly).
static int (*g_real_setcontext)(uid_t, int, const char*, const char*) = nullptr;
#ifdef ZS_HOST_TEST
// Round 35 — test-only override for the real setcontext (recorder +
// deterministic return value); see zs_impl_setcontext.
static long (*g_test_setcontext_fn)(long, long, const char*,
                                    const char*) = nullptr;
#endif

struct RealCtx3 { long a, b, c; };
struct RealCtx1 { long a; };

static long call_real_setresgid(void* ctx) {
    RealCtx3* c = (RealCtx3*)ctx;
#ifdef ZS_HOST_TEST
    if (ZsDropSeam* s = zs_test_drop_seam(); s && s->setresgid)
        return s->setresgid((gid_t)c->a, (gid_t)c->b, (gid_t)c->c);
#endif
    return g_real_setresgid ? g_real_setresgid((gid_t)c->a, (gid_t)c->b, (gid_t)c->c)
                            : syscall(SYS_setresgid, c->a, c->b, c->c);
}
static long call_real_setresuid(void* ctx) {
    RealCtx3* c = (RealCtx3*)ctx;
#ifdef ZS_HOST_TEST
    if (ZsDropSeam* s = zs_test_drop_seam(); s && s->setresuid)
        return s->setresuid((uid_t)c->a, (uid_t)c->b, (uid_t)c->c);
#endif
    return g_real_setresuid ? g_real_setresuid((uid_t)c->a, (uid_t)c->b, (uid_t)c->c)
                            : syscall(SYS_setresuid, c->a, c->b, c->c);
}
static long call_real_setgid(void* ctx) {
    RealCtx1* c = (RealCtx1*)ctx;
#ifdef ZS_HOST_TEST
    if (ZsDropSeam* s = zs_test_drop_seam(); s && s->setgid)
        return s->setgid((gid_t)c->a);
#endif
    return g_real_setgid ? g_real_setgid((gid_t)c->a)
                         : syscall(SYS_setgid, c->a);
}
static long call_real_setuid(void* ctx) {
    RealCtx1* c = (RealCtx1*)ctx;
#ifdef ZS_HOST_TEST
    if (ZsDropSeam* s = zs_test_drop_seam(); s && s->setuid)
        return s->setuid((uid_t)c->a);
#endif
    return g_real_setuid ? g_real_setuid((uid_t)c->a)
                         : syscall(SYS_setuid, c->a);
}

// The shared body of the GID-drop hooks (setresgid/setgid — the first
// privilege-drop call the runtime makes in the child).
//
// `id` is the gid the runtime is about to install. Real zygote
// specialization always calls setresgid() and setresuid() (in that
// order) in the child, both while it is still root — exactly the
// window we need.
//
// Round 12: on the non-hidden path the gid is recorded for the module
// dispatch args; the module callbacks themselves fire from the
// UID-drop hooks (the uid argument is the identity key).
static long gid_drop_hook(void* wrapper_fp, uid_t id,
                          long (*call_real)(void*), void* real_ctx) {
    if (getpid() != g_origin_pid &&
        !g_hide_done.load(std::memory_order_acquire)) {
        if (hide_setup_for_target_uid(id)) {
            g_hide_done.store(1, std::memory_order_release);
            if (run_hide_pipeline(wrapper_fp, call_real, real_ctx)) {
                return 0;  // unreachable — Tier A already jumped out
            }
            // Tier B: the real call still needs to run.
            return call_real(real_ctx);
        }
        // Not hidden: remember the gid the runtime is installing so
        // the module args carry the real value.
        zs_module_record_gid((gid_t)id);
    }
    return call_real(real_ctx);
}

// Apply a module-requested gid change from inside the UID-drop hook.
// Still legal here: euid is 0 until the real setresuid runs (gid
// changes alone do not clear the effective capability set), so
// CAP_SETGID is still held. Failure is logged and ignored — the
// runtime's own gid stands.
static void apply_module_gid_override(gid_t gid) {
#ifdef ZS_HOST_TEST
    if (ZsDropSeam* s = zs_test_drop_seam(); s && s->setresgid) {
        (void)s->setresgid(gid, gid, gid);
        return;
    }
#endif
    if (g_real_setresgid) {
        if (g_real_setresgid(gid, gid, gid) != 0) {
            ZS_LOGW("payload: module gid override to %u failed: %s",
                    (unsigned)gid, strerror(errno));
        }
    } else {
        if (syscall(SYS_setresgid, gid, gid, gid) != 0) {
            ZS_LOGW("payload: module gid override to %u failed: %s",
                    (unsigned)gid, strerror(errno));
        }
    }
}

// The shared body of the UID-drop hooks (setresuid/setuid — the LAST
// privilege-drop call, the one that actually changes euid).
//
// Round 12 dispatch order (non-denylisted children):
//   1. (still root) FORCE_DENYLIST_UNMOUNT mount work, if requested —
//      module pre callbacks see the unmounted state and can still add
//      their own mounts in the private namespace.
//   2. (still root) preAppSpecialize / preServerSpecialize with the
//      real args; module writes to args->uid/args->gid are forwarded
//      to the real calls below.
//   3. the real privilege drop.
//   4. postAppSpecialize / postServerSpecialize (specialized).
//   5. the FORCE spoof/unmap phase — the post callbacks were the last
//      module code that will ever execute here.
//
// Denylisted children never reach the dispatch: the hide pipeline
// (which unmaps the module .so's) takes over at the first drop.
static long uid_drop_hook(void* wrapper_fp, uid_t id,
                          long (*call_real)(void*), void* real_ctx,
                          int arg_count) {
    // ROUND 39 (C1): fail-inert — in a policy-denied environment the
    // child pipeline must not run against the half-state that
    // crash-looped the system_server children on the Android 7.1.1
    // emulator. Relay the call untouched; the module stays resident
    // and injected, the machinery stays off.
    if (ZS_UNLIKELY(zs_module_env_denied())) {
        return call_real(real_ctx);
    }
    if (getpid() != g_origin_pid &&
        !g_hide_done.load(std::memory_order_acquire)) {
        // ROUND 37 (Bug 4): an ANCESTOR's dispatch latch (an app
        // zygote that dispatched — see g_dispatch_pid's comment) must
        // block re-dispatch only for NON-isolated children: an app's
        // own fork() worker is not a zygote specialization, so it
        // keeps the inherited "already dispatched" semantics (exactly
        // the pre-R37 behavior for that case). Isolated-range children
        // (appId 90000-99999) keep their OWN coverage: the deny check,
        // the setcontext deferral, the deferred module dispatch.
        int own_dispatch = dispatch_latched_in_this_process();
        int ancestor_dispatch =
            !own_dispatch &&
            g_dispatch_done.load(std::memory_order_acquire);
        uid_t app_id = (uid_t)(id % 100000);
        int isolated_range = (app_id >= 90000 && app_id <= 99999);
        if (own_dispatch || (ancestor_dispatch && !isolated_range)) {
            return call_real(real_ctx);
        }
        // The DenyList check in case the gid drop did not fire (or
        // decided on a DIFFERENT key — uid != gid): denylisted
        // children hide instead of dispatching. Round 14: when the
        // gid-drop hook already decided on exactly this key (the
        // standard specialization order, gid == uid), the re-check
        // is skipped — one hash lookup less per app fork.
        if (!hide_deny_decided_for(id) &&
            hide_setup_for_target_uid(id)) {
            g_hide_done.store(1, std::memory_order_release);
            if (run_hide_pipeline(wrapper_fp, call_real, real_ctx)) {
                return 0;  // unreachable — Tier A already jumped out
            }
            return call_real(real_ctx);
        }

        // ---- Round 36: the isolated-process deferral ----
        // Isolated-range uids (appId 90000-99999 in the uid%100000
        // frame: 99000-99999 system-zygote, 90000-98999 app-zygote —
        // Process.java FIRST_/LAST_ISOLATED_UID and
        // FIRST_/LAST_APP_ZYGOTE_ISOLATED_UID, verified from AOSP)
        // belong to NO package: the uid map cannot decide them, so
        // the pre-R36 code fell straight into the module dispatch
        // below — injecting modules (and leaving them mapped) into
        // the isolated children of DENYLISTED apps, and latching
        // g_dispatch_done so the setcontext name matcher (this
        // round's coverage) never fired. The owner's identity is
        // only knowable from the nice_name, which AOSP hands to
        // selinux_android_setcontext AFTER this hook (verified
        // 5.0.0_r1 / 10.0.0_r1 / 12.0.0_r1 / 16.0.0_r1 / main: the
        // call is the tail of SpecializeCommon, setresuid is the
        // middle). So: run the root-only work we CAN run here (the
        // FORCE mount phase), make the real call, and leave the
        // decision + dispatch to zs_impl_setcontext. A vendor build
        // without the setcontext symbol (g_setcontext_hook_live == 0)
        // takes the old path instead — modules keep dispatching at
        // uid-drop time, with no isolated coverage (graceful).
        if (g_setcontext_hook_live.load(std::memory_order_acquire)) {
            uid_t iso_app_id = (uid_t)(id % 100000);
            if (iso_app_id >= 90000 && iso_app_id <= 99999) {
                if (zs_module_dispatch_wanted() &&
                    zs_module_force_unmount()) {
                    // Round 36 Bug B: the FORCED variant — the gated
                    // hide_mount_phase was a silent no-op here since
                    // Round 12 (g_will_hide == 0 for undecidable
                    // uids). Still root: the last chance for the
                    // namespace work.
                    hide_mount_phase_forced();
                }
                // NOTE: no dispatch, no latches — zs_impl_setcontext
                // owns this child from here. If specialization dies
                // before setcontext (fail_fn on a failed drop), the
                // child is dying anyway; the module callbacks of a
                // failed specialization were never a contract.
                return call_real(real_ctx);
            }
        }

        // ---- Round 12: module dispatch ----
        if (zs_module_dispatch_wanted()) {
            if (zs_module_force_unmount()) {
                // Round 36 Bug B: the FORCE mount phase. Pre-R36 this
                // called the DECISION-GATED hide_mount_phase(), which
                // returns immediately for every non-denylisted child
                // (g_will_hide == 0) — i.e. for exactly the children
                // FORCE exists for. The mount half of the option has
                // been a no-op since Round 12; this now runs the real
                // fail-closed namespace dance (see hide.cpp).
                hide_mount_phase_forced();          // still root
            }

            uid_t eff_uid = id, eff_gid = 0;
            ZsChildKind kind =
                zs_module_pre_specialize(id, &eff_uid, &eff_gid);
            if (kind != ZS_CHILD_NONE) {
                if ((gid_t)eff_gid != zs_module_recorded_gid()) {
                    apply_module_gid_override((gid_t)eff_gid);
                }
                // The runtime calls setresuid(uid, uid, uid) /
                // setuid(uid) — forward the (possibly module-rewritten)
                // effective uid. RealCtx1 is a layout prefix of
                // RealCtx3 (both start with the `a` field).
                if (arg_count == 3) {
                    RealCtx3* c = (RealCtx3*)real_ctx;
                    c->a = (long)eff_uid;
                    c->b = (long)eff_uid;
                    c->c = (long)eff_uid;
                } else {
                    RealCtx1* c = (RealCtx1*)real_ctx;
                    c->a = (long)eff_uid;
                }
                long rv = call_real(real_ctx);

                zs_module_post_specialize();
                // R37: pid BEFORE the release store (acquire readers).
                g_dispatch_pid = getpid();
                g_dispatch_done.store(1, std::memory_order_release);

                // Re-read the flag: a module may have called
                // setOption(FORCE_DENYLIST_UNMOUNT) from its pre
                // callback (late request — the mount phase of this
                // fork was already decided, but the spoof/unmap phase
                // still applies after its post callback).
                if (zs_module_force_unmount()) {
                    if (hide_process_phase(wrapper_fp, priv_drop_nop,
                                           nullptr, true, rv)) {
                        return 0;  // Tier A jumped out with rv relayed
                    }
                }
                return rv;
            }
        }
    }
    return call_real(real_ctx);
}

// The C++ implementations the asm wrappers call.
// Signatures must match unmap_trampoline_<arch>.S exactly.

extern "C" long zs_impl_setresgid(void* wrapper_fp, long a0, long a1, long a2) {
    RealCtx3 ctx{a0, a1, a2};
    return gid_drop_hook(wrapper_fp, (uid_t)a0,
                         call_real_setresgid, &ctx);
}

extern "C" long zs_impl_setresuid(void* wrapper_fp, long a0, long a1, long a2) {
    RealCtx3 ctx{a0, a1, a2};
    return uid_drop_hook(wrapper_fp, (uid_t)a0,
                         call_real_setresuid, &ctx, 3);
}

extern "C" long zs_impl_setgid(void* wrapper_fp, long a0) {
    RealCtx1 ctx{a0};
    return gid_drop_hook(wrapper_fp, (uid_t)a0,
                         call_real_setgid, &ctx);
}

extern "C" long zs_impl_setuid(void* wrapper_fp, long a0) {
    RealCtx1 ctx{a0};
    return uid_drop_hook(wrapper_fp, (uid_t)a0,
                         call_real_setuid, &ctx, 1);
}

// Round 35 — the isolated-process coverage hook. Called (through the
// patched GOT slot) as AOSP's SpecializeCommon winds down:
//     selinux_android_setcontext(uid, isSystemServer, seInfo, niceName)
// — AFTER setresuid/setresgid already ran and returned. The uid-only
// matcher has therefore already decided for every package-backed uid;
// the ONLY decisions still open are the ranges Android never maps to
// a package: the isolated ranges (appId 99000-99999 forked from the
// system zygote; 90000-98999 forked from an app zygote — covered for
// free when the app zygote itself was hidden, but matched here too
// because a NON-denylisted app's app-zygote keeps the payload
// resident and its isolated children deserve the same check).
//
// The name is the authoritative signal: ActiveServices builds
// isolated process names as "<package>:<class>" / "<pkg>:ishared:<n>"
// (verified in main), so a denylist entry prefix decides. This is
// beyond what Magisk's DenyList mechanism itself does (its uid map
// carries package uids only) — closing a documented coverage gap.
//
// Ordering constraints honored here:
//   * The REAL setcontext runs FIRST — the SELinux domain transition
//     must happen exactly once, before any of our unmap work.
//   * The mount phase (unshare + unmounts) is SKIPPED: at this point
//     the child already dropped uid (no CAP_SYS_ADMIN) — an honest,
//     documented residual: the isolated child keeps the platform's
//     mount view; the maps scrub (the actual detection surface for a
//     process that can read /proc/self/maps) runs in full.
//   * hide_process_phase(..., real_already_ran=true, rv) is the exact
//     shape the FORCE path uses: the trampoline relays the ALREADY
//     OBTAINED return value instead of calling anything again.
//
// ROUND 36 — the deferred dispatch. The uid-drop hook defers the
// module dispatch for isolated-range uids to HERE (the only point
// where the nice_name exists); a NO-MATCH (or null name — a child
// AOSP specialized without one) therefore still owes the child its
// module callbacks. They run HERE, after the real setcontext:
// preAppSpecialize fires with the FULL name in the args (closer to
// real Zygisk's semantics than the old uid-map path, which had
// nothing — /proc/self/cmdline still holds the zygote's name at
// this point in SpecializeCommon), then postAppSpecialize, then the
// latch. Documented residuals of the deferral (vs the old uid-drop
// position, which could not know the name at all):
//   * module writes to args->uid/args->gid are accepted but INERT —
//     the runtime's setresuid already executed; an isolated child's
//     uid is assigned by system_server and is not module business
//     anyway;
//   * module log writes are dropped — SpecializeCommon ran
//     __android_log_close() before the setcontext call (verified
//     main: the close is 5 lines above), so logd sockets are gone;
//   * the callbacks run unprivileged (euid = the isolated uid) —
//     the price of deciding by NAME instead of by uid. The FORCE
//     mount phase is NOT affected: the uid-drop deferral arm runs
//     it while still root, before returning.
extern "C" long zs_impl_setcontext(void* wrapper_fp, long a0, long a1,
                                   long a2, long a3) {
    // a0 = uid, a1 = is_system_server, a2 = se_info, a3 = nice_name.
    long rv;
#ifdef ZS_HOST_TEST
    if (g_test_setcontext_fn) {
        rv = g_test_setcontext_fn(a0, a1, (const char*)a2,
                                  (const char*)a3);
    } else
#endif
    if (ZS_LIKELY(g_real_setcontext != nullptr)) {
        rv = g_real_setcontext((uid_t)a0, (int)a1, (const char*)a2,
                               (const char*)a3);
    } else {
        // Unresolved real (the hook is not registered when resolution
        // failed; this arm exists only for direct-call tests).
        rv = -1;
    }

    // ROUND 39 (C1): fail-inert in policy-denied environments (see
    // module_dispatch.cpp) — the coverage/dispatch below is exactly
    // the machinery that ran on half-state on the 7.1.1 emulator.
    if (ZS_UNLIKELY(zs_module_env_denied())) {
        return rv;
    }
    // Isolated coverage: forked children only, undecidable ranges
    // only, once only. ROUND 37 (Bug 4): the dispatch-latch bounce is
    // now pid-aware — an INHERITED latch (an app zygote that
    // dispatched) must not disable this hook for the app zygote's own
    // isolated children (the deferral was shipped for exactly them;
    // the guard was the last link that made it unreachable). A latch
    // set in THIS process still returns: this child already
    // dispatched (own uid-drop or this same hook earlier).
    if (ZS_LIKELY(getpid() == g_origin_pid) ||
        g_hide_done.load(std::memory_order_acquire) ||
        dispatch_latched_in_this_process()) {
        return rv;
    }
    uid_t app_id = (uid_t)(((uid_t)a0) % 100000);
    if (ZS_UNLIKELY(app_id < 90000 || app_id > 99999)) {
        // Package-backed uid (or the system server): the uid-drop
        // hook already decided — dispatch or hide, both latched.
        return rv;
    }
    if (a3 != 0 && hide_setup_for_isolated_name((const char*)a3)) {
        g_hide_done.store(1, std::memory_order_release);
        // No mount phase possible post-drop; spoof + unmap phases run
        // (hide_process_phase handles both tiers). Modules never ran
        // in this child (the uid hook deferred, the name matched) —
        // the same "modules vanish with everything else in hidden
        // processes" contract the uid path keeps.
        if (hide_process_phase(wrapper_fp, priv_drop_nop, nullptr,
                               true, rv)) {
            return 0;   // Tier A jumped out with rv relayed
        }
        // Tier B fell through — the payload stays resident with the
        // Tier B hooks installed; return the real call's value.
        return rv;
    }
    // Round 36 — the deferred isolated dispatch: the owner is NOT
    // denylisted (or the name is null — undecidable, treated as
    // non-denylisted exactly like the pre-R36 uid path treated every
    // isolated uid). Modules run now, with the real name in the args.
    if (zs_module_dispatch_wanted()) {
        uid_t eff_uid = (uid_t)a0, eff_gid = 0;
        ZsChildKind kind = zs_module_pre_specialize(
            (uid_t)a0, &eff_uid, &eff_gid, (const char*)a3);
        if (kind != ZS_CHILD_NONE) {
            // (uid_t)eff_uid / eff_gid are the module's requested
            // overrides — INERT here by the documented residual; the
            // runtime's own drop already ran.
            zs_module_post_specialize();
            // R37: pid BEFORE the release store (acquire readers).
            g_dispatch_pid = getpid();
            g_dispatch_done.store(1, std::memory_order_release);
        }
    }
    return rv;
}

// Kept for the fork wrapper (registered but not required — the pid
// comparison above is the primary child detection).
extern "C" long zs_impl_fork(void* /*wrapper_fp*/) {
    // Round 12: the zygote's first fork is the earliest moment the
    // VM exists AND we still run pre-fork — acquire the JNIEnv and
    // dispatch module onLoad there (once per process lifetime).
    if (getpid() == g_origin_pid) {
        // ROUND 39 (C1): in a policy-denied environment the first
        // fork's zygote-side dispatch would run against the
        // half-initialized daemon state that crashed the children
        // on the Android 7.1.1 emulator — skip it entirely once the
        // gate tripped (the lazy init itself keeps running so the
        // gate can only ever be set by a REAL EACCES probe).
        if (!zs_module_env_denied()) {
        // ROUND 34: refresh the denylist/packages.list HERE, in the
        // long-lived zygote, pre-fork. Child-side refreshes were
        // COW-private: the 2 s throttle never elided a stat (every
        // child started with next_check == 0) and mtime changes
        // re-parsed both files in every child. From here the state
        // advances once per interval for the whole system and every
        // child inherits the fresh map. Steady state: 2 stat() calls
        // per 2 s in the zygote, zero per child (a vDSO clock read
        // when throttled).
        hide_refresh_tick();
        // Round 19: daemon-dependent init (module list fetch, the
        // spoofed properties_serial handoff) retries here until it
        // latches — the daemon is never up at native-bridge init on
        // real devices (late service stage vs zygote start).
        (void)zs_module_lazy_daemon_init();
        zs_module_on_first_fork();
        }
    }
    // Direct libc fork; ART's pthread_atfork handlers must still run.
    if (g_real_fork) return g_real_fork();
    return syscall(SYS_clone, SIGCHLD, 0, nullptr, nullptr, nullptr);
}

// ------------------------------------------------------------------------
// The trampoline builder (see unmap_trampoline.h)
// ------------------------------------------------------------------------

// Data-area layout shared with the .S blobs:
//   [0   .. 512)  records[32] {base, size}
//   [512]         count
//   [520]         wrapper_fp
//   [528]         retval      (returned to the wrapper's caller)
//
// ROUND 32 (found by cross-compiling for armeabi-v7a with the NDK):
// the offsets above are a contract with the .S blobs, which exist ONLY
// for aarch64/x86_64 (64-bit pointers). The layout asserts used to be
// unconditional, which made every 32-bit ABI build fail to compile —
// the 32-bit path uses the stub trampoline functions below and never
// touches this struct. Gate the contract to the arches that ship a
// blob; on 32-bit the struct is inert.
struct ZsTrampData {
    ZsTrampRecord records[kTrampMaxRecords];  // 512 bytes (64-bit)
    size_t    count;        // offset 512
    uintptr_t wrapper_fp;   // offset 520
    long      retval;       // offset 528
    // ROUND 34 (stealth scrub): the blob mprotects its own page
    // R|W (the page is sealed R|X by zs_trampoline_jump before the
    // entry), zeroes the whole data area, and re-seals R|X. The
    // page base is needed for that mprotect; the page size is
    // derived (data occupies the page tail).
    uintptr_t page_base;    // offset 536
};
#if defined(__aarch64__) || defined(__x86_64__)
static_assert(sizeof(ZsTrampData) == 512 + 8 + 8 + 8 + 8,
              "trampoline data layout");
static_assert(offsetof(ZsTrampData, count) == 512, "count offset");
static_assert(offsetof(ZsTrampData, wrapper_fp) == 520, "fp offset");
static_assert(offsetof(ZsTrampData, retval) == 528, "retval offset");
static_assert(offsetof(ZsTrampData, page_base) == 536, "page offset");
#endif

#if defined(__aarch64__) || defined(__x86_64__)
int zs_trampoline_supported() { return 1; }

// Round 30 split: every operation that can FAIL lives in prepare();
// jump() only writes the final retval, seals the page and enters the
// blob. hide_process_phase runs the payload's own atexit purge
// between the two — after the purge there is no Tier B fallback, so
// the tail must be infallible.
void* zs_trampoline_prepare(const ZsTrampRecord* records, size_t count,
                            void* wrapper_fp) {
    if (!records || count == 0 || count > kTrampMaxRecords || !wrapper_fp) {
        return nullptr;
    }
    const size_t code_size = (size_t)(zs_trampoline_code_end
                                      - zs_trampoline_code_start);
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    // ROUND 34: the guard must be page-size-aware and reserve the
    // FULL data area (536 bytes), not a magic 64: on a 4 KB page the
    // data occupies [page+3560, page+4096), so a blob of 3561..4032
    // bytes would have its tail overwritten by the memset below (the
    // old `4096 - 64` bound allowed exactly that — latent only
    // because today's blobs are ~200 bytes).
    if (code_size == 0 ||
        (size_t)code_size > (size_t)page_size - sizeof(ZsTrampData)) {
        return nullptr;
    }

    // One private executable page. RW for the copy; jump() seals it.
    void* page = mmap(nullptr, (size_t)page_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        ZS_LOGW("trampoline: mmap failed: %s", strerror(errno));
        return nullptr;
    }
    // STEALTH: name the page so /proc/self/maps shows
    // "[anon:jit-cache]" — ART processes legitimately carry
    // executable anon pages; a bare rwxp anon page is rarer.
    // (PR_SET_VMA: Android-born, upstreamed to mainline in 5.17 —
    // verified from include/uapi/linux/prctl.h; on older kernels
    // the prctl fails silently and the page stays unnamed, which
    // is why the host test accepts BOTH shapes.)
    constexpr int kPrSetVma = 0x53564d41;
    constexpr int kPrSetVmaAnonName = 0;
    const char kPageName[] = "jit-cache";
    (void)prctl(kPrSetVma, kPrSetVmaAnonName,
                (unsigned long)(uintptr_t)page, (unsigned long)page_size,
                (unsigned long)(uintptr_t)kPageName);

    memcpy(page, (const void*)zs_trampoline_code_start, code_size);
    ZsTrampData* data = (ZsTrampData*)((char*)page + page_size
                                       - sizeof(ZsTrampData));
    memset(data, 0, sizeof *data);
    for (size_t i = 0; i < count; ++i) data->records[i] = records[i];
    data->count      = count;
    data->wrapper_fp = (uintptr_t)wrapper_fp;
    data->page_base  = (uintptr_t)page;   // ROUND 34: for the scrub's mprotect
    // data->retval is written by zs_trampoline_jump() — the real
    // privilege-drop call happens between prepare and jump.
    return page;
}

int zs_trampoline_jump(void* page, long retval) {
    if (!page) return -1;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    ZsTrampData* data = (ZsTrampData*)((char*)page + page_size
                                       - sizeof(ZsTrampData));
    data->retval = retval;   // handed back to the wrapper's caller

    // Make the page read-execute (drop W; nothing writes it again).
    // Keep EXEC: the blob must run. (mprotect on the data area too —
    // it lives on the same page and is only read by the blob.)
    if (mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC) != 0) {
        // Not fatal on every kernel, but W^X hygiene when possible.
        ZS_LOGD("trampoline: mprotect(R|X) failed (continuing): %s",
                strerror(errno));
    }
    __builtin___clear_cache((char*)page, (char*)page + page_size);

    // Enter the blob. Never returns on success.
    ((void(*)(void*))page)((void*)data);
    return -1;  // unreachable on success; caller falls back to Tier B
}

// The Round 7 single-call form (kept for tests and any external
// caller): prepare + jump back to back.
int zs_trampoline_unmap(const ZsTrampRecord* records, size_t count,
                        void* wrapper_fp, long retval) {
    void* page = zs_trampoline_prepare(records, count, wrapper_fp);
    if (!page) return -1;
    return zs_trampoline_jump(page, retval);
}
#else
int zs_trampoline_supported() { return 0; }
int zs_trampoline_unmap(const ZsTrampRecord*, size_t, void*, long) {
    return -1;
}
void* zs_trampoline_prepare(const ZsTrampRecord*, size_t, void*) {
    return nullptr;
}
int zs_trampoline_jump(void*, long) { return -1; }

// ROUND 32 (found by cross-compiling for armeabi-v7a / x86 with the
// NDK): the GOT hooks install these five wrapper addresses on EVERY
// arch, but the wrappers themselves only existed in the aarch64/x86_64
// assembly — every 32-bit build failed to link. On a no-blob arch the
// wrapper has nothing special to do: no frame has to be captured for a
// self-unmap that cannot happen, and hide_process_phase() already
// accepts a null frame pointer (it is the documented Tier B input —
// see the public pre-fork API passing nullptr). The plain C ABI is
// call-compatible with the real libc functions on every 32-bit ABI
// (args and return ride the same registers/stack slots; long and int
// are the same size there).
extern "C" long zs_fork_wrapper(void) {
    return zs_impl_fork(nullptr);
}
extern "C" long zs_setresgid_wrapper(long a0, long a1, long a2) {
    return zs_impl_setresgid(nullptr, a0, a1, a2);
}
extern "C" long zs_setresuid_wrapper(long a0, long a1, long a2) {
    return zs_impl_setresuid(nullptr, a0, a1, a2);
}
extern "C" long zs_setgid_wrapper(long a0) {
    return zs_impl_setgid(nullptr, a0);
}
extern "C" long zs_setuid_wrapper(long a0) {
    return zs_impl_setuid(nullptr, a0);
}
// ROUND 36 (the Round 32 class, found by the 4-ABI cross-build gate
// again): the Round 35 WIP added the setcontext registration to
// zs_entry_init unconditionally but only wrote the aarch64/x86_64
// wrappers — armeabi-v7a and x86 failed to LINK (undefined
// zs_setcontext_wrapper; the module zip could not be built at all).
// The 32-bit stub keeps the hook fully functional as a Tier B hook
// (null frame = the documented Tier B input): the isolated-process
// deferral, name matcher and hide phases all run — only the Tier A
// self-unmap is absent, exactly like the other five wrappers on a
// no-blob arch. Plain-C-ABI call compatibility for a 4-argument
// function: arm32 passes a0-a3 in r0-r3, i386 on the stack slots —
// both match four long parameters (long == int width on 32-bit).
extern "C" long zs_setcontext_wrapper(long a0, long a1, long a2,
                                      long a3) {
    return zs_impl_setcontext(nullptr, a0, a1, a2, a3);
}
#endif

// ------------------------------------------------------------------------
// One-time initialization. Called from libzygisk's constructor (Round
// 25: the bridge library's __attribute__((constructor)), which runs in
// the zygote during Runtime::Init's dlopen — the only hook point that
// exists on EVERY Android version; ART itself never calls initialize()
// in the zygote, see native/libzygisk/src/entry.cpp's header comment).
// ------------------------------------------------------------------------

// Round 25 — self-pin. On every Android version studied (7.0 through
// 13), each same-arch child calls InitNonZygoteOrPostFork(kUnload),
// which dlclose()s the bridge handle ART holds (libzygisk.so). The
// linker's unload chain then walks libzygisk's dlopen-children — which
// includes THIS library — and would unmap the very GOT-hook code every
// future setresgid/setresuid call in that child jumps through. One
// extra reference on ourselves makes the chain stop one short:
//   zygote:  libzygisk dlopen(libpayload)  -> refcount 1
//            libpayload dlopen(self, RTLD_NOLOAD) -> refcount 2
//   child:   ART dlclose(libzygisk) -> NODELETE makes the linker
//            return before any destructor/unmap; libpayload's count
//            is untouched anyway: STILL MAPPED (defense in depth —
//            the -z nodelete link flag on both .so's is the primary
//            guard; see the CMakeLists and libzygisk's entry.cpp).
// RTLD_NOLOAD returns the existing handle without touching disk, so
// this is a pure refcount bump. If the path lookup somehow misses, a
// plain dlopen of the same path resolves to the same soinfo anyway.
extern "C" void zs_entry_init();   // defined below
static void self_pin() {
    Dl_info info{};
    if (dladdr((const void*)&zs_entry_init, &info) == 0 ||
        !info.dli_fname) {
        ZS_LOGW("payload: dladdr(self) failed; relying on the bridge "
                "handle alone");
        return;
    }
    void* pin = dlopen(info.dli_fname, RTLD_NOLOAD | RTLD_LAZY);
    if (!pin) {
        pin = dlopen(info.dli_fname, RTLD_LAZY);
    }
    if (!pin) {
        ZS_LOGW("payload: self-pin failed (%s): a child-side bridge "
                "dlclose could unmap our hooks", dlerror());
    }
}

extern "C"
__attribute__((visibility("default")))
void zs_entry_init() {
    int expected = 0;
    if (!g_initialized.compare_exchange_strong(expected, 1)) {
        return; // already initialized
    }

    g_origin_pid = getpid();
    ZS_LOGI("payload: init (pid %d)", (int)g_origin_pid);

    // Round 25: pin ourselves before anything else (see self_pin()) —
    // it must happen before any hook is installed, so the hook code is
    // guaranteed to stay mapped for the process lifetime.
    self_pin();

    // Resolve the libc functions our hooks delegate to. dlsym on
    // libc.so directly — we are RTLD_LOCAL and not in the global
    // search order (the old "LD_PRELOAD-style override" comment was
    // wrong about that).
    g_real_setresgid = (int (*)(gid_t,gid_t,gid_t))zs_resolve_libc("setresgid");
    g_real_setresuid = (int (*)(uid_t,uid_t,uid_t))zs_resolve_libc("setresuid");
    g_real_setgid    = (int (*)(gid_t))zs_resolve_libc("setgid");
    g_real_setuid    = (int (*)(uid_t))zs_resolve_libc("setuid");
    g_real_fork      = (long (*)(void))zs_resolve_libc("fork");
    if (!g_real_setresgid || !g_real_setresuid) {
        ZS_LOGW("payload: cannot resolve setresgid/setresuid; "
                "hooks will fall back to raw syscalls");
    }
    // Round 35 — resolve libselinux's setcontext. RTLD_NOLOAD first
    // (libselinux is loaded into the zygote by libandroid_runtime's
    // own dependencies — a NOLOAD lookup never touches disk), then
    // the default scope. On host test builds both miss (glibc has no
    // such symbol) and the hook simply does not register — the test
    // seam installs a fake real instead.
    {
        void* sel_h = dlopen("libselinux.so", RTLD_NOLOAD | RTLD_LAZY);
        void* fn = sel_h ? dlsym(sel_h, "selinux_android_setcontext")
                         : nullptr;
        if (!fn) fn = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");
        g_real_setcontext =
            (int (*)(uid_t, int, const char*, const char*))fn;
    }

    // Layer init: snapshots our own segments, loads the DenyList and
    // the uid map, resolves symbols, registers Tier B hooks as
    // DEFERRED (they are only walked if a hide lands on Tier B).
    hide_register_globals();
    hide_advanced_init();
    hide_stealth_init();

    // ROUND 39 (C1, hardened): the environment probe runs BEFORE any
    // GOT hook is installed. In a policy-denied environment (the
    // Android 7.1.1 emulator: the zygote domain is EACCES-denied the
    // daemon/session socket), the fork-child pipeline that these
    // hooks drive was the crash vector — children died executing
    // de-permissioned payload pages and system_server re-entered
    // ZygoteInit.main in a fork cascade (tombstones + kernel log
    // verified). With the gate tripped HERE, the five privilege-drop
    // wrappers and the fork wrapper are never installed: no module
    // code ever runs in a forked child. The bridge injection, the
    // magic mounts, the daemon and the module files all stay; what
    // is lost is the in-child dispatch/hide machinery — the honest
    // stability trade for an environment the module cannot safely
    // operate its pipeline in.
    zs_module_env_probe();

    // Load Zygisk modules (their .so paths get registered for the
    // unmap set inside zs_module_init).
    zs_module_init();
    zs_module_capture_zygote_name();

    // Install ONLY the privilege-drop hooks (plus fork) — the four
    // entry points that detect + drive the whole pipeline. Every
    // other process forked from the zygote executes these hooks as a
    // single pid-compare + branch and nothing else.
    if (zs_module_env_denied()) {
        ZS_LOGW("payload: environment denied — fork-child hooks NOT "
                "installed (fail-inert; module stays mounted and "
                "injected)");
        return;
    }
    hide_advanced_register_got_hook("setresgid",
        (void*)&zs_setresgid_wrapper);
    hide_advanced_register_got_hook("setresuid",
        (void*)&zs_setresuid_wrapper);
    hide_advanced_register_got_hook("setgid",
        (void*)&zs_setgid_wrapper);
    hide_advanced_register_got_hook("setuid",
        (void*)&zs_setuid_wrapper);
    hide_advanced_register_got_hook("fork",
        (void*)&zs_fork_wrapper);
    // Round 35 — the isolated-process coverage hook. Registered ONLY
    // when the real selinux_android_setcontext resolved: the GOT
    // walker matches the slot by this exact symbol name across every
    // DSO, and the wrapper's impl needs a real target to relay. The
    // cost for non-isolated children is one patched-GOT indirect call
    // plus four compares (pid, two latches, the appId range) before
    // falling through to the real call's already-returned value.
    if (g_real_setcontext) {
        hide_advanced_register_got_hook("selinux_android_setcontext",
            (void*)&zs_setcontext_wrapper);
        // Round 36: the hook is live — the uid-drop hook may now
        // DEFER isolated-range children to it (see uid_drop_hook).
        g_setcontext_hook_live.store(1, std::memory_order_release);
    }
    hide_advanced_install_got_hooks();
}

// ------------------------------------------------------------------------
// Public pre/post-fork callbacks.
//
// These implement the package-name-keyed pipeline for callers that
// know the target name (the future JNI-hook layer, and the host
// tests). On-device, the uid-keyed hooks above are the real driver.
// ------------------------------------------------------------------------

extern "C"
__attribute__((visibility("default")))
void zs_entry_pre_fork(const char* package_name,
                                   int is_system_server) {
    (void)is_system_server;
    // Decide now so the post-fork side is a single flag check.
    hide_setup_for_target(package_name ? package_name : "");
}

extern "C"
__attribute__((visibility("default")))
void zs_entry_post_fork(const char* package_name,
                                    int is_system_server) {
    (void)is_system_server;
    if (g_hide_done.load(std::memory_order_acquire)) return; // uid path ran
    if (hide_setup_for_target(package_name ? package_name : "")) {
        g_hide_done.store(1, std::memory_order_release);
        // No wrapper frame and no real libc call to relay — Tier B.
        // (The future JNI-hook layer that knows the package name can
        // pass a real thunk; for the exported API the runtime has
        // already done its own privilege handling by the time it
        // would call this.)
        run_hide_pipeline(nullptr, priv_drop_nop, nullptr);
    }
}

// ------------------------------------------------------------------------
// Test-only exports (host tests build the real sources into a
// libpayload.so and drive the pipeline through the REAL wrappers).
// ------------------------------------------------------------------------

#ifdef ZS_HOST_TEST
extern "C" __attribute__((visibility("default")))
void zs_test_force_deny_uid(int uid) {
    hide_test_force_deny_uid((uid_t)uid);
}

// Round 35 — force a denylisted PACKAGE name (drives the
// isolated-process name matcher on the host).
extern "C" __attribute__((visibility("default")))
void zs_test_force_deny_name(const char* pkg) {
    hide_test_force_deny_name(pkg);
}

// Round 35 — install a FAKE real setcontext (recorder + deterministic
// rv) and register the GOT hook under the exact production symbol
// name, so host tests can drive zs_setcontext_wrapper the way the
// patched GOT does on a device.
extern "C" __attribute__((visibility("default")))
void zs_test_install_setcontext(long (*fn)(long, long, const char*,
                                           const char*)) {
    g_test_setcontext_fn = fn;
    if (fn) {
        hide_advanced_register_got_hook(
            "selinux_android_setcontext",
            (void*)&zs_setcontext_wrapper);
        hide_advanced_install_got_hooks();
        // Round 36: mirror the production init — installing the hook
        // is what arms the uid-drop deferral.
        g_setcontext_hook_live.store(1, std::memory_order_release);
    }
}

// Round 36 — force the deferral flag OFF (drives the degradation
// path: a vendor build without the setcontext symbol must keep the
// pre-R36 uid-drop dispatch for isolated children).
extern "C" __attribute__((visibility("default")))
void zs_test_setcontext_live(int live) {
    g_setcontext_hook_live.store(live ? 1 : 0,
                                 std::memory_order_release);
}

// Round 36 — read the deferral flag back (test assertions).
extern "C" __attribute__((visibility("default")))
int zs_test_setcontext_is_live() {
    return g_setcontext_hook_live.load(std::memory_order_acquire);
}

// Round 35 — call the REAL impl directly with a null wrapper frame
// (Tier B path; mirrors zs_test_setresuid's shape).
extern "C" __attribute__((visibility("default")))
long zs_test_setcontext(long uid, long is_sys, const char* seinfo,
                        const char* nice_name) {
    return zs_impl_setcontext(nullptr, uid, is_sys, (long)seinfo,
                              (long)nice_name);
}

// Round 12 — drive the REAL hook implementations from the dispatch
// tests (wrapper_fp = null -> Tier B forced; the dispatch paths under
// test never enter Tier A).
extern "C" __attribute__((visibility("default")))
void zs_test_first_fork() {
    zs_module_on_first_fork();
}

// ROUND 37 (Bug 4): arm the uid-drop dispatch latch exactly the way a
// real dispatched ancestor leaves it (done=1, pid=THIS process). The
// app-zygote simulation forks a child that already dispatched in
// itself, then that child forks ANOTHER one which inherits the latch.
extern "C" __attribute__((visibility("default")))
void zs_test_arm_dispatch_latch() {
    g_dispatch_pid = getpid();
    g_dispatch_done.store(1, std::memory_order_release);
}

// ROUND 37 (Bug 4): clear it again (test isolation).
extern "C" __attribute__((visibility("default")))
void zs_test_clear_dispatch_latch() {
    g_dispatch_done.store(0, std::memory_order_release);
    g_dispatch_pid = 0;
}

extern "C" __attribute__((visibility("default")))
long zs_test_setresgid(long g) {
    return zs_impl_setresgid(nullptr, g, g, g);
}

extern "C" __attribute__((visibility("default")))
long zs_test_setresuid(long u) {
    return zs_impl_setresuid(nullptr, u, u, u);
}

extern "C" __attribute__((visibility("default")))
long zs_test_setuid(long u) {
    return zs_impl_setuid(nullptr, u);
}

extern "C" __attribute__((visibility("default")))
int zs_test_trampoline_pending() {
    return hide_trampoline_unmap_pending();
}

extern "C" __attribute__((visibility("default")))
size_t zs_test_record_count() {
    return hide_unmap_record_count();
}

// Round 30 — the Tier A atexit-purge seams for the dlopen-based
// trampoline test.
// zs_test_disable_atexit_purge(1): prove the regression the purge
// fixes — with the purge off, a Tier A child that calls exit()
// SIGSEGVs on libc's walk over the dangling __cxa_atexit entries.
extern "C" __attribute__((visibility("default")))
void zs_test_disable_atexit_purge(int disabled) {
    g_disable_atexit_purge = disabled ? 1 : 0;
}
// zs_test_collect_dso_handles(): expose the record-scan so the test
// can learn libpayload's own __dso_handle (a hidden symbol) BEFORE
// driving the pipeline, then register a sentinel entry against it.
extern "C" __attribute__((visibility("default")))
size_t zs_test_collect_dso_handles(struct ZsDsoHandle* out,
                                   size_t cap) {
    return zs_collect_dso_handles(out, cap);
}
#endif // ZS_HOST_TEST

} // namespace zygisk_study
