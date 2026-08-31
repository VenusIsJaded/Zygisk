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
//   zygisk_study_payload_init         — one-time setup
//   zygisk_study_payload_pre_fork     — module pre-fork dispatch
//   zygisk_study_payload_post_fork    — package-name-keyed hide pipeline
//   (test-only exports under ZS_HOST_TEST at the bottom)

#include "hide.h"
#include "hide_advanced.h"
#include "hide_stealth.h"
#include "log.h"
#include "module_dispatch.h"
#include "resolve_libc.h"
#include "unmap_trampoline.h"

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
static std::atomic<int> g_dispatch_done{0};

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
        // 3. Drop privileges for real — the specialization code that
        //    resumes after us assumes the call succeeded.
        long rv = real_already_ran ? rv_in : call_real(real_ctx);
        // 4. Hand everything left to the trampoline: it unmaps our
        //    own remaining segments (text/data — the read-only
        //    metadata survives as anonymous pages) and returns `rv`
        //    to the wrapper's caller without executing another
        //    libpayload instruction.
        ZsTrampRecord tramp_recs[kTrampMaxRecords];
        size_t tn = 0;
        for (size_t i = 0; i < pn && tn < kTrampMaxRecords; ++i) {
            tramp_recs[tn].base = prep_out[i].base;
            tramp_recs[tn].size = prep_out[i].size;
            ++tn;
        }
        if (zs_trampoline_unmap(tramp_recs, tn, wrapper_fp, rv) == 0) {
            return true;  // never reached — the trampoline jumped out
        }
        ZS_LOGW("payload: trampoline setup failed; falling back to "
                "hook-based hiding (Tier B)");
        // Fall through: the real call already ran above; the caller's
        // second invocation of an idempotent setres*/set* is harmless.
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
    if (getpid() != g_origin_pid &&
        !g_hide_done.load(std::memory_order_acquire) &&
        !g_dispatch_done.load(std::memory_order_acquire)) {
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

        // ---- Round 12: module dispatch ----
        if (zs_module_dispatch_wanted()) {
            if (zs_module_force_unmount()) {
                hide_mount_phase();               // still root
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

// Kept for the fork wrapper (registered but not required — the pid
// comparison above is the primary child detection).
extern "C" long zs_impl_fork(void* /*wrapper_fp*/) {
    // Round 12: the zygote's first fork is the earliest moment the
    // VM exists AND we still run pre-fork — acquire the JNIEnv and
    // dispatch module onLoad there (once per process lifetime).
    if (getpid() == g_origin_pid) {
        // Round 19: daemon-dependent init (module list fetch, the
        // spoofed properties_serial handoff) retries here until it
        // latches — the daemon is never up at native-bridge init on
        // real devices (late service stage vs zygote start).
        (void)zs_module_lazy_daemon_init();
        zs_module_on_first_fork();
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
struct ZsTrampData {
    ZsTrampRecord records[kTrampMaxRecords];  // 512 bytes
    size_t    count;        // offset 512
    uintptr_t wrapper_fp;   // offset 520
    long      retval;       // offset 528
};
static_assert(sizeof(ZsTrampData) == 512 + 8 + 8 + 8, "trampoline data layout");
static_assert(offsetof(ZsTrampData, count) == 512, "count offset");
static_assert(offsetof(ZsTrampData, wrapper_fp) == 520, "fp offset");
static_assert(offsetof(ZsTrampData, retval) == 528, "retval offset");

#if defined(__aarch64__) || defined(__x86_64__)
int zs_trampoline_supported() { return 1; }

int zs_trampoline_unmap(const ZsTrampRecord* records, size_t count,
                        void* wrapper_fp, long retval) {
    if (!records || count == 0 || count > kTrampMaxRecords || !wrapper_fp) {
        return -1;
    }
    const size_t code_size = (size_t)(zs_trampoline_code_end
                                      - zs_trampoline_code_start);
    if (code_size == 0 || code_size > 4096 - 64) return -1;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    // One private executable page. RW for the copy, then X-only.
    void* page = mmap(nullptr, (size_t)page_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        ZS_LOGW("trampoline: mmap failed: %s", strerror(errno));
        return -1;
    }
    // STEALTH: name the page so /proc/self/maps shows
    // "[anon:jit-cache]" — ART processes legitimately carry
    // executable anon pages; a bare rwxp anon page is rarer.
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
    data->retval     = retval;   // handed back to the wrapper's caller

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
#else
int zs_trampoline_supported() { return 0; }
int zs_trampoline_unmap(const ZsTrampRecord*, size_t, void*, long) {
    return -1;
}
#endif

// ------------------------------------------------------------------------
// One-time initialization. Called from libzygisk's NativeBridge hook.
// ------------------------------------------------------------------------


extern "C"
__attribute__((visibility("default")))
void zygisk_study_payload_init() {
    int expected = 0;
    if (!g_initialized.compare_exchange_strong(expected, 1)) {
        return; // already initialized
    }

    g_origin_pid = getpid();
    ZS_LOGI("payload: init (pid %d)", (int)g_origin_pid);

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

    // Layer init: snapshots our own segments, loads the DenyList and
    // the uid map, resolves symbols, registers Tier B hooks as
    // DEFERRED (they are only walked if a hide lands on Tier B).
    hide_register_globals();
    hide_advanced_init();
    hide_stealth_init();

    // Load Zygisk modules (their .so paths get registered for the
    // unmap set inside zs_module_init).
    zs_module_init();
    zs_module_capture_zygote_name();

    // Install ONLY the privilege-drop hooks (plus fork) — the four
    // entry points that detect + drive the whole pipeline. Every
    // other process forked from the zygote executes these hooks as a
    // single pid-compare + branch and nothing else.
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
void zygisk_study_payload_pre_fork(const char* package_name,
                                   int is_system_server) {
    (void)is_system_server;
    // Decide now so the post-fork side is a single flag check.
    hide_setup_for_target(package_name ? package_name : "");
}

extern "C"
__attribute__((visibility("default")))
void zygisk_study_payload_post_fork(const char* package_name,
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

// Round 12 — drive the REAL hook implementations from the dispatch
// tests (wrapper_fp = null -> Tier B forced; the dispatch paths under
// test never enter Tier A).
extern "C" __attribute__((visibility("default")))
void zs_test_first_fork() {
    zs_module_on_first_fork();
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
#endif // ZS_HOST_TEST

} // namespace zygisk_study
