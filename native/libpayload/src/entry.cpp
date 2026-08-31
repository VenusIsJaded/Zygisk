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

// Socket path the daemon opened.
static constexpr const char* kDaemonSocket =
    "/data/system/zygisk_study/sock/sock";

struct LoadedModule {
    void* dl_handle;
    zygisk::Module* instance;
    std::string path;
    std::string id;
};
static std::vector<LoadedModule> g_modules;
static std::atomic<int>          g_modules_loaded{0};

// The pid that loaded the payload (the zygote). Any process whose pid
// differs is a fork. This is the primary "are we in a child?" check —
// more robust than a fork-hook flag, because it also covers children
// forked through paths that do not call fork() through a patched GOT
// slot (the USAP pool).
static pid_t g_origin_pid = -1;

// Set once the hide pipeline has run in this process (guards against
// setresgid AND setresuid both triggering it).
static std::atomic<int> g_hide_done{0};

// ------------------------------------------------------------------------
// The zygisk::Api surface we hand back to modules.
// ------------------------------------------------------------------------

class PayloadApi : public zygisk::Api {
public:
    void setOption(uint32_t) override {}
    int  connectCompanion(void*) override { return -1; }

    void getModuleDir(char* out, size_t cap) override {
        strncpy(out, "/data/system/zygisk_study/modules", cap - 1);
        out[cap - 1] = '\0';
    }

    void getProcessName(char* out, size_t cap) override {
        int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
        if (fd < 0) { out[0] = '\0'; return; }
        ssize_t n = read(fd, out, cap - 1);
        close(fd);
        if (n < 0) n = 0;
        out[n] = '\0';
    }

    int  hookJniEnv(JNIEnv**) override { return 0; }
    void cleanTrace() override { hide_clean_trace(); }
    uint32_t apiVersion() override { return 1; }
};

static PayloadApi g_api;

// ------------------------------------------------------------------------
// Module loading
// ------------------------------------------------------------------------

static std::vector<LoadedModule> fetch_module_list_from_daemon() {
    std::vector<LoadedModule> out;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return out;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kDaemonSocket, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0) {
        close(sock);
        return out;
    }
    char req = 'L';
    if (send(sock, &req, 1, 0) != 1) {
        close(sock);
        return out;
    }
    char buf[8192];
    ssize_t n = recv(sock, buf, sizeof buf - 1, 0);
    close(sock);
    if (n <= 0) return out;
    buf[n] = '\0';

    char* save_outer = nullptr;
    for (char* line = strtok_r(buf, "\n", &save_outer);
         line != nullptr;
         line = strtok_r(nullptr, "\n", &save_outer)) {
        char* save_inner = nullptr;
        char* id   = strtok_r(line, ";", &save_inner);
        char* path = strtok_r(nullptr, ";",  &save_inner);
        if (!id || !path) continue;
        LoadedModule m{};
        m.id   = id;
        m.path = path;
        out.push_back(std::move(m));
    }
    return out;
}

static void load_all_modules() {
    auto list = fetch_module_list_from_daemon();
    g_modules.reserve(list.size());
    g_modules.clear();
    for (auto& m : list) {
        // Register the module .so path BEFORE dlopen'ing so the
        // record rescan below sees both the fragment and the fresh
        // maps entries in one pass.
        hide_register_extra_so(m.path.c_str());
        m.dl_handle = dlopen(m.path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!m.dl_handle) {
            ZS_LOGW("payload: dlopen(%s) failed: %s",
                    m.path.c_str(), dlerror());
            continue;
        }
        using FactoryFn = zygisk::Module* (*)(zygisk::Api*, JNIEnv*);
        auto factory = (FactoryFn)dlsym(m.dl_handle, "zygisk_module");
        if (!factory) {
            ZS_LOGW("payload: %s: no zygisk_module symbol", m.id.c_str());
            dlclose(m.dl_handle);
            continue;
        }
        m.instance = factory(&g_api, nullptr);
        if (!m.instance) {
            ZS_LOGW("payload: %s: factory returned null", m.id.c_str());
            dlclose(m.dl_handle);
            continue;
        }
        ZS_LOGI("payload: loaded module %s from %s",
                m.id.c_str(), m.path.c_str());
        g_modules.push_back(std::move(m));
    }
    // One maps rescan picks up every module's segments.
    hide_rescan_records();

    // CRITICAL: mark modules as loaded so nothing re-fetches the list
    // from the daemon (per-fork socket round-trips would be a major
    // latency regression).
    g_modules_loaded.store(1);
}

// ------------------------------------------------------------------------
// The hide pipeline (shared by the uid hooks and the exported
// package-name API).
// ------------------------------------------------------------------------

// Unmap every ZS_SO_OTHER record (module .so files, the loader, the
// bridge — none of their code runs past this point) via plain C.
// Returns the number of records unmapped. The ZS_SO_SELF records are
// left for the trampoline.
static void unmap_non_self_records() {
    so_record recs[kTrampMaxRecords];
    size_t n = hide_unmap_records(recs, kTrampMaxRecords);
    for (size_t i = 0; i < n; ++i) {
        if (!(recs[i].flags & ZS_SO_OTHER)) continue;
        if (munmap((void*)recs[i].base, recs[i].size) != 0) {
            ZS_LOGW("payload: munmap(%lx, %zu) failed",
                    (unsigned long)recs[i].base, recs[i].size);
        }
    }
}

// A no-op "real call" for pipeline invocations that have no libc
// function to relay (the exported package-name API).
static long priv_drop_nop(void*) { return 0; }

// Run the full hide pipeline for a target we have ALREADY decided to
// hide (hide_setup_for_target* returned 1). `wrapper_fp` is non-null
// when invoked from an asm wrapper (Tier A possible); null when
// invoked from the exported API (Tier B forced).
//
// `call_real`/`real_ctx` invoke the real libc function this hook
// replaced. In the Tier A path it MUST run before the trampoline
// jumps out — the runtime expects setresgid/setresuid to have
// actually executed, and skipping it would leave the app running as
// root (an instant detection and a security hole).
//
// Returns true if the real call was already made (Tier A).
static bool run_hide_pipeline(void* wrapper_fp,
                              long (*call_real)(void*), void* real_ctx) {
    // ---- still root here: mount namespace work ----
    hide_apply_for_target(nullptr);          // unshare + unmount

    // ---- per-process spoofing + cleanup (both tiers) ----
    hide_advanced_apply_post_fork(nullptr);  // props clone+spoof, fds, env
    hide_stealth_apply_post_fork(nullptr);   // comm, rlimit_core, cwd

    if (wrapper_fp && zs_trampoline_supported() &&
        hide_trampoline_unmap_pending()) {
        // ---------------- Tier A: vanish ----------------
        // 1. Modules/loader segments go first (plain C is safe for
        //    them — nothing of theirs executes past this point).
        unmap_non_self_records();
        // 2. Restore every GOT slot we ever patched. A slot pointing
        //    into soon-to-be-unmapped memory is a guaranteed crash on
        //    the app's next libc call.
        hide_advanced_uninstall_got_hooks();
        // 3. Drop privileges for real — the specialization code that
        //    resumes after us assumes the call succeeded.
        long rv = call_real(real_ctx);
        // 4. Hand everything left to the trampoline: it unmaps our
        //    own segments and returns `rv` to the wrapper's caller
        //    without executing another libpayload instruction.
        ZsTrampRecord tramp_recs[kTrampMaxRecords];
        so_record all[kTrampMaxRecords];
        size_t an = hide_unmap_records(all, kTrampMaxRecords);
        size_t tn = 0;
        for (size_t i = 0; i < an && tn < kTrampMaxRecords; ++i) {
            tramp_recs[tn].base = all[i].base;
            tramp_recs[tn].size = all[i].size;
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

// The shared body of the privilege-drop hooks.
//
// `id` is the uid/gid the runtime is about to switch to. Real zygote
// specialization always calls setresgid() and setresuid() (in that
// order) in the child, both while it is still root — exactly the
// window we need.
static long priv_drop_hook(void* wrapper_fp, uid_t id,
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
    }
    return call_real(real_ctx);
}

// Real-call thunks (resolved from libc at init).
static int (*g_real_setresgid)(gid_t, gid_t, gid_t) = nullptr;
static int (*g_real_setresuid)(uid_t, uid_t, uid_t) = nullptr;
static int (*g_real_setgid)(gid_t)                  = nullptr;
static int (*g_real_setuid)(uid_t)                  = nullptr;
static long (*g_real_fork)(void)                    = nullptr;

struct RealCtx3 { long a, b, c; };
struct RealCtx1 { long a; };

static long call_real_setresgid(void* ctx) {
    RealCtx3* c = (RealCtx3*)ctx;
    return g_real_setresgid ? g_real_setresgid((gid_t)c->a, (gid_t)c->b, (gid_t)c->c)
                            : syscall(SYS_setresgid, c->a, c->b, c->c);
}
static long call_real_setresuid(void* ctx) {
    RealCtx3* c = (RealCtx3*)ctx;
    return g_real_setresuid ? g_real_setresuid((uid_t)c->a, (uid_t)c->b, (uid_t)c->c)
                            : syscall(SYS_setresuid, c->a, c->b, c->c);
}
static long call_real_setgid(void* ctx) {
    RealCtx1* c = (RealCtx1*)ctx;
    return g_real_setgid ? g_real_setgid((gid_t)c->a)
                         : syscall(SYS_setgid, c->a);
}
static long call_real_setuid(void* ctx) {
    RealCtx1* c = (RealCtx1*)ctx;
    return g_real_setuid ? g_real_setuid((uid_t)c->a)
                         : syscall(SYS_setuid, c->a);
}

// The C++ implementations the asm wrappers call.
// Signatures must match unmap_trampoline_<arch>.S exactly.

extern "C" long zs_impl_setresgid(void* wrapper_fp, long a0, long a1, long a2) {
    RealCtx3 ctx{a0, a1, a2};
    return priv_drop_hook(wrapper_fp, (uid_t)a0,
                          call_real_setresgid, &ctx);
}

extern "C" long zs_impl_setresuid(void* wrapper_fp, long a0, long a1, long a2) {
    RealCtx3 ctx{a0, a1, a2};
    return priv_drop_hook(wrapper_fp, (uid_t)a0,
                          call_real_setresuid, &ctx);
}

extern "C" long zs_impl_setgid(void* wrapper_fp, long a0) {
    RealCtx1 ctx{a0};
    return priv_drop_hook(wrapper_fp, (uid_t)a0,
                          call_real_setgid, &ctx);
}

extern "C" long zs_impl_setuid(void* wrapper_fp, long a0) {
    RealCtx1 ctx{a0};
    return priv_drop_hook(wrapper_fp, (uid_t)a0,
                          call_real_setuid, &ctx);
}

// Kept for the fork wrapper (registered but not required — the pid
// comparison above is the primary child detection).
extern "C" long zs_impl_fork(void* /*wrapper_fp*/) {
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

    // DEBUG markers (temporary)
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
    // unmap set inside load_all_modules).
    load_all_modules();

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
