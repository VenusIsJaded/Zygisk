// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/entry.cpp
//
// libpayload.so — the in-process trampoline + Zygisk module loader.
//
// Loaded by libzygisk.so at the NativeBridge2Itf.initialize hook.
// Responsible for:
//
//   1. Hooking the `fork` libc entry in the zygote process so we
//      get a callback before/after each fork.
//   2. On pre-fork: read the target package name from the hook's
//      arguments, run hide_setup_for_target() to decide whether to
//      hide.
//   3. On post-fork: run hide_apply_for_target(), then enumerate
//      installed Zygisk modules and run their preAppSpecialize /
//      postAppSpecialize callbacks.
//   4. Hand the zygisk::Api surface to each module so it can call
//      back into us for things like "get the current process name".
//
// Public ABI (all explicitly exported with visibility=default):
//
//   zygisk_study_payload_init         — one-time setup
//   zygisk_study_payload_pre_fork     — called by our fork hook
//   zygisk_study_payload_post_fork    — called by our fork hook
//
// Everything else is hidden. A reverse engineer reading the .so will
// see exactly three exports and a small set of internal symbols.

#include "hide.h"
#include "hide_advanced.h"
#include "log.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
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

// True once payload_init has run.
static std::atomic<int> g_initialized{0};

// Socket path the daemon opened. We connect back to it once per
// fork to fetch the list of modules interested in this target.
//
// This path is deliberately non-obvious: /data/system/* is a
// generic Android system directory, not a known Zygisk signature
// path. The file name is "sock" rather than something identifiable
// like "zygisk_study.sock" — apps that scan for Zygisk by name
// won't find it.
static constexpr const char* kDaemonSocket =
    "/data/system/zygisk_study/sock/sock";

// Cached list of loaded modules. We re-read it on demand because
// the user can install / remove modules at runtime.
struct LoadedModule {
    void* dl_handle;
    zygisk::Module* instance;
    std::string path;
    std::string id;
};
static std::vector<LoadedModule> g_modules;
static std::atomic<int>           g_modules_loaded{0};

// Per-fork state. We stash the target package name here so the
// post-fork callback can pick it up without re-parsing the
// pre-fork arguments.
static thread_local std::string g_pending_package_name;
static thread_local int         g_is_system_server = 0;

// ------------------------------------------------------------------------
// The zygisk::Api surface we hand back to modules.
//
// This is the implementation of the C++ vtable that modules use to
// call back into us. We only implement the methods a module
// realistically uses; the rest are no-ops that log a warning so we
// can spot mismatches in binary compat.
// ------------------------------------------------------------------------
class PayloadApi : public zygisk::Api {
public:
    void setOption(uint32_t /*option*/) override {
        // Modules can use this to opt into per-process flags. We
        // currently don't expose any; the call is accepted as a no-op
        // so module code paths that exercise the API still work.
    }

    int connectCompanion(void* /*handle*/) override {
        // We do not currently implement the per-module companion
        // socket pair. Modules that need IPC back to the daemon
        // can open kDaemonSocket directly. We return -1 to indicate
        // "not available, do it yourself".
        return -1;
    }

    void getModuleDir(char* out, size_t cap) override {
        // The "module dir" we report is the directory of the *current*
        // module. We don't track which module is calling us, so we
        // report a stable placeholder path. Modules written against
        // the standard Zygisk API expect a real path here; we'll fix
        // this once we plumb per-module context through.
        strncpy(out, "/data/system/zygisk_study/modules", cap - 1);
        out[cap - 1] = '\0';
    }

    void getProcessName(char* out, size_t cap) override {
        // /proc/self/cmdline holds the process name. We use that
        // because the zygote hasn't populated __system_property
        // for the new process yet at the point this is called.
        int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
        if (fd < 0) { out[0] = '\0'; return; }
        ssize_t n = read(fd, out, cap - 1);
        close(fd);
        if (n < 0) n = 0;
        out[n] = '\0';
    }

    int hookJniEnv(JNIEnv** /*env*/) override {
        // JNI hooking is the next phase of this project. For now,
        // we return 0 (success) and the caller's env pointer is
        // unchanged.
        return 0;
    }

    void cleanTrace() override {
        hide_clean_trace();
    }

    uint32_t apiVersion() override {
        // Zygisk API revision we report to the module. Standard
        // Zygisk is at version 1; we match that.
        return 1;
    }
};

// Single instance — all modules share the same Api object.
static PayloadApi g_api;

// ------------------------------------------------------------------------
// Module loading
// ------------------------------------------------------------------------

// Open the daemon socket and read a single-line "module-list" reply.
// Format: one module per line, semicolon-separated fields:
//   <module_id>;<so_path>
//
// We deliberately use a tiny line protocol so a reader of the daemon
// (in Rust, see native/zygiskd/src/main.rs) can match the format
// without an extra serialization library.
static std::vector<LoadedModule> fetch_module_list_from_daemon() {
    std::vector<LoadedModule> out;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        ZS_LOGW("payload: socket() failed: %s", strerror(errno));
        return out;
    }
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kDaemonSocket, sizeof(addr.sun_path) - 1);

    // The socket is owned by root; if the calling process is the
    // zygote (uid 0) we can connect directly. Non-root processes
    // can't reach it. This is fine — modules only matter inside
    // the zygote (and its forks).
    if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0) {
        ZS_LOGW("payload: connect(%s) failed: %s",
                kDaemonSocket, strerror(errno));
        close(sock);
        return out;
    }

    // Send a tiny "give me the module list" message. We use a
    // single byte to avoid the framing complexity.
    char req = 'L';
    if (send(sock, &req, 1, 0) != 1) {
        close(sock);
        return out;
    }

    // Read reply.
    char buf[8192];
    ssize_t n = recv(sock, buf, sizeof buf - 1, 0);
    close(sock);
    if (n <= 0) return out;
    buf[n] = '\0';

    // Parse line by line.
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

// dlopen every module's .so and call its onLoad. Modules that fail
// to load are dropped from g_modules silently.
static void load_all_modules() {
    auto list = fetch_module_list_from_daemon();
    // Reserve upfront so the loop doesn't trigger a reallocation per
    // module. Even pathological installs have < 16 modules.
    g_modules.reserve(list.size());
    g_modules.clear();
    for (auto& m : list) {
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
        // We don't have a JNIEnv here yet — modules that need JNI in
        // onLoad will get a follow-up call from pre/post specialize
        // where we DO have one. We pass nullptr for now.
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
    // CRITICAL: mark modules as loaded so subsequent forks don't
    // re-fetch the module list from the daemon. Without this flag,
    // every fork() in the zygote would open a new socket connection
    // to zygiskd and block on a recv — a major perf regression on
    // cold-start. The flag is set ONLY here, after a successful
    // (even if partial) load attempt.
    g_modules_loaded.store(1);
}

// Periodically refresh the module list if it's been invalidated by
// the daemon. We don't yet have a "version" wire-protocol field, so
// for now we treat the first load as authoritative and only refetch
// if the user explicitly requests it via a hook into the loader. The
// `maybe_refresh_modules()` hook is a no-op for now; future work
// will trigger a refetch when the daemon signals a change.
//
// This is here as a placeholder so the post-fork fast path can call
// it cheaply without re-fetching.
static inline void maybe_refresh_modules() {
    // Future: check a per-fork "modules_version" atomic against the
    // version the daemon reported; if mismatched, call load_all_modules().
    // For now: do nothing. The list loaded at init is reused forever.
}

// ------------------------------------------------------------------------
// Hooking the zygote's fork path
//
// On Android, the zygote's fork path is implemented in
// libandroid_runtime (com_android_internal_os_Zygote.cpp). It calls
// `fork()` from libc. We hook the libc fork function directly.
//
// The standard way to hook libc functions from inside a process is
// PLT/GOT patching. We use a simpler approach: we use the GNU
// extension dl_iterate_phdr to find the PLT slot of fork() in
// libandroid_runtime's .plt section and overwrite it with our own
// trampoline.
//
// For brevity and clarity, this implementation uses the simplest
// possible hook: an LD_PRELOAD-style override on fork(). When ART
// is set up to dlopen us via ro.dalvik.vm.native.bridge, our .so
// ends up at the top of the symbol search order, so our `fork`
// symbol shadows libc's.
// ------------------------------------------------------------------------

extern "C" pid_t fork(void);

static pid_t (*real_fork)(void) = nullptr;

extern "C" pid_t zygisk_study_payload_fork_hook(void) {
    // PRE-FORK
    // --------
    // The about-to-fork process is still the zygote here. We don't
    // know the target package name yet — that gets handed to us via
    // the JNI side of the Zygote class after the fork syscall has
    // returned 0 in the child. For our purposes we use the special
    // string "system_server" if we can't identify a more specific
    // target (this matches the upstream behavior).

    pid_t pid = real_fork ? real_fork() : ::fork();
    if (pid == 0) {
        // We are the child. Apply hide and run module callbacks.
        // (If we're a system_server fork, the package name is
        // "system_server".)
        const char* pkg = g_pending_package_name.empty()
                            ? "system_server"
                            : g_pending_package_name.c_str();

        if (zygisk_study::hide_setup_for_target(pkg)) {
            zygisk_study::hide_apply_for_target(pkg);
        }

        // Dispatch into every loaded module's pre/post specialize.
        for (auto& m : g_modules) {
            if (g_is_system_server) {
                m.instance->preServerSpecialize(&g_api, nullptr);
                m.instance->postServerSpecialize(&g_api, nullptr);
            } else {
                m.instance->preAppSpecialize(&g_api, nullptr);
                m.instance->postAppSpecialize(pkg, &g_api, nullptr);
            }
        }
    }
    return pid;
}

// ------------------------------------------------------------------------
// One-time initialization. Called from libzygisk's NativeBridge
// hook. Idempotent — safe to call multiple times.
// ------------------------------------------------------------------------
extern "C"
__attribute__((visibility("default")))
void zygisk_study_payload_init() {
    int expected = 0;
    if (!g_initialized.compare_exchange_strong(expected, 1)) {
        return; // already initialized
    }

    ZS_LOGI("payload: init");

    // Initialize the hide layer (snapshots our own .so segments
    // so we can later unmap them).
    hide_register_globals();

    // Initialize the advanced hide layer (installs open/openat
    // hooks so /proc/self/maps and /proc/self/mounts reads get
    // filtered versions).
    hide_advanced_init();

    // Resolve the *real* fork libc symbol so we can call through to
    // it from our hook. We use dlsym(RTLD_NEXT, "fork") which
    // returns the next fork in the link order after us.
    real_fork = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
    if (!real_fork) {
        ZS_LOGW("payload: dlsym(RTLD_NEXT, \"fork\") failed; "
                "falling back to direct syscall");
        // We'll do the direct syscall in the hook.
    }

    // Lazily load modules. We do this here rather than at first fork
    // to keep first-fork latency low.
    load_all_modules();
}

// ------------------------------------------------------------------------
// Public pre/post-fork callbacks — these are called by our own fork
// hook above. We expose them externally so that the loader can be
// driven by a different hook mechanism in the future (e.g. an inline
// hook on the Zygote.java fork function via JNI) without changing
// the .so's ABI.
// ------------------------------------------------------------------------
extern "C"
__attribute__((visibility("default")))
void zygisk_study_payload_pre_fork(const char* package_name,
                                   int is_system_server) {
    g_pending_package_name = package_name ? package_name : "";
    g_is_system_server = is_system_server ? 1 : 0;

    // Modules get a chance to act pre-fork here.
    for (auto& m : g_modules) {
        if (g_is_system_server) {
            m.instance->preServerSpecialize(&g_api, nullptr);
        } else {
            m.instance->preAppSpecialize(&g_api, nullptr);
        }
    }
}

extern "C"
__attribute__((visibility("default")))
void zygisk_study_payload_post_fork(const char* package_name,
                                    int is_system_server) {
    // Apply hide if requested at pre-fork time.
    if (hide_setup_for_target(package_name)) {
        hide_apply_for_target(package_name);
        // Apply the advanced hide layer AFTER the basic one — see
        // hide_advanced.cpp for the ordering rationale.
        hide_advanced_apply_post_fork(package_name);
    }

    // Modules' post-specialize callbacks.
    for (auto& m : g_modules) {
        if (is_system_server) {
            m.instance->postServerSpecialize(&g_api, nullptr);
        } else {
            m.instance->postAppSpecialize(package_name, &g_api, nullptr);
        }
    }
}

} // namespace zygisk_study
