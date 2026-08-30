// SPDX-License-Identifier: Apache-2.0
// native/libzn_loader/src/entry.cpp
//
// libzn_loader.so — the init-oriented injection bridge.
//
// This library is used on platforms where the
// ro.dalvik.vm.native.bridge trick does not work (e.g. on stock
// Android devices where the system won't tolerate a third-party
// native bridge, or on system_server forks where the bridge isn't
// loaded).
//
// What it does:
//
//   1. The daemon (zygiskd) ptrace-attaches to a target process and
//      injects our libzn_loader.so via the standard LD_PRELOAD
//      trick (PTRACE_SEIZE, modify auxv, PTRACE_CONT, etc.).
//   2. Once we're loaded, our entry point:
//      a. dlopen-s libpayload.so to get access to the shared module
//         registry and hide layer.
//      b. Exports a small function-pointer table (see
//         zygisk_study_api.h) so any module the user has installed can
//         find us via dlsym and use the init-oriented API.
//
// The API surface we expose is intentionally minimal — just enough
// for a module to ask "should I be injected for this target?" and
// "what should I do post-fork?". Modules that need more (e.g. to
// actually inject their own .so files) are expected to use the
// standard zygisk::Module surface via libpayload's v-table.
//
// Public ABI:
//
//   - zygisk_study_api_v1  (named via ZYGISK_STUDY_API_VERSION_STRING)
//     A function-pointer table. See zygisk_study_api.h.
//
//   - zygisk_study_loader_entry
//     The daemon calls this in the injected process to bring us up.
//     Returns 0 on success.
//
// Everything else is hidden.

#include "log.h"
#include "zygisk_study_api.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace zygisk_study {

// Magic value of our API table. The first field of struct
// zygisk_study_api. Picked arbitrarily; modules check this to make
// sure they got the right table back from dlsym.
static constexpr uint32_t kApiMagic = 0x5A535354u; // "ZSST" (Zygisk STudy)

// Socket the loader uses to ask the daemon "should I inject for this
// process?". Same path libpayload uses. See the comment in
// libpayload/src/entry.cpp for why we use a generic-looking path.
static constexpr const char* kDaemonSocket =
    "/data/system/zygisk_study/sock/sock";

// Forward decls.
static uint32_t api_caps(const struct zygisk_study_api* self);
static int      api_should_inject(const struct zygisk_study_api* self,
                                  const struct zygisk_study_process_info* info);
static void     api_post_fork(const struct zygisk_study_api* self,
                              const struct zygisk_study_process_info* info,
                              void* child_opaque);
static int      api_open_companion_fd(const struct zygisk_study_api* self);

// The single exported API table.
extern "C"
__attribute__((visibility("default")))
const struct zygisk_study_api zygisk_study_api_v1 = {
    .magic              = kApiMagic,
    .version            = 1,
    .caps               = &api_caps,
    .should_inject      = &api_should_inject,
    .post_fork          = &api_post_fork,
    .open_companion_fd  = &api_open_companion_fd,
};

// ---------------------------------------------------------------------------
// API implementations
// ---------------------------------------------------------------------------

static uint32_t api_caps(const struct zygisk_study_api* /*self*/) {
    // We provide all three capabilities.
    return ZS_CAP_EARLY_RETURN
         | ZS_CAP_FD_PASSING
         | ZS_CAP_SERVER_SPECIALIZE;
}

// Ask the daemon whether to inject for this target. The daemon is
// the source of truth for "is this target on the user's denylist"
// and "are any installed modules interested in this target".
static int api_should_inject(const struct zygisk_study_api* /*self*/,
                             const struct zygisk_study_process_info* info) {
    if (!info || !info->process_name) return 0;

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return 0;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kDaemonSocket, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0) {
        close(sock);
        return 0;
    }

    // Tiny protocol: send 'I' + process_name + '\n', recv '1' or '0'.
    char req[256];
    int n = snprintf(req, sizeof req, "I%s\n", info->process_name);
    if (n < 0 || n >= (int)sizeof req) { close(sock); return 0; }

    if (send(sock, req, (size_t)n, 0) != n) { close(sock); return 0; }

    char reply[4] = {0};
    if (recv(sock, reply, sizeof reply - 1, 0) <= 0) { close(sock); return 0; }
    close(sock);

    return reply[0] == '1';
}

// Post-fork: we are now in the new child process. Hand control to
// libpayload via its public post-fork callback so the actual hide +
// module-dispatch logic happens there. libpayload is already loaded
// by libzygisk in zygote-context, so this is just a dlsym.
static void api_post_fork(const struct zygisk_study_api* /*self*/,
                          const struct zygisk_study_process_info* info,
                          void* /*child_opaque*/) {
    const char* pkg = info ? info->process_name : nullptr;
    int is_server = info ? info->is_system_server : 0;

    void* h = dlopen("libpayload.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!h) h = dlopen("libpayload.so", RTLD_LAZY);
    if (!h) {
        ZS_LOGW("libzn_loader: cannot find libpayload at post_fork");
        return;
    }

    using PostForkFn = void (*)(const char*, int);
    auto post_fork = (PostForkFn)dlsym(h, "zygisk_study_payload_post_fork");
    if (post_fork) {
        post_fork(pkg, is_server);
    } else {
        ZS_LOGW("libzn_loader: libpayload has no post_fork symbol");
    }
}

// Open a per-process fd back to the daemon. Returns the fd or -1.
static int api_open_companion_fd(const struct zygisk_study_api* /*self*/) {
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, kDaemonSocket, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0) {
        close(sock);
        return -1;
    }
    // Send the "companion" marker so the daemon knows this is a
    // persistent socket (not a single-shot query).
    char req = 'C';
    if (send(sock, &req, 1, 0) != 1) { close(sock); return -1; }
    return sock;
}

// ---------------------------------------------------------------------------
// Loader entry — called by the daemon via ptrace after it has
// injected this .so into a target process. The daemon is responsible
// for the actual injection mechanics (LD_PRELOAD swap, /proc/self/auxv
// rewrite, or whatever technique is appropriate for the platform).
// ---------------------------------------------------------------------------
extern "C"
__attribute__((visibility("default")))
int zygisk_study_loader_entry(const char* workdir) {
    ZS_LOGI("libzn_loader: entry (workdir=%s)", workdir ? workdir : "(null)");

    // Touch the API table so we know it's referenced from inside the
    // .so (otherwise the linker may strip it under -O1).
    volatile uint32_t magic = zygisk_study_api_v1.magic;
    (void)magic;

    // Try to bring up libpayload as well, so the standard Zygisk
    // module surface is available alongside the init-oriented API.
    void* h = dlopen("libpayload.so", RTLD_LAZY);
    if (!h) {
        ZS_LOGW("libzn_loader: cannot dlopen libpayload: %s", dlerror());
    } else {
        using InitFn = void (*)();
        auto init = (InitFn)dlsym(h, "zygisk_study_payload_init");
        if (init) init();
    }

    return 0;
}

} // namespace zygisk_study
