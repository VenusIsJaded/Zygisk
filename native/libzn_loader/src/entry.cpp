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
#include <stdio.h>
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
// process?". Round 28 fix: this is only the LEGACY FALLBACK path.
// Since Round 13 the daemon binds a randomized per-boot socket and
// publishes the real path in the session file (the same handshake
// libpayload uses — see module_dispatch.cpp). The previous version
// of this file hardwired the fixed path, so on every boot where the
// randomization succeeded the connect() here failed and
// api_should_inject() silently answered "no" for every target while
// api_open_companion_fd() always returned -1 — the init-oriented API
// was dead on real devices while the host tests stayed green (nothing
// exercised the path).
static constexpr const char* kDaemonSocketLegacy =
    "/data/system/zygisk_study/sock/sock";

// The session file the daemon writes before binding (root-only
// directory; see module_dispatch.cpp for the full stealth rationale
// for why the path is handed over in a file instead of a fixed name).
static constexpr const char* kSessionFile =
    "/data/adb/modules/zygisk_study/session.sock";
// Round 29 — the daemon's second session record (in the /data/system
// workdir). Fallback when the module tree cannot be opened from this
// process (the ReZygisk #380 Samsung class: kernel path rules
// blocking app_process64's /data/adb/modules opens). See
// module_dispatch.cpp's kSessionFileAlt — same content, same parser.
static constexpr const char* kSessionFileAlt =
    "/data/system/zygisk_study/session.sock";

#ifdef ZS_HOST_TEST
// Test seam: point the resolver at temp "session files".
static const char* g_session_file = kSessionFile;
static const char* g_session_file_alt = kSessionFileAlt;
extern "C" void zs_test_zn_set_session_file(const char* path) {
    g_session_file = path ? path : kSessionFile;
}
// Round 29: pin the ALTERNATE record for tests.
extern "C" void zs_test_zn_set_session_file_alt(const char* path) {
    g_session_file_alt = path ? path : kSessionFileAlt;
}
// Test seam: run the resolver directly (the static function below
// is not otherwise visible outside the TU).
static int resolve_daemon_socket(char* out, size_t outsz);
extern "C" int zs_test_zn_resolve_socket(char* out, size_t outsz) {
    return resolve_daemon_socket(out, outsz);
}
#endif

// Resolve the daemon socket for a connection attempt. Reads the
// session file (daemon up, randomized path); on any failure (daemon
// not started yet, file missing, malformed content) falls back to
// the legacy fixed path. Returns 1 when the session file supplied
// the path, 0 when the legacy fallback is in use — callers may use
// that to decide whether a retry is worthwhile (the daemon may come
// up later in the boot; the payload's lazy-init does the same).
//
// Called per-connection rather than cached: the calls are per
// process-injection (rare), the file is 96 bytes, and the daemon
// starts AFTER zygote (class main) while libzn_loader may be asked
// from init-context processes at any point — a cached miss from
// before daemon start would pin the fallback forever.
static int resolve_daemon_socket(char* out, size_t outsz) {
    if (!out || outsz == 0) return 0;
#ifdef ZS_HOST_TEST
    const char* session = g_session_file;
    const char* session_alt = g_session_file_alt;
#else
    const char* session = kSessionFile;
    const char* session_alt = kSessionFileAlt;
#endif
    int fd = open(session, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        // Round 29: the module tree is unreadable from here — the
        // daemon also writes its record into the /data/system workdir.
        fd = open(session_alt, O_RDONLY | O_CLOEXEC);
    }
    if (fd >= 0) {
        // 96 bytes read into a 97-byte buffer: a path that fills the
        // full 96 is longer than any legitimate session path (the
        // daemon's randomized paths are ~50 bytes) AND cannot fit the
        // callers' 96-byte buffers — it would be silently truncated
        // into a garbage path. Reject it outright (the earlier
        // version accepted the first 95 bytes of a 120-byte file).
        char path[97];
        ssize_t n = read(fd, path, sizeof path - 1);
        close(fd);
        if (n > 0 && n <= (ssize_t)(sizeof path - 2)) {
            path[n] = '\0';
            // Trim trailing whitespace (the daemon writes a bare
            // line; mirror the payload's parser exactly).
            while (n > 0 && (path[n - 1] == '\n' || path[n - 1] == '\r' ||
                             path[n - 1] == ' ')) {
                path[--n] = '\0';
            }
            // Sanity: absolute path and it must fit both the output
            // buffer and sockaddr_un::sun_path (108 on Linux).
            if (path[0] == '/' && (size_t)n + 1 <= outsz &&
                (size_t)n + 1 <= sizeof(((struct sockaddr_un*)0)->sun_path)) {
                memcpy(out, path, (size_t)n + 1);
                return 1;
            }
        }
    }
    snprintf(out, outsz, "%s", kDaemonSocketLegacy);
    return 0;
}

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

    char sock_path[96];
    resolve_daemon_socket(sock_path, sizeof sock_path);

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return 0;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
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
    char sock_path[96];
    resolve_daemon_socket(sock_path, sizeof sock_path);

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
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
