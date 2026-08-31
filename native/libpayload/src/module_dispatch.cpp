// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/module_dispatch.cpp
//
// Round 12 — the module dispatch layer. See module_dispatch.h for the
// architecture notes. This TU owns everything module-facing that used
// to live (stubbed) in entry.cpp:
//
//   - the module registry (fetch from daemon, dlopen, factory call)
//   - the zygisk::Api implementation handed to modules
//   - JNIEnv acquisition (JNI_GetCreatedJavaVMs + GetEnv/Attach)
//   - the onLoad / pre/post specialize dispatch state machines
//
// entry.cpp calls into this layer from the privilege-drop hooks; it
// never touches module state directly.

#include "module_dispatch.h"

#include "hide.h"
#include "hide_advanced.h"
#include "log.h"
#include "resolve_libc.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

namespace zygisk_study {

// ------------------------------------------------------------------------
// Module registry
// ------------------------------------------------------------------------

struct LoadedModule {
    void* dl_handle;
    zygisk::Module* instance;
    std::string path;
    std::string id;
};

static std::vector<LoadedModule> g_modules;
static std::atomic<int>          g_modules_loaded{0};

// ------------------------------------------------------------------------
// Round 19 — daemon-dependent init is LAZY (retry at the zygote's
// fork hook).
//
// REAL-DEVICE BUG this fixes (found by auditing the boot order, not
// by any host test — the host tests start the fake daemon BEFORE
// init, which is exactly the order real devices DO NOT have):
//
//   zs_module_init() runs at native-bridge initialize time, i.e. at
//   ZYGOTE START. The daemon is launched by service.sh at the
//   LATE SERVICE stage — which runs AFTER the zygote (and most of
//   the system) is already up. On a real device every connect() in
//   fetch_module_list_from_daemon() failed with ENOENT/ECONNREFUSED
//   at init, the module list came back EMPTY, and ZERO Zygisk
//   modules ever loaded for the whole boot — the entire Rounds 12-14
//   dispatch layer was dead code on device while 133 host tests
//   stayed green (the fake daemon was already listening when they
//   ran).
//
// The fix: every daemon-dependent step (module list fetch, the
// Round 19 properties-file 'P' send) is attempted at init AND retried
// at each zygote fork (zs_impl_fork calls zs_module_lazy_daemon_init)
// until it succeeds once. The retry is two relaxed atomic loads when
// everything is done, and a failed connect is ~1 usec — negligible
// even at system_server's fork rate during boot. Once the daemon
// answers, everything latches and the per-fork cost is those two
// loads.
//
// Modules that load late are inherited only by processes forked
// AFTER the successful fetch (upstream Zygisk loads at zygote start;
// we late-load; documented residual — system_server itself may miss
// modules on boots where the daemon is slow to bind).
// ------------------------------------------------------------------------
static std::atomic<int> g_module_fetch_done{0};   // latched: daemon answered the 'L'
static std::atomic<int> g_props_sent{0};          // latched: 'P' answered or permanently off

// Round 19: the spoofed property-area image. Built ONCE (the
// build reads /proc/self/maps + the real area file); held until the
// daemon accepts it, then freed. Null + build_attempted = feature
// permanently unavailable this boot (no bionic find / no mapping /
// zero spoofable keys).
static int    g_props_build_attempted = 0;
static char*  g_props_area = nullptr;
static size_t g_props_area_size = 0;

// Round 26 — WHICH property file does this platform map?
//   7.0+: /dev/__properties__/properties_serial (the magic-bearing
//         serial + default-context area, inside the
//         /dev/__properties__/ DIRECTORY)
//   6.x:  /dev/__properties__ itself — a single regular FILE, one
//         128K area holding the whole trie (verified from AOSP
//         bionic android-6.0.0_r1 libc/bionic/system_properties.cpp:
//         PROP_FILENAME "/dev/__properties__", no directory, no
//         per-context files; the trie/prop_info/area-header layouts
//         and the serial protocol are byte-identical to 7.0's, so
//         only the PATH changes).
// stat() distinguishes them (regular file = 6.x form, directory =
// 7.0+); the answer is cached after the first probe. Host tests
// override via zs_test_set_prop_file_mode.
static int g_prop_file_mode = -1;   // -1 = not probed, 0 = legacy(6.x), 1 = modern(7.0+)
#ifdef ZS_HOST_TEST
static int g_test_prop_file_mode = -1;  // test pin: 0/1, -1 = auto
#endif
static const char kPropFileModern[] = "/dev/__properties__/properties_serial";
static const char kPropFileLegacy[]  = "/dev/__properties__";

static const char* props_file_path_for_platform() {
#ifdef ZS_HOST_TEST
    if (g_test_prop_file_mode >= 0) {
        return g_test_prop_file_mode == 0 ? kPropFileLegacy
                                          : kPropFileModern;
    }
#endif
    if (g_prop_file_mode < 0) {
        struct stat st{};
        int mode = 1;   // default: the modern directory form
        if (stat("/dev/__properties__", &st) == 0 && S_ISREG(st.st_mode)) {
            mode = 0;   // the 6.x single-file form
        }
        g_prop_file_mode = mode;
    }
    return g_prop_file_mode == 0 ? kPropFileLegacy : kPropFileModern;
}

// Forward declarations (both defined with the module-loading code
// below; zs_module_init and the fork hook call them).
int  zs_module_lazy_daemon_init();
static int send_props_file_to_daemon(const char* area, size_t size);

// Round 13: durable storage for a runtime-set socket path — the
// session reader parses into a stack buffer, so the setter must COPY
// (the first version of this code stored the stack pointer itself:
// a use-after-return the session e2e test caught immediately).
static char g_daemon_socket_buf[96];
static const char* kDaemonSocketDefault =
    "/data/system/zygisk_study/sock/sock";
static const char* g_daemon_socket = kDaemonSocketDefault;

// Round 13 — the daemon's socket lives in a randomized per-boot
// directory (neutral name, so /proc/net/unix — a WORLD-READABLE file
// that lists every unix socket's path string regardless of directory
// permissions — carries no "zygisk_study" identifier). The daemon
// hands the actual path to the payload through a session file inside
// our own module directory (root-only, never listed in any
// world-readable proc file).
static constexpr const char* kSessionFile =
    "/data/adb/modules/zygisk_study/session.sock";
static const char* g_session_file = kSessionFile;

#ifdef ZS_HOST_TEST
// Round 26: pin the platform form for tests (-1 = restore auto).
extern "C" void zs_test_set_prop_file_mode(int mode) {
    g_test_prop_file_mode = mode;
}
// Round 26: read back the auto-detected mode (for the detection
// test itself: point the stat at a temp path).
extern "C" int zs_test_prop_file_mode_detected(const char* probe_path) {
    struct stat st{};
    return (probe_path && stat(probe_path, &st) == 0 &&
            S_ISREG(st.st_mode)) ? 0 : 1;
}
extern "C" void zs_test_reset_prop_file_mode_probe() {
    g_prop_file_mode = -1;
}
// Round 26: the path the lazy-init last handed to the image builder
// (tests assert the 6.x/7.x selection end-to-end through the
// dispatch path).
static char g_test_last_build_path[256] = {0};
extern "C" const char* zs_test_last_props_build_path() {
    return g_test_last_build_path;
}
#endif

#ifdef ZS_HOST_TEST
extern "C" void zs_test_set_session_file(const char* path) {
    g_session_file = path ? path : kSessionFile;
}
extern "C" int zs_test_load_session() {
    return zs_module_load_session_socket();
}
// Round 19: drive the 'P' sender directly (the builder needs a real
// /dev/__properties__ mapping, which the host does not have — the
// builder itself is covered by the hide_advanced tests against a
// synthetic mapped file).
extern "C" int zs_test_send_props_file(const char* area, size_t size) {
    return send_props_file_to_daemon(area, size);
}
// Reset the lazy-init latches (and the one-shot builder state) so a
// test can replay the boot order (daemon down at init, daemon up
// later) starting from a clean slate.
extern "C" void zs_test_reset_lazy_init() {
    g_module_fetch_done.store(0, std::memory_order_release);
    g_props_sent.store(0, std::memory_order_release);
    if (g_props_area) {
        free(g_props_area);
        g_props_area = nullptr;
    }
    g_props_area_size = 0;
    g_props_build_attempted = 0;
}
// extern "C" for the dlopen-based dispatch test (the C++ name is
// mangled; dlsym needs the plain name).
extern "C" int zs_module_lazy_daemon_init_c() {
    return zs_module_lazy_daemon_init();
}
#endif

void zs_module_set_daemon_socket(const char* path) {
    if (path && *path) {
        strncpy(g_daemon_socket_buf, path, sizeof g_daemon_socket_buf - 1);
        g_daemon_socket_buf[sizeof g_daemon_socket_buf - 1] = '\0';
        g_daemon_socket = g_daemon_socket_buf;
    }
}

// Read the session file and register the random dir with every
// filter that matches paths: the mount unmounter, the fd-link
// scanner, and the /proc/net/unix line filter. Returns 1 when a
// session path was loaded.
int zs_module_load_session_socket() {
    int fd = open(g_session_file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;                  // pre-R13 daemon: fallback
    // Round 28: read up to 96 bytes into a 97-byte buffer. A path
    // that fills the full 96 is longer than any legitimate session
    // path (the daemon's randomized paths are ~50 bytes) and would
    // be silently TRUNCATED into a garbage socket path plus garbage
    // filter prefixes — the earlier version accepted the first 95
    // bytes of a 120-byte file and registered them. Reject instead.
    char path[97];
    ssize_t n = read(fd, path, sizeof path - 1);
    close(fd);
    if (n <= 0 || n > (ssize_t)(sizeof path - 2)) return 0;
    path[n] = '\0';
    // Trim trailing whitespace (the daemon writes a bare line).
    while (n > 0 && (path[n - 1] == '\n' || path[n - 1] == '\r' ||
                     path[n - 1] == ' ')) {
        path[--n] = '\0';
    }
    if (path[0] != '/') return 0;          // sanity: absolute path

    zs_module_set_daemon_socket(path);

    // Derive the directory (everything before the last '/').
    char dir[96];
    size_t len = (size_t)n;
    size_t slash = len;
    while (slash > 0 && path[slash - 1] != '/') --slash;
    if (slash <= 1) return 1;              // "/sock": no dir to trim
    memcpy(dir, path, slash - 1);
    dir[slash - 1] = '\0';

    // Register with a trailing slash so prefix matching cannot
    // swallow sibling names sharing a stem.
    char prefix[112];
    snprintf(prefix, sizeof prefix, "%.94s/", dir);
    hide_register_root_path_prefix(prefix);
    hide_advanced_register_root_path_prefix(prefix);
    hide_advanced_register_unix_hidden_substring(dir);
    return 1;
}

#ifdef ZS_HOST_TEST
extern "C" void zs_test_set_daemon_socket(const char* path) {
    if (path) {
        strncpy(g_daemon_socket_buf, path, sizeof g_daemon_socket_buf - 1);
        g_daemon_socket_buf[sizeof g_daemon_socket_buf - 1] = '\0';
        g_daemon_socket = g_daemon_socket_buf;
    } else {
        g_daemon_socket = kDaemonSocketDefault;
    }
}
#endif

// `was_connected` (optional): set to 1 when the daemon ACCEPTED the
// connection (an empty module list is a valid, FINAL answer — the
// registry file is empty — while a failed connect means "daemon not
// up yet, retry"). This is how the Round 19 lazy retry distinguishes
// the two without a separate reachability probe.
static std::vector<LoadedModule> fetch_module_list_from_daemon(
        int* was_connected = nullptr) {
    std::vector<LoadedModule> out;
    if (was_connected) *was_connected = 0;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return out;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_daemon_socket, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0) {
        close(sock);
        return out;
    }
    if (was_connected) *was_connected = 1;
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

// ------------------------------------------------------------------------
// The zygisk::Api surface we hand back to modules.
// ------------------------------------------------------------------------

// FORCE_DENYLIST_UNMOUNT state. Set in the zygote by onLoad; children
// inherit it through fork (copy-on-write statics).
static std::atomic<int> g_force_unmount{0};

class PayloadApi : public zygisk::Api {
public:
    void setOption(zygisk::Api::Option option) override {
        if (option == zygisk::Api::FORCE_DENYLIST_UNMOUNT) {
            g_force_unmount.store(1, std::memory_order_release);
        }
    }

    int  connectCompanion() override {
        int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sock < 0) return -1;
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, g_daemon_socket,
                sizeof(addr.sun_path) - 1);
        if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0 ||
            send(sock, "C", 1, 0) != 1) {
            close(sock);
            return -1;
        }
        return sock;  // long-lived; the module owns it now
    }

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

    // Replace env's function-table pointer. The JNIEnv object is
    // ART-allocated writable memory whose first (and only) field is
    // the table pointer; writing it redirects every call made through
    // this thread's env. The module supplies the (patched copy of
    // the) table — see zygisk.hpp.
    int  hookJniEnv(JNIEnv* env, const JNINativeInterface* newTable,
                    const JNINativeInterface** oldTable) override {
        if (!env || !newTable) return -1;
        // `struct _JNIEnv { const JNINativeInterface* functions; }`
        // — the leading slot IS the table pointer under the real JNI
        // ABI. Cast through void* so the host typedefs compile too.
        const JNINativeInterface** slot =
            (const JNINativeInterface**)(void*)env;
        if (oldTable) *oldTable = *slot;
        *slot = newTable;
        return 0;
    }

    void cleanTrace() override { hide_clean_trace(); }
    uint32_t apiVersion() override { return 2; }
};

static PayloadApi g_api;

// ------------------------------------------------------------------------
// JNIEnv acquisition (see module_dispatch.h).
//
// Raw-pointer arithmetic over the standard JNI ABI:
//   JavaVM*          -> [invoke-table pointer]
//   invoke table     -> { reserved0..2, DestroyJavaVM(3),
//                         AttachCurrentThread(4), Detach(5),
//                         GetEnv(6), AttachAsDaemon(7) }
// Identical layout under jni.h and under the host stubs.
// ------------------------------------------------------------------------

static constexpr int kVmGetEnvIdx        = 6;
static constexpr int kVmAttachDaemonIdx  = 7;

typedef int  (*ZsVmGetEnvFn)(void*, void**, int);
typedef int  (*ZsVmAttachFn)(void*, void**, void*);

static void*    g_java_vm = nullptr;
static JNIEnv* g_env     = nullptr;
static std::atomic<int> g_env_tried{0};

static void* zs_lookup_get_created_java_vms() {
    // Primary: global scope (libart is RTLD_GLOBAL in every zygote).
    void* fn = dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    if (fn) return fn;
    // Fallback: dlopen by soname returns the already-loaded libart
    // handle without re-loading it.
    void* art = dlopen("libart.so", RTLD_NOW | RTLD_LOCAL);
    if (art) fn = dlsym(art, "JNI_GetCreatedJavaVMs");
    return fn;
}

// Returns the JNIEnv of the current thread, or null if the VM cannot
// be found / the thread cannot be attached. Never crashes on failure:
// modules simply see a null env ("no JNI available").
static JNIEnv* zs_module_ensure_env() {
    if (g_env) return g_env;
    int expected = 0;
    if (!g_env_tried.compare_exchange_strong(expected, 1)) {
        return g_env;  // another init attempt already finished
    }

    typedef int (*GetVmsFn)(void**, int, int*);
    auto get_vms = (GetVmsFn)zs_lookup_get_created_java_vms();
    if (!get_vms) {
        ZS_LOGD("modules: JNI_GetCreatedJavaVMs not found");
        return nullptr;
    }
    void* vms[1] = {nullptr};
    int   count  = 0;
    if (get_vms(vms, 1, &count) != 0 || count < 1 || !vms[0]) {
        ZS_LOGD("modules: no created Java VM yet");
        return nullptr;
    }
    g_java_vm = vms[0];

    void** table = *(void***)g_java_vm;
    if (!table) return nullptr;

    void* env = nullptr;
    auto get_env = (ZsVmGetEnvFn)table[kVmGetEnvIdx];
    if (get_env &&
        get_env(g_java_vm, &env, JNI_VERSION_1_6) == 0 && env) {
        g_env = (JNIEnv*)env;                     // already attached
        return g_env;
    }
    auto attach = (ZsVmAttachFn)table[kVmAttachDaemonIdx];
    if (attach && attach(g_java_vm, &env, nullptr) == 0 && env) {
        g_env = (JNIEnv*)env;                     // attached as daemon
        return g_env;
    }
    ZS_LOGW("modules: could not obtain a JNIEnv");
    return nullptr;
}

// ------------------------------------------------------------------------
// Module loading (payload init — zygote, native-bridge time)
// ------------------------------------------------------------------------

// Load every module in `list` (dlopen + factory + unmap-set
// registration). Split out of zs_module_init in Round 19 so the lazy
// retry path (zs_module_lazy_daemon_init) can run the SAME code once
// the daemon finally answers.
static void load_modules_from(std::vector<LoadedModule>&& list) {
    g_modules.reserve(list.size());
    for (auto& m : list) {
        // Register the module .so path BEFORE dlopen'ing so the
        // record rescan below sees both the fragment and the fresh
        // maps entries in one pass.
        hide_register_extra_so(m.path.c_str());
        m.dl_handle = dlopen(m.path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!m.dl_handle) {
            ZS_LOGW("modules: dlopen(%s) failed: %s",
                    m.path.c_str(), dlerror());
            continue;
        }
        using FactoryFn = zygisk::Module* (*)(zygisk::Api*, JNIEnv*);
        auto factory = (FactoryFn)dlsym(m.dl_handle, "zygisk_module");
        if (!factory) {
            ZS_LOGW("modules: %s: no zygisk_module symbol", m.id.c_str());
            dlclose(m.dl_handle);
            continue;
        }
        // env is null here on purpose: the VM does not exist yet at
        // native-bridge initialize time. onLoad gets a REAL env at
        // the first fork (see zs_module_on_first_fork).
        m.instance = factory(&g_api, nullptr);
        if (!m.instance) {
            ZS_LOGW("modules: %s: factory returned null", m.id.c_str());
            dlclose(m.dl_handle);
            continue;
        }
        ZS_LOGI("modules: loaded %s from %s",
                m.id.c_str(), m.path.c_str());
        g_modules.push_back(std::move(m));
    }
    // One maps rescan picks up every module's segments.
    hide_rescan_records();

    // CRITICAL: mark modules as loaded so nothing re-fetches the list
    // from the daemon (per-fork socket round-trips would be a major
    // latency regression).
    g_modules_loaded.store(1, std::memory_order_release);
}

void zs_module_init() {
    // Round 13: learn the daemon's randomized socket path first —
    // the module fetch below connects through it.
    zs_module_load_session_socket();

    // Round 19: attempt everything once here. On a real device the
    // daemon is NOT up yet at zygote start (see the boot-order audit
    // above the g_module_fetch_done declaration) — the attempts fail
    // fast and zs_module_lazy_daemon_init retries them at every
    // zygote fork until the daemon answers. On host tests the fake
    // daemon is already up, so this single attempt succeeds.
    (void)zs_module_lazy_daemon_init();
}

// Round 19: one lazy-init attempt. Returns 1 when BOTH daemon-
// dependent steps are latched (module fetch + props send), 0 when
// something still needs a retry. Called from zs_module_init and from
// the zygote-side fork hook (zs_impl_fork) — always in the ZYGOTE,
// never in a forked child (children inherit the results via COW).
int zs_module_lazy_daemon_init() {
    if (g_module_fetch_done.load(std::memory_order_acquire) &&
        g_props_sent.load(std::memory_order_acquire)) {
        return 1;   // hot path: two relaxed-ish loads
    }

    // (a) Module list: retry until the daemon ANSWERS (an empty list
    // is a valid, final answer — the registry file is empty; only a
    // failed CONNECT means "not up yet, retry"). g_module_fetch_done
    // is the single latch — g_modules_loaded is a legacy flag kept
    // for the R12 hot-path contract, not a retry gate (the failed
    // connect retry must stay cheap AND must not double-load).
    if (!g_module_fetch_done.load(std::memory_order_acquire)) {
        int was_connected = 0;
        auto list = fetch_module_list_from_daemon(&was_connected);
        if (was_connected) {
            load_modules_from(std::move(list));
            g_module_fetch_done.store(1, std::memory_order_release);
        }
        // else: connect() failed — the daemon is not up yet; a failed
        // connect costs ~1 usec, retried on the next fork.
    }

    // (b) Properties file: build once, send when the daemon is up.
    if (!g_props_sent.load(std::memory_order_acquire)) {
        if (!g_props_build_attempted) {
            g_props_build_attempted = 1;
#ifdef ZS_HOST_TEST
            {
                const char* p = props_file_path_for_platform();
                snprintf(g_test_last_build_path, sizeof g_test_last_build_path,
                         "%s", p);
            }
#endif
            g_props_area = zs_build_spoofed_serial_area(
                props_file_path_for_platform(),
                &g_props_area_size);
            if (!g_props_area) {
                // Feature unavailable on this device — final.
                g_props_sent.store(1, std::memory_order_release);
            }
        }
        if (g_props_area) {
            if (send_props_file_to_daemon(g_props_area,
                                          g_props_area_size)) {
                // Sent: the buffer has been handed off in full.
                g_props_sent.store(1, std::memory_order_release);
                free(g_props_area);
                g_props_area = nullptr;
            }
            // else: daemon not up / refused — keep the buffer and
            // retry on the next fork (bounded by the daemon actually
            // starting; the window is a few seconds of boot).
        }
    }
    return g_module_fetch_done.load(std::memory_order_acquire) &&
           g_props_sent.load(std::memory_order_acquire);
}

// Send the 'P' verb: <'P'><u32 LE len><bytes>. The daemon (root side)
// writes the file into the session dir, relabels it with the
// platform's own label (properties_serial on 7.0+,
// properties_device on 6.x), and replies "1<session_dir>/p\n" — the
// payload then registers that path with the hide layer, and every
// hidden child bind-mounts it over the platform's property file
// (/dev/__properties__/properties_serial on 7.0+, the single
// /dev/__properties__ file on 6.x) at hide time.
// Returns 1 = latched (sent OR feature acknowledged off), 0 = retry
// later.
static int send_props_file_to_daemon(const char* area, size_t size) {
    // Round 26: the daemon requires the real 16-byte area header
    // (bytes_used + serial + magic + version); anything shorter is
    // not a sane image — final, not a retry.
    if (!area || size < 16) return 1;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return 0;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_daemon_socket, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof addr) != 0) {
        ZS_LOGD("props send: connect(%s) failed: %s", g_daemon_socket,
                strerror(errno));
        close(sock);
        return 0;   // daemon not up: retry
    }
    uint32_t len = (uint32_t)size;
    char hdr[5] = {'P', (char)(len & 0xff), (char)((len >> 8) & 0xff),
                   (char)((len >> 16) & 0xff), (char)((len >> 24) & 0xff)};
    size_t off = 0;
    while (off < sizeof hdr) {
        ssize_t n = send(sock, hdr + off, sizeof hdr - off, MSG_NOSIGNAL);
        if (n <= 0) { close(sock); return 0; }
        off += (size_t)n;
    }
    off = 0;
    while (off < size) {
        size_t chunk = size - off;
        if (chunk > 256 * 1024) chunk = 256 * 1024;
        ssize_t n = send(sock, area + off, chunk, MSG_NOSIGNAL);
        if (n <= 0) { close(sock); return 0; }
        off += (size_t)n;
    }
    // Reply: "1<path>\n" or "0\n".
    char reply[160];
    ssize_t n = recv(sock, reply, sizeof reply - 1, 0);
    close(sock);
    if (n <= 0) { ZS_LOGD("props send: no reply"); return 0; }
    reply[n] = '\0';
    ZS_LOGD("props send: reply %s", reply);
    if (reply[0] != '1') return 0;
    char* nl = strchr(reply, '\n');
    if (nl) *nl = '\0';
    const char* path = reply + 1;
    if (path[0] != '/') return 0;
    // Round 26 — the self-check magic is the AREA magic (header
    // offset 8: bytes_used@0, serial@4, magic@8, version@12 —
    // verified from AOSP bionic at 6.0/7.0/9.0). The daemon rejects
    // anything shorter than 16 bytes, so a successful reply means a
    // real-format image; the size guard here is belt-and-braces.
    uint32_t magic = 0;
    if (size >= 12) {
        memcpy(&magic, (const char*)area + 8, sizeof magic);
    }
    hide_props_file_set_source(path, magic);
    ZS_LOGI("modules: spoofed properties file staged at %s", path);
    return 1;
}

// ------------------------------------------------------------------------
// onLoad dispatch (zygote, at the first fork hook entry)
// ------------------------------------------------------------------------

static std::atomic<int> g_onload_done{0};

// The zygote's own argv[0] ("zygote" / "zygote64"), captured at init.
// A child whose /proc/self/cmdline still equals this has not had its
// name rewritten yet -> the package name is the better nice_name.
static char g_zygote_name[64] = {0};

static void capture_zygote_name() {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = read(fd, g_zygote_name, sizeof g_zygote_name - 1);
    close(fd);
    if (n <= 0) g_zygote_name[0] = '\0';
    else g_zygote_name[n] = '\0';
}

extern "C" int zs_module_onload_done() {
    return g_onload_done.load(std::memory_order_acquire);
}

void zs_module_on_first_fork() {
    if (g_modules.empty()) return;  // hot path: zero modules installed
    int expected = 0;
    if (!g_onload_done.compare_exchange_strong(expected, 1)) return;

    JNIEnv* env = zs_module_ensure_env();
    for (auto& m : g_modules) {
        m.instance->onLoad(&g_api, env);
    }
}

// ------------------------------------------------------------------------
// Per-child dispatch state
// ------------------------------------------------------------------------

// Args storage: per-child (fresh copy-on-write statics after fork).
// Kept in static storage so the pointers a module stashes in pre
// remain valid for the post callback (upstream has the same contract:
// the args live in the specialize frame).
static struct {
    jint uid;
    jint gid;
    char nice_name[256];
    char package_name[256];
    char app_data_dir[512];
    zygisk::AppSpecializeArgs app_args;
    zygisk::ServerSpecializeArgs server_args;
} g_child{};

static gid_t g_child_gid_recorded = 0;   // from the setresgid hook
static std::atomic<int> g_pre_done{0};
static std::atomic<int> g_post_done{0};
static ZsChildKind      g_child_kind = ZS_CHILD_NONE;

#ifdef ZS_HOST_TEST
extern "C" void zs_test_reset_child_state() {
    g_child_gid_recorded = 0;
    g_pre_done.store(0);
    g_post_done.store(0);
    g_child_kind = ZS_CHILD_NONE;
    memset(&g_child, 0, sizeof g_child);
}
#endif

void zs_module_record_gid(gid_t gid) {
    g_child_gid_recorded = (gid_t)gid;
}

gid_t zs_module_recorded_gid() {
    return g_child_gid_recorded;
}

ZsChildKind zs_module_classify(uid_t uid) {
    if (uid == 1000) return ZS_CHILD_SERVER;  // AID_SYSTEM (the only
                                              // uid-1000 zygote child
                                              // is system_server)
    if (uid >= 10000) return ZS_CHILD_APP;
    return ZS_CHILD_NONE;
}

extern "C" int zs_module_dispatch_wanted() {
    return g_modules.empty() ? 0 : 1;
}

int zs_module_force_unmount() {
    return g_force_unmount.load(std::memory_order_acquire);
}

// Round 14 — single-entry derived-args cache. The common app fork
// pattern is the SAME package launching repeatedly; the cache
// skips the hash lookup + snprintf for every fork after the first
// of that uid. Keyed on the FULL uid (not the appId family: users
// 0 and 10 of the same package share the map entry but need
// different /data/user/<id>/ dirs) AND the packages.map
// generation, so a reload (R13 staleness fix) invalidates it in the
// same breath as the map itself. Per-child copy-on-write storage —
// no locking (the specialize path is single-threaded).
static struct {
    uid_t     key;
    uint32_t  gen;
    char package_name[256];
    char app_data_dir[512];
    int  valid;
} g_args_cache{};

// Fill the app args from in-child observables. Only reads /proc when
// a module actually asked for names (PROCESS_UNPRIORITY); the package
// name comes from the packages.list map the hide layer already loads.
static void fill_app_args(uid_t uid) {
    g_child.uid = (jint)uid;
    // The setresgid hook recorded the gid the runtime installed; if
    // it never fired, getgid() reflects the actual current state.
    gid_t gid = g_child_gid_recorded ? g_child_gid_recorded : getgid();
    g_child.gid = (jint)gid;

    uint32_t gen = hide_pkg_map_generation();
    if (g_args_cache.valid && g_args_cache.key == uid &&
        g_args_cache.gen == gen) {
        memcpy(g_child.package_name, g_args_cache.package_name,
               sizeof g_child.package_name);
        memcpy(g_child.app_data_dir, g_args_cache.app_data_dir,
               sizeof g_child.app_data_dir);
    } else {
        g_child.package_name[0] = '\0';
        hide_lookup_package_for_uid(uid, g_child.package_name,
                                    sizeof g_child.package_name);
        // /data/user/<userId>/<pkg> is the canonical per-user data
        // dir (equals /data/data/<pkg> for user 0 through the
        // well-known symlink; we report the canonical form).
        g_child.app_data_dir[0] = '\0';
        if (g_child.package_name[0] != '\0') {
            long user_id = (long)uid / 100000L;
            snprintf(g_child.app_data_dir, sizeof g_child.app_data_dir,
                     "/data/user/%ld/%s", user_id, g_child.package_name);
        }
        g_args_cache.key = uid;
        g_args_cache.gen = gen;
        memcpy(g_args_cache.package_name, g_child.package_name,
               sizeof g_args_cache.package_name);
        memcpy(g_args_cache.app_data_dir, g_child.app_data_dir,
               sizeof g_args_cache.app_data_dir);
        g_args_cache.valid = 1;
    }

    g_child.nice_name[0] = '\0';
    int wants_names = 0;
    for (auto& m : g_modules) {
        if (m.instance->caps() & zygisk::PROCESS_UNPRIORITY) {
            wants_names = 1;
            break;
        }
    }
    if (wants_names) {
        int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, g_child.nice_name,
                             sizeof g_child.nice_name - 1);
            close(fd);
            if (n > 0) g_child.nice_name[n] = '\0';
        }
        // If the runtime has not rewritten argv yet, the name is still
        // the zygote's — the package name is the better answer.
        if (g_child.nice_name[0] == '\0' ||
            strcmp(g_child.nice_name, g_zygote_name) == 0) {
            if (g_child.package_name[0] != '\0') {
                strncpy(g_child.nice_name, g_child.package_name,
                        sizeof g_child.nice_name - 1);
                g_child.nice_name[sizeof g_child.nice_name - 1] = '\0';
            }
        }
    }

    g_child.app_args.uid          = &g_child.uid;
    g_child.app_args.gid          = &g_child.gid;
    g_child.app_args.nice_name    = g_child.nice_name;
    g_child.app_args.package_name = g_child.package_name;
    g_child.app_args.app_data_dir = g_child.app_data_dir;
}

ZsChildKind zs_module_pre_specialize(uid_t uid, uid_t* out_uid,
                                     uid_t* out_gid) {
    if (g_modules.empty() || g_pre_done.load(std::memory_order_acquire))
        return ZS_CHILD_NONE;

    ZsChildKind kind = zs_module_classify(uid);
    if (kind == ZS_CHILD_NONE) return ZS_CHILD_NONE;

    g_pre_done.store(1, std::memory_order_release);
    g_child_kind = kind;

    JNIEnv* env = zs_module_ensure_env();
    if (kind == ZS_CHILD_SERVER) {
        g_child.uid = (jint)uid;
        gid_t gid = g_child_gid_recorded ? g_child_gid_recorded
                                         : getgid();
        g_child.gid = (jint)gid;
        g_child.server_args.uid = &g_child.uid;
        g_child.server_args.gid = &g_child.gid;
        for (auto& m : g_modules)
            m.instance->preServerSpecialize(env, &g_child.server_args);
    } else {
        fill_app_args(uid);
        for (auto& m : g_modules)
            m.instance->preAppSpecialize(env, &g_child.app_args);
    }

    // Module-visible writes through args->uid/args->gid.
    if (out_uid) *out_uid = (uid_t)g_child.uid;
    if (out_gid) *out_gid = (uid_t)g_child.gid;
    return kind;
}

void zs_module_post_specialize() {
    if (g_modules.empty()) return;
    if (!g_pre_done.load(std::memory_order_acquire)) return;
    int expected = 0;
    if (!g_post_done.compare_exchange_strong(expected, 1)) return;

    if (g_child_kind == ZS_CHILD_SERVER) {
        for (auto& m : g_modules)
            m.instance->postServerSpecialize(&g_child.server_args);
    } else if (g_child_kind == ZS_CHILD_APP) {
        for (auto& m : g_modules)
            m.instance->postAppSpecialize(&g_child.app_args);
    }
}

#ifdef ZS_HOST_TEST
static ZsDropSeam g_drop_seam{};
extern "C" void zs_test_set_drop_seam(const ZsDropSeam* seam) {
    if (seam) g_drop_seam = *seam;
    else memset(&g_drop_seam, 0, sizeof g_drop_seam);
}
extern "C" ZsDropSeam* zs_test_drop_seam() { return &g_drop_seam; }
#endif

// The zygote-name capture lives here (not in zs_module_init) so the
// host tests can drive it independently of the daemon fetch.
void zs_module_capture_zygote_name() { capture_zygote_name(); }

} // namespace zygisk_study
