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
extern "C" void zs_test_set_session_file(const char* path) {
    g_session_file = path ? path : kSessionFile;
}
extern "C" int zs_test_load_session() {
    return zs_module_load_session_socket();
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
    char path[96];
    ssize_t n = read(fd, path, sizeof path - 1);
    close(fd);
    if (n <= 0) return 0;
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

static std::vector<LoadedModule> fetch_module_list_from_daemon() {
    std::vector<LoadedModule> out;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return out;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_daemon_socket, sizeof(addr.sun_path) - 1);

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

void zs_module_init() {
    // Round 13: learn the daemon's randomized socket path first —
    // the module fetch below connects through it.
    zs_module_load_session_socket();

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

// Fill the app args from in-child observables. Only reads /proc when
// a module actually asked for names (PROCESS_UNPRIORITY); the package
// name comes from the packages.list map the hide layer already loads.
static void fill_app_args(uid_t uid) {
    g_child.uid = (jint)uid;
    // The setresgid hook recorded the gid the runtime installed; if
    // it never fired, getgid() reflects the actual current state.
    gid_t gid = g_child_gid_recorded ? g_child_gid_recorded : getgid();
    g_child.gid = (jint)gid;

    g_child.package_name[0] = '\0';
    hide_lookup_package_for_uid(uid, g_child.package_name,
                                sizeof g_child.package_name);

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

    // /data/user/<userId>/<pkg> is the canonical per-user data dir
    // (equals /data/data/<pkg> for user 0 through the well-known
    // symlink; we report the canonical form).
    g_child.app_data_dir[0] = '\0';
    if (g_child.package_name[0] != '\0') {
        long user_id = (long)uid / 100000L;
        snprintf(g_child.app_data_dir, sizeof g_child.app_data_dir,
                 "/data/user/%ld/%s", user_id, g_child.package_name);
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
