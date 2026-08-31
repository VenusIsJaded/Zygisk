// SPDX-License-Identifier: Apache-2.0
// tests/test_module_dispatch.cpp
//
// Round 12 — end-to-end test of the module dispatch layer (the
// "module pre/post-specialize callbacks with real Zygote arguments"
// feature) against the REAL libpayload.so:
//
//   1. A fake zygiskd (a thread with a Unix socket) serves the REAL
//      'L' (list) and 'C' (companion) protocol.
//   2. The REAL payload (dlopen'd libpayload.so) fetches the module
//      list, dlopens the REAL module .so (libzs_test_module.so built
//      from module_stub.cpp) and runs the factory.
//   3. A fake JavaVM (exported via -rdynamic as
//      JNI_GetCreatedJavaVMs) feeds the REAL env-acquisition path.
//   4. The REAL hook implementations (zs_impl_setresgid /
//      zs_impl_setresuid / zs_impl_setuid, driven through the
//      zs_test_* exports with wrapper_fp=null) dispatch onLoad /
//      preApp / postApp / preServer / postServer into the module.
//   5. A drop-seam recorder proves module-rewritten uid/gid values
//      are forwarded to the real privilege-drop calls.
//   6. The DenyList interplay: a denylisted child hides instead of
//      dispatching (no callbacks).
//
// What is deliberately NOT covered here: Tier A (the asm trampoline
// self-unmap) — wrapper_fp is null on every drive, so the dispatch
// tests never enter the trampoline path. The trampoline itself has
// its own dedicated test (test_unmap_trampoline).

#include "test_framework.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// ----------------------------------------------------------------------
// Recorder protocol (must match module_stub.cpp)
// ----------------------------------------------------------------------
enum {
    ZS_CB_ONLOAD      = 1,
    ZS_CB_PRE_APP     = 2,
    ZS_CB_POST_APP    = 3,
    ZS_CB_PRE_SERVER  = 4,
    ZS_CB_POST_SERVER = 5,
};

struct RecEntry {
    int32_t cb;
    int32_t uid;
    int32_t gid;
    uintptr_t env;
    uintptr_t jni_old_table;
    uintptr_t jni_new_table;
    int32_t companion_fd;
    char nice_name[64];
    char package_name[64];
    char app_data_dir[160];
};

struct RecPage {
    int32_t count;
    int32_t _pad;
    RecEntry entries[32];
    // Drop recorders live on the SHARED page too: the hooks run in
    // forked children, and copy-on-write would hide their records
    // from the asserting parent.
    long setresgid_calls[8][3];
    int32_t setresgid_count;
    int32_t _pad2;
    long setresuid_calls[8][3];
    int32_t setresuid_count;
    int32_t _pad3;
};

static RecPage* g_rec;          // MAP_SHARED page

static void rec_reset() {
    g_rec->count = 0;
    g_rec->setresgid_count = 0;
    g_rec->setresuid_count = 0;
}
static int  rec_count() { return g_rec->count; }
static const RecEntry* rec(int i) { return &g_rec->entries[i]; }

// ----------------------------------------------------------------------
// Fake JNI machinery. The REAL payload resolves
// JNI_GetCreatedJavaVMs via dlsym(RTLD_DEFAULT, ...) — exporting it
// from the test binary (linked with -rdynamic) feeds the real path.
//
// Layout follows the real JNI ABI:
//   JavaVM -> [invoke table ptr]; invoke table: {resv0..2, Destroy(3),
//   Attach(4), Detach(5), GetEnv(6), AttachAsDaemon(7)}
//   JNIEnv -> [function table ptr] (64 slots on the fake layout)
// ----------------------------------------------------------------------
static void* g_invoke_table[8];
static void* g_jni_table[64];
static const void* g_fake_vm = g_invoke_table;  // "JavaVM*"
struct FakeJNIEnv { const void* functions; };
static FakeJNIEnv g_fake_env;

static int fake_get_env(void* /*vm*/, void** env, int /*ver*/) {
    *env = &g_fake_env;
    return 0;  // JNI_OK
}
static int fake_attach(void* /*vm*/, void** env, void* /*args*/) {
    *env = &g_fake_env;
    return 0;
}

extern "C" __attribute__((visibility("default")))
int JNI_GetCreatedJavaVMs(void** vms, int /*size*/, int* count) {
    *vms = (void*)&g_fake_vm;
    *count = 1;
    return 0;
}

// ----------------------------------------------------------------------
// Fake zygiskd: Unix socket serving the real verbs.
// ----------------------------------------------------------------------
static std::string g_sock_path;
static volatile int g_companion_hits = 0;

// Round 13: the daemon thread is parameterized so a SECOND fake
// daemon can serve a "randomized" session-path socket.
struct DaemonCfg {
    std::string path;
    int         max_serve;
    volatile int* companion_hits;
};
static DaemonCfg g_main_daemon_cfg;

static void* daemon_thread(void* arg) {
    DaemonCfg* cfg = (DaemonCfg*)arg;
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) return nullptr;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, cfg->path.c_str(), sizeof(addr.sun_path) - 1);
    unlink(cfg->path.c_str());
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof addr) != 0 ||
        listen(listen_fd, 4) != 0) {
        std::fprintf(stderr, "fake-daemon: bind/listen failed: %s\n",
                     std::strerror(errno));
        close(listen_fd);
        return nullptr;
    }

    for (int served = 0; served < cfg->max_serve; ++served) {
        int c = accept(listen_fd, nullptr, nullptr);
        if (c < 0) break;
        char verb = 0;
        if (read(c, &verb, 1) == 1) {
            if (verb == 'L') {
                char module_path[4096];
                ssize_t n = readlink("/proc/self/exe", module_path,
                                     sizeof module_path - 1);
                if (n < 0) n = 0;
                module_path[n] = '\0';
                // Same directory as this binary.
                char* slash = strrchr(module_path, '/');
                std::string dir = slash ? std::string(module_path,
                                                      slash - module_path + 1)
                                        : std::string("./");
                std::string line = "stub;" + dir + "libzs_test_module.so\n";
                (void)write(c, line.c_str(), line.size());
            } else if (verb == 'C') {
                ++*cfg->companion_hits;
                // Hold the connection open (the real daemon's
                // companion channel); the client owns its fd.
                usleep(50 * 1000);
            }
        }
        close(c);
    }
    close(listen_fd);
    return nullptr;
}

// ----------------------------------------------------------------------
// Real-call drop seam: recorders proving what the hooks forwarded.
// (They write into the shared page — see RecPage.)
// ----------------------------------------------------------------------
static long rec_setresgid(gid_t a, gid_t b, gid_t c) {
    if (g_rec->setresgid_count < 8) {
        g_rec->setresgid_calls[g_rec->setresgid_count][0] = a;
        g_rec->setresgid_calls[g_rec->setresgid_count][1] = b;
        g_rec->setresgid_calls[g_rec->setresgid_count][2] = c;
        ++g_rec->setresgid_count;
    }
    return 0;
}
static long rec_setresuid(uid_t a, uid_t b, uid_t c) {
    if (g_rec->setresuid_count < 8) {
        g_rec->setresuid_calls[g_rec->setresuid_count][0] = a;
        g_rec->setresuid_calls[g_rec->setresuid_count][1] = b;
        g_rec->setresuid_calls[g_rec->setresuid_count][2] = c;
        ++g_rec->setresuid_count;
    }
    return 0;
}

// ----------------------------------------------------------------------
// Payload symbols (dlopen'd, ZS_HOST_TEST exports)
// ----------------------------------------------------------------------
static void* g_payload = nullptr;

typedef void  (*Fn_init)();
typedef void  (*Fn_set_sock)(const char*);
typedef void  (*Fn_set_drop_seam)(const void*);
typedef void* (*Fn_drop_seam)();
typedef void  (*Fn_reset_child)();
typedef void  (*Fn_first_fork)();
typedef long  (*Fn_setresgid)(long);
typedef long  (*Fn_setresuid)(long);
typedef long  (*Fn_setuid)(long);
typedef void  (*Fn_set_pkg_list)(const char*);
typedef void  (*Fn_set_denylist)(const char*);
typedef void  (*Fn_force_deny)(int);
typedef int   (*Fn_dispatch_wanted)();
typedef int   (*Fn_onload_done)();
typedef void  (*Fn_set_session_file)(const char*);
typedef int   (*Fn_load_session)();

static Fn_init            fn_init;
static Fn_set_sock        fn_set_sock;
static Fn_set_drop_seam   fn_set_drop_seam;
static Fn_drop_seam       fn_drop_seam;
static Fn_reset_child     fn_reset_child;
static Fn_first_fork      fn_first_fork;
static Fn_setresgid       fn_setresgid;
static Fn_setresuid       fn_setresuid;
static Fn_setuid          fn_setuid;
static Fn_set_pkg_list    fn_set_pkg_list;
static Fn_set_denylist    fn_set_denylist;
static Fn_force_deny      fn_force_deny;
static Fn_dispatch_wanted fn_dispatch_wanted;
static Fn_onload_done     fn_onload_done;
static Fn_set_session_file fn_set_session_file;
static Fn_load_session     fn_load_session;

static void* sym(const char* name) {
    void* p = dlsym(g_payload, name);
    if (!p) {
        std::fprintf(stderr, "FATAL: libpayload.so is missing %s\n",
                     name);
        std::exit(2);
    }
    return p;
}

// One-time setup: recorder page, fake VM, fake daemon, real payload.
static void setup_payload() {
    g_rec = (RecPage*)mmap(nullptr, sizeof(RecPage),
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ZS_CHECK(g_rec != MAP_FAILED);
    memset(g_rec, 0, sizeof *g_rec);
    char addr[32];
    snprintf(addr, sizeof addr, "%llu",
             (unsigned long long)(uintptr_t)g_rec);
    setenv("ZS_TEST_REC", addr, 1);

    g_invoke_table[6] = (void*)&fake_get_env;
    g_invoke_table[7] = (void*)&fake_attach;
    g_fake_env.functions = g_jni_table;

    // Fake denylist + packages.list under /tmp.
    char path[] = "/tmp/zs_test_denylist_XXXXXX";
    int fd = mkstemp(path);
    ZS_CHECK(fd >= 0);
    // Empty denylist: nobody is hidden in the plain tests.
    close(fd);
    g_sock_path = std::string(path) + ".sock";

    char pkg_path[] = "/tmp/zs_test_packages_XXXXXX";
    fd = mkstemp(pkg_path);
    ZS_CHECK(fd >= 0);
    const char* content =
        "com.example.app 10234 0 /data/data/com.example.app seinfo "
        "targetSdk\n"
        "com.other.app 10195 0 /data/data/com.other.app seinfo "
        "targetSdk\n";
    ZS_CHECK(write(fd, content, strlen(content)) > 0);
    close(fd);

    pthread_t th;
    g_main_daemon_cfg.path = g_sock_path;
    g_main_daemon_cfg.max_serve = 16;
    g_main_daemon_cfg.companion_hits = &g_companion_hits;
    ZS_CHECK(pthread_create(&th, nullptr, daemon_thread,
                            &g_main_daemon_cfg) == 0);
    pthread_detach(th);
    // Give the listener a moment to bind (the payload connect is
    // blocking; the socket must exist).
    usleep(100 * 1000);

    g_payload = dlopen("./libpayload.so", RTLD_NOW);
    if (!g_payload) {
        std::fprintf(stderr, "FATAL: dlopen(libpayload.so): %s\n",
                     dlerror());
        std::exit(2);
    }

    fn_init            = (Fn_init)sym("zygisk_study_payload_init");
    fn_set_sock        = (Fn_set_sock)sym("zs_test_set_daemon_socket");
    fn_set_drop_seam   = (Fn_set_drop_seam)sym("zs_test_set_drop_seam");
    fn_drop_seam       = (Fn_drop_seam)sym("zs_test_drop_seam");
    fn_reset_child     = (Fn_reset_child)sym("zs_test_reset_child_state");
    fn_first_fork      = (Fn_first_fork)sym("zs_test_first_fork");
    fn_setresgid       = (Fn_setresgid)sym("zs_test_setresgid");
    fn_setresuid       = (Fn_setresuid)sym("zs_test_setresuid");
    fn_setuid          = (Fn_setuid)sym("zs_test_setuid");
    fn_set_pkg_list    = (Fn_set_pkg_list)sym("hide_test_set_packages_list_path");
    fn_set_denylist    = (Fn_set_denylist)sym("hide_test_set_denylist_path");
    fn_force_deny      = (Fn_force_deny)sym("zs_test_force_deny_uid");
    fn_dispatch_wanted = (Fn_dispatch_wanted)sym("zs_module_dispatch_wanted");
    fn_onload_done     = (Fn_onload_done)sym("zs_module_onload_done");
    fn_set_session_file = (Fn_set_session_file)sym("zs_test_set_session_file");
    fn_load_session     = (Fn_load_session)sym("zs_test_load_session");

    // Point the REAL hide layer at the fake files BEFORE init (init
    // loads the denylist), and the module fetch at the fake daemon.
    fn_set_sock(g_sock_path.c_str());
    fn_set_pkg_list(pkg_path);
    fn_set_denylist(path);

    // Install the drop recorders.
    struct Seam {
        long (*setresgid)(gid_t, gid_t, gid_t);
        long (*setresuid)(uid_t, uid_t, uid_t);
        long (*setgid)(gid_t);
        long (*setuid)(uid_t);
    } seam{};
    seam.setresgid = &rec_setresgid;
    seam.setresuid = &rec_setresuid;
    fn_set_drop_seam(&seam);

    fn_init();
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

ZS_TEST(modules_load_from_daemon_and_dispatch_wanted) {
    setup_payload();
    ZS_CHECK(fn_dispatch_wanted() == 1);  // the module really loaded
    ZS_CHECK(rec_count() == 0);           // ...but nothing ran yet
    ZS_CHECK(fn_onload_done() == 0);
}

ZS_TEST(onload_gets_real_env_and_first_fork_gate) {
    fn_first_fork();                      // zygote's first fork
    ZS_CHECK(fn_onload_done() == 1);
    ZS_CHECK(rec_count() == 1);
    const RecEntry* e = rec(0);
    ZS_CHECK(e->cb == ZS_CB_ONLOAD);

    // The env handed to onLoad is the fake VM's JNIEnv — the REAL
    // acquisition path (dlsym JNI_GetCreatedJavaVMs -> GetEnv)
    // resolved our exported symbol.
    ZS_CHECK(e->env == (uintptr_t)&g_fake_env);

    // hookJniEnv: the module's table swap went through the REAL
    // Api implementation — the fake env's slot now holds the module's
    // table, and the module saw the ORIGINAL table as old.
    ZS_CHECK(e->jni_old_table == (uintptr_t)g_jni_table);
    ZS_CHECK(e->jni_new_table != 0);
    ZS_CHECK((uintptr_t)g_fake_env.functions == e->jni_new_table);
    ZS_CHECK(((void**)(uintptr_t)e->jni_new_table)[5] ==
             (void*)(uintptr_t)0x5A5A5A5A);

    // connectCompanion went through the REAL client path to the fake
    // daemon ('C'). The daemon-side hit is asynchronous (the client
    // returns after send()); give the thread a moment before
    // asserting it saw the verb.
    ZS_CHECK(e->companion_fd >= 0);
    usleep(150 * 1000);
    ZS_CHECK(g_companion_hits >= 1);

    // Second first-fork drive: nothing re-runs (one-shot).
    fn_first_fork();
    ZS_CHECK(rec_count() == 1);
    rec_reset();
}

// Drive one forked child through the REAL gid+uid drop hooks and wait
// for it. Returns the child's exit status.
static int drive_child(long uid, long gid) {
    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        // Child: fresh dispatch state (production children get this
        // from copy-on-write; the test drives multiple cases in one
        // process, so reset explicitly).
        fn_reset_child();
        fn_setresgid(gid);   // gid-drop hook: records the gid
        fn_setresuid(uid);   // uid-drop hook: dispatch + real call
        _exit(0);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    return st;
}

ZS_TEST(app_dispatch_full_lifecycle_with_real_args) {
    int st = drive_child(10234, 10234);
    ZS_CHECK(st == 0);                     // the child survived

    ZS_CHECK(rec_count() == 2);            // pre + post (no re-onLoad)
    const RecEntry* pre  = rec(0);
    const RecEntry* post = rec(1);
    ZS_CHECK(pre->cb == ZS_CB_PRE_APP);
    ZS_CHECK(post->cb == ZS_CB_POST_APP);

    // The REAL zygote arguments:
    ZS_CHECK(pre->uid == 10234);
    ZS_CHECK(pre->gid == 10234);
    ZS_CHECK(strcmp(pre->package_name, "com.example.app") == 0);
    ZS_CHECK(strcmp(pre->app_data_dir,
                    "/data/user/0/com.example.app") == 0);
    // nice_name: the child's cmdline was still the test binary (not
    // the zygote's), so the loader passes it through.
    ZS_CHECK(pre->nice_name[0] != '\0');

    // The env handed to the pre callback is the acquired JNIEnv.
    ZS_CHECK(pre->env == (uintptr_t)&g_fake_env);

    // post sees the SAME args struct with the same final values.
    ZS_CHECK(post->uid == 10234);
    ZS_CHECK(strcmp(post->package_name, "com.example.app") == 0);

    // The real setresuid call actually ran with the runtime's uid.
    ZS_CHECK(g_rec->setresuid_count == 1);
    ZS_CHECK(g_rec->setresuid_calls[0][0] == 10234);
    ZS_CHECK(g_rec->setresuid_calls[0][1] == 10234);
    ZS_CHECK(g_rec->setresuid_calls[0][2] == 10234);

    // setresgid ran once from the gid-drop hook, unmodified.
    ZS_CHECK(g_rec->setresgid_count == 1);
    ZS_CHECK(g_rec->setresgid_calls[0][0] == 10234);
    rec_reset();
}

ZS_TEST(multi_user_app_maps_to_same_package) {
    int st = drive_child(1010234, 1010234);   // user 10
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    const RecEntry* pre = rec(0);
    ZS_CHECK(pre->cb == ZS_CB_PRE_APP);
    ZS_CHECK(strcmp(pre->package_name, "com.example.app") == 0);
    // userId derived from the uid family.
    ZS_CHECK(strcmp(pre->app_data_dir,
                    "/data/user/10/com.example.app") == 0);
    rec_reset();
}

ZS_TEST(module_rewritten_uid_and_gid_forwarded_to_real_calls) {
    setenv("ZS_TEST_MODIFY", "1", 1);
    int st = drive_child(10195, 10195);
    unsetenv("ZS_TEST_MODIFY");
    ZS_CHECK(st == 0);

    ZS_CHECK(rec_count() == 2);
    const RecEntry* pre  = rec(0);
    const RecEntry* post = rec(1);
    // The module SAW the runtime's arguments in pre...
    ZS_CHECK(pre->uid == 10195);
    // ...rewrote them through the args pointers...
    // (post observes the struct with the module's values)
    ZS_CHECK(post->uid == 4242);
    ZS_CHECK(post->gid == 4243);

    // ...and the hooks forwarded the rewritten values to the REAL
    // calls: setresuid(4242,4242,4242) and the gid override
    // setresgid(4243,4243,4243).
    ZS_CHECK(g_rec->setresuid_count == 1);
    ZS_CHECK(g_rec->setresuid_calls[0][0] == 4242);
    ZS_CHECK(g_rec->setresuid_calls[0][1] == 4242);
    ZS_CHECK(g_rec->setresuid_calls[0][2] == 4242);
    ZS_CHECK(g_rec->setresgid_count == 2);
    ZS_CHECK(g_rec->setresgid_calls[0][0] == 10195);  // runtime's own
    ZS_CHECK(g_rec->setresgid_calls[1][0] == 4243);   // module's
    rec_reset();
}

ZS_TEST(system_server_dispatches_server_callbacks) {
    int st = drive_child(1000, 1000);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->cb == ZS_CB_PRE_SERVER);
    ZS_CHECK(rec(1)->cb == ZS_CB_POST_SERVER);
    ZS_CHECK(rec(0)->uid == 1000);
    ZS_CHECK(rec(0)->gid == 1000);
    ZS_CHECK(rec(0)->env == (uintptr_t)&g_fake_env);
    ZS_CHECK(g_rec->setresuid_count == 1);
    ZS_CHECK(g_rec->setresuid_calls[0][0] == 1000);
    rec_reset();
}

ZS_TEST(legacy_setuid_path_dispatches) {
    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_setuid(10234);   // legacy single-arg drop
        _exit(0);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->cb == ZS_CB_PRE_APP);
    ZS_CHECK(rec(1)->cb == ZS_CB_POST_APP);
    rec_reset();
}

ZS_TEST(non_app_uid_dispatches_nothing) {
    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_setresgid(0);
        fn_setresuid(0);   // root: not an app, not system_server
        _exit(0);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 0);
    ZS_CHECK(g_rec->setresuid_count == 1);   // real call still ran
    rec_reset();
}

ZS_TEST(denylisted_child_hides_instead_of_dispatching) {
    // LAST dispatch test on purpose: the forced deny uid is injected
    // into the payload's deny set and inherited by every later child.
    fn_force_deny(10234);
    int st = drive_child(10234, 10234);
    ZS_CHECK(st == 0);                  // hide pipeline survived

    // No module callbacks at all — modules vanish with everything
    // else in hidden processes (the DenyList contract).
    ZS_CHECK(rec_count() == 0);

    // The real calls still ran (the pipeline relays them).
    ZS_CHECK(g_rec->setresgid_count >= 1);
    ZS_CHECK(g_rec->setresuid_count >= 1);
    rec_reset();
}

ZS_TEST(forced_unmount_runs_after_post_callbacks) {
    // The late-setOption deviation: the mount phase was decided
    // before pre, but the spoof/unmap phase must still run AFTER the
    // post callbacks. Observable: hide_advanced_apply_post_fork
    // scrubs the environ array — a known ZYGISK_STUDY_* variable
    // disappears.
    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        setenv("ZYGISK_STUDY_DEBUG", "1", 1);
        setenv("ZS_TEST_FORCE", "1", 1);
        fn_setresgid(10195);
        fn_setresuid(10195);
        // The forced-unmount phase must have scrubbed our env var by
        // now (post callbacks ran first — asserted via the recorder).
        int scrubbed = (getenv("ZYGISK_STUDY_DEBUG") == nullptr);
        unsetenv("ZS_TEST_FORCE");
        _exit(scrubbed ? 0 : 3);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(WEXITSTATUS(st) == 0);

    // Callbacks ran (pre + post) — the unmount did not eat them.
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->cb == ZS_CB_PRE_APP);
    ZS_CHECK(rec(1)->cb == ZS_CB_POST_APP);
    // And the module's identity args were real.
    ZS_CHECK(strcmp(rec(0)->package_name, "com.other.app") == 0);
    rec_reset();
}


// ----------------------------------------------------------------------
// Round 13 — the randomized daemon socket session handoff.
// ----------------------------------------------------------------------
ZS_TEST(session_file_switches_daemon_socket_end_to_end) {
    // 1. A second fake daemon at a "randomized" neutral path (what
    //    the real daemon now creates per boot under /data/system/.<hex>).
    std::string rand_dir = "/tmp/zstest_randdir_XXXXXX";
    char* d = mkdtemp(&rand_dir[0]);
    ZS_CHECK(d != nullptr);
    std::string sock2 = rand_dir + "/s";
    static volatile int session_hits = 0;
    static DaemonCfg cfg2;
    cfg2.path = sock2;
    cfg2.max_serve = 4;
    cfg2.companion_hits = &session_hits;
    pthread_t th2;
    ZS_CHECK(pthread_create(&th2, nullptr, daemon_thread, &cfg2) == 0);
    pthread_detach(th2);
    usleep(100 * 1000);

    // 2. The session file (what the daemon writes before binding).
    char sess[] = "/tmp/zs_test_session_XXXXXX";
    int sfd = mkstemp(sess);
    ZS_CHECK(sfd >= 0);
    std::string line = sock2 + "\n";
    ZS_CHECK(write(sfd, line.c_str(), line.size()) > 0);
    close(sfd);
    fn_set_session_file(sess);

    // 3. The REAL reader: switches the socket and registers the
    //    random dir with the hide filters.
    ZS_CHECK(fn_load_session() == 1);

    // 4. End-to-end: a dispatch child's pre callback calls
    //    connectCompanion — through the NEW path (the old daemon
    //    thread is still up, so a stale path would also hit; the
    //    session_hits counter on the NEW daemon is the discriminator).
    //    (uid 10195: com.other.app — never denied by the earlier
    //    deny test.)
    int st = drive_child(10195, 10195);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->cb == ZS_CB_PRE_APP);
    ZS_CHECK(rec(0)->companion_fd >= 0);
    usleep(100 * 1000);
    ZS_CHECK(session_hits >= 1);

    // 5. Absent session file -> fallback, no registration.
    fn_set_session_file("/tmp/zs_test_session_nonexistent");
    ZS_CHECK(fn_load_session() == 0);
    fn_set_session_file(nullptr);
    unlink(sess);
    rmdir(rand_dir.c_str());
    rec_reset();
}

// // ----------------------------------------------------------------------
// main
// ----------------------------------------------------------------------
int main() {
    std::fprintf(stderr, "test_module_dispatch\n");
    int rc = zstest::run_all();
    if (g_rec) munmap(g_rec, sizeof(RecPage));
    if (!g_sock_path.empty()) unlink(g_sock_path.c_str());
    return rc;
}
