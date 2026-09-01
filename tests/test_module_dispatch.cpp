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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <fcntl.h>
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
    // Round 19: when set, this daemon also answers the 'P' verb by
    // writing the received area to <props_dir>/p and replying
    // "1<props_dir>/p\n" — exactly what the real Rust daemon does.
    std::string props_dir;
};
static std::string g_last_props_content;
// Round 19: directory the fake daemon materializes the props file in.
static std::string g_props_dir;
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
            } else if (verb == 'P' && !cfg->props_dir.empty()) {
                // Round 19: mirror the Rust daemon's 'P' handler —
                // u32-LE length, that many bytes, the AREA-MAGIC check
                // (Round 26: at offset 8 — the real bionic layout is
                // bytes_used@0, serial@4, magic@8, version@12; the
                // old offset-0 check would reject every real image),
                // write to <dir>/p, reply "1<dir>/p\n".
                unsigned char lenb[4];
                if (read(c, lenb, 4) == 4) {
                    uint32_t len = lenb[0] | (lenb[1] << 8) |
                                   (lenb[2] << 16) | (lenb[3] << 24);
                    if (len >= 16 && len < 1024 * 1024) {
                        std::string area(len, '\0');
                        size_t got = 0;
                        while (got < len) {
                            ssize_t n = read(c, &area[got], len - got);
                            if (n <= 0) break;
                            got += (size_t)n;
                        }
                        bool magic_ok = got == len &&
                            area.compare(8, 4, "PROP", 4) == 0;
                        if (got == len && len >= 16) {
                            uint32_t ver = 0;
                            memcpy(&ver, area.data() + 12, 4);
                            if (ver != 0xfc6ed0abu) magic_ok = false;
                        }
                        if (magic_ok) {
                            std::string path = cfg->props_dir + "/p";
                            FILE* fp = fopen(path.c_str(), "wb");
                            if (fp) {
                                fwrite(area.data(), 1, area.size(), fp);
                                fclose(fp);
                                g_last_props_content = area;
                                std::string reply = "1" + path + "\n";
                                (void)write(c, reply.c_str(), reply.size());
                            } else {
                                (void)write(c, "0\n", 2);
                            }
                        } else {
                            (void)write(c, "0\n", 2);
                        }
                    } else {
                        (void)write(c, "0\n", 2);
                    }
                }
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
typedef void  (*Fn_set_session_file_alt)(const char*);
typedef int   (*Fn_load_session)();
typedef void  (*Fn_reset_refresh)();

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
static Fn_set_session_file_alt fn_set_session_file_alt;
static Fn_load_session     fn_load_session;
static Fn_reset_refresh    fn_reset_refresh;

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
    g_main_daemon_cfg.max_serve = 32;
    // Round 19: this daemon answers 'P' with a real file write.
    char pd[] = "/tmp/zs_daemon_props_XXXXXX";
    if (mkdtemp(pd)) {
        g_props_dir = pd;
        g_main_daemon_cfg.props_dir = g_props_dir;
    }
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

    fn_init            = (Fn_init)sym("zs_entry_init");
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
    fn_set_session_file_alt = (Fn_set_session_file_alt)sym("zs_test_set_session_file_alt");
    fn_load_session     = (Fn_load_session)sym("zs_test_load_session");
    fn_reset_refresh    = (Fn_reset_refresh)sym("hide_test_reset_refresh");

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

// Round 28 — the session-file parser must REJECT overlong content
// instead of silently truncating it. Before the fix, a 120-byte
// session file was read as its first 95 bytes: the daemon socket
// became a garbage path (harmless — connects fail — fail-closed)
// BUT the truncated garbage was also REGISTERED as a hide-filter
// prefix and a /proc/net/unix substring, polluting the filters with
// attacker-controlled junk. The parser now returns 0 and registers
// nothing.
ZS_TEST(session_file_rejects_overlong_paths_instead_of_truncating) {
    char sess[] = "/tmp/zs_test_sess_over_XXXXXX";
    int sfd = mkstemp(sess);
    ZS_CHECK(sfd >= 0);
    // 120 bytes, starting with '/' so only the length is invalid.
    std::string long_path = "/" + std::string(119, 'x');
    ZS_CHECK(write(sfd, long_path.c_str(), long_path.size()) > 0);
    close(sfd);
    fn_set_session_file(sess);

    ZS_CHECK(fn_load_session() == 0);

    // The socket must still be the fallback (not the garbage prefix)
    // and no filter prefix may start with the junk stem. The public
    // seam for the active socket: dispatch uses it on the next
    // connect; the most direct observable here is the loader's
    // return value (0 = nothing registered/switched).
    fn_set_session_file(nullptr);
    unlink(sess);
}

// Round 28 — the same parser's whitespace/relative/blank rejections
// on the payload side (mirror of the libzn_loader resolver tests).
ZS_TEST(session_file_rejects_relative_and_blank_content) {
    struct Case { const char* content; };
    Case cases[] = {
        {"relative/path\n"},
        {"   \n\r\n"},
        {"\n"},
        {"noleadingslash"},
    };
    for (const auto& c : cases) {
        char sess[] = "/tmp/zs_test_sess_bad_XXXXXX";
        int sfd = mkstemp(sess);
        ZS_CHECK(sfd >= 0);
        ZS_CHECK(write(sfd, c.content, strlen(c.content)) > 0);
        close(sfd);
        fn_set_session_file(sess);
        ZS_CHECK(fn_load_session() == 0);
        unlink(sess);
    }
    fn_set_session_file(nullptr);
}

//
// ----------------------------------------------------------------------
// Round 29 — the SECOND session record (the /data/system workdir
// copy). ReZygisk issue #380 documents Samsung devices where kernel
// path rules block app_process64 from opening /data/adb/modules
// paths; our loader .so loads from the systemless /system/lib64
// magic mount, but the module-dir session file would be unreadable.
// The daemon now writes the same record into its workdir and the
// payload falls back to it.
// ----------------------------------------------------------------------
ZS_TEST(session_fallback_record_used_when_module_dir_is_unreadable) {
    // A fake daemon at a "randomized" neutral path (as the real
    // daemon creates per boot under /data/system/.<hex>).
    std::string rand_dir = "/tmp/zstest_randdir2_XXXXXX";
    char* d = mkdtemp(&rand_dir[0]);
    ZS_CHECK(d != nullptr);
    std::string sock2 = rand_dir + "/s";
    static volatile int alt_hits = 0;
    static DaemonCfg cfg2;
    cfg2.path = sock2;
    cfg2.max_serve = 4;
    cfg2.companion_hits = &alt_hits;
    pthread_t th2;
    ZS_CHECK(pthread_create(&th2, nullptr, daemon_thread, &cfg2) == 0);
    pthread_detach(th2);
    usleep(100 * 1000);

    // The module-dir record is UNREADABLE (the Samsung block), the
    // workdir record carries the path.
    char alt_sess[] = "/tmp/zs_test_sess_alt_XXXXXX";
    int afd = mkstemp(alt_sess);
    ZS_CHECK(afd >= 0);
    std::string line = sock2 + "\n";
    ZS_CHECK(write(afd, line.c_str(), line.size()) > 0);
    close(afd);
    fn_set_session_file("/tmp/zs_test_session_blocked_by_kernel");
    fn_set_session_file_alt(alt_sess);

    // The fallback record must switch the socket + register filters.
    ZS_CHECK(fn_load_session() == 1);

    // End-to-end: the dispatch child reaches the daemon through the
    // alt record's path (alt_hits is the discriminator).
    int st = drive_child(10195, 10195);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->companion_fd >= 0);
    usleep(100 * 1000);
    ZS_CHECK(alt_hits >= 1);

    // Cleanup + the healthy case pays nothing: with BOTH records
    // readable and equal, the PRIMARY wins (already covered by the
    // Round 13 test); with both missing, load fails closed.
    fn_set_session_file(nullptr);
    fn_set_session_file_alt(nullptr);
    unlink(alt_sess);
    rmdir(rand_dir.c_str());
    rec_reset();
}

// Round 29 — the fallback parser gets the SAME hygiene as the
// primary (the R28 overlong/truncation fix applies to both records:
// garbage in the workdir record must not register filter prefixes).
ZS_TEST(session_fallback_record_rejects_overlong_content) {
    char alt_sess[] = "/tmp/zs_test_sess_alto_XXXXXX";
    int afd = mkstemp(alt_sess);
    ZS_CHECK(afd >= 0);
    std::string long_path = "/" + std::string(119, 'x');
    ZS_CHECK(write(afd, long_path.c_str(), long_path.size()) > 0);
    close(afd);
    fn_set_session_file("/tmp/zs_test_session_blocked_by_kernel");
    fn_set_session_file_alt(alt_sess);

    ZS_CHECK(fn_load_session() == 0);

    fn_set_session_file(nullptr);
    fn_set_session_file_alt(nullptr);
    unlink(alt_sess);
}

// ----------------------------------------------------------------------
// Round 14 — derived-args correctness + deny-decision skip
// (ROUND 34: the args CACHE itself is gone — per-child COW made it
// dead weight on device; see fill_app_args. The test stays: it pins
// the VALUES the modules see and the reload invalidation through the
// packages.map generation, which is the surviving invariant.)
// ----------------------------------------------------------------------
ZS_TEST(derived_args_are_correct_and_reload_invalidates_the_map) {
    // uid 10234 is force-denied by the earlier deny test; use 10195
    // (com.other.app). A repeat fork of the SAME uid must observe the
    // identical values, and a packages.list edit + reload must swap
    // them in the same breath as the map itself.
    int st = drive_child(10195, 10195);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(strcmp(rec(0)->package_name, "com.other.app") == 0);
    ZS_CHECK(strcmp(rec(0)->app_data_dir,
                    "/data/user/0/com.other.app") == 0);

    // Now edit packages.list (rename the package behind uid 10234)
    // and bump its mtime. The reload bumps the generation, which must
    // invalidate the cache IN THE SAME BREATH as the map.
    const char* new_content =
        "com.example.app 10234 0 /data/data/com.example.app seinfo "
        "targetSdk\n"
        "com.renamed.app 10195 0 /data/data/com.renamed.app seinfo "
        "targetSdk\n";
    // rewrite the SAME temp file the setup used (its path is not
    // tracked here — re-point via the packages seam using a fresh
    // file with the SAME path as setup: re-derive it).
    static char pkg_path[128];
    if (pkg_path[0] == '\0') {
        snprintf(pkg_path, sizeof pkg_path, "/tmp/zs_test_pkgr_XXXXXX");
        int fd = mkstemp(pkg_path);
        ZS_CHECK(fd >= 0);
        close(fd);
        fn_set_pkg_list(pkg_path);
    }
    {
        FILE* fp = fopen(pkg_path, "w");
        ZS_CHECK(fp != nullptr);
        fputs(new_content, fp);
        fclose(fp);
        struct timespec times[2];
        times[0].tv_sec = time(nullptr) + 10;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        utimensat(AT_FDCWD, pkg_path, times, 0);
    }
    fn_reset_refresh();

    st = drive_child(10195, 10195);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(strcmp(rec(0)->package_name, "com.renamed.app") == 0);
    ZS_CHECK(strcmp(rec(0)->app_data_dir,
                    "/data/user/0/com.renamed.app") == 0);
    rec_reset();
}

ZS_TEST(deny_decision_skip_still_hides_setuid_only_children) {
    // The gid-drop hook never fired here (setuid-only legacy path),
    // so no decision key exists: the uid hook MUST run its own
    // DenyList check — the Round 14 skip must never become a gap.
    // (The cache test's packages.list switch invalidated the
    // parent-side mtime bookkeeping: a reload in this child would
    // rebuild the deny set from the (empty) denylist file and lose
    // the earlier force-deny. Point the denylist at a file that
    // MAPPING-SAFELY denies uid 10234: com.example.app, which the
    // cache test's packages.list maps to 10234 — any reload now
    // rebuilds the same deny.)
    char deny2[] = "/tmp/zs_test_deny2_XXXXXX";
    {
        int dfd = mkstemp(deny2);
        ZS_CHECK(dfd >= 0);
        const char* dl = "com.example.app\n";
        ZS_CHECK(write(dfd, dl, strlen(dl)) > 0);
        close(dfd);
    }
    fn_set_denylist(deny2);
    fn_force_deny(10234);
    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_setuid(10234);   // denied uid, no prior gid decision
        _exit(0);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    std::fprintf(stderr, "setuid-deny child status = 0x%x (sig %d, exit %d)\n",
                 st, WIFSIGNALED(st) ? WTERMSIG(st) : 0,
                 WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    ZS_CHECK(st == 0);
    ZS_CHECK(rec_count() == 0);   // hidden, not dispatched
    rec_reset();
}


// ----------------------------------------------------------------------
// Round 19 — the 'P' protocol end to end against the fake daemon,
// plus the lazy boot-order retry (daemon down at init, up later).
// ----------------------------------------------------------------------

// 1. 'P' round trip: area bytes with spoofed values are written by
// the daemon to <dir>/p; the payload registers the replied path.
ZS_TEST(props_file_protocol_round_trips_to_daemon) {
    static int (*fn_send)(const char*, size_t) =
        (int (*)(const char*, size_t))sym("zs_test_send_props_file");
    static int (*fn_ready)() = (int (*)())sym("zs_test_props_ready_c");
    static void (*fn_set_sock)(const char*) =
        (void (*)(const char*))sym("zs_test_set_daemon_socket");
    // The session-file test (registered earlier) leaves the payload
    // pointed at the SECOND fake daemon, which does not serve 'P'.
    // Point back at the main daemon — the one with props_dir set.
    fn_set_sock(g_sock_path.c_str());

    // Build a fake spoofed area in the REAL bionic file format
    // (Round 26: the old fixture put "PROP" at offset 0 — a fantasy
    // layout that only ever agreed with the daemon's equally-wrong
    // offset-0 check; a real image has bytes_used@0, serial@4,
    // magic@8, version@12, then the trie data).
    std::string area;
    {
        uint32_t bytes_used = 112;   // root(20) + first entry
        uint32_t serial     = 7;
        uint32_t magic      = 0x504f5250u;
        uint32_t version    = 0xfc6ed0abu;
        area.append((const char*)&bytes_used, 4);
        area.append((const char*)&serial, 4);
        area.append((const char*)&magic, 4);
        area.append((const char*)&version, 4);
        area += "ro.boot.verifiedbootstate=green;";
        area += "ro.magisk.version=;";
    }

    g_last_props_content.clear();
    int rc = fn_send(area.data(), area.size());
    ZS_CHECK_EQ(rc, 1);
    ZS_CHECK_EQ(fn_ready(), 1);
    // The daemon wrote exactly our bytes.
    ZS_CHECK_EQ(g_last_props_content.size(), area.size());
    ZS_CHECK(g_last_props_content == area);
    // The file exists on disk with the same content.
    FILE* fp = fopen((g_props_dir + "/p").c_str(), "rb");
    ZS_CHECK(fp != nullptr);
    if (fp) {
        std::string disk((size_t)0, '\0');
        char buf[512];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, fp)) > 0)
            disk.append(buf, n);
        fclose(fp);
        ZS_CHECK(disk == area);
    }
}

// 2. Retry semantics: with the daemon UNREACHABLE the send returns 0
// (retry later) — never latches a failure as final.
ZS_TEST(props_file_send_retries_when_daemon_is_down) {
    static int (*fn_send)(const char*, size_t) =
        (int (*)(const char*, size_t))sym("zs_test_send_props_file");

    // Point at a socket nothing is listening on.
    static void (*fn_set_sock)(const char*) =
        (void (*)(const char*))sym("zs_test_set_daemon_socket");
    const char* old = g_sock_path.c_str();
    std::string saved = old;
    fn_set_sock("/tmp/zs_no_such_daemon_socket");
    // A real-format area (>= 16 bytes — smaller buffers are now
    // "final" on the payload side, not a retry, mirroring the
    // daemon's header floor).
    std::string area(64, 'x');
    uint32_t magic = 0x504f5250u, version = 0xfc6ed0abu;
    area.resize(16);
    memcpy(&area[8], &magic, 4);
    memcpy(&area[12], &version, 4);
    area.resize(64, 'x');
    ZS_CHECK_EQ(fn_send(area.data(), area.size()), 0);
    // Restore.
    fn_set_sock(saved.c_str());
}

// 3. The lazy boot order: init with the daemon DOWN fails and stays
// unlatched; a later retry with the daemon UP latches everything.
ZS_TEST(lazy_daemon_init_latches_only_after_daemon_answers) {
    static void (*fn_reset_lazy)() = (void (*)())sym("zs_test_reset_lazy_init");
    static int (*fn_lazy)() = (int (*)())sym("zs_module_lazy_daemon_init_c");
    static void (*fn_set_sock)(const char*) =
        (void (*)(const char*))sym("zs_test_set_daemon_socket");

    std::string saved = g_sock_path;
    fn_reset_lazy();
    // Daemon down: both steps fail, nothing latches.
    fn_set_sock("/tmp/zs_no_such_daemon_socket_2");
    ZS_CHECK_EQ(fn_lazy(), 0);
    ZS_CHECK_EQ(fn_lazy(), 0);   // still retrying, still cheap

    // Daemon up: everything latches in ONE attempt (module list
    // answers; the props builder is unavailable on host, which is a
    // FINAL answer, not a retry).
    fn_set_sock(saved.c_str());
    ZS_CHECK_EQ(fn_lazy(), 1);
}

// ----------------------------------------------------------------------
// Round 25 — the self-pin. On every Android version studied (7.0
// through 13), each same-arch zygote child calls
// InitNonZygoteOrPostFork(kUnload), which dlclose()s the bridge
// handle ART holds; the linker's unload chain then unrefs everything
// the bridge dlopen'd — including libpayload, whose code every GOT
// slot in the process points into. The payload's init self-pins
// (dlopen(self, RTLD_NOLOAD)), so ONE dlclose of the caller's handle
// leaves it mapped. Simulated here exactly: close OUR handle (the
// role ART's UnloadNativeBridge plays) and prove the code is still
// alive by calling through a cached pointer.
//
// ----------------------------------------------------------------------
// Round 26 — the property-file path selection: a 6.x platform maps
// ONE regular file (/dev/__properties__); 7.0+ map properties_serial
// inside the directory. The lazy-init must hand the image builder
// the platform's own path, and the stat-based detection must tell a
// regular file from a directory.
// ----------------------------------------------------------------------
// ROUND 36 — the isolated-process deferral + the FORCE mount fix.
//
// Production order (AOSP SpecializeCommon, verified at 5.0.0_r1 /
// 10.0.0_r1 / 12.0.0_r1 / 16.0.0_r1 / main):
//     setresgid -> setresuid -> ... -> selinux_android_setcontext
// The uid-drop hook fires FIRST; the nice_name only exists at the
// setcontext call. These tests drive BOTH hooks in the production
// order through the real impls — the missing coverage that let the
// Round 35 WIP ship a coverage hook its own guard made unreachable.
// ----------------------------------------------------------------------

typedef void (*Fn_set_force_unmount)(int);
typedef void (*Fn_setcontext_live)(int);
typedef int  (*Fn_setcontext_is_live)(void);
// Local twins of hide.h's Zs*Fn recorder types (the dispatch test
// deliberately does not include the payload's private headers).
typedef int  (*R36UnshareFn)(int);
typedef int  (*R36MountSlaveFn)(void);
typedef int  (*R36Umount2Fn)(const char*, int);
typedef void (*Fn_set_mount_fns_c)(R36UnshareFn, R36MountSlaveFn,
                                   R36Umount2Fn);
typedef void (*Fn_mount_log_reset_c)(void);
typedef const char* (*Fn_mount_log_c)(void);
typedef void (*Fn_mount_log_append_c)(char);
typedef void (*Fn_install_setcontext)(long (*)(long, long,
                                               const char*,
                                               const char*));
typedef long (*Fn_setcontext)(long, long, const char*, const char*);
typedef void (*Fn_force_deny_name)(const char*);

static Fn_set_force_unmount   fn_set_force_unmount;
static Fn_setcontext_live     fn_setcontext_live;
static Fn_setcontext_is_live  fn_setcontext_is_live;
static Fn_set_mount_fns_c     fn_set_mount_fns_c;
static Fn_mount_log_reset_c   fn_mount_log_reset_c;
static Fn_mount_log_c         fn_mount_log_c;
static Fn_mount_log_append_c  fn_mount_log_append_c;
static Fn_install_setcontext  fn_install_setcontext;
static Fn_setcontext          fn_setcontext;
static Fn_force_deny_name     fn_force_deny_name;

static void r36_syms() {
    static bool done = false;
    if (done) return;
    done = true;
    fn_set_force_unmount  = (Fn_set_force_unmount)sym("zs_test_set_force_unmount");
    fn_setcontext_live    = (Fn_setcontext_live)sym("zs_test_setcontext_live");
    fn_setcontext_is_live = (Fn_setcontext_is_live)sym("zs_test_setcontext_is_live");
    fn_set_mount_fns_c    = (Fn_set_mount_fns_c)sym("zs_test_set_mount_fns_c");
    fn_mount_log_reset_c  = (Fn_mount_log_reset_c)sym("zs_test_mount_log_reset_c");
    fn_mount_log_c        = (Fn_mount_log_c)sym("zs_test_mount_log_c");
    fn_mount_log_append_c =
        (Fn_mount_log_append_c)sym("zs_test_mount_log_append_c");
    fn_install_setcontext = (Fn_install_setcontext)sym("zs_test_install_setcontext");
    fn_setcontext         = (Fn_setcontext)sym("zs_test_setcontext");
    fn_force_deny_name    = (Fn_force_deny_name)sym("zs_test_force_deny_name");
}

// A fake "real" setcontext: records its args in the shared rec page's
// spare fields and returns a distinctive rv the test can verify was
// relayed (the trampoline contract: the runtime sees the real call's
// return value).
static long r36_fake_setcontext(long uid, long is_sys, const char* se,
                                const char* name) {
    (void)is_sys; (void)se;
    g_rec->entries[0].uid = (int)uid;   // RecEntry.uid doubles as the
    g_rec->entries[0].gid = 0;          // recorder slot here (count
                                        // stays 0: no module cb)
    snprintf(g_rec->entries[0].nice_name,
             sizeof g_rec->entries[0].nice_name, "%s",
             name ? name : "");
    return 4242;
}

// Bug A: with the setcontext hook live, an isolated uid must NOT
// dispatch at uid-drop time; the dispatch happens at setcontext with
// the real name in the args — the exact production order.
ZS_TEST(isolated_uid_defers_dispatch_to_setcontext) {
    r36_syms();
    fn_install_setcontext(r36_fake_setcontext);
    ZS_CHECK(fn_setcontext_is_live() == 1);

    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        // Production order: gid hook, uid hook (isolated uid —
        // NOTHING must dispatch here), then setcontext with the name.
        fn_setresgid(99123);
        fn_setresuid(99123);
        int dispatched_early = (rec_count() > 0);   // pre/post fired?
        // THE Round 36 regression: pre-R36 the module's pre+post ran
        // HERE (isolated children of denylisted apps got modules).
        _exit(dispatched_early ? 3 : 0);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(WEXITSTATUS(st) == 0);

    // Now the setcontext half — same child shape, name first.
    rec_reset();
    fflush(nullptr);
    pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_setresgid(99123);
        fn_setresuid(99123);       // deferred: nothing dispatched
        long rv = fn_setcontext(99123, 0, nullptr, "com.other.app:svc");
        // The deferred dispatch ran at setcontext (pre + post), and
        // the fake real's rv was relayed through the impl.
        _exit((rec_count() == 2 && rv == 4242) ? 0 : 4);
    }
    st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(WEXITSTATUS(st) == 0);
    // Parent-side view: the child's RecPage writes are shared.
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->cb == ZS_CB_PRE_APP);
    ZS_CHECK(rec(1)->cb == ZS_CB_POST_APP);
    // The module saw the FULL isolated name (Round 36: the
    // nice_name_override — the uid map alone had nothing for 99123,
    // and /proc/self/cmdline still held the test binary's name).
    ZS_CHECK(strcmp(rec(0)->nice_name, "com.other.app:svc") == 0);
    // The fake real setcontext ran FIRST (recorded uid in the args
    // the module then saw).
    ZS_CHECK(rec(0)->uid == 99123);
    rec_reset();
    fn_install_setcontext(nullptr);
    fn_setcontext_live(0);   // leave clean for later tests
}

// Bug A (the coverage): a denylisted owner's isolated child HIDES at
// setcontext — no module callbacks ever run in it, and the fake
// real's rv is relayed.
ZS_TEST(isolated_uid_setcontext_hides_denylisted_owner) {
    r36_syms();
    fn_install_setcontext(r36_fake_setcontext);
    ZS_CHECK(fn_setcontext_is_live() == 1);

    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_force_deny_name("com.deny.app");
        fn_setresgid(99555);
        fn_setresuid(99555);       // deferred (isolated)
        long rv = fn_setcontext(99555, 0, nullptr,
                                "com.deny.app:com.deny.Svc");
        // Modules never ran in this child (the hide contract), and
        // the real call's rv was relayed through the Tier B path.
        _exit((rec_count() == 0 && rv == 4242) ? 0 : 5);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(WEXITSTATUS(st) == 0);
    ZS_CHECK(rec_count() == 0);   // no module callbacks anywhere
    rec_reset();
    fn_install_setcontext(nullptr);
    fn_setcontext_live(0);
}

// The degradation guard: with the setcontext hook NOT live (a vendor
// build without the symbol), isolated children keep the pre-R36
// uid-drop dispatch — modules keep working.
ZS_TEST(isolated_uid_without_hook_dispatches_at_uid_time) {
    r36_syms();
    ZS_CHECK(fn_setcontext_is_live() == 0);   // cleaned by prior tests

    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_setresgid(99123);
        fn_setresuid(99123);   // NO setcontext hook: dispatch NOW
        _exit(rec_count() == 2 ? 0 : 6);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(WEXITSTATUS(st) == 0);
    ZS_CHECK(rec_count() == 2);
    ZS_CHECK(rec(0)->cb == ZS_CB_PRE_APP);
    ZS_CHECK(rec(1)->cb == ZS_CB_POST_APP);
    rec_reset();
}

// Bug B: the EARLY FORCE mount phase actually unshares/unmounts.
// Pre-R36 the log below stayed EMPTY for a non-denylisted FORCE
// child (the g_will_hide gate no-op'd the whole path) — this is the
// assertion shape that would have caught the dead gate in Round 12.
static int r36_rec_unshare(int) { fn_mount_log_append_c('u'); return 0; }
static int r36_rec_slave(void) { fn_mount_log_append_c('s'); return 0; }
static int r36_rec_umount(const char*, int) {
    fn_mount_log_append_c('m');
    return 0;
}

ZS_TEST(force_unmount_mount_phase_actually_unmounts) {
    r36_syms();
    // Arm FORCE the way onLoad does in the zygote (children inherit).
    fn_set_force_unmount(1);
    // Mount recorders through the extern-C seams (the dispatch test
    // cannot reach the C++-namespace recorders test_hide uses).
    fn_set_mount_fns_c(r36_rec_unshare, r36_rec_slave, r36_rec_umount);

    rec_reset();
    fflush(nullptr);
    pid_t pid = fork();
    ZS_CHECK(pid >= 0);
    if (pid == 0) {
        fn_reset_child();
        fn_mount_log_reset_c();
        // Non-denylisted app uid: the dispatch path (not the hide
        // path) — the FORCE arm's exact production shape.
        fn_setresgid(10195);
        fn_setresuid(10195);
        const char* log = fn_mount_log_c();
        // The namespace dance ran: unshare + slave + (any) umounts.
        int has_u = strchr(log, 'u') != nullptr;
        int has_s = strchr(log, 's') != nullptr;
        _exit((has_u && has_s) ? 0 : 7);
    }
    int st = 0;
    ZS_CHECK(waitpid(pid, &st, 0) == pid);
    ZS_CHECK(WEXITSTATUS(st) == 0);
    // The module callbacks still ran (FORCE unmounts, it does not
    // suppress dispatch).
    ZS_CHECK(rec_count() == 2);
    rec_reset();

    // Restore: prod mount fns + FORCE off for later tests.
    fn_set_mount_fns_c(nullptr, nullptr, nullptr);
    fn_set_force_unmount(0);
}

// ----------------------------------------------------------------------
ZS_TEST(props_file_mode_detection_uses_the_stat_form) {
    static int (*fn_detect)(const char*) =
        (int (*)(const char*))sym("zs_test_prop_file_mode_detected");

    // A regular file = the 6.x single-file form (0).
    char file[] = "/tmp/zs_mode_probe_file_XXXXXX";
    int fd = mkstemp(file);
    ZS_CHECK(fd >= 0);
    close(fd);
    ZS_CHECK_EQ(fn_detect(file), 0);

    // A directory = the 7.0+ form (1).
    char dir[] = "/tmp/zs_mode_probe_dir_XXXXXX";
    ZS_CHECK(mkdtemp(dir) != nullptr);
    ZS_CHECK_EQ(fn_detect(dir), 1);

    // Missing / null default to the modern form.
    ZS_CHECK_EQ(fn_detect("/nonexistent/zs/mode_probe"), 1);
    ZS_CHECK_EQ(fn_detect(nullptr), 1);

    unlink(file);
    rmdir(dir);
}

ZS_TEST(lazy_init_builds_the_platform_property_file_path) {
    static void (*fn_set_mode)(int) =
        (void (*)(int))sym("zs_test_set_prop_file_mode");
    static const char* (*fn_last_path)() =
        (const char* (*)())sym("zs_test_last_props_build_path");
    static void (*fn_reset_lazy)() =
        (void (*)())sym("zs_test_reset_lazy_init");
    static int (*fn_lazy)() =
        (int (*)())sym("zs_module_lazy_daemon_init_c");
    static void (*fn_set_sock)(const char*) =
        (void (*)(const char*))sym("zs_test_set_daemon_socket");

    // Keep the daemon out of the way: the build attempt happens
    // before any send, so the recorded path is set either way.
    std::string saved = g_sock_path;
    fn_set_sock("/tmp/zs_no_such_daemon_socket");

    // The 6.x single-file form.
    fn_set_mode(0);
    fn_reset_lazy();
    (void)fn_lazy();
    ZS_CHECK(strcmp(fn_last_path(), "/dev/__properties__") == 0);

    // The 7.0+ directory form.
    fn_set_mode(1);
    fn_reset_lazy();
    (void)fn_lazy();
    ZS_CHECK(strcmp(fn_last_path(),
                    "/dev/__properties__/properties_serial") == 0);

    // Restore: auto-detect (stat /dev/__properties__), and the
    // original latches/socket.
    fn_set_mode(-1);
    fn_reset_lazy();
    fn_set_sock(saved.c_str());
}

// Runs LAST (registration order): it closes the test's own handle on
// purpose; everything after would only use cached pointers — which is
// precisely the contract being verified.
// ----------------------------------------------------------------------
ZS_TEST(self_pin_survives_the_child_side_bridge_dlclose) {
    ZS_CHECK(g_payload != nullptr);
    // The role of ART's UnloadNativeBridge: drop the loader's
    // reference. Pre-Round-25 this was the refcount hitting zero.
    dlclose(g_payload);
    g_payload = nullptr;   // never dlsym through it again
    // The GOT-slot contract: a cached code pointer must still work.
    // (If the library had been unmapped this is a SEGV, not a check
    // failure — the test binary crashing is the regression signal.)
    int w = fn_dispatch_wanted();
    ZS_CHECK(w == 0 || w == 1);
    // And a second entry point through another cached pointer.
    int od = fn_onload_done();
    ZS_CHECK(od == 0 || od == 1);
}

// ----------------------------------------------------------------------
// main
// ----------------------------------------------------------------------
int main() {
    std::fprintf(stderr, "test_module_dispatch\n");
    int rc = zstest::run_all();
    if (g_rec) munmap(g_rec, sizeof(RecPage));
    if (!g_sock_path.empty()) unlink(g_sock_path.c_str());
    if (!g_props_dir.empty()) {
        unlink((g_props_dir + "/p").c_str());
        rmdir(g_props_dir.c_str());
    }
    return rc;
}
