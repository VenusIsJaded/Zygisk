// libzygisk.so — from-scratch reimplementation
//
// Purpose
// -------
// libzygisk.so is the in-zygote companion library. It is dlopen'd
// inside the Android Zygote process via android_dlopen_ext by the
// zygiskd root daemon (which uses ptrace to inject the call). It
// exports exactly one symbol:
//
//     void zygisk_entry(int fd);
//
// After zygisk_entry returns, libzygisk stays resident inside
// zygote for the lifetime of the process. It owns:
//   * the bridge socket connected to zygiskd
//   * the Zygisk API table that modules call into
//   * the dispatch of pre/post-fork + specialize callbacks to
//     libzn_loader (which loads per-module .so companions)
//
// Public API surface (from the original binary's symbol table,
// verified by `readelf -sW libzygisk.so`):
//   zygisk_entry      FUNC  GLOBAL DEFAULT (size ~3252 bytes on arm64)
//
// Internal sub-symbols are hidden (-fvisibility=hidden), only
// zygisk_entry is exported (see zygisk.map).
//
// The Zygisk API table layout
// ---------------------------
// Zygisk is a stable, publicly-documented API. Magisk ships the
// official header (`native/include/zygisk/zygisk.h`); this code
// implements the same callback table so existing Zygisk modules
// can be loaded unmodified. The table has the following slots:
//
//   struct ZygiskAPI {
//     void* module;                              // opaque
//     void (*setOption)(void*, Option);          // toggle option flags
//     void* (*getModuleDir)();                   // get /data/adb/modules/<id>/
//     int  (*connectCompanion)(void*);           // get an fd to talk to zygiskd
//     void (*setModuleDescriptor)(void*, const ModuleDescriptor&);
//     void (*preAppSpecialize)(void*, const AppSpecializeArgs*);
//     void (*postAppSpecialize)(void*, const AppSpecializeArgs*);
//     void (*preServerSpecialize)(void*, const ServerSpecializeArgs*);
//     void (*postServerSpecialize)(void*, const ServerSpecializeArgs*);
//     int  (*getFlags)();                        // runtime flags
//     int  (*getFlagsExt)(const char*);
//     void* (*getModuleInfo)();                 // get module self info
//   };
//
// Pre/post-fork callbacks for generic specialize are routed
// through preSpecialize/postSpecialize in newer API revisions.
//
// IPC protocol with zygiskd (my design)
// -------------------------------------
// Each message on the bridge fd is:
//   [opcode:4 LE][len:4 LE][body:len]
// Reply:
//   [opcode:4 LE][status:4 LE][len:4 LE][body:len]
// Where opcode is one of the Msg* enum values below.

// ==================================================================
//  Bridge protocol to zygiskd
// ==================================================================
#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==================================================================
//  Zygisk API structures (mirroring zygisk.h, simplified)
// ==================================================================

enum Option : uint32_t {
    FORCE_DENYLIST_UNMOUNT = 0,
    DLCLOSE_MODULE_LIBRARY = 1,
};

struct ModuleDescriptor {
    uint32_t api_version;
    const char *name;
    const char *support_dir;
};

struct AppSpecializeArgs_v5 {
    int32_t  uid;
    int32_t  gid;
    int32_t  runtime_flags;
    int32_t  mount_external;
    const char *nice_name;
    const char *instruction_set;
    int32_t  app_data_dir;
    // v5-specific fields elided for brevity
};

struct ServerSpecializeArgs_v1 {
    void *placeholder;
};

// API function pointer types (so we can build the table)
typedef void  (*setOption_t)         (void *, Option);
typedef void* (*getModuleDir_t)      ();
typedef int   (*connectCompanion_t)  (void *);
typedef void  (*setModuleDescriptor_t)(void*, const ModuleDescriptor*);
typedef void  (*preAppSpecialize_t)  (void*, const AppSpecializeArgs_v5*);
typedef void  (*postAppSpecialize_t) (void*, const AppSpecializeArgs_v5*);
typedef void  (*preServerSpecialize_t)(void*, const ServerSpecializeArgs_v1*);
typedef void  (*postServerSpecialize_t)(void*, const ServerSpecializeArgs_v1*);
typedef int   (*getFlags_t)          ();
typedef int   (*getFlagsExt_t)       (const char*);
typedef void* (*getModuleInfo_t)     ();

// The Zygisk API table.
struct ZygiskAPI {
    setOption_t          setOption;
    getModuleDir_t       getModuleDir;
    connectCompanion_t   connectCompanion;
    setModuleDescriptor_t setModuleDescriptor;
    preAppSpecialize_t   preAppSpecialize;
    postAppSpecialize_t  postAppSpecialize;
    preServerSpecialize_t preServerSpecialize;
    postServerSpecialize_t postServerSpecialize;
    getFlags_t           getFlags;
    getFlagsExt_t        getFlagsExt;
    getModuleInfo_t      getModuleInfo;
};

// ==================================================================
//  Bridge protocol to zygiskd
// ==================================================================
enum MsgOp : uint32_t {
    MSG_PING                = 0,   // alive check
    MSG_REGISTER_MODULE     = 1,   // child process -> daemon: tell it
                                   // we're forked from zygote, send pid
    MSG_GET_MODULE_LIST     = 2,   // request list of enabled modules
    MSG_CONNECT_COMPANION   = 3,   // get a per-module socketpair fd
    MSG_LOG                 = 4,   // pipe a log line to klog
    MSG_REQUEST_REWRITE     = 5,   // ask daemon about an execve
    MSG_SPECIALIZE_DONE     = 6,   // notify after specialize
    MSG_GET_FLAGS           = 7,   // get runtime flags
};

struct BridgeMsg {
    uint32_t op;
    uint32_t len;
    uint8_t  body[];
} __attribute__((packed));

// ==================================================================
//  Globals (single-process, single-thread within zygote)
// ==================================================================
static int       g_bridge_fd = -1;
static void     *g_libzn_loader = NULL;
static void     *g_libpayload = NULL;
static void     *(*g_zn_entry)(int fd, const ZygiskAPI *api) = NULL;

// ==================================================================
//  Bridge helpers
// ==================================================================
static int bridge_send(int fd, uint32_t op,
                       const void *body, uint32_t len) {
    uint8_t hdr[8];
    hdr[0] = (uint8_t)(op & 0xff);
    hdr[1] = (uint8_t)((op >> 8) & 0xff);
    hdr[2] = (uint8_t)((op >> 16) & 0xff);
    hdr[3] = (uint8_t)((op >> 24) & 0xff);
    hdr[4] = (uint8_t)(len & 0xff);
    hdr[5] = (uint8_t)((len >> 8) & 0xff);
    hdr[6] = (uint8_t)((len >> 16) & 0xff);
    hdr[7] = (uint8_t)((len >> 24) & 0xff);
    struct iovec iov[2] = {
        { .iov_base = hdr,    .iov_len = sizeof(hdr) },
        { .iov_base = (void*)body, .iov_len = len },
    };
    return writev(fd, iov, len ? 2 : 1) >= 0 ? 0 : -1;
}

static int bridge_recv(int fd, uint32_t *op_out, uint32_t *status_out,
                       void **body_out, uint32_t *len_out) {
    *body_out = NULL;
    *len_out = 0;
    uint8_t hdr[12];
    ssize_t n = recv(fd, hdr, sizeof(hdr), MSG_WAITALL);
    if (n != (ssize_t)sizeof(hdr)) return -1;
    uint32_t op = (uint32_t)hdr[0]
                | ((uint32_t)hdr[1] << 8)
                | ((uint32_t)hdr[2] << 16)
                | ((uint32_t)hdr[3] << 24);
    uint32_t status = (uint32_t)hdr[4]
                    | ((uint32_t)hdr[5] << 8)
                    | ((uint32_t)hdr[6] << 16)
                    | ((uint32_t)hdr[7] << 24);
    uint32_t len = (uint32_t)hdr[8]
                 | ((uint32_t)hdr[9] << 8)
                 | ((uint32_t)hdr[10] << 16)
                 | ((uint32_t)hdr[11] << 24);
    if (len > 1u << 24) return -1;
    void *body = NULL;
    if (len) {
        body = malloc(len);
        if (!body) return -1;
        if (recv(fd, body, len, MSG_WAITALL) != (ssize_t)len) {
            free(body);
            return -1;
        }
    }
    *op_out = op;
    *status_out = status;
    *body_out = body;
    *len_out = len;
    return 0;
}

// ==================================================================
//  Zygisk API callback implementations
//
//  These are the functions whose pointers go into the ZygiskAPI
//  table that we hand to libzn_loader. libzn_loader then passes
//  this table to each module's companion .so at module-init time.
//  Each module holds a copy of the table and calls these functions
//  back during pre/post-fork.
// ==================================================================

// Runtime option flags set by modules. The most important is
// FORCE_DENYLIST_UNMOUNT — modules set it via setOption() to ask
// zygiskd to unmount Magisk denylist entries in the new process.
static uint32_t g_runtime_flags = 0;

static void cb_setOption(void *module, Option opt) {
    (void)module;
    switch (opt) {
    case FORCE_DENYLIST_UNMOUNT:
        g_runtime_flags |= 0x01;
        break;
    case DLCLOSE_MODULE_LIBRARY:
        // Module wants us to dlclose it after init. We defer until
        // the next fork completes (the dlopen handle is stored in
        // libzn_loader's state).
        g_runtime_flags |= 0x02;
        break;
    }
}

// Each module's support directory lives under
// /data/adb/modules/<id>/zygisk/. We don't know <id> for the
// calling module from here (libzygisk is module-agnostic), so
// ask zygiskd.
static void* cb_getModuleDir() {
    // Request from daemon — returns a UTF-8 path string.
    if (bridge_send(g_bridge_fd, MSG_GET_MODULE_LIST, NULL, 0) < 0)
        return NULL;
    uint32_t op, status;
    void *body;
    uint32_t len;
    if (bridge_recv(g_bridge_fd, &op, &status, &body, &len) < 0)
        return NULL;
    // The returned string is a malloc'd path; modules that need it
    // typically keep a copy.
    if (!body) {
        // Empty response — return NULL.
        return NULL;
    }
    return body;
}

// Connect a per-module companion fd. The daemon will create a
// fresh socketpair, return one end to us, and keep the other end
// for talking to the module's companion process (a fork of zygiskd
// that runs as the module's uid/gid).
static int cb_connectCompanion(void *module) {
    (void)module;
    if (bridge_send(g_bridge_fd, MSG_CONNECT_COMPANION, NULL, 0) < 0)
        return -1;
    uint32_t op, status;
    void *body;
    uint32_t len;
    if (bridge_recv(g_bridge_fd, &op, &status, &body, &len) < 0)
        return -1;
    if (len < 4) { free(body); return -1; }
    // We use SCM_RIGHTS for fd passing over the bridge socket.
    // The body is unused in this minimal protocol — we expect the
    // fd to arrive via a separate recvmsg with SCM_RIGHTS control.
    free(body);
    // Read the ancillary fd.
    struct msghdr msg = {};
    struct iovec iov;
    char dummy;
    iov.iov_base = &dummy;
    iov.iov_len  = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    char cbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    if (recvmsg(g_bridge_fd, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET
              || cmsg->cmsg_type  != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

static void cb_setModuleDescriptor(void *module,
                                   const ModuleDescriptor *desc) {
    (void)module;
    (void)desc;
    // Modules use this to introspect their own metadata. We could
    // store it on the module's behalf, but typically modules cache
    // it locally and the daemon is the source of truth.
}

static void cb_preAppSpecialize(void *module,
                                const AppSpecializeArgs_v5 *args) {
    (void)module;
    (void)args;
    // In a real implementation, this would:
    //   1. Send the to-be-forked process's uid/gid/package-name
    //      to zygiskd.
    //   2. Receive denylist decision and apply mounts/unmounts.
    // For now, libzn_loader handles the orchestration; this stub
    // is here so modules that call it directly don't crash.
}

static void cb_postAppSpecialize(void *module,
                                 const AppSpecializeArgs_v5 *args) {
    (void)module;
    (void)args;
    // No-op post-fork hook in this minimal implementation.
}

static void cb_preServerSpecialize(void *module,
                                   const ServerSpecializeArgs_v1 *args) {
    (void)module;
    (void)args;
}

static void cb_postServerSpecialize(void *module,
                                    const ServerSpecializeArgs_v1 *args) {
    (void)module;
    (void)args;
}

static int cb_getFlags() {
    return (int)g_runtime_flags;
}

static int cb_getFlagsExt(const char *key) {
    (void)key;
    return 0;
}

static void* cb_getModuleInfo() {
    // Reserved for future Zygisk API revisions; return NULL.
    return NULL;
}

// ==================================================================
//  Build the API table.
// ==================================================================
static const ZygiskAPI k_api = {
    .setOption              = cb_setOption,
    .getModuleDir           = cb_getModuleDir,
    .connectCompanion       = cb_connectCompanion,
    .setModuleDescriptor    = cb_setModuleDescriptor,
    .preAppSpecialize       = cb_preAppSpecialize,
    .postAppSpecialize      = cb_postAppSpecialize,
    .preServerSpecialize    = cb_preServerSpecialize,
    .postServerSpecialize   = cb_postServerSpecialize,
    .getFlags               = cb_getFlags,
    .getFlagsExt            = cb_getFlagsExt,
    .getModuleInfo          = cb_getModuleInfo,
};

// ==================================================================
//  Load sibling libraries
//
//  libzygisk.so is always installed alongside libzn_loader.so and
//  libpayload.so under /data/adb/modules/zygisksu/lib/<arch>/.
//  We dlopen them lazily so that this .so is self-contained.
// ==================================================================
static int load_siblings(const char *dir) {
    char path[PATH_MAX];

    // libzn_loader.so
    snprintf(path, sizeof(path), "%s/libzn_loader.so", dir);
    g_libzn_loader = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!g_libzn_loader) {
        return -1;
    }
    g_zn_entry = (void*(*)(int, const ZygiskAPI*))
                  dlsym(g_libzn_loader, "zn_entry");
    if (!g_zn_entry) {
        dlclose(g_libzn_loader);
        g_libzn_loader = NULL;
        return -1;
    }

    // libpayload.so (optional — only loaded on demand)
    snprintf(path, sizeof(path), "%s/libpayload.so", dir);
    g_libpayload = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    // Failure here is non-fatal: libpayload is only needed for
    // processes that get exec trampolines installed.

    return 0;
}

// Locate our own install dir by reading /proc/self/maps.
//
// libzygisk.so is mapped from /data/adb/modules/zygisksu/lib*/libzygisk.so.
// Walk /proc/self/maps, find that line, extract the dir.
static int find_self_dir(char *out, size_t out_sz) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return -1;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "libzygisk.so");
        if (!p) continue;
        // line looks like:
        //   7f00100000-7f00200000 r-xp 00000000 fe:00 1234 /data/adb/modules/zygisksu/lib64/libzygisk.so
        char *path = strchr(line, '/');
        if (!path) continue;
        char *end = strstr(path, "libzygisk.so");
        if (!end) continue;
        size_t dir_len = (size_t)(end - path);
        if (dir_len >= out_sz) continue;
        memcpy(out, path, dir_len);
        out[dir_len] = '\0';
        // Strip trailing slash if any.
        if (dir_len > 0 && out[dir_len - 1] == '/')
            out[dir_len - 1] = '\0';
        found = 1;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

// ==================================================================
//  Public entry: zygisk_entry
//
//  Called by zygiskd immediately after this .so is android_dlopen_ext'd
//  into the zygote address space. The fd is the bridge socket —
//  zygiskd has the other end.
// ==================================================================
__attribute__((visibility("default")))
void zygisk_entry(int fd) {
    g_bridge_fd = fd;

    // Set up the bridge socket as non-blocking during handshake, then
    // switch back to blocking for normal operation.
    int flags = fcntl(g_bridge_fd, F_GETFL, 0);
    fcntl(g_bridge_fd, F_SETFL, flags & ~O_NONBLOCK);

    // Send a PING so zygiskd knows we got loaded successfully.
    if (bridge_send(g_bridge_fd, MSG_PING, NULL, 0) < 0) {
        // Couldn't even say hello. Bail out without doing anything else
        // — zygote will continue normally, just without Zygisk Next
        // active for this boot.
        return;
    }
    uint32_t op, status;
    void *body;
    uint32_t len;
    if (bridge_recv(g_bridge_fd, &op, &status, &body, &len) < 0) {
        return;
    }
    free(body);
    if (op != MSG_PING || status != 0) {
        return;
    }

    // Locate our sibling libraries (libzn_loader.so, libpayload.so)
    // from /proc/self/maps.
    char self_dir[PATH_MAX];
    if (find_self_dir(self_dir, sizeof(self_dir)) < 0) {
        // As a fallback, use the canonical install path.
        strncpy(self_dir,
                "/data/adb/modules/zygisksu/lib"
#ifdef __LP64__
                "64"
#else
                ""
#endif
                , sizeof(self_dir));
        self_dir[sizeof(self_dir) - 1] = '\0';
    }

    if (load_siblings(self_dir) < 0) {
        // Without libzn_loader, we can't actually do anything useful.
        // Stay resident (we don't want zygote to crash if some module
        // later tries to call our API), but no modules will be loaded.
        return;
    }

    // Hand control to libzn_loader with the API table. zn_entry will
    // never return for the lifetime of this process (it sets up the
    // fork hooks via pthread_atfork and then idles).
    g_zn_entry(g_bridge_fd, &k_api);

    // If we somehow reach here, clean up.
    if (g_libpayload) dlclose(g_libpayload);
    if (g_libzn_loader) dlclose(g_libzn_loader);
    close(g_bridge_fd);
    g_bridge_fd = -1;
}

#ifdef __cplusplus
}
#endif
