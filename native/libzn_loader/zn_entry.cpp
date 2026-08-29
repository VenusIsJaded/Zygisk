// libzn_loader.so — from-scratch reimplementation
//
// Purpose
// -------
// libzn_loader.so is the second-stage in-zygote library. After
// libzygisk.so finishes its bridge handshake with zygiskd, it
// dlopens libzn_loader.so and calls:
//
//     void *zn_entry(int bridge_fd, const ZygiskAPI *api);
//
// zn_entry then:
//   1. Iterates /data/adb/modules/*/zygisk/<arch>.so to discover
//      every enabled module's companion library.
//   2. dlopens each one (with RTLD_LOCAL | RTLD_NODELETE so the
//      library stays mapped across forks).
//   3. Calls each module's `void zygisk_module_entry(const void
//      *api_table)` entry point. The module uses the api table to
//      register its pre/post-fork + specialize callbacks.
//   4. Sets up pthread_atfork hooks so that every time zygote forks
//      a new app/server process, libzn_loader routes the
//      pre/post-fork callbacks into every loaded module in order.
//   5. Idles forever (or until zygote exits).
//
// Public API surface (from the original binary's symbol table,
// verified by `readelf -sW libzn_loader.so`):
//   zn_entry     FUNC  GLOBAL DEFAULT (size ~7392 bytes on arm64)
//
// Module entry ABI (publicly documented in Magisk's zygisk.h):
//
//   struct ZygiskModule {
//     void *impl;
//     void (*on_module_load)(void*, const char *path, void *api);
//     void (*pre_app_specialize)(void*, const AppSpecializeArgs*);
//     void (*post_app_specialize)(void*, const AppSpecializeArgs*);
//     void (*pre_server_specialize)(void*, const ServerSpecializeArgs*);
//     void (*post_server_specialize)(void*, const ServerSpecializeArgs*);
//     void (*on_unload)(void*);
//   };
//
// The companion .so exports a constructor:
//   void *zygisk_module_create() -> returns a new ZygiskModule*.
//
// In real Zygisk Next, the entry symbol is `zygisk_module_entry` taking
// a `void *api` argument. I follow that convention here.

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward-declare the Zygisk API table struct from libzygisk. The
// actual definition is in zygisk_entry.cpp. We define a minimal
// forward-declared struct here and use a void* for the api arg.
struct ZygiskAPI;
typedef struct ZygiskAPI ZygiskAPI;

// Module entry symbol — every companion .so exports this.
typedef void (*zygisk_module_entry_t)(void *api);

// Module callback slots (mirror Magisk zygisk.h)
typedef void (*cb_pre_app_specialize)(void*, const void*);
typedef void (*cb_post_app_specialize)(void*, const void*);
typedef void (*cb_pre_server_specialize)(void*, const void*);
typedef void (*cb_post_server_specialize)(void*, const void*);
typedef void (*cb_on_unload)(void*);

// One loaded module.
struct LoadedModule {
    void *handle;            // dlopen handle
    char  id[256];           // module id (folder name)
    char *path;              // full path to the .so
    void *impl;              // module's own context
    cb_pre_app_specialize    pre_app;
    cb_post_app_specialize   post_app;
    cb_pre_server_specialize pre_server;
    cb_post_server_specialize post_server;
    cb_on_unload             on_unload;
    bool  dlclose_after_init;
};

// ==================================================================
//  Globals
// ==================================================================
static int g_bridge_fd = -1;
static const ZygiskAPI *g_api = NULL;
static struct LoadedModule *g_modules = NULL;
static size_t g_module_count = 0;
static size_t g_module_cap   = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// True when we're between pre_app_specialize and post_app_specialize
// (i.e. inside a fork child before exec). Used to make the fork
// hooks fork-safe.
static __thread bool g_in_specialize = false;

// ==================================================================
//  Helpers
// ==================================================================
static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) abort();
    return p;
}
static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) abort();
    return q;
}

// Returns the current process's ABI directory name.
//   "arm64-v8a" on 64-bit ARM
//   "armeabi-v7a" on 32-bit ARM
//   "x86_64" on 64-bit x86
//   "x86" on 32-bit x86
static const char *current_abi(void) {
#if defined(__aarch64__)
    return "arm64-v8a";
#elif defined(__arm__)
    return "armeabi-v7a";
#elif defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#else
#error "unknown arch"
#endif
}

// Read a directory and collect all subdir names that look like
// module ids (i.e. that contain a "module.prop" file).
static char **list_module_ids(size_t *count) {
    *count = 0;
    DIR *d = opendir("/data/adb/modules");
    if (!d) return NULL;
    char **ids = (char **)xmalloc(sizeof(char *) * 16);
    size_t cap = 16;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path),
                 "/data/adb/modules/%s/module.prop", e->d_name);
        if (access(path, R_OK) != 0) continue;
        // Check that module is not disabled
        char disable[PATH_MAX];
        snprintf(disable, sizeof(disable),
                 "/data/adb/modules/%s/disable", e->d_name);
        if (access(disable, F_OK) == 0) continue;
        // Check the "remove" file too.
        char rm[PATH_MAX];
        snprintf(rm, sizeof(rm),
                 "/data/adb/modules/%s/remove", e->d_name);
        if (access(rm, F_OK) == 0) continue;

        if (*count == cap) {
            cap *= 2;
            ids = (char **)xrealloc(ids, sizeof(char *) * cap);
        }
        ids[*count] = strdup(e->d_name);
        (*count)++;
    }
    closedir(d);
    return ids;
}

// dlopen a module's companion .so. Returns handle + populated
// LoadedModule, or NULL on failure.
static int load_one_module(struct LoadedModule *out,
                          const char *id) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path),
             "/data/adb/modules/%s/zygisk/%s.so",
             id, current_abi());
    if (access(path, R_OK) != 0) return -1;

    void *h = dlopen(path, RTLD_LOCAL | RTLD_NOW | RTLD_NODELETE);
    if (!h) return -1;

    zygisk_module_entry_t entry = (zygisk_module_entry_t)
        dlsym(h, "zygisk_module_entry");
    if (!entry) {
        dlclose(h);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->handle = h;
    out->path = strdup(path);
    strncpy(out->id, id, sizeof(out->id) - 1);
    out->id[sizeof(out->id) - 1] = '\0';

    // The module's entry function is responsible for filling in the
    // callback slots via the API table. We don't directly know the
    // module's callback addresses here — the module registers them
    // through the api->setModuleDescriptor() and friends.
    //
    // For our minimal implementation, we just call entry() with the
    // api table. The module is expected to call back into our
    // ZygiskAPI to register its slots.
    entry((void *)g_api);

    // dlsym the optional slots (modules that export these symbols
    // get routed through here directly; this is an alternative to
    // the API-table registration and is the more common pattern in
    // real Zygisk modules).
    out->pre_app    = (cb_pre_app_specialize)
                       dlsym(h, "zygisk_pre_app_specialize");
    out->post_app  = (cb_post_app_specialize)
                       dlsym(h, "zygisk_post_app_specialize");
    out->pre_server = (cb_pre_server_specialize)
                       dlsym(h, "zygisk_pre_server_specialize");
    out->post_server= (cb_post_server_specialize)
                       dlsym(h, "zygisk_post_server_specialize");
    out->on_unload  = (cb_on_unload)
                       dlsym(h, "zygisk_on_unload");

    return 0;
}

// ==================================================================
//  pthread_atfork hooks
//
//  Zygote forks for every new app/server process. We hook the fork
//  so that:
//    - pre  (parent, before fork): nothing (modules registered
//              pre_app_specialize and similar are called in the
//              CHILD after fork, not in the parent before fork)
//    - parent (after fork, in parent): nothing (parent is the
//              zygote and continues idling)
//    - child  (after fork, in child): trigger pre_app_specialize
//              for each module, wait for the app to specialize,
//              then trigger post_app_specialize
//
//  Note: real Zygisk is invoked via JNI hooks inside
//  Zygote.nativeForkAndSpecialize, not via pthread_atfork. The
//  difference: pthread_atfork runs *before* the zygote sets the
//  child's uid/gid/mount namespace. Using pthread_atfork here is
//  a simplification — modules that need post-specialize callbacks
//  at the correct time would need a more elaborate hook.
// ==================================================================
static void atfork_prepare(void) {
    pthread_mutex_lock(&g_lock);
}
static void atfork_parent(void) {
    pthread_mutex_unlock(&g_lock);
}
static void atfork_child(void) {
    // We are now in the fork child. Reset the bridge fd — we no
    // longer want to talk to zygiskd from here (the parent owns
    // the bridge).
    if (g_bridge_fd >= 0) {
        close(g_bridge_fd);
        g_bridge_fd = -1;
    }
    pthread_mutex_unlock(&g_lock);

    g_in_specialize = true;

    // Call pre_app_specialize on every loaded module that has one.
    // The "args" pointer is NULL here — a real implementation would
    // populate it from the zygote's fork arguments.
    for (size_t i = 0; i < g_module_count; i++) {
        if (g_modules[i].pre_app) {
            g_modules[i].pre_app(g_modules[i].impl, NULL);
        }
    }
}

// Called by the zygote or by an explicit post-specialize hook
// after the child's uid/gid has been set. Not exposed via
// pthread_atfork — modules call this through the Zygisk API.
__attribute__((visibility("default")))
void zn_post_specialize(void) {
    if (!g_in_specialize) return;
    for (size_t i = 0; i < g_module_count; i++) {
        if (g_modules[i].post_app) {
            g_modules[i].post_app(g_modules[i].impl, NULL);
        }
    }
    g_in_specialize = false;
}

// ==================================================================
//  Public entry: zn_entry
//
//  Called by libzygisk.so with the bridge fd and the Zygisk API
//  table. Never returns for the lifetime of the zygote process.
// ==================================================================
__attribute__((visibility("default")))
void zn_entry(int bridge_fd, const ZygiskAPI *api) {
    g_bridge_fd = bridge_fd;
    g_api = api;

    // Register the atfork hooks.
    pthread_atfork(atfork_prepare, atfork_parent, atfork_child);

    // Discover all enabled modules.
    size_t n_ids = 0;
    char **ids = list_module_ids(&n_ids);
    if (!ids) {
        // No modules — nothing to do.
        goto idle;
    }

    g_module_cap = n_ids;
    g_modules = (struct LoadedModule *)xmalloc(sizeof(*g_modules) * g_module_cap);

    for (size_t i = 0; i < n_ids; i++) {
        struct LoadedModule m;
        if (load_one_module(&m, ids[i]) == 0) {
            if (g_module_count == g_module_cap) {
                g_module_cap *= 2;
                g_modules = (struct LoadedModule *)xrealloc(g_modules,
                                     sizeof(*g_modules) * g_module_cap);
            }
            g_modules[g_module_count++] = m;
        } else {
            // Couldn't load this module — skip silently. (Real
            // Zygisk would log this via klog.)
        }
        free(ids[i]);
    }
    free(ids);

idle:
    // Idle forever. We don't block — we just poll the bridge
    // socket periodically for any commands (e.g. zygiskd asking
    // us to refresh the module list, or trigger a per-module
    // companion).
    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (g_bridge_fd >= 0) FD_SET(g_bridge_fd, &rfds);
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        int n = select(g_bridge_fd + 1, &rfds, NULL, NULL, &tv);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n > 0 && g_bridge_fd >= 0
                 && FD_ISSET(g_bridge_fd, &rfds)) {
            // Bridge closed or message pending.
            char buf[256];
            ssize_t r = read(g_bridge_fd, buf, sizeof(buf));
            if (r <= 0) break;
            // Process any command here. For the minimal
            // implementation, we just keep the bridge open.
        }
    }

    // Unload all modules on shutdown (rarely reached — zygote
    // is killed, not exited cleanly).
    for (size_t i = 0; i < g_module_count; i++) {
        if (g_modules[i].on_unload) {
            g_modules[i].on_unload(g_modules[i].impl);
        }
        if (g_modules[i].dlclose_after_init) {
            dlclose(g_modules[i].handle);
        }
        free(g_modules[i].path);
    }
    free(g_modules);
    g_modules = NULL;
    g_module_count = g_module_cap = 0;
}

#ifdef __cplusplus
}
#endif
