/* SPDX-License-Identifier: Apache-2.0
 * zygisk_study_api.h
 *
 * Optional companion API for Zygisk Study: an init-oriented injection
 * surface that extends the standard Zygisk API with the ability to
 * hook into processes other than zygote (e.g. vold, surfaceflinger,
 * netd, etc.).
 *
 * The upstream ZygiskNext project describes a similar API in its public
 * README ("API for injecting into init-oriented processes"). The
 * interface in this file is an ORIGINAL reimplementation of the
 * same documented concept — every line was written for this
 * repository; no code was copied from anywhere.
 *
 * To make sure modules written against upstream's API do NOT
 * accidentally link against our loader (which would be a silent
 * ABI break), we deliberately use different names for every symbol:
 *
 *   zygisk_study_api        (struct)
 *   zygisk_study_module     (struct)
 *   ZYGISK_STUDY_API_VERSION_STRING  (dlsym lookup name)
 *   ZYGISK_STUDY_MODULE_ENTRY_NAME  (module .so entry symbol)
 *
 * A module that wants to use OUR api has to opt in by name. A module
 * written for upstream's `zygisk_next_api` will not load against us
 * and vice versa.
 *
 * Usage from a module's perspective:
 *
 *   #include "zygisk_study_api.h"
 *   static const struct zygisk_study_api* zs_api = nullptr;
 *
 *   // In your onLoad():
 *   void* h = dlopen("libzn_loader.so", RTLD_LAZY);
 *   if (h) {
 *     zs_api = (const struct zygisk_study_api*)
 *         dlsym(h, ZYGISK_STUDY_API_VERSION_STRING);
 *   }
 *
 *   // Later, anywhere you have a hookable target process:
 *   if (zs_api) zs_api->should_inject(...);
 *
 * If the loader is not present, `dlsym` returns null and the module
 * simply falls back to standard Zygisk callbacks. This keeps modules
 * written against this API forward-compatible with the standard
 * Zygisk surface.
 *
 * NOTE: This is a NATIVE-ONLY API. It does not provide ART or JNI
 * compatibility to regular Zygisk modules. Modules that need ART
 * should stay on the zygisk::Module API from zygisk.hpp.
 */
#ifndef ZYGISK_STUDY_API_H
#define ZYGISK_STUDY_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version string used as the dlsym name. */
#define ZYGISK_STUDY_API_VERSION_STRING "zygisk_study_api_v1"

/* Forward declarations so the struct layout stays small. */
struct zygisk_study_process_info;
struct zygisk_study_module;

/* Capability bits — what the loader exposes to the module. */
enum {
    /* Loader allows the module to long-jump out of init callbacks
     * without aborting the rest of the pipeline. */
    ZS_CAP_EARLY_RETURN     = 1u << 0,
    /* Loader provides per-process fd passing for IPC back to the
     * daemon. */
    ZS_CAP_FD_PASSING       = 1u << 1,
    /* Loader implements the "post-server-specialize" hook for
     * init-oriented processes (system_server equivalents). */
    ZS_CAP_SERVER_SPECIALIZE = 1u << 2,
};

/* Per-process information the loader hands to the module at the
 * "about to fork" stage. The module uses this to decide whether
 * to inject for a given target. */
struct zygisk_study_process_info {
    const char* process_name;   /* e.g. "system_server"             */
    const char* package_name;   /* e.g. "com.android.systemui" or "" */
    uid_t        uid;
    gid_t        gid;
    int          is_system_server; /* 1 if true, 0 otherwise */
    /* Loader-specific opaque token the module can hand back to the
     * loader when it wants to inject. */
    void*        opaq;
};

/* The API surface. Function-pointer table. */
struct zygisk_study_api {
    /* ABI version of this table. Always starts with a known magic
     * value so a module can sanity-check. */
    uint32_t magic;            /* 0x5A535354 == "ZSST" (Zygisk STudy) */
    uint32_t version;          /* 1 for this revision                */

    uint32_t (*caps)(const struct zygisk_study_api* self);

    /* Decide whether the module wants to be injected for this
     * target. Called from inside the loader, BEFORE the fork.
     * Returns 1 to inject, 0 to skip. */
    int (*should_inject)(const struct zygisk_study_api* self,
                         const struct zygisk_study_process_info* info);

    /* Hand a freshly-forked child process back to the module so it
     * can run its post-fork setup. Called once per fork for every
     * module that returned 1 from should_inject(). */
    void (*post_fork)(const struct zygisk_study_api* self,
                      const struct zygisk_study_process_info* info,
                      void* child_opaque);

    /* Open a per-process socket back to the daemon. Returns -1
     * if the loader cannot provide one. */
    int  (*open_companion_fd)(const struct zygisk_study_api* self);
};

/* A module that wants to opt into the init-oriented API must export
 * this symbol: */
#define ZYGISK_STUDY_MODULE_ENTRY_NAME "zygisk_study_module"

struct zygisk_study_module {
    /* Called once at loader startup. The module stores `api` for
     * later use. */
    void (*on_load)(struct zygisk_study_module* self,
                    const struct zygisk_study_api* api);

    /* Should we inject? Implementation of should_inject. */
    int  (*should_inject)(struct zygisk_study_module* self,
                          const struct zygisk_study_process_info* info);

    /* Post-fork setup. */
    void (*post_fork)(struct zygisk_study_module* self,
                      const struct zygisk_study_process_info* info,
                      void* child_opaque);

    /* Reserved for forward compatibility. */
    void* reserved[4];
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZYGISK_STUDY_API_H */
