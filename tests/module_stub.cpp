// SPDX-License-Identifier: Apache-2.0
// tests/module_stub.cpp
//
// Round 12 — a REAL Zygisk module .so for test_module_dispatch.
//
// It is loaded by the REAL payload (libpayload.so) through the REAL
// path: fake daemon 'L' response -> dlopen(this .so) -> dlsym
// "zygisk_module" -> factory -> onLoad at the first fork ->
// pre/postSpecialize from the REAL setresgid/setresuid hooks.
//
// Every callback appends a record into a shared mmap page whose
// address is passed via the ZS_TEST_REC environment variable
// (MAP_SHARED, so forked children write into the page the parent
// asserts against).
//
// Behavior knobs (also env vars, so the tests can flip them per
// child):
//   ZS_TEST_MODIFY=1  -> preAppSpecialize rewrites uid/gid through
//                        the args pointers (tests the forwarding to
//                        the real privilege-drop calls).
//   ZS_TEST_FORCE=1   -> preAppSpecialize calls
//                        setOption(FORCE_DENYLIST_UNMOUNT) late
//                        (tests the post-callback unmount phase).

#include "zygisk.hpp"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ---- recorder protocol (shared with test_module_dispatch.cpp) ----
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
    uintptr_t env;              // the JNIEnv we were handed
    uintptr_t jni_old_table;    // hookJniEnv: previous table
    uintptr_t jni_new_table;    // hookJniEnv: table we installed
    int32_t companion_fd;
    char nice_name[64];
    char package_name[64];
    char app_data_dir[160];
};

struct RecPage {
    int32_t count;
    int32_t _pad;
    RecEntry entries[32];
};

static RecPage* rec_page() {
    const char* a = getenv("ZS_TEST_REC");
    if (!a || !*a) return nullptr;
    return (RecPage*)(uintptr_t)strtoull(a, nullptr, 0);
}

static void copy_str(char* dst, size_t cap, const char* src) {
    if (!src) src = "";
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

class TestModule : public zygisk::Module {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        g_api = api;
        RecPage* p = rec_page();
        if (!p || p->count >= 32) return;
        RecEntry* e = &p->entries[p->count++];
        memset(e, 0, sizeof *e);
        e->cb = ZS_CB_ONLOAD;
        e->env = (uintptr_t)env;

        // Exercise the REAL hookJniEnv table swap: copy the "table"
        // (host: 64 pointer slots per the test's fake layout), patch
        // slot 5 (unused by the test), install, record old + new.
        void** old_table = *(void***)env;
        void** new_table = (void**)malloc(64 * sizeof(void*));
        memcpy(new_table, old_table, 64 * sizeof(void*));
        new_table[5] = (void*)(uintptr_t)0x5A5A5A5A;  // marker slot
        const void* old_out = nullptr;
        if (api->hookJniEnv(env, (const void*)new_table, &old_out) == 0) {
            e->jni_old_table = (uintptr_t)old_out;
            e->jni_new_table = (uintptr_t)new_table;
        } else {
            free(new_table);
        }

        // Exercise the REAL connectCompanion (fake daemon accepts).
        e->companion_fd = api->connectCompanion();
    }

    void preAppSpecialize(JNIEnv* env, zygisk::AppSpecializeArgs* args) override {
        RecPage* p = rec_page();
        if (p && p->count < 32) {
            RecEntry* e = &p->entries[p->count++];
            memset(e, 0, sizeof *e);
            e->cb = ZS_CB_PRE_APP;
            e->env = (uintptr_t)env;
            e->uid = args->uid ? *args->uid : -1;
            e->gid = args->gid ? *args->gid : -1;
            copy_str(e->nice_name, sizeof e->nice_name, args->nice_name);
            copy_str(e->package_name, sizeof e->package_name,
                     args->package_name);
            copy_str(e->app_data_dir, sizeof e->app_data_dir,
                     args->app_data_dir);
        }
        const char* mod = getenv("ZS_TEST_MODIFY");
        if (mod && strcmp(mod, "1") == 0) {
            *args->uid = 4242;
            *args->gid = 4243;
        }
        const char* force = getenv("ZS_TEST_FORCE");
        if (force && strcmp(force, "1") == 0 && g_api) {
            // Late setOption: the mount phase of this fork has already
            // been decided, but the post-callback unmount phase still
            // applies (documented deviation from the onLoad contract —
            // see tests/test_module_dispatch.cpp).
            g_api->setOption(zygisk::Api::FORCE_DENYLIST_UNMOUNT);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        RecPage* p = rec_page();
        if (!p || p->count >= 32) return;
        RecEntry* e = &p->entries[p->count++];
        memset(e, 0, sizeof *e);
        e->cb = ZS_CB_POST_APP;
        e->uid = args->uid ? *args->uid : -1;
        e->gid = args->gid ? *args->gid : -1;
        copy_str(e->nice_name, sizeof e->nice_name, args->nice_name);
        copy_str(e->package_name, sizeof e->package_name,
                 args->package_name);
        copy_str(e->app_data_dir, sizeof e->app_data_dir,
                 args->app_data_dir);
    }

    void preServerSpecialize(JNIEnv* env,
                             zygisk::ServerSpecializeArgs* args) override {
        RecPage* p = rec_page();
        if (!p || p->count >= 32) return;
        RecEntry* e = &p->entries[p->count++];
        memset(e, 0, sizeof *e);
        e->cb = ZS_CB_PRE_SERVER;
        e->env = (uintptr_t)env;
        e->uid = args->uid ? *args->uid : -1;
        e->gid = args->gid ? *args->gid : -1;
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs* args) override {
        RecPage* p = rec_page();
        if (!p || p->count >= 32) return;
        RecEntry* e = &p->entries[p->count++];
        memset(e, 0, sizeof *e);
        e->cb = ZS_CB_POST_SERVER;
        e->uid = args->uid ? *args->uid : -1;
        e->gid = args->gid ? *args->gid : -1;
    }

    // Ask for names so the PROCESS_UNPRIORITY gating is exercised on
    // the real path.
    uint32_t caps() const override { return zygisk::PROCESS_UNPRIORITY; }

    // (kept public-in-spirit: the factory initializes it)
    static zygisk::Api* g_api;
};

zygisk::Api* TestModule::g_api = nullptr;

extern "C" __attribute__((visibility("default")))
zygisk::Module* zygisk_module(zygisk::Api* api, JNIEnv* env) {
    (void)env;
    static TestModule instance;
    TestModule::g_api = api;
    return &instance;
}
