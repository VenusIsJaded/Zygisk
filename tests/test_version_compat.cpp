// SPDX-License-Identifier: Apache-2.0
// tests/test_version_compat.cpp
//
// Round 25 — Android version-compatibility tests for the BRIDGE
// library (libzygisk.so), built on the host and dlopen'd exactly the
// way ART's Runtime::Init loads it on a device.
//
// What this suite pins down (each check is a device-fatal class this
// round's AOSP research found — sources: system/core/libnativebridge
// native_bridge.h + native_bridge.cc at android-7.0.0_r1,
// android-7.1.2_r33, android-8.0.0_r17, android-8.1.0_r81,
// android-9.0.0_r1; art/runtime/runtime.cpp and
// dalvik_system_ZygoteHooks.cc at 7.1.2 / 9.0 / 13.0):
//
//   1. The constructor bootstrap: the dynamic linker runs
//      __attribute__((constructor)) INSIDE the zygote during the
//      Runtime::Init dlopen — the only load-time hook point that
//      exists on every Android version (initialize() is never called
//      in the zygote: ZygoteHooks_nativePostForkChild only calls it
//      for foreign-arch children, and dlcloses the bridge for
//      everyone else).
//
//   2. isCompatibleWith is implemented and answers 1..4 true /
//      everything else false: libnativebridge 7.x–9.x CALLS this slot
//      during LoadNativeBridge whenever the table's version >= 2 (a
//      NULL slot is a zygote-boot NULL call).
//
//   3. Every table slot the runtime of ANY studied version can index
//      is non-NULL (foreign-arch forks call several v1 slots
//      unguarded).
//
//   4. The table layout is the authoritative 15-slot AOSP form (v1
//      through v4, ending at getVendorNamespace) — a SHORT or
//      misaligned table is how ART ends up calling into .data.

#include "test_framework.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// The table type, re-declared from the AOSP layout (8.1 == 9.0;
// 7.x reads exactly the first 8 slots). Mirrors the definition in
// native/libzygisk/src/entry.cpp.
struct NativeBridgeRuntimeValues;
struct native_bridge_namespace_t;
typedef bool (*NativeBridgeSignalHandlerFn)(int, void*, void*);
struct NativeBridgeCallbacks {
    uint32_t version;
    bool (*initialize)(const struct NativeBridgeCallbacks*, const char*,
                       const char*);
    void* (*loadLibrary)(const char*, int);
    void* (*getTrampoline)(void*, const char*, const char*, uint32_t);
    bool (*isSupported)(const char*);
    const struct NativeBridgeRuntimeValues* (*getAppEnv)(const char*);
    bool (*isCompatibleWith)(uint32_t);
    NativeBridgeSignalHandlerFn (*getSignalHandler)(int);
    int (*unloadLibrary)(void*);
    const char* (*getError)();
    bool (*isPathSupported)(const char*);
    bool (*initAnonymousNamespace)(const char*, const char*);
    struct native_bridge_namespace_t* (*createNamespace)(
        const char*, const char*, const char*, uint64_t, const char*,
        struct native_bridge_namespace_t*);
    bool (*linkNamespaces)(struct native_bridge_namespace_t*,
                           struct native_bridge_namespace_t*,
                           const char*);
    void* (*loadLibraryExt)(const char*, int,
                            struct native_bridge_namespace_t*);
    struct native_bridge_namespace_t* (*getVendorNamespace)();
};

// The layout of the REAL AOSP table: version@0 (u32), then 15
// function pointers (v1:5 + v2:2 + v3:6 + v4:2), 8-aligned —
// getVendorNamespace at offset 120, total size 128.
static_assert(sizeof(NativeBridgeCallbacks) == 128,
              "NativeBridgeCallbacks must be the 15-slot AOSP layout");
static_assert(offsetof(NativeBridgeCallbacks, initialize) == 8,
              "initialize sits first after the version + padding");
static_assert(offsetof(NativeBridgeCallbacks, isCompatibleWith) == 48,
              "isCompatibleWith is the v2 slot after the five v1 slots");
static_assert(offsetof(NativeBridgeCallbacks, getVendorNamespace) == 120,
              "the table ends at getVendorNamespace (v4)");

typedef int (*zs_int_fn)(void);
typedef int (*zs_compat_fn)(uint32_t);

// The dlopen handle + resolved pieces, shared by the tests.
static void* g_bridge = nullptr;
static const NativeBridgeCallbacks* g_table = nullptr;
static zs_int_fn g_ctor_ran = nullptr;
static zs_int_fn g_slots_ok = nullptr;
static zs_compat_fn g_is_compat = nullptr;

static int load_bridge() {
    if (g_bridge) return 1;
    g_bridge = dlopen("./libzygisk.so", RTLD_LAZY);
    if (!g_bridge) return 0;
    g_table = (const NativeBridgeCallbacks*)dlsym(g_bridge,
                                                  "NativeBridgeItf");
    g_ctor_ran = (zs_int_fn)dlsym(g_bridge, "zs_test_libzygisk_ctor_ran");
    g_slots_ok = (zs_int_fn)dlsym(g_bridge,
                                  "zs_test_libzygisk_table_slots");
    g_is_compat = (zs_compat_fn)dlsym(g_bridge,
                                      "zs_test_libzygisk_is_compatible");
    return g_table && g_ctor_ran && g_slots_ok && g_is_compat ? 1 : 0;
}

ZS_TEST(bridge_exports_the_native_bridge_symbol) {
    ZS_CHECK(load_bridge());
    // The historical alias too (kept since Round 7).
    ZS_CHECK(dlsym(g_bridge, "NativeBridge2Itf") != nullptr);
}

ZS_TEST(bridge_constructor_bootstraps_at_dlopen_time) {
    ZS_CHECK(load_bridge());
    // The constructor is the ONLY hook point that runs in the zygote
    // on real devices — the dlopen above already ran it (exactly what
    // Runtime::Init's LoadNativeBridge dlopen does). If this is 0,
    // the whole pipeline is dead-on-arrival on hardware.
    ZS_CHECK_EQ(g_ctor_ran(), 1);
}

ZS_TEST(bridge_table_is_the_15_slot_aosp_layout) {
    ZS_CHECK(load_bridge());
    // The version every libnativebridge accepts (minimum 2 on all
    // studied versions; 7.x–9.x additionally interrogate
    // isCompatibleWith when they see >= 2).
    ZS_CHECK_EQ(g_table->version, 2u);
    // The table must be exactly the AOSP 15-slot layout: every slot
    // non-NULL (crash class: unguarded NULL calls on foreign-arch
    // forks; the 7.x–9.x isCompatibleWith NULL call at boot).
    ZS_CHECK_EQ(g_slots_ok(), 1);
    ZS_CHECK(g_table->initialize != nullptr);
    ZS_CHECK(g_table->loadLibrary != nullptr);
    ZS_CHECK(g_table->getTrampoline != nullptr);
    ZS_CHECK(g_table->isSupported != nullptr);
    ZS_CHECK(g_table->getAppEnv != nullptr);
    ZS_CHECK(g_table->isCompatibleWith != nullptr);
    ZS_CHECK(g_table->getSignalHandler != nullptr);
    ZS_CHECK(g_table->unloadLibrary != nullptr);
    ZS_CHECK(g_table->getError != nullptr);
    ZS_CHECK(g_table->isPathSupported != nullptr);
    ZS_CHECK(g_table->initAnonymousNamespace != nullptr);
    ZS_CHECK(g_table->createNamespace != nullptr);
    ZS_CHECK(g_table->linkNamespaces != nullptr);
    ZS_CHECK(g_table->loadLibraryExt != nullptr);
    ZS_CHECK(g_table->getVendorNamespace != nullptr);
}

ZS_TEST(bridge_is_compatible_answers_the_version_matrix) {
    ZS_CHECK(load_bridge());
    // 7.x asks isCompatibleWith(2) during LoadNativeBridge;
    // 8.x/9.x ask isCompatibleWith(3); feature guards ask up to (4).
    // All must be true — every slot 1..4 is a contract-valid no-op.
    ZS_CHECK_EQ(g_is_compat(1), 1);
    ZS_CHECK_EQ(g_is_compat(2), 1);   // 7.0 / 7.1.x / 8.x VersionCheck
    ZS_CHECK_EQ(g_is_compat(3), 1);   // 8.0 / 8.1 / 9.0 LoadNativeBridge
    ZS_CHECK_EQ(g_is_compat(4), 1);   // vendor-namespace guards
    // 0 and 5+ must be refused (we do not provide v5+ slots, and 0 is
    // "unsupported" by definition in libnativebridge).
    ZS_CHECK_EQ(g_is_compat(0), 0);
    ZS_CHECK_EQ(g_is_compat(5), 0);
    ZS_CHECK_EQ(g_is_compat(100), 0);
}

ZS_TEST(bridge_initialize_is_safe_and_idempotent) {
    ZS_CHECK(load_bridge());
    // initialize() IS still called on foreign-arch children (and by
    // any runtime that changes the lifecycle again). It must be safe
    // to call with null arguments, return success, and leave the
    // constructor's bootstrap latched.
    bool ok = g_table->initialize(nullptr, nullptr, nullptr);
    ZS_CHECK(ok);
    ZS_CHECK_EQ(g_ctor_ran(), 1);
}

ZS_TEST(bridge_no_op_slots_answer_contract_neutral_values) {
    ZS_CHECK(load_bridge());
    // Same-arch device semantics: nothing is "supported" through the
    // bridge, no handle exists, no namespace exists. Each answer is
    // the documented "feature absent" value — never a crash, never a
    // bogus success that would make the runtime take a bridged path.
    ZS_CHECK_EQ(g_table->isSupported("/system/lib64/libart.so"), false);
    ZS_CHECK(g_table->loadLibrary("/system/lib64/libart.so", 0) == nullptr);
    ZS_CHECK(g_table->getTrampoline((void*)1, "x", "()V", 3) == nullptr);
    ZS_CHECK(g_table->getAppEnv("x86") == nullptr);
    ZS_CHECK(g_table->getSignalHandler(11) == nullptr);
    ZS_CHECK_EQ(g_table->unloadLibrary((void*)1), -1);
    ZS_CHECK(g_table->getError() == nullptr);
    ZS_CHECK_EQ(g_table->isPathSupported("/system/lib64"), false);
    ZS_CHECK_EQ(g_table->initAnonymousNamespace("libc.so", "/system/lib64"),
                false);
    ZS_CHECK(g_table->createNamespace("n", nullptr, nullptr, 0, nullptr,
                                      nullptr) == nullptr);
    ZS_CHECK_EQ(g_table->linkNamespaces(nullptr, nullptr, "libc.so"),
                false);
    ZS_CHECK(g_table->loadLibraryExt("/system/lib64/libart.so", 0,
                                     nullptr) == nullptr);
    ZS_CHECK(g_table->getVendorNamespace() == nullptr);
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study version-compat (bridge) tests ===\n");
    return zstest::run_all();
}
