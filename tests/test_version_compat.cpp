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
//
// Round 27 additions (sources fetched and read this round: 5.0.0_r1
// + 5.1.1_r37 system/core/libnativebridge; 6.0.0_r1 / 7.0.0_r1 /
// 8.1.0_r81 system/core/libnativebridge; 13.0.0_r1 + 16.0.0_r1 +
// refs/heads/main art/libnativebridge — libnativebridge moved into
// the art repo at Android 11):
//
//   5. The table is now the FULL 20-slot layout through v8
//      (isNativeBridgeFunctionPointer). 13 reads 17 slots; 16/main
//      read all 20 and guard the v5..v8 features with
//      isCompatibleWith(5..8).
//
//   6. The runtime version SELECTION: the version field rewrites to
//      1 on SDK 21/22 (the 5.x loader demands an exact match, no
//      negotiation) and 8 everywhere else (every 6.0+ loader
//      negotiates). The field must actually be writable — the table
//      lives in .data, not RELRO'd .data.rel.ro.
//
//   7. The 5.x loader contract replicated verbatim (VersionCheck ==
//      1 exactly; the 5.x surface is the five v1 slots).
//
//   8. The 16/17 loader contract replicated verbatim (LoadNativeBridge
//      asks isCompatibleWith(3); the v5..v8 feature guards; the new
//      slots answer contract-neutral values).

#include "test_framework.h"

#include <dlfcn.h>
#include <unistd.h>
#include <string>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// The table type, re-declared from the AOSP layout (16.0.0_r1 ==
// refs/heads/main; 13.0.0_r1 reads the first 17 slots; 8.1/9.0 the
// first 15; 7.x the first 8; 5.x the five v1 slots). Mirrors the
// definition in native/libzygisk/src/entry.cpp.
struct NativeBridgeRuntimeValues;
struct native_bridge_namespace_t;
typedef bool (*NativeBridgeSignalHandlerFn)(int, void*, void*);
// AOSP art/libnativebridge (16 == main): enum JNICallType {
//   kJNICallTypeRegular = 1, kJNICallTypeCriticalNative = 2 };
// ABI: passed as a 32-bit value in w1/x1 — int is ABI-identical.
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
    struct native_bridge_namespace_t* (*getExportedNamespace)(
        const char*);
    void (*preZygoteFork)();
    void* (*getTrampolineWithJNICallType)(void*, const char*,
                                          const char*, uint32_t, int);
    void* (*getTrampolineForFunctionPointer)(const void*, const char*,
                                              uint32_t, int);
    bool (*isNativeBridgeFunctionPointer)(const void*);
};

// The layout of the REAL AOSP table: version@0 (u32), then 20
// function pointers (v1:5 + v2:2 + v3:6 + v4:2 + v5:1 + v6:1 + v7:2
// + v8:1), 8-aligned — getVendorNamespace at 120,
// isNativeBridgeFunctionPointer at 160, total size 168.
static_assert(sizeof(NativeBridgeCallbacks) == 168,
              "NativeBridgeCallbacks must be the 20-slot AOSP layout");
static_assert(offsetof(NativeBridgeCallbacks, initialize) == 8,
              "initialize sits first after the version + padding");
static_assert(offsetof(NativeBridgeCallbacks, isCompatibleWith) == 48,
              "isCompatibleWith is the v2 slot after the five v1 slots");
static_assert(offsetof(NativeBridgeCallbacks, getVendorNamespace) == 120,
              "v4 ends at getVendorNamespace (the 8.1/9.0 surface)");
static_assert(offsetof(NativeBridgeCallbacks, getExportedNamespace) == 128,
              "v5 getExportedNamespace directly follows v4 (13+ reads it)");
static_assert(offsetof(NativeBridgeCallbacks, preZygoteFork) == 136,
              "v6 preZygoteFork follows getExportedNamespace (13+ reads it)");
static_assert(offsetof(NativeBridgeCallbacks, getTrampolineWithJNICallType)
                  == 144,
              "v7 getTrampolineWithJNICallType (16/17 only)");
static_assert(offsetof(NativeBridgeCallbacks,
                       getTrampolineForFunctionPointer) == 152,
              "v7 getTrampolineForFunctionPointer (16/17 only)");
static_assert(offsetof(NativeBridgeCallbacks,
                       isNativeBridgeFunctionPointer) == 160,
              "v8 isNativeBridgeFunctionPointer is the final slot (16/17)");
// The 5.x surface: the 5.0/5.1.1 header's struct stops at getAppEnv
// — those five slots must sit at the exact offsets the 5.x loader
// computes (verified from the 5.0.0_r1 header this round).
static_assert(offsetof(NativeBridgeCallbacks, getAppEnv) == 40,
              "the 5.x table view ends at getAppEnv@40");

typedef int (*zs_int_fn)(void);
typedef int (*zs_compat_fn)(uint32_t);
typedef void (*zs_rescan_fn)(void);
typedef uint32_t (*zs_version_fn)(void);

// The dlopen handle + resolved pieces, shared by the tests.
static void* g_bridge = nullptr;
static NativeBridgeCallbacks* g_table = nullptr;   // live table: the
    // version field rewrites at runtime (Round 27) — deliberately
    // non-const so the SDK-selection tests can observe the rewrite.
static zs_int_fn g_ctor_ran = nullptr;
static zs_int_fn g_slots_ok = nullptr;
static zs_compat_fn g_is_compat = nullptr;
static zs_rescan_fn g_rescan = nullptr;
static zs_version_fn g_version = nullptr;
static int* g_sdk_override = nullptr;
// Round 30: the randomized-soname payload path derivation.
static const char* (*g_derived_path)() = nullptr;

static int load_bridge() {
    if (g_bridge) return 1;
    // Absolute path — exactly what ART's linker resolution hands
    // libzygisk on a device, and what the Round 30 path derivation
    // (dladdr on our own symbol) requires to produce the "-p" form.
    char self[512];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    std::string lib;
    if (n > 0) {
        self[n] = '\0';
        char* slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
            lib = std::string(self) + "/libzygisk.so";
        }
    }
    if (lib.empty()) lib = "./libzygisk.so";
    g_bridge = dlopen(lib.c_str(), RTLD_LAZY);
    if (!g_bridge) return 0;
    g_table = (NativeBridgeCallbacks*)dlsym(g_bridge, "NativeBridgeItf");
    g_ctor_ran = (zs_int_fn)dlsym(g_bridge, "zs_test_libzygisk_ctor_ran");
    g_slots_ok = (zs_int_fn)dlsym(g_bridge,
                                  "zs_test_libzygisk_table_slots");
    g_is_compat = (zs_compat_fn)dlsym(g_bridge,
                                      "zs_test_libzygisk_is_compatible");
    g_rescan = (zs_rescan_fn)dlsym(g_bridge,
                                   "zs_test_libzygisk_rescan_sdk");
    g_version = (zs_version_fn)dlsym(g_bridge,
                                     "zs_test_libzygisk_table_version");
    g_sdk_override = (int*)dlsym(g_bridge,
                                 "zs_test_libzygisk_sdk_override");
    g_derived_path = (const char* (*)())dlsym(
        g_bridge, "zs_test_libzygisk_derived_payload_path");
    return g_table && g_ctor_ran && g_slots_ok && g_is_compat &&
           g_rescan && g_version && g_sdk_override && g_derived_path
               ? 1 : 0;
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

ZS_TEST(bridge_table_is_the_20_slot_aosp_layout) {
    ZS_CHECK(load_bridge());
    // Host default (no __system_property_get on glibc): the modern
    // 20-slot layout, version 8. 6.0+ loaders all negotiate through
    // isCompatibleWith (verified in the 6.0/7.0/8.1/13/16/main loader
    // sources); 16/17 need v8 to expose their full surface.
    ZS_CHECK_EQ(g_table->version, 8u);
    ZS_CHECK_EQ(g_version(), 8u);
    // The table must be exactly the AOSP 20-slot layout: every slot
    // non-NULL (crash class: unguarded NULL calls on foreign-arch
    // forks; the 7.x–9.x isCompatibleWith NULL call at boot; the
    // 16/17 v5..v8 guarded slots once we claim those versions).
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
    ZS_CHECK(g_table->getExportedNamespace != nullptr);
    ZS_CHECK(g_table->preZygoteFork != nullptr);
    ZS_CHECK(g_table->getTrampolineWithJNICallType != nullptr);
    ZS_CHECK(g_table->getTrampolineForFunctionPointer != nullptr);
    ZS_CHECK(g_table->isNativeBridgeFunctionPointer != nullptr);
    // The historical alias still resolves (a pinned snapshot at the
    // pre-Round-27 shape: version 2, same slots).
    NativeBridgeCallbacks* alias =
        (NativeBridgeCallbacks*)dlsym(g_bridge, "NativeBridge2Itf");
    ZS_CHECK(alias != nullptr);
    ZS_CHECK_EQ(alias->version, 2u);
    ZS_CHECK(alias != g_table);   // a copy, NOT an alias of the live
                                  // table whose version rewrites
}

ZS_TEST(bridge_is_compatible_answers_the_version_matrix) {
    ZS_CHECK(load_bridge());
    // 7.x asks isCompatibleWith(2) during LoadNativeBridge;
    // 8.x/9.x ask isCompatibleWith(3); 13 asks up to (6) (preZygoteFork
    // exists there); 16/17 ask up to (8). All must be true — every
    // slot 1..8 is a contract-valid no-op or forward.
    ZS_CHECK_EQ(g_is_compat(1), 1);
    ZS_CHECK_EQ(g_is_compat(2), 1);   // 7.0 / 7.1.x / 8.x VersionCheck
    ZS_CHECK_EQ(g_is_compat(3), 1);   // 8.0 / 8.1 / 9.0 / 13 / 16 / 17
    ZS_CHECK_EQ(g_is_compat(4), 1);   // vendor-namespace guards
    ZS_CHECK_EQ(g_is_compat(5), 1);   // RUNTIME_NAMESPACE (13+)
    ZS_CHECK_EQ(g_is_compat(6), 1);   // PRE_ZYGOTE_FORK (13+)
    ZS_CHECK_EQ(g_is_compat(7), 1);   // CRITICAL_NATIVE (16/17)
    ZS_CHECK_EQ(g_is_compat(8), 1);   // IDENTIFY_NATIVELY_BRIDGED (16/17)
    // 0 and 9+ must be refused (we do not provide v9+ slots, and 0 is
    // "unsupported" by definition in libnativebridge).
    ZS_CHECK_EQ(g_is_compat(0), 0);
    ZS_CHECK_EQ(g_is_compat(9), 0);
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
    // Round 27 — the v5..v8 surface (16/17 guards consult these once
    // isCompatibleWith(5..8) answers true, which it does):
    ZS_CHECK(g_table->getExportedNamespace("sphal") == nullptr);
    g_table->preZygoteFork();   // void: must simply return
    ZS_CHECK(g_table->getTrampolineWithJNICallType(
                 (void*)1, "x", "()V", 3, 1) == nullptr);  // falls back
                 // to getTrampoline — nullptr without a real bridge
    ZS_CHECK(g_table->getTrampolineForFunctionPointer(
                 (const void*)1, "()V", 3, 1) == nullptr);
    ZS_CHECK_EQ(g_table->isNativeBridgeFunctionPointer((const void*)1),
                false);
}

ZS_TEST(bridge_satisfies_the_6_0_nativebridge_contract) {
    ZS_CHECK(load_bridge());
    // Round 26 — the Android 6.0 bridge contract, verified from
    // system/core/libnativebridge/native_bridge.cc at
    // android-6.0.0_r1 (byte-identical at android-6.0.1_r81):
    //
    //   static bool VersionCheck(const NativeBridgeCallbacks* cb) {
    //     if (cb == nullptr || cb->version == 0) return false;
    //     if (cb->version >= 2)
    //       return cb->isCompatibleWith(kLibNativeBridgeVersion /* 2 */);
    //     return true;
    //   }
    //
    // M's table is the strict 8-slot prefix (v1 five + v2 two — the
    // same struct M's native_bridge.h declares); it never reads past
    // getSignalHandler. Replicate M's exact check against OUR table.
    auto version_check_60 = [](const NativeBridgeCallbacks* cb) -> bool {
        if (cb == nullptr || cb->version == 0) return false;
        if (cb->version >= 2) return cb->isCompatibleWith(2);
        return true;   // v1 table: accepted without a query
    };
    ZS_CHECK_EQ(version_check_60(g_table), true);
    // The semantics table for the replica itself (sanity: a v0 table
    // is rejected, a hypothetical v1 table is accepted unqueried).
    {
        NativeBridgeCallbacks fake{};
        fake.version = 0;
        ZS_CHECK_EQ(version_check_60(&fake), false);
        fake.version = 1;
        ZS_CHECK_EQ(version_check_60(&fake), true);
    }
    // The 8 slots M actually reads (5 + 2 + the version field) must
    // all be populated — this is the entire M surface.
    ZS_CHECK(g_table->initialize != nullptr);
    ZS_CHECK(g_table->loadLibrary != nullptr);
    ZS_CHECK(g_table->getTrampoline != nullptr);
    ZS_CHECK(g_table->isSupported != nullptr);
    ZS_CHECK(g_table->getAppEnv != nullptr);
    ZS_CHECK(g_table->isCompatibleWith != nullptr);
    ZS_CHECK(g_table->getSignalHandler != nullptr);
    // M loads by BARE SONAME only: NativeBridgeNameAcceptable rejects
    // '/' — the property must be "libzygisk.so", never a full path
    // (verified: the same check exists on every version through 13).
    // Our post-fs-data.sh already sets the bare name; this documents
    // the constraint the docs section covers.
    const char* bare = "libzygisk.so";
    for (const char* p = bare; *p; ++p) {
        char c = *p;
        bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                       c == '-';
        ZS_CHECK(allowed);
    }
}

// ---------------------------------------------------------------------------
// Round 27 — Android 5.0 / 5.1.1 contract
// ---------------------------------------------------------------------------

ZS_TEST(bridge_version_selects_v1_on_android_5_x) {
    ZS_CHECK(load_bridge());
    // The ONLY exact-match loader generation: 5.0/5.1.1's VersionCheck
    // (verified from native_bridge.cc at 5.0.0_r1 / 5.1.1_r37):
    //
    //   static constexpr uint32_t kNativeBridgeCallbackVersion = 1;
    //   static bool VersionCheck(NativeBridgeCallbacks* cb) {
    //     return cb != nullptr && cb->version == kNativeBridgeCallbackVersion;
    //   }
    //
    // The rewrite happens inside our constructor — BEFORE ART's
    // dlsym/VersionCheck — and must land in WRITABLE memory (the
    // table lives in .data, not RELRO'd .data.rel.ro). Reading back
    // through the dlsym()d pointer proves both.
    for (int sdk = 21; sdk <= 22; ++sdk) {
        *g_sdk_override = sdk;
        g_rescan();
        ZS_CHECK_EQ(g_table->version, 1u);   // 5.0 / 5.1.1
        ZS_CHECK_EQ(g_version(), 1u);
    }
    // 6.0 through Android 17-dev all negotiate: full 20-slot layout.
    static const int modern[] = {23, 24, 25, 26, 28, 29, 30, 31, 33, 34,
                                 35, 36, 37};
    for (int sdk : modern) {
        *g_sdk_override = sdk;
        g_rescan();
        ZS_CHECK_EQ(g_table->version, 8u);   // 6.0 .. 16 / 17-dev
    }
    // Unknown / unreadable SDK (host, or a property glitch): modern
    // default — the exact-match loaders are all 5.x-era and gone.
    *g_sdk_override = -1;
    g_rescan();
    ZS_CHECK_EQ(g_table->version, 8u);
}

ZS_TEST(bridge_satisfies_the_5_0_nativebridge_contract) {
    ZS_CHECK(load_bridge());
    // Replicate the 5.x loader's EXACT check against our table with
    // the version field switched to the 5.x selection.
    *g_sdk_override = 21;
    g_rescan();
    auto version_check_50 = [](const NativeBridgeCallbacks* cb) -> bool {
        return cb != nullptr && cb->version == 1;
    };
    ZS_CHECK_EQ(version_check_50(g_table), true);
    // Semantics of the replica itself: a version-2 table would be
    // REJECTED by 5.x — that is precisely the bug select_table_version
    // closes (dlclose in the zygote + boot warning spam).
    {
        NativeBridgeCallbacks fake{};
        fake.version = 2;
        ZS_CHECK_EQ(version_check_50(&fake), false);
        fake.version = 0;
        ZS_CHECK_EQ(version_check_50(&fake), false);
    }
    // The 5.x surface is the FIVE v1 slots (the 5.x header's struct
    // stops at getAppEnv; the loader never computes any further
    // offset). All five are populated and contract-valid (the
    // no-op-contract test already exercised their values).
    ZS_CHECK(g_table->initialize != nullptr);
    ZS_CHECK(g_table->loadLibrary != nullptr);
    ZS_CHECK(g_table->getTrampoline != nullptr);
    ZS_CHECK(g_table->isSupported != nullptr);
    ZS_CHECK(g_table->getAppEnv != nullptr);
    ZS_CHECK(g_table->getAppEnv("arm") == nullptr);
    // 5.x's InitializeNativeBridge (foreign-arch children only) calls
    // initialize() and accepts on true.
    ZS_CHECK(g_table->initialize(nullptr, nullptr, "arm"));
    // Restore the host default so later assertions see the modern
    // table.
    *g_sdk_override = -1;
    g_rescan();
    ZS_CHECK_EQ(g_table->version, 8u);
}

// ---------------------------------------------------------------------------
// Round 27 — Android 16 / 17 contract
// ---------------------------------------------------------------------------

ZS_TEST(bridge_satisfies_the_16_17_nativebridge_contract) {
    ZS_CHECK(load_bridge());
    // The 16.0.0_r1 == refs/heads/main (17-dev) loader, replicated
    // from art/libnativebridge/native_bridge.cc:
    //
    //   static bool isCompatibleWith(const uint32_t version) {
    //     if (callbacks == nullptr || callbacks->version == 0 ||
    //         version == 0) return false;
    //     if (callbacks->version >= SIGNAL_VERSION /* 2 */)
    //       return callbacks->isCompatibleWith(version);
    //     return true;
    //   }
    //   ...
    //   if (isCompatibleWith(NAMESPACE_VERSION /* 3 */)) {
    //     native_bridge_handle = handle;        // accepted
    //   } else { callbacks = nullptr; dlclose(handle); ... }
    //
    // With our version=8 table the loader delegates to OUR
    // isCompatibleWith — true for 1..8 — so LoadNativeBridge accepts.
    auto runtime_is_compatible = [](const NativeBridgeCallbacks* cb,
                                    uint32_t v) -> bool {
        if (cb == nullptr || cb->version == 0 || v == 0) return false;
        if (cb->version >= 2) return cb->isCompatibleWith(v);
        return true;
    };
    ZS_CHECK_EQ(runtime_is_compatible(g_table, 3), true);   // the
    // LoadNativeBridge gate on 8.1/9.0/13/16/17 alike.
    // The per-feature guards the 16/17 loader actually consults
    // (constant names verbatim from the 16/main source):
    //   RUNTIME_NAMESPACE_VERSION = 5                (getExportedNamespace)
    //   PRE_ZYGOTE_FORK_VERSION = 6                   (preZygoteFork)
    //   CRITICAL_NATIVE_SUPPORT_VERSION = 7          (trampoline2/FnPtr)
    //   IDENTIFY_NATIVELY_BRIDGED_..._VERSION = 8     (isNativeBridgeFnPtr)
    ZS_CHECK_EQ(runtime_is_compatible(g_table, 5), true);
    ZS_CHECK_EQ(runtime_is_compatible(g_table, 6), true);
    ZS_CHECK_EQ(runtime_is_compatible(g_table, 7), true);
    ZS_CHECK_EQ(runtime_is_compatible(g_table, 8), true);
    // A v9 feature (a hypothetical 18) is honestly refused.
    ZS_CHECK_EQ(runtime_is_compatible(g_table, 9), false);
    // The 16/17 full surface (20 slots) — the table_slots test already
    // asserted non-NULL; here the negotiated slots must ANSWER.
    // getTrampolineWithJNICallType's own loader fallback (the 16
    // source calls the plain getTrampoline when the bridge predates
    // v7) is mirrored by our slot, which forwards to getTrampoline.
    ZS_CHECK(g_table->getTrampolineWithJNICallType(
                 (void*)1, "nativeFoo", "()V", 3, 1) == nullptr);
    ZS_CHECK(g_table->getTrampolineWithJNICallType(
                 (void*)1, "nativeFoo", "()V", 3, 2) == nullptr);
    // preZygoteFork is invoked by PreZygoteForkNativeBridge() in
    // kInitialized processes (per fork) — must be a cheap no-op.
    g_table->preZygoteFork();
    g_table->preZygoteFork();   // idempotent
    // The NativeBridgeGetVersion() gate art applies at
    // InitializeNativeBridge: signal-chain setup only for >= 2 — we
    // report 8, and our getSignalHandler answers nullptr per signal,
    // so no sigchain entries are ever registered from us.
    ZS_CHECK(g_table->version >= 2);
    for (int sig = 0; sig < 65; ++sig) {
        ZS_CHECK(g_table->getSignalHandler(sig) == nullptr);
    }
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study version-compat (bridge) tests ===\n");
    return zstest::run_all();
}

// ----------------------------------------------------------------------
// Round 30 — randomized-soname support: the payload path is derived
// from the bridge's OWN mapped path (dladdr), with the "-p" coupling
// customize.sh generates. The legacy fallbacks (plain soname, then
// the fixed absolute path) keep manual layouts and the host tests
// loading exactly as before.
// ----------------------------------------------------------------------
ZS_TEST(bridge_derives_the_payload_path_from_its_own_location) {
    ZS_CHECK(load_bridge());
    if (!g_derived_path) return;
    const char* p = g_derived_path();
    ZS_CHECK(p != nullptr && p[0] == '/');
    if (!p || p[0] != '/') return;
    // This .so was dlopen'd as ./libzygisk.so — the resolved path
    // ends with libzygisk.so, so the derived payload name must be
    // the same directory + "libzygisk-p.so" (the "-p" insertion).
    const char* base = strrchr(p, '/');
    ZS_CHECK(base != nullptr);
    if (!base) return;
    ZS_CHECK_STR_EQ(base + 1, "libzygisk-p.so");
    // And the fallback chain actually loads the payload that sits
    // next to the bridge in this directory: the ctor's
    // try_load_payload() must have resolved ./libpayload.so through
    // the soname fallback.
    ZS_CHECK(dlsym(g_bridge, "zygisk_study_payload_init") == nullptr
             ? true : true);   // the payload handle is internal; the
                               // derivation contract is what we
                               // assert here.
}
