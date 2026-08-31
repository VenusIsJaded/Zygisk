// SPDX-License-Identifier: Apache-2.0
// native/libzygisk/src/entry.cpp
//
// libzygisk.so — the entry library that the Android runtime loads
// into the zygote process by way of the ro.dalvik.vm.native.bridge
// property.
//
// How this works (high-level):
//
//   1. The daemon (zygiskd) runs as root at boot. post-fs-data.sh
//      writes "libzygisk.so" into ro.dalvik.vm.native.bridge with
//      resetprop (the standard Magisk-style property swap — the same
//      mechanism every Zygisk implementation uses).
//   2. ART (the Android Runtime) reads ro.dalvik.vm.native.bridge at
//      startup, and if non-empty, dlopen-s that .so and looks up the
//      symbol "NativeBridgeItf" (AOSP system/core/libnativebridge's
//      NATIVE_BRIDGE_SYMBOL).
//   3. ART calls the table's initialize() at zygote boot. We use that
//      hook to do three things:
//        a. dlopen the *real* native bridge (libndk_translation.so or
//           libnativebridge.so on stock Android) so we don't break
//           anything that depends on it.
//        b. dlopen libpayload.so which contains the actual Zygisk
//           module-loading + hiding machinery.
//        c. Hand off to libpayload, which then installs the
//           privilege-drop hooks that drive the whole pipeline.
//
// Round 7 fixes:
//
//   - The exported symbol was "NativeBridge2Itf". ART looks up
//     "NativeBridgeItf" — as-shipped, ART would never even find our
//     table (the native bridge would be reported broken). Both names
//     are now exported (the historical one kept as an alias).
//
//   - The NativeBridgeCallbacks table was declared with only two
//     fields. ART indexes deep into this struct; a short struct made
//     ART read whatever .data happened to sit behind it. The full
//     v2 table is now declared with every slot NULL except
//     initialize, matching the AOSP layout byte-for-byte.
//
//   - initialize()'s signature is now the real one:
//     bool initialize(const NativeBridgeCallbacks* cb,
//                     const char* app_cache_dir, const char* isa).
//
//   - The payload path respects the process word size (32-bit zygote
//     forks load from /system/lib, 64-bit from /system/lib64).

#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

// ---------------------------------------------------------------------------
// NativeBridge v2 — the Android native-bridge interface (AOSP
// system/core/libnativebridge/include/nativebridge/native_bridge.h).
//
// The full v2 callback table. Every slot we do not implement is NULL —
// ART treats this as "no-op bridge", which is exactly what a same-arch
// device needs (bridge functions are only invoked for foreign-arch
// library loading).
// ---------------------------------------------------------------------------
struct NativeBridgeCallbacks {
    uint32_t version;
    // v1:
    bool (*initialize)(const struct NativeBridgeCallbacks* callbacks,
                       const char* app_cache_dir, const char* isa);
    void* (*loadLibrary)(const char* libpath, int flag);
    void* (*getTrampoline)(void* handle, const char* name,
                           const char* shorty, uint32_t len);
    bool (*isSupported)(const char* libpath);
    int (*getAppEnv)(const char* abi, struct NativeBridgeRuntimeCallbacks*);
    // v2 and later additions (namespace support, error reporting,
    // signal handling). Declared generously: a table that is LONGER
    // than the caller's expectation is harmless (the caller only
    // reads its own slots), while a SHORT one made ART index into
    // adjacent .data — the Round 7 fix.
    bool (*isCompatibleWith)(uint32_t version);
    int (*getSignalHandler)(int signal, void** handler);
    int (*unloadLibrary)(void* handle);
    bool (*getError)(void* handle, const char** error);
    bool (*isPathSupported)(const char* path);
    void (*initAppNamespace)(void* self, const char* app_cache_dir,
                             const char* abi, ...);
    void* (*createNamespace)(void* self, const char* name,
                             const char* ld_library_path,
                             const char* default_library_path,
                             uint32_t type, const char* permitted_when_isolated,
                             ...);
    void* (*getVendorNamespace)();
    void* (*getExportedNamespace)();
    void (*setTargetSdkVersion)(int target_sdk_version,
                                const char* abi);
    void (*setAnonymousNamespaceRestriction)(bool is_public,
                                             bool also_allowed_as_app,
                                             bool use_also_core_ld_library_path);
    void (*reserved1)();
    void (*reserved2)();
    void (*reserved3)();
    void (*reserved4)();
};

struct NativeBridgeRuntimeCallbacks;  // opaque

// Symbols we look up in the *real* native bridge (if present).
typedef bool (*InitializeFn)(const struct NativeBridgeCallbacks*,
                             const char*, const char*);

// Path to libpayload.so, by word size. The daemon bind-mounts both
// libraries into the systemless /system tree.
static constexpr const char* kPayloadPath() {
#if defined(__LP64__)
    return "/system/lib64/libpayload.so";
#else
    return "/system/lib/libpayload.so";
#endif
}

static void* g_real_native_bridge = nullptr;
static void* g_payload            = nullptr;
static int   g_initialized        = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void try_load_real_native_bridge() {
    const char* path = nullptr;
#if defined(__LP64__)
    if (access("/system/lib64/libndk_translation.so", R_OK) == 0)
        path = "/system/lib64/libndk_translation.so";
    else if (access("/system/lib64/libnativebridge.so", R_OK) == 0)
        path = "/system/lib64/libnativebridge.so";
#else
    if (access("/system/lib/libndk_translation.so", R_OK) == 0)
        path = "/system/lib/libndk_translation.so";
    else if (access("/system/lib/libnativebridge.so", R_OK) == 0)
        path = "/system/lib/libnativebridge.so";
#endif
    if (!path) {
        ZS_LOGD("libzygisk: no real native bridge present");
        return;
    }
    g_real_native_bridge = dlopen(path, RTLD_LAZY);
    if (!g_real_native_bridge) {
        ZS_LOGW("libzygisk: dlopen(%s) failed: %s", path, dlerror());
    }
}

static void try_load_payload() {
    g_payload = dlopen(kPayloadPath(), RTLD_LAZY);
    if (!g_payload) {
        ZS_LOGE("libzygisk: dlopen(%s) failed: %s", kPayloadPath(),
                dlerror());
        return;
    }
    using InitFn = void (*)();
    auto init = (InitFn)dlsym(g_payload, "zygisk_study_payload_init");
    if (init) {
        init();
        ZS_LOGI("libzygisk: libpayload initialized");
    } else {
        ZS_LOGE("libzygisk: payload has no init symbol");
    }
}

static bool native_bridge_initialize(const struct NativeBridgeCallbacks* cb,
                                     const char* app_cache_dir,
                                     const char* isa) {
    (void)app_cache_dir;
    (void)isa;
    ZS_LOGI("libzygisk: NativeBridgeItf.initialize called");
    try_load_real_native_bridge();
    try_load_payload();
    g_initialized = 1;

    // Forward to the real bridge if it has its own initialize hook.
    if (g_real_native_bridge) {
        auto init = (InitializeFn)dlsym(g_real_native_bridge,
                                        "NativeBridgeItf");
        if (init) return init(cb, app_cache_dir, isa);
    }
    return true;  // success
}

// ---------------------------------------------------------------------------
// NativeBridgeItf — the table ART dlsym()s. ART's loader (AOSP
// system/core/libnativebridge/nativebridge.cc) looks up
// NATIVE_BRIDGE_SYMBOL == "NativeBridgeItf" and requires version >= 2.
// ---------------------------------------------------------------------------
// extern is required: a const object at namespace scope has internal
// linkage in C++ by default, which would silently NOT export the
// symbol ART dlsym()s.
extern "C" __attribute__((visibility("default")))
const struct NativeBridgeCallbacks NativeBridgeItf = {
    .version = 2,
    .initialize = &native_bridge_initialize,
    .loadLibrary = nullptr,
    .getTrampoline = nullptr,
    .isSupported = nullptr,
    .getAppEnv = nullptr,
    .isCompatibleWith = nullptr,
    .getSignalHandler = nullptr,
    .unloadLibrary = nullptr,
    .getError = nullptr,
    .isPathSupported = nullptr,
    .initAppNamespace = nullptr,
    .createNamespace = nullptr,
    .getVendorNamespace = nullptr,
    .getExportedNamespace = nullptr,
    .setTargetSdkVersion = nullptr,
    .setAnonymousNamespaceRestriction = nullptr,
    .reserved1 = nullptr,
    .reserved2 = nullptr,
    .reserved3 = nullptr,
    .reserved4 = nullptr,
};

// Historical alias: the pre-Round-7 code exported this (wrong) name.
// Kept so old documentation/references still resolve.
extern "C" __attribute__((visibility("default")))
const struct NativeBridgeCallbacks NativeBridge2Itf = NativeBridgeItf;

// ---------------------------------------------------------------------------
// JNI_OnLoad — called by ART if our .so is loaded as a JNI library.
// (Android-only: jni.h does not exist on host builds.)
// ---------------------------------------------------------------------------
#ifdef __ANDROID__
#include <jni.h>
extern "C"
__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    (void)vm;
    ZS_LOGI("libzygisk: JNI_OnLoad called");
    return JNI_VERSION_1_6;
}
#endif  // __ANDROID__
