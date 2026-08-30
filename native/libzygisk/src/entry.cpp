// SPDX-License-Identifier: Apache-2.0
// native/libzygisk/src/entry.cpp
//
// libzygisk.so — the entry library that the Android runtime loads
// into the zygote process by way of the ro.dalvik.vm.native.bridge
// property.
//
// How this works (high-level):
//
//   1. The daemon (zygiskd) runs as root at boot. It writes the path
//      to /system/lib64/libzygisk.so into ro.dalvik.vm.native.bridge
//      using the standard Magisk-style property swap trick.
//   2. ART (the Android Runtime) reads ro.dalvik.vm.native.bridge at
//      startup, and if non-empty, dlopen-s that .so and asks it for
//      the NativeBridge2 interface.
//   3. ART calls our NativeBridge2 `initialize` hook at zygote boot.
//      We use that hook to do three things:
//        a. dlopen the *real* native bridge (libndk_translation.so or
//           libnativebridge.so on stock Android) so we don't break
//           anything that depends on it.
//        b. dlopen libpayload.so which contains the actual Zygisk
//           module-loading + hiding machinery.
//        c. Hand off to libpayload, which then runs the per-fork
//           pre/post-specialize callbacks.
//
// The job of libzygisk.so itself is *tiny*. It's a bootstrap. All
// the heavy lifting lives in libpayload.so. This keeps the surface
// area we expose to ART very small (one native-bridge entry), and it
// keeps the library small enough that it loads fast at zygote boot.
//
// Public symbols of this .so (deliberately minimal):
//   - JNI_OnLoad          (called by ART)
//   - NativeBridge2Itf    (Android's native bridge ABI table)
// Everything else is `visibility=hidden`.

#include <dlfcn.h>
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

// ---------------------------------------------------------------------------
// NativeBridge2 — the Android native-bridge interface.
//
// We only need a couple of fields out of this struct to be a
// functional "no-op" native bridge. The struct layout here is the
// public Android layout (defined in AOSP's
// frameworks/base/core/jni/nativebridge/Android.s.txt). We need a
// partial layout because ART calls the first member (initialize) at
// startup and we don't want to depend on a private header.
//
// On stock devices, ro.dalvik.vm.native.bridge is empty and ART never
// touches any of these. On devices where the property is set (Houdini
// for ARM-x86 translation, or our case), ART dlopens the named .so
// and looks for `NativeBridge2Itf`.
// ---------------------------------------------------------------------------
struct NativeBridgeCallbacks {
    uint32_t version;
    uint32_t (*initialize)(const struct NativeBridgeCallbacks** cb);
    // ... many more callbacks we don't need for the bootstrap stage
    // We only define the first two because that's all we ever call.
};

// Symbols we look up in the *real* native bridge (if present).
typedef uint32_t (*InitializeFn)(const struct NativeBridgeCallbacks** cb);

// Path to libpayload.so. We expect it next to us under
// /system/lib64/libpayload.so (the daemon sets up the bind-mount).
static constexpr const char* kPayloadPath =
    "/system/lib64/libpayload.so";

static void* g_real_native_bridge = nullptr;
static void* g_payload            = nullptr;
static int   g_initialized        = 0;

// ---------------------------------------------------------------------------
// Forward decls
// ---------------------------------------------------------------------------
static void  try_load_real_native_bridge();
static void  try_load_payload();

// ---------------------------------------------------------------------------
// NativeBridge2Itf — the table ART dlopen-s us to find. We declare it
// as a global with default visibility so it shows up in the .so's
// export table. Only the first two fields are populated; the rest is
// zero. ART will check the version field and call initialize().
// ---------------------------------------------------------------------------
__attribute__((visibility("default")))
const struct NativeBridgeCallbacks NativeBridge2Itf = {
    .version = 2,
    .initialize = [](const struct NativeBridgeCallbacks** cb) -> uint32_t {
        ZS_LOGI("libzygisk: NativeBridge2Itf.initialize called");

        // Load the *real* native bridge so we don't break translation
        // on devices that need it (e.g. x86 phones with ARM
        // translation, ChromeOS-style bridge, etc.).
        try_load_real_native_bridge();

        // Then load libpayload.so — that's where all the Zygisk
        // loader logic actually lives.
        try_load_payload();

        g_initialized = 1;

        // Forward to the real bridge if it has its own initialize
        // hook. Otherwise return 0 (success) so ART doesn't bail.
        if (g_real_native_bridge) {
            auto init = (InitializeFn)dlsym(g_real_native_bridge, "NativeBridge2Itf");
            if (init) return init(cb);
        }
        return 0; // 0 = success
    },
};

// ---------------------------------------------------------------------------
// JNI_OnLoad — called by ART if our .so is loaded as a JNI library.
// We don't do anything Zygisk-specific here; we just register
// ourselves as "loaded" so ART doesn't unload us.
// ---------------------------------------------------------------------------
extern "C"
__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    ZS_LOGI("libzygisk: JNI_OnLoad called");
    return JNI_VERSION_1_6;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void try_load_real_native_bridge() {
    // The stock path on devices that need an actual bridge.
    // Empty on most stock Android.
    const char* path = nullptr;
    if (access("/system/lib64/libndk_translation.so", R_OK) == 0)
        path = "/system/lib64/libndk_translation.so";
    else if (access("/system/lib64/libnativebridge.so", R_OK) == 0)
        path = "/system/lib64/libnativebridge.so";

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
    g_payload = dlopen(kPayloadPath, RTLD_LAZY);
    if (!g_payload) {
        ZS_LOGE("libzygisk: dlopen(%s) failed: %s", kPayloadPath, dlerror());
        return;
    }

    // libpayload exports a single symbol `zygisk_study_payload_init`
    // which takes no arguments and runs the one-time setup (loads
    // modules, hooks fork). We call it now; it is idempotent.
    using InitFn = void (*)();
    auto init = (InitFn)dlsym(g_payload, "zygisk_study_payload_init");
    if (init) {
        init();
        ZS_LOGI("libzygisk: libpayload initialized");
    } else {
        ZS_LOGE("libzygisk: payload has no init symbol");
    }
}
