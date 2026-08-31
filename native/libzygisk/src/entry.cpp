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
//   3. Round 25 (the version-research round): the dlopen happens inside
//      Runtime::Init(), IN THE ZYGOTE, on every Android version
//      studied (7.0 / 7.1.2 / 8.0 / 8.1 / 9.0 / 13.0 — sources fetched
//      and read this round). But ART NEVER calls initialize() there:
//      ZygoteHooks_nativePostForkChild (which runs in every FORKED
//      child) is what calls InitNonZygoteOrPostFork, and it passes
//      NativeBridgeAction::kUnload for every same-arch child — i.e.
//      the runtime dlcloses our library handle in every app child and
//      never runs our initialize() in the zygote at all. The pre-Round-25
//      design (bootstrap from initialize()) therefore never executed on
//      a real device: no hooks, no modules, nothing.
//
//      The bootstrap now runs from a library CONSTRUCTOR —
//      __attribute__((constructor)) — which the dynamic linker runs
//      inside the zygote during that same dlopen, before Runtime::Init
//      returns, before the first fork. This is version-independent
//      (constructors always run at dlopen) and is also the earliest
//      possible point in the process.
//
//      The child-side dlclose is neutralized TWICE: libpayload
//      self-pins at init (dlopen(self, RTLD_NOLOAD), see
//      native/libpayload/src/entry.cpp) and BOTH libraries are linked
//      with -z nodelete (see the CMakeLists). The link flag is the
//      load-bearing one: bionic's soinfo_unload calls DT_FINI when a
//      refcount hits zero, and a Tier A (self-unmapped) hidden child
//      no longer has that code mapped — the destructor call would be
//      a crash in every hidden Tier A child at callPostForkChildHooks.
//      NODELETE makes can_unload() fail and the unload return before
//      any destructor runs (bionic linker sources read this round at
//      7.1.2/8.1; there is no exit-time destructor walk in bionic
//      either, so nothing else can reach that fini).
//
// Round 7 history (kept for context):
//
//   - The exported symbol was "NativeBridge2Itf". ART looks up
//     "NativeBridgeItf" — as-shipped, ART would never even find our
//     table (the native bridge would be reported broken). Both names
//     are now exported (the historical one kept as an alias).
//
//   - The NativeBridgeCallbacks table was declared with only two
//     fields. ART indexes deep into this struct; a short struct made
//     ART read whatever .data happened to sit behind it. The full
//     table is now declared (Round 25: exactly the AOSP layout, see
//     below).
//
//   - initialize()'s signature is the real one:
//     bool initialize(const NativeBridgeCallbacks* cb,
//                     const char* app_cache_dir, const char* isa).
//
//   - The payload path respects the process word size (32-bit zygote
//     forks load from /system/lib, 64-bit from /system/lib64).
//
// Round 25 — the table itself (researched from AOSP
// system/core/libnativebridge/include/nativebridge/native_bridge.h at
// android-7.0.0_r1, android-7.1.2_r33, android-8.0.0_r17,
// android-8.1.0_r81 and android-9.0.0_r1; 8.1 and 9.0 are
// byte-identical, and 7.x's table is a strict 8-slot prefix of it):
//
//   v1: initialize, loadLibrary, getTrampoline, isSupported, getAppEnv
//   v2: isCompatibleWith, getSignalHandler
//   v3: unloadLibrary, getError, isPathSupported, initAnonymousNamespace,
//       createNamespace, linkNamespaces
//   v4: loadLibraryExt, getVendorNamespace
//
//   15 slots (5+2+6+2), ending at getVendorNamespace — the final
//   layout (versions past 9 kept it; later additions go through
//   isCompatibleWith negotiation, which we answer honestly).
//
// TWO device-fatal Round 25 fixes baked into this table:
//
//   (a) libnativebridge 7.0–9.x CALLS callbacks->isCompatibleWith()
//       during LoadNativeBridge whenever version >= 2 (7.x asks about
//       version 2, 8.x/9.x about version 3). A NULL slot there is a
//       NULL CALL — zygote death at boot. Ours is implemented: true
//       for versions 1..4 (every slot we declare is a contract-valid
//       no-op or a forward to the real bridge), false above (we do
//       not promise v5+ slots we do not have).
//
//   (b) Every slot the runtime can index is IMPLEMENTED — no NULLs.
//       NULL is only contract-valid for slots the runtime guards with
//       an isCompatibleWith check of its own; several slots (e.g.
//       getAppEnv, loadLibrary) are called UNGUARDED once a foreign-arch
//       app forks. Each no-op returns the contract's "feature absent"
//       answer, and each forwards to the real bridge (ndk_translation /
// houdini / libnativebridge) when one is present, gated on the real
//       table's version so we never index past its layout.

#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

// ---------------------------------------------------------------------------
// NativeBridge — the Android native-bridge interface (AOSP
// system/core/libnativebridge/include/nativebridge/native_bridge.h).
//
// The layout is the 15-slot authoritative table (verified byte-identical
// at android-8.1.0_r81 and android-9.0.0_r1; android-7.0.0_r1 /
// android-7.1.2_r33 read exactly the first 8 slots of it). A LONGER
// table than the caller's expectation is harmless (the caller only
// reads its own slots); a SHORT one made ART index into adjacent
// .data — the Round 7 fix that is preserved here.
// ---------------------------------------------------------------------------

// Opaque AOSP types (never dereferenced by us).
struct NativeBridgeRuntimeCallbacks;
struct NativeBridgeRuntimeValues;
struct native_bridge_namespace_t;

// AOSP: typedef bool (*NativeBridgeSignalHandlerFn)(int, siginfo_t*, void*);
// (declared with the exact parameter types so the slot is ABI-correct
// even if a runtime ever hands it to the signal chain).
typedef bool (*NativeBridgeSignalHandlerFn)(int, siginfo_t*, void*);

struct NativeBridgeCallbacks {
    uint32_t version;
    // v1:
    bool (*initialize)(const struct NativeBridgeCallbacks* callbacks,
                       const char* app_cache_dir, const char* isa);
    void* (*loadLibrary)(const char* libpath, int flag);
    void* (*getTrampoline)(void* handle, const char* name,
                           const char* shorty, uint32_t len);
    bool (*isSupported)(const char* libpath);
    const struct NativeBridgeRuntimeValues* (*getAppEnv)(
        const char* instruction_set);
    // v2:
    bool (*isCompatibleWith)(uint32_t bridge_version);
    NativeBridgeSignalHandlerFn (*getSignalHandler)(int signal);
    // v3:
    int (*unloadLibrary)(void* handle);
    const char* (*getError)();
    bool (*isPathSupported)(const char* library_path);
    bool (*initAnonymousNamespace)(const char* public_ns_sonames,
                                   const char* anon_ns_library_path);
    struct native_bridge_namespace_t* (*createNamespace)(
        const char* name, const char* ld_library_path,
        const char* default_library_path, uint64_t type,
        const char* permitted_when_isolated_path,
        struct native_bridge_namespace_t* parent_ns);
    bool (*linkNamespaces)(struct native_bridge_namespace_t* from,
                           struct native_bridge_namespace_t* to,
                           const char* shared_libs_sonames);
    // v4:
    void* (*loadLibraryExt)(const char* libpath, int flag,
                            struct native_bridge_namespace_t* ns);
    struct native_bridge_namespace_t* (*getVendorNamespace)();
};

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
static const struct NativeBridgeCallbacks* g_real_table = nullptr;
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
    else if (access("/system/lib64/libhoudini.so", R_OK) == 0)
        path = "/system/lib64/libhoudini.so";
#else
    if (access("/system/lib/libndk_translation.so", R_OK) == 0)
        path = "/system/lib/libndk_translation.so";
    else if (access("/system/lib/libnativebridge.so", R_OK) == 0)
        path = "/system/lib/libnativebridge.so";
    else if (access("/system/lib/libhoudini.so", R_OK) == 0)
        path = "/system/lib/libhoudini.so";
#endif
    if (!path) {
        ZS_LOGD("libzygisk: no real native bridge present");
        return;
    }
    g_real_native_bridge = dlopen(path, RTLD_LAZY);
    if (!g_real_native_bridge) {
        ZS_LOGW("libzygisk: dlopen(%s) failed: %s", path, dlerror());
        return;
    }
    // Round 25: keep the real bridge's TABLE so every bridge-ish slot
    // can forward to it (translation devices keep working). The handle
    // we keep ALSO pins the real bridge against our own child-side
    // unload story (a same-arch child never needs it; a foreign-arch
    // child kInitialize's the bridge instead of unloading it).
    g_real_table = (const struct NativeBridgeCallbacks*)dlsym(
        g_real_native_bridge, "NativeBridgeItf");
    if (g_real_table && g_real_table->version < 1) {
        g_real_table = nullptr;   // refuse a garbage table
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

// Idempotent bootstrap: constructor (zygote, at dlopen) AND initialize
// (kept for the rare foreign-arch child that actually receives the
// kInitialize action — and for any future runtime that changes the
// lifecycle again). Whichever runs first wins; the payload's own init
// is CAS-guarded, so a second entry is a no-op there.
static void bootstrap() {
    if (g_initialized) return;
    g_initialized = 1;
    ZS_LOGI("libzygisk: bootstrap (pid %d)", (int)getpid());
    try_load_real_native_bridge();
    try_load_payload();
}

// Round 25: THE bootstrap point. The linker runs this inside the
// zygote during Runtime::Init's dlopen of the bridge — before any
// fork, before the VM finishes initializing, before anything else can
// observe the process. See the file header for the version research
// that moved the bootstrap here (initialize() is never called in the
// zygote on ANY studied Android version).
__attribute__((constructor))
static void libzygisk_ctor() {
    bootstrap();
}

static bool native_bridge_initialize(const struct NativeBridgeCallbacks* cb,
                                     const char* app_cache_dir,
                                     const char* isa) {
    (void)cb;
    ZS_LOGI("libzygisk: NativeBridgeItf.initialize called");
    // Constructor already bootstrapped us; this is now just the
    // forward to the real bridge (which does its own real setup on
    // translation devices).
    bootstrap();
    if (g_real_table && g_real_table->initialize) {
        return g_real_table->initialize(cb, app_cache_dir, isa);
    }
    return true;  // success
}

// ---------------------------------------------------------------------------
// The no-op / forwarding slots. Every value is the contract's
// "feature absent" answer when no real bridge is present, and a
// version-gated forward when one is.
// ---------------------------------------------------------------------------

static bool native_bridge_is_compatible(uint32_t bridge_version) {
    // We implement every slot of versions 1..4 as a valid no-op (or a
    // forward). Versions above 4 would need slots we do not have —
    // answer false so the runtime logs-and-skips the feature instead
    // of calling a slot past our table.
    return bridge_version >= 1 && bridge_version <= 4;
}

// v1 slots — called UNGUARDED by the runtime once a foreign-arch app
// forks, so these must never be NULL.
static void* native_bridge_load_library(const char* libpath, int flag) {
    if (g_real_table && g_real_table->version >= 1 &&
        g_real_table->loadLibrary) {
        return g_real_table->loadLibrary(libpath, flag);
    }
    return nullptr;   // no translation available: the load fails cleanly
}

static void* native_bridge_get_trampoline(void* handle, const char* name,
                                          const char* shorty, uint32_t len) {
    if (g_real_table && g_real_table->version >= 1 &&
        g_real_table->getTrampoline) {
        return g_real_table->getTrampoline(handle, name, shorty, len);
    }
    return nullptr;
}

static bool native_bridge_is_supported(const char* libpath) {
    if (g_real_table && g_real_table->version >= 1 &&
        g_real_table->isSupported) {
        return g_real_table->isSupported(libpath);
    }
    return false;    // same-arch device: every lib loads the normal way
}

static const struct NativeBridgeRuntimeValues* native_bridge_get_app_env(
        const char* instruction_set) {
    if (g_real_table && g_real_table->version >= 1 &&
        g_real_table->getAppEnv) {
        return g_real_table->getAppEnv(instruction_set);
    }
    return nullptr;  // "no environment values needed" — the documented
                     // NULL-means-absent contract
}

// v2 slots. getSignalHandler returning NULL is the documented
// "bridge doesn't use a handler" answer; libnativebridge's own
// NativeBridgeGetSignalHandler then reports "no handler" to the
// signal chain.
static NativeBridgeSignalHandlerFn native_bridge_get_signal_handler(
        int signal) {
    if (g_real_table && g_real_table->version >= 2 &&
        g_real_table->getSignalHandler) {
        return g_real_table->getSignalHandler(signal);
    }
    return nullptr;
}

// v3 slots.
static int native_bridge_unload_library(void* handle) {
    if (g_real_table && g_real_table->version >= 3 &&
        g_real_table->unloadLibrary) {
        return g_real_table->unloadLibrary(handle);
    }
    return -1;       // nonzero = error (nothing was ever loaded through us)
}

static const char* native_bridge_get_error() {
    if (g_real_table && g_real_table->version >= 3 &&
        g_real_table->getError) {
        return g_real_table->getError();
    }
    return nullptr;
}

static bool native_bridge_is_path_supported(const char* library_path) {
    if (g_real_table && g_real_table->version >= 3 &&
        g_real_table->isPathSupported) {
        return g_real_table->isPathSupported(library_path);
    }
    return false;
}

static bool native_bridge_init_anon_namespace(
        const char* public_ns_sonames, const char* anon_ns_library_path) {
    if (g_real_table && g_real_table->version >= 3 &&
        g_real_table->initAnonymousNamespace) {
        return g_real_table->initAnonymousNamespace(public_ns_sonames,
                                                    anon_ns_library_path);
    }
    return false;
}

static struct native_bridge_namespace_t* native_bridge_create_namespace(
        const char* name, const char* ld_library_path,
        const char* default_library_path, uint64_t type,
        const char* permitted_when_isolated_path,
        struct native_bridge_namespace_t* parent_ns) {
    if (g_real_table && g_real_table->version >= 3 &&
        g_real_table->createNamespace) {
        return g_real_table->createNamespace(
            name, ld_library_path, default_library_path, type,
            permitted_when_isolated_path, parent_ns);
    }
    return nullptr;  // documented error answer: no namespace
}

static bool native_bridge_link_namespaces(
        struct native_bridge_namespace_t* from,
        struct native_bridge_namespace_t* to,
        const char* shared_libs_sonames) {
    if (g_real_table && g_real_table->version >= 3 &&
        g_real_table->linkNamespaces) {
        return g_real_table->linkNamespaces(from, to, shared_libs_sonames);
    }
    return false;
}

// v4 slots.
static void* native_bridge_load_library_ext(
        const char* libpath, int flag,
        struct native_bridge_namespace_t* ns) {
    if (g_real_table && g_real_table->version >= 4 &&
        g_real_table->loadLibraryExt) {
        return g_real_table->loadLibraryExt(libpath, flag, ns);
    }
    return nullptr;
}

static struct native_bridge_namespace_t* native_bridge_get_vendor_namespace() {
    if (g_real_table && g_real_table->version >= 4 &&
        g_real_table->getVendorNamespace) {
        return g_real_table->getVendorNamespace();
    }
    return nullptr;  // documented: no bridged vendor namespace
}

// ---------------------------------------------------------------------------
// NativeBridgeItf — the table ART dlsym()s. ART's loader (AOSP
// system/core/libnativebridge nativebridge.cc / native_bridge.cc)
// looks up NATIVE_BRIDGE_SYMBOL == "NativeBridgeItf" and, on every
// studied version, either requires version >= 2 (modern) or asks
// isCompatibleWith(...) (7.x–9.x) — both answered by our table.
//
// extern is required: a const object at namespace scope has internal
// linkage in C++ by default, which would silently NOT export the
// symbol ART dlsym()s.
// ---------------------------------------------------------------------------
extern "C" __attribute__((visibility("default")))
const struct NativeBridgeCallbacks NativeBridgeItf = {
    .version = 2,   // satisfies the >= 2 minimum on every version;
                    // isCompatibleWith() negotiates the rest honestly
    .initialize = &native_bridge_initialize,
    .loadLibrary = &native_bridge_load_library,
    .getTrampoline = &native_bridge_get_trampoline,
    .isSupported = &native_bridge_is_supported,
    .getAppEnv = &native_bridge_get_app_env,
    .isCompatibleWith = &native_bridge_is_compatible,
    .getSignalHandler = &native_bridge_get_signal_handler,
    .unloadLibrary = &native_bridge_unload_library,
    .getError = &native_bridge_get_error,
    .isPathSupported = &native_bridge_is_path_supported,
    .initAnonymousNamespace = &native_bridge_init_anon_namespace,
    .createNamespace = &native_bridge_create_namespace,
    .linkNamespaces = &native_bridge_link_namespaces,
    .loadLibraryExt = &native_bridge_load_library_ext,
    .getVendorNamespace = &native_bridge_get_vendor_namespace,
};

// Historical alias: the pre-Round-7 code exported this (wrong) name.
// Kept so old documentation/references still resolve.
extern "C" __attribute__((visibility("default")))
const struct NativeBridgeCallbacks NativeBridge2Itf = NativeBridgeItf;

// ---------------------------------------------------------------------------
// Test-only exports (host). The version-compat tests build this file,
// dlopen it, and verify the table + the constructor.
// ---------------------------------------------------------------------------
#ifdef ZS_HOST_TEST
extern "C" __attribute__((visibility("default")))
int zs_test_libzygisk_ctor_ran() {
    return g_initialized;
}

extern "C" __attribute__((visibility("default")))
int zs_test_libzygisk_table_slots() {
    // Every slot the runtime of ANY studied version can index must be
    // non-NULL (the Round 25 crash class: NULL slots that 7.x–9.x
    // call during LoadNativeBridge / foreign-arch forks).
    const struct NativeBridgeCallbacks* t = &NativeBridgeItf;
    if (!t->initialize) return 0;
    if (!t->loadLibrary) return 0;
    if (!t->getTrampoline) return 0;
    if (!t->isSupported) return 0;
    if (!t->getAppEnv) return 0;
    if (!t->isCompatibleWith) return 0;
    if (!t->getSignalHandler) return 0;
    if (!t->unloadLibrary) return 0;
    if (!t->getError) return 0;
    if (!t->isPathSupported) return 0;
    if (!t->initAnonymousNamespace) return 0;
    if (!t->createNamespace) return 0;
    if (!t->linkNamespaces) return 0;
    if (!t->loadLibraryExt) return 0;
    if (!t->getVendorNamespace) return 0;
    return 1;
}

extern "C" __attribute__((visibility("default")))
int zs_test_libzygisk_is_compatible(uint32_t v) {
    return native_bridge_is_compatible(v) ? 1 : 0;
}
#endif  // ZS_HOST_TEST

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
