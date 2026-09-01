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
//   15 slots (5+2+6+2), ending at getVendorNamespace — and (Round 27)
//   now extended to the current 20-slot AOSP layout: v5
//   getExportedNamespace, v6 preZygoteFork (both verified from
//   android-13.0.0_r1, art/libnativebridge — libnativebridge moved
//   into the art repo at Android 11), v7 getTrampolineWithJNICallType +
//   getTrampolineForFunctionPointer and v8 isNativeBridgeFunctionPointer
//   (android-16.0.0_r1 and refs/heads/main, byte-identical; 16 renamed
//   the v3 initAnonymousNamespace slot to unused_initAnonymousNamespace —
//   same position, ABI-stable). Every v5..v8 entry point in the 16/17
//   loader guards the slot with an isCompatibleWith(<v>) check (verified
//   from the loader source), so the slots must exist and be valid once
//   we claim those versions.
//
// THREE device-fatal fixes baked into this table (R25 + R27):
//
//   (a) libnativebridge 7.0–9.x CALLS callbacks->isCompatibleWith()
//       during LoadNativeBridge whenever version >= 2 (7.x asks about
//       version 2, 8.x/9.x about version 3). A NULL slot there is a
//       NULL CALL — zygote death at boot. Ours is implemented: true
//       for versions 1..8 (every slot we declare is a contract-valid
//       no-op or a forward to the real bridge), false for 0 and 9+
//       (we do not promise v9+ slots we do not have).
//
//   (b) Every slot the runtime can index is IMPLEMENTED — no NULLs.
//       NULL is only contract-valid for slots the runtime guards with
//       an isCompatibleWith check of its own; several slots (e.g.
//       getAppEnv, loadLibrary) are called UNGUARDED once a foreign-arch
//       app forks. Each no-op returns the contract's "feature absent"
//       answer, and each forwards to the real bridge (ndk_translation /
// houdini / libnativebridge) when one is present, gated on the real
//       table's version so we never index past its layout.
//
//   (c) R27, Android 5.x: the 5.0/5.1.1 loader (sources fetched and
//       read this round: system/core/libnativebridge at 5.0.0_r1 and
//       5.1.1_r37) has kNativeBridgeCallbackVersion = 1 and a
//       VersionCheck that demands cb->version == 1 EXACTLY — no
//       isCompatibleWith negotiation exists on 5.x. A version=2 table
//       is rejected ("Unsupported native bridge interface"), the
//       handle is dlclosed in the zygote, and every boot logs the
//       warning. select_table_version() therefore rewrites the version
//       field to 1 on SDK 21/22 before ART's dlsym/VersionCheck ever
//       runs (the constructor executes inside the same dlopen). The
//       5.x struct stops at getAppEnv — our 20-slot table is a
//       harmless superset (the loader only ever reads its five).

#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "obfstr.h"

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

// AOSP art/libnativebridge (android-16.0.0_r1 == refs/heads/main):
//   enum JNICallType { kJNICallTypeRegular = 1,
//                      kJNICallTypeCriticalNative = 2 };
// (v7 slots take it by value; the values are ABI.)
enum JNICallType {
    kJNICallTypeRegular       = 1,
    kJNICallTypeCriticalNative = 2,
};

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
    // v5 (verified from android-13.0.0_r1 and 16.0.0_r1/main):
    struct native_bridge_namespace_t* (*getExportedNamespace)(
        const char* name);
    // v6:
    void (*preZygoteFork)();
    // v7:
    void* (*getTrampolineWithJNICallType)(void* handle, const char* name,
                                          const char* shorty, uint32_t len,
                                          enum JNICallType jni_call_type);
    void* (*getTrampolineForFunctionPointer)(const void* method,
                                              const char* shorty,
                                              uint32_t len,
                                              enum JNICallType jni_call_type);
    // v8:
    bool (*isNativeBridgeFunctionPointer)(const void* method);
};

// Symbols we look up in the *real* native bridge (if present).
typedef bool (*InitializeFn)(const struct NativeBridgeCallbacks*,
                             const char*, const char*);

// Path to the payload, by word size. The daemon bind-mounts both
// libraries into the systemless /system tree. ROUND 33: the literals
// are obfuscated (ZS_OBFS) — this file is world-readable in
// /system/lib[64], and a plaintext "libpayload" inside a randomized
// file name would undo Round 30's rename entirely. The directory is
// a macro (not a ternary) so ZS_OBFS sees a true string literal and
// sizeof() yields the array size, not a pointer size.
#if defined(__LP64__)
#  define ZS_BRIDGE_DIR_LITERAL "/system/lib64"
#else
#  define ZS_BRIDGE_DIR_LITERAL "/system/lib"
#endif

// Copy the legacy fixed payload path for this bitness into `out`.
static void copy_legacy_payload_path(char* out, size_t cap) {
    snprintf(out, cap, "%s/%s",
             ZS_OBFS(ZS_BRIDGE_DIR_LITERAL), ZS_OBFS("libpayload.so"));
}

// Round 30 — randomized-soname support (STEALTH).
//
// customize.sh installs the bridge and the payload under per-install
// randomized names: lib<8-hex>.so (bridge) and lib<8-hex>-p.so
// (payload), recorded in the module's .loader_names file and mounted
// systemlessly into /system/lib[64]. A fixed "libzygisk.so" /
// "libpayload.so" in every process's /proc/self/maps is a trivial
// string-match signature for name-based Zygisk detectors; a random
// name per install defeats that class of scan (Magisk ships the
// fixed name — topjohnwu/Magisk daemon.rs, ZYGISKLDR — and accepts
// the exposure; we do not have to).
//
// The bridge learns the payload's name from ITS OWN mapped path:
// dladdr() reports the exact file the linker resolved for this
// library ("/system/lib64/lib<8-hex>.so"), and the payload's name
// is the same stem with a "-p" inserted before ".so" — the coupling
// customize.sh generates. Two fallbacks cover every other layout:
// the legacy fixed names (manual installs, host tests) and the
// plain soname (lets the default search path find a legacy
// libpayload.so next to the bridge, which is what the host
// version-compat tests do).
static void libzygisk_ctor();   // defined below (bootstrap section)
static void derive_payload_path(char* out, size_t cap) {
    if (!out || cap == 0) return;
    out[0] = '\0';
    Dl_info info{};
    if (dladdr((const void*)&libzygisk_ctor, &info) != 0 &&
        info.dli_fname && info.dli_fname[0] == '/') {
        const char* fname = info.dli_fname;
        size_t len = strlen(fname);
        // ".../lib<stem>.so" -> ".../lib<stem>-p.so"
        if (len >= 4 && strcmp(fname + len - 3, ".so") == 0 &&
            len + 2 < cap) {
            memcpy(out, fname, len - 3);
            memcpy(out + len - 3, "-p.so", 6);
            return;
        }
        // Any other extension shape: keep the directory and try the
        // legacy fixed name inside it (Round 33: obfuscated).
        const char* slash = strrchr(fname, '/');
        if (slash && (size_t)(slash - fname) + 1 + 14 < cap) {
            auto&& legacy = ZS_OBFS_H("libpayload.so");
            memcpy(out, fname, (size_t)(slash - fname) + 1);
            strcpy(out + (slash - fname) + 1, legacy.c_str());
            return;
        }
    }
    copy_legacy_payload_path(out, cap);
}

static void* g_real_native_bridge = nullptr;
static const struct NativeBridgeCallbacks* g_real_table = nullptr;
static void* g_payload            = nullptr;
static int   g_initialized        = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Round 33: probe helper — combines an obfuscated directory and
// candidate name into `path` and checks readability. The ZS_OBFS
// temporaries live through the snprintf inside this function (they
// are arguments of the full expression that is this call).
static bool probe_bridge_candidate(char* path, size_t cap,
                                    const char* name) {
    snprintf(path, cap, "%s/%s", ZS_OBFS(ZS_BRIDGE_DIR_LITERAL), name);
    return access(path, R_OK) == 0;
}

static void try_load_real_native_bridge() {
    // Round 33: candidate names obfuscated — plaintext "houdini" /
    // "ndk_translation" references inside a /system/lib64 resident
    // are an obvious tell for anyone comparing against the stock
    // library list.
    char path[64];
    if (probe_bridge_candidate(path, sizeof path,
                               ZS_OBFS("libndk_translation.so")) ||
        probe_bridge_candidate(path, sizeof path,
                               ZS_OBFS("libnativebridge.so")) ||
        probe_bridge_candidate(path, sizeof path,
                               ZS_OBFS("libhoudini.so"))) {
        g_real_native_bridge = dlopen(path, RTLD_LAZY);
    } else {
        path[0] = '\0';
    }
    if (!g_real_native_bridge) {
        ZS_LOGD("libzygisk: no real native bridge present");
        return;
    }
    // Round 25: keep the real bridge's TABLE so every bridge-ish slot
    // can forward to it (translation devices keep working). The handle
    // we keep ALSO pins the real bridge against our own child-side
    // unload story (a same-arch child never needs it; a foreign-arch
    // child kInitialize's the bridge instead of unloading it).
    g_real_table = (const struct NativeBridgeCallbacks*)dlsym(
        g_real_native_bridge, ZS_OBFS("NativeBridgeItf"));
    if (g_real_table && g_real_table->version < 1) {
        g_real_table = nullptr;   // refuse a garbage table
    }
}

static void try_load_payload() {
    // Round 30: randomized-soname install (see derive_payload_path):
    // try the name derived from our own mapped path first, then the
    // plain soname (legacy layout: the payload next to the bridge in
    // the linker search path), then the legacy absolute path. On a
    // device with the Round 30 install layout the derived name hits;
    // on host tests and manual installs the soname fallback resolves
    // ./libpayload.so exactly as before.
    char path[512];
    derive_payload_path(path, sizeof path);
    g_payload = dlopen(path, RTLD_LAZY);
    if (!g_payload) {
        g_payload = dlopen(ZS_OBFS("libpayload.so"), RTLD_LAZY);
    }
    if (!g_payload) {
        char legacy[64];
        copy_legacy_payload_path(legacy, sizeof legacy);
        g_payload = dlopen(legacy, RTLD_LAZY);
    }
    if (!g_payload) {
        ZS_LOGE("libzygisk: dlopen(%s) failed: %s", path, dlerror());
        return;
    }
    using InitFn = void (*)();
    auto init = (InitFn)dlsym(g_payload, ZS_OBFS("zs_entry_init"));
    if (init) {
        init();
        ZS_LOGI("libzygisk: libpayload initialized");
    } else {
        ZS_LOGE("libzygisk: payload has no init symbol");
    }
}

// ---------------------------------------------------------------------------
// Round 27: runtime table-version selection.
//
// The single exported table must satisfy EVERY loader generation:
//
//   5.0/5.1.1 (kNativeBridgeCallbackVersion = 1): VersionCheck demands
//       cb->version == 1 exactly — no negotiation (sources read at
//       android-5.0.0_r1 / android-5.1.1_r37 this round).
//   6.0+ (every version through 16.0.0_r1 and main, sources read):
//       VersionCheck/isCompatibleWith accepts any version >= 2 as long
//       as our isCompatibleWith(their version) says true — and 16/17
//       only expose their v5..v8 features when we claim those versions.
//
// So the version field is 1 on SDK 21/22 and 8 (the newest layout we
// implement) everywhere else. The write happens inside the constructor
// — the same dlopen the loader performs — i.e. strictly before ART's
// dlsym/VersionCheck can observe the field. The table lives in .data
// (deliberately non-const: a const struct of function pointers is
// relocated into .data.rel.ro and RELRO'd read-only; a non-const one
// is plain writable .data), so the rewrite needs no mprotect.
//
// __system_property_get is resolved through dlsym: it exists in every
// bionic since 1.0 but NOT on a host glibc, where the lookup cleanly
// returns null and we default to the modern layout.
// ---------------------------------------------------------------------------

// Round 27: picks the exported table's version field (defined after
// the table itself, below).
static void select_table_version();

static void bootstrap() {
    if (g_initialized) return;
    g_initialized = 1;
    ZS_LOGI("libzygisk: bootstrap (pid %d)", (int)getpid());
    select_table_version();
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
    // We implement every slot of versions 1..8 as a valid no-op (or a
    // forward) — the full 20-slot AOSP table through
    // isNativeBridgeFunctionPointer (verified byte-identical at
    // android-16.0.0_r1 and refs/heads/main = Android 17 dev; the
    // v5/v6 slots exist since 13.0.0_r1, v7/v8 are new in 16).
    // Versions above 8 would need slots we do not have — answer false
    // so the runtime logs-and-skips the feature instead of calling a
    // slot past our table.
    return bridge_version >= 1 && bridge_version <= 8;
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

// v5 slots (RUNTIME_NAMESPACE_VERSION = 5, verified from the 16/main
// loader: NativeBridgeGetExportedNamespace asks the bridge for a
// named exported namespace; sphal falls back to getVendorNamespace
// when the bridge predates v5 — a same-arch device with no real
// bridge simply has no bridged namespaces at all).
static struct native_bridge_namespace_t* native_bridge_get_exported_namespace(
        const char* name) {
    if (g_real_table && g_real_table->version >= 5 &&
        g_real_table->getExportedNamespace) {
        return g_real_table->getExportedNamespace(name);
    }
    return nullptr;  // "no such namespace" — the caller's documented
                     // fallback answer (nativeloader then resolves the
                     // library in its own namespaces)
}

// v6 slot (PRE_ZYGOTE_FORK_VERSION = 6). Called by
// PreZygoteForkNativeBridge() from Runtime::PreZygoteFork() — once per
// zygote fork, and in kInitialized processes only (app-zygote children
// on 10+). A bridge that needs no pre-fork work does nothing here;
// the real bridge's slot is forwarded so translation devices keep
// their behavior. Must stay cheap and idempotent.
static void native_bridge_pre_zygote_fork() {
    if (g_real_table && g_real_table->version >= 6 &&
        g_real_table->preZygoteFork) {
        g_real_table->preZygoteFork();
    }
    // else: nothing to prepare — forks are transparent to us.
}

// v7 slots (CRITICAL_NATIVE_SUPPORT_VERSION = 7, added in 16; both
// verified from the 16/main loader source). The loader itself falls
// back to the plain getTrampoline when the bridge predates v7 — our
// no-bridge path mirrors exactly that fallback.
static void* native_bridge_get_trampoline_with_jni_call_type(
        void* handle, const char* name, const char* shorty, uint32_t len,
        enum JNICallType jni_call_type) {
    (void)jni_call_type;   // a non-critical-aware bridge is the loader's
                           // own documented fallback case
    if (g_real_table && g_real_table->version >= 7 &&
        g_real_table->getTrampolineWithJNICallType) {
        return g_real_table->getTrampolineWithJNICallType(
            handle, name, shorty, len, jni_call_type);
    }
    return native_bridge_get_trampoline(handle, name, shorty, len);
}

static void* native_bridge_get_trampoline_for_function_pointer(
        const void* method, const char* shorty, uint32_t len,
        enum JNICallType jni_call_type) {
    if (g_real_table && g_real_table->version >= 7 &&
        g_real_table->getTrampolineForFunctionPointer) {
        return g_real_table->getTrampolineForFunctionPointer(
            method, shorty, len, jni_call_type);
    }
    return nullptr;  // no function-pointer trampolines without a real
                     // translation bridge
}

// v8 slot (IDENTIFY_NATIVELY_BRIDGED_FUNCTION_POINTERS_VERSION = 8,
// added in 16): "is this code pointer a bridge-generated trampoline?"
// Without a real bridge nothing in this process is one.
static bool native_bridge_is_native_bridge_function_pointer(
        const void* method) {
    if (g_real_table && g_real_table->version >= 8 &&
        g_real_table->isNativeBridgeFunctionPointer) {
        return g_real_table->isNativeBridgeFunctionPointer(method);
    }
    return false;
}

// ---------------------------------------------------------------------------
// NativeBridgeItf — the table ART dlsym()s. ART's loader (AOSP
// libnativebridge: system/core/libnativebridge through 10, then
// art/libnativebridge from 11 on) looks up NATIVE_BRIDGE_SYMBOL ==
// "NativeBridgeItf" and, on every version studied (5.0 through
// 16.0.0_r1 and main), either demands version == 1 exactly (5.x),
// requires version >= 2, or asks isCompatibleWith(...) — all answered
// by our table after select_table_version() picks the field.
//
// Round 27: the object is deliberately NON-CONST. A const struct of
// function pointers is relocated into .data.rel.ro, which the linker
// seals read-only (RELRO) — a runtime version rewrite would then need
// an mprotect that could also hit unrelated data sharing the page. A
// plain non-const definition lives in writable .data, so the
// constructor-time rewrite of the version field is a plain store.
// Visibility("default") + extern "C" still export the symbol for
// dlsym exactly as before (the symbol type changes from R to D, which
// no loader inspects).
// ---------------------------------------------------------------------------
extern "C" {
__attribute__((visibility("default")))
struct NativeBridgeCallbacks NativeBridgeItf = {
    .version = 8,   // the newest layout we implement (see
                    // select_table_version(): rewritten to 1 on
                    // Android 5.x, where the loader demands an exact
                    // match; every 6.0+ loader negotiates through
                    // isCompatibleWith, which we answer honestly)
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
    // v5..v8 (Round 27: the 16/17 extension slots; 13 knows through
    // preZygoteFork, 16/main through isNativeBridgeFunctionPointer)
    .getExportedNamespace = &native_bridge_get_exported_namespace,
    .preZygoteFork = &native_bridge_pre_zygote_fork,
    .getTrampolineWithJNICallType =
        &native_bridge_get_trampoline_with_jni_call_type,
    .getTrampolineForFunctionPointer =
        &native_bridge_get_trampoline_for_function_pointer,
    .isNativeBridgeFunctionPointer =
        &native_bridge_is_native_bridge_function_pointer,
};  // NativeBridgeItf
}   // extern "C"

// Historical alias: the pre-Round-7 code exported this (wrong) name.
// Kept so old documentation/references still resolve. Deliberately a
// SEPARATE SNAPSHOT (a copy of the initial values, version pinned to
// 2): nobody dlsym()s it, and it must not alias the live table whose
// version field now rewrites at runtime. Non-const for the same
// reason as the live table (const would give it internal linkage and
// silently un-export the symbol).
extern "C" {
__attribute__((visibility("default")))
struct NativeBridgeCallbacks NativeBridge2Itf = {
    .version = 2,
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
    .getExportedNamespace = &native_bridge_get_exported_namespace,
    .preZygoteFork = &native_bridge_pre_zygote_fork,
    .getTrampolineWithJNICallType =
        &native_bridge_get_trampoline_with_jni_call_type,
    .getTrampolineForFunctionPointer =
        &native_bridge_get_trampoline_for_function_pointer,
    .isNativeBridgeFunctionPointer =
        &native_bridge_is_native_bridge_function_pointer,
};  // NativeBridge2Itf
}   // extern "C"

#ifdef ZS_HOST_TEST
// Test seam: when non-negative, overrides the SDK detection. (Brace-
// form extern "C": a storage-class extern together with an initializer
// is the one spelling -Wall flags.)
extern "C" {
int zs_test_libzygisk_sdk_override = -1;
}
#endif

// PROP_VALUE_MAX is 92 on every Android release (verified in the 5.x
// and 16 headers this round); glibc hosts lack the header, so spell
// the bound locally instead of pulling in <sys/system_properties.h>.
static constexpr int kPropValueMax = 92;

static int detect_android_sdk() {
#ifdef ZS_HOST_TEST
    if (zs_test_libzygisk_sdk_override >= 0)
        return zs_test_libzygisk_sdk_override;
#endif
    using PropGetFn = int (*)(const char*, char*);
    auto prop_get = (PropGetFn)dlsym(RTLD_DEFAULT, "__system_property_get");
    if (!prop_get) return -1;   // host / unknown: modern default
    char v[kPropValueMax] = {0};
    // __system_property_get returns the value LENGTH (0 = not found);
    // an sdk string is 2+ chars ("21".."37"+), never negative.
    if (prop_get("ro.build.version.sdk", v) <= 0 || !v[0]) return -1;
    return atoi(v);
}

static void select_table_version() {
    int sdk = detect_android_sdk();
    // 5.x (API 21/22) is the only exact-match loader: serve v1.
    // Everything else negotiates and can use the full 20-slot table.
    uint32_t v = (sdk == 21 || sdk == 22) ? 1u : 8u;
    if (NativeBridgeItf.version != v) {
        ZS_LOGI("libzygisk: table version %u (sdk %d)",
                (unsigned)v, sdk);
        NativeBridgeItf.version = v;
    }
}



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
    // call during LoadNativeBridge / foreign-arch forks; Round 27
    // extended the same invariant to the 16/17 v5–v8 slots).
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
    if (!t->getExportedNamespace) return 0;
    if (!t->preZygoteFork) return 0;
    if (!t->getTrampolineWithJNICallType) return 0;
    if (!t->getTrampolineForFunctionPointer) return 0;
    if (!t->isNativeBridgeFunctionPointer) return 0;
    return 1;
}

// Round 27: expose the LIVE version field (post-constructor) and the
// SDK seam so tests can drive the 5.x/16/17 selection matrix.
extern "C" __attribute__((visibility("default")))
uint32_t zs_test_libzygisk_table_version() {
    return NativeBridgeItf.version;
}

extern "C" __attribute__((visibility("default")))
void zs_test_libzygisk_rescan_sdk() {
    select_table_version();
}

extern "C" __attribute__((visibility("default")))
int zs_test_libzygisk_is_compatible(uint32_t v) {
    return native_bridge_is_compatible(v) ? 1 : 0;
}

// Round 30: the randomized-soname derivation (see
// derive_payload_path). The test dlopens this .so, calls this, and
// asserts the derived path is our own path with "-p" before ".so".
extern "C" __attribute__((visibility("default")))
const char* zs_test_libzygisk_derived_payload_path() {
    static char path[512];
    derive_payload_path(path, sizeof path);
    return path;
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
