// SPDX-License-Identifier: Apache-2.0
// zygisk.hpp
//
// Public Zygisk module API surface — i.e. the C++ base class that third-
// party Zygisk modules derive from. This is the documented public API
// originally defined by Magisk's `zygisk/zygisk.hpp` and reused by every
// downstream Zygisk implementation (including this study project).
//
// The interface contract is reproduced here from the public documentation
// (https://topjohnwu.github.io/Magisk/guides.html#zygisk) so that
// downstream modules written against that API can compile against this
// project unchanged. The implementation behind it is original to this
// repository.
//
// A Zygisk module is a .so file placed under
//   /data/adb/modules/<module_id>/zygisk/<abi>.so
// On boot the loader (libpayload in this project) enumerates those .so
// files, dlopen-s each one, and looks up the symbol `zygisk_module`
// which must be a function returning a `ZygiskModule*` factory.
//
// The module then receives the lifecycle callbacks below in
// order. The loader's job is to feed them in at the right moment
// relative to the zygote fork.
//
// Round 12 (API v2): the module lifecycle is now actually driven.
//
//   onLoad            — called once in the zygote, at the first fork
//                       (the earliest moment a JNIEnv exists), with a
//                       REAL JNIEnv obtained via JNI_GetCreatedJavaVMs.
//   preAppSpecialize  — called in the forked child at the
//                       setresuid/setuid hook ENTRY: the child is still
//                       root, and the specialize arguments are real.
//   postAppSpecialize — called right after the real privilege drop.
//   preServer/postServerSpecialize — same pair for system_server
//                       (uid 1000).
//
// AppSpecializeArgs deviates from upstream v4 on purpose: it contains
// only the arguments this loader can source WITHOUT ART-internal
// method hooking (which this project deliberately avoids). uid/gid
// are pointers into the live dispatch state — writes made in the pre
// callback are forwarded to the real privilege-drop calls. The string
// arguments are read-only C strings.

#pragma once

#include <stdint.h>
#include <stddef.h>

// The default callback bodies below are intentionally empty (modules
// opt in by overriding). Silence the unused-parameter warnings so the
// test builds stay clean with -Wall -Wextra.
#define ZS_UNUSED(x) (void)(x)

#if defined(__ANDROID__)
#include <jni.h>
#else
// Host builds (unit tests, static analysis) have no NDK jni.h. The
// payload only passes JNIEnv pointers through opaquely, so minimal
// typedefs are enough for the header to compile anywhere.
using JNIEnv = void;
using JavaVM = void;
using JNINativeInterface = void;
using jint = int;
using jboolean = unsigned char;
#define JNI_VERSION_1_6 0x00010006
#endif

namespace zygisk {

// ------------------------------------------------------------------
// Capabilities — feature flags a module can opt into.
// The loader checks the module's reported caps to decide whether to
// spend time on per-fork work (e.g. reading the process name only if
// some module declared it wants names).
// ------------------------------------------------------------------
enum : uint32_t {
    // Module wants the process/nice name at pre-specialize time.
    // Declaring nothing means the loader skips the /proc read on
    // every fork — see PERFORMANCE-CLAIMS.md (Round 12).
    PROCESS_UNPRIORITY = 1u << 0,
    // Module wants a file descriptor to the companion socket.
    MODULE_BINDER      = 1u << 1,
};

// ------------------------------------------------------------------
// AppSpecializeArgs — the real Zygote arguments this loader can see.
//
// Upstream's v4 struct exposes pointers into the Java-side argument
// list of forkAndSpecialize (jstring nice_name, jint runtime_flags,
// ...). Sourcing those requires hooking the JNI native methods
// themselves (ART ArtMethod patching), which this project avoids by
// design. What we CAN source honestly, at the privilege-drop hook:
//
//   uid/gid   — the actual arguments of the setresuid/setresgid the
//               runtime is about to execute. Writable in pre: the
//               modified values are forwarded to the real calls.
//   nice_name — /proc/self/cmdline of the child (the runtime rewrites
//               argv before specializing in the common path; if the
//               name is still the zygote's, the package name is used).
//   package_name — the owning package from packages.list.
//   app_data_dir — derived: /data/user/<uid/100000>/<package>.
//
// ------------------------------------------------------------------
struct AppSpecializeArgs {
    jint*       uid;
    jint*       gid;
    const char* nice_name;
    const char* package_name;
    const char* app_data_dir;
};

struct ServerSpecializeArgs {
    jint* uid;
    jint* gid;
};

// ------------------------------------------------------------------
// Api — surface the loader exposes back to the module. Implemented by
// libpayload; a v-table pointer is handed to the module at registration
// time. The order here is fixed for binary compatibility.
// ------------------------------------------------------------------
class Api {
public:
    enum Option {
        // Force the DenyList-style unmount for every process the
        // module runs in, even when the process is not denylisted.
        // Modules stay loaded and get their callbacks; the unmount
        // runs AFTER postAppSpecialize returns (their last executed
        // code — the module .so is then unmapped).
        FORCE_DENYLIST_UNMOUNT = 0,
    };

    // Set a loader option. Call from onLoad().
    virtual void setOption(Option option) = 0;

    // Connect to the companion daemon. Returns a blocking fd to the
    // daemon's companion channel, or -1 (module should fall back).
    virtual int  connectCompanion() = 0;

    // Read the running process's module directory (where the module
    // itself was loaded from).
    virtual void getModuleDir(char* out, size_t cap) = 0;

    // Read the running process's name.
    virtual void getProcessName(char* out, size_t cap) = 0;

    // Replace the JNI function table of `env` with `newTable`,
    // returning the previous table through `oldTable`. This is the
    // documented mechanism for module-side JNI hooking: the module
    // copies the original table, patches the slots it wants, installs
    // the copy, and keeps the original for chaining. Affects calls
    // made through that JNIEnv on that thread (the JNIEnv object is
    // per-thread ART state; the slot itself is writable memory).
    // Returns 0 on success.
    virtual int  hookJniEnv(JNIEnv* env, const JNINativeInterface* newTable,
                            const JNINativeInterface** oldTable) = 0;

    // Schedule cleanup of any signals the module left behind before
    // the app's first user code runs. Called once per fork; idempotent.
    virtual void cleanTrace() = 0;

    // API version negotiation. 2 since Round 12.
    virtual uint32_t apiVersion() = 0;
};

// ------------------------------------------------------------------
// Module — the C++ base class. A Zygisk module's .so must export an
// entry point `extern "C" zygisk::Module* zygisk_module(Api*, JNIEnv*)`
// returning a pointer to an instance of a class derived from this one.
// ------------------------------------------------------------------
class Module {
public:
    // Called once per module in the zygote, before the first fork.
    // The loader acquires a real JNIEnv (JNI_GetCreatedJavaVMs +
    // GetEnv/AttachCurrentThreadAsDaemon) for this call.
    virtual void onLoad(Api* api, JNIEnv* env) = 0;

    // Called in the forked app child while it is STILL ROOT (the
    // runtime's setresuid has not executed yet) with the specialize
    // arguments. Modules doing mount work must do it here.
    virtual void preAppSpecialize(JNIEnv* env, AppSpecializeArgs* args) {
        ZS_UNUSED(env); ZS_UNUSED(args);
    }

    // Called right after the real privilege drop: the process runs as
    // the app user and is on its way to executing app code.
    virtual void postAppSpecialize(const AppSpecializeArgs* args) {
        ZS_UNUSED(args);
    }

    // Server equivalents (system_server, uid 1000).
    virtual void preServerSpecialize(JNIEnv* env, ServerSpecializeArgs* args) {
        ZS_UNUSED(env); ZS_UNUSED(args);
    }
    virtual void postServerSpecialize(const ServerSpecializeArgs* args) {
        ZS_UNUSED(args);
    }

    // Module declares which capabilities it wants. The loader uses
    // this to skip per-fork work nobody asked for.
    virtual uint32_t caps() const { return 0; }

    // Empty virtual dtor for safe deletion through base pointer.
    virtual ~Module() = default;
};

} // namespace zygisk

// Every module .so must export this exact symbol. Signature:
//   extern "C" __attribute__((visibility("default")))
//   zygisk::Module* zygisk_module(zygisk::Api*, JNIEnv*);
#define ZYGISK_MODULE_ENTRY __attribute__((visibility("default")))
