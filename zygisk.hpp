// SPDX-License-Identifier: Apache-2.0
// zygisk.hpp
//
// Public Zygisk module API surface — i.e. the C++ base class that third-
// party Zygisk modules derive from. This is the documented public API
// originally defined by Magisk's `zygisk/zygisk.hpp` and reused by every
// downstream Zygisk implementation (including this study project).
//
// The API is reproduced here from the public documentation
// (https://topjohnwu.github.io/Magisk/guides.html#zygisk) so that
// downstream modules written against that API can compile against this
// project unchanged. The interface contract is identical; the
// implementation behind it is original to this repository.
//
// A Zygisk module is a .so file placed under
//   /data/adb/modules/<module_id>/zygisk/<abi>.so
// On boot the loader (libpayload in this project) enumerates those .so
// files, dlopen-s each one, and looks up the symbol `zygisk_module`
// which must be a function returning a `ZygiskModule*` factory.
//
// The module then receives the four lifecycle callbacks below in
// order. The loader's job is to feed them in at the right moment
// relative to the zygote fork.

#pragma once

#include <jni.h>

namespace zygisk {

// ------------------------------------------------------------------
// Capabilities — feature flags a module can opt into.
// The loader checks the module's reported caps to decide whether to
// park data on its behalf or skip its callbacks entirely.
// ------------------------------------------------------------------
enum : uint32_t {
    // Module wants the process name and the nice name at pre-fork time.
    PROCESS_UNPRIORITY = 1u << 0,
    // Module wants the file descriptors of the companion socket pair
    // so it can talk to zygiskd directly from inside the app.
    MODULE_BINDER      = 1u << 1,
};

// ------------------------------------------------------------------
// Api — surface the loader exposes back to the module. Implemented by
// libpayload; a v-table pointer is handed to the module at registration
// time. The order here is fixed for binary compatibility.
// ------------------------------------------------------------------
class Api {
public:
    // Write a single value into the running process's environment
    // (properties, env vars, etc.). Used by modules that need to
    // scrub/replace Magisk-related signals before the app's first
    // line of code runs.
    virtual void setOption(uint32_t option) = 0;

    // Module can ask the loader to dlopen another module's .so on
    // its behalf. Returns the unique handle (or -1 on error).
    virtual int  connectCompanion(void* handle) = 0;

    // Read the running process's package name. Empty string if the
    // loader hasn't populated it yet (e.g. during pre-server specialize).
    virtual void getModuleDir(char* out, size_t cap) = 0;

    // Read the running process's nice name (the per-process label
    // Android uses for logcat). Same caveat as getModuleDir.
    virtual void getProcessName(char* out, size_t cap) = 0;

    // Hook the JNIEnv of the new app. Returns 0 on success.
    virtual int  hookJniEnv(JNIEnv** env) = 0;

    // Schedule cleanup of any signals the module left behind before
    // the app's first user code runs. Called once per fork; idempotent.
    virtual void cleanTrace() = 0;

    // API version negotiation.
    virtual uint32_t apiVersion() = 0;
};

// ------------------------------------------------------------------
// Module — the C++ base class. A Zygisk module's .so must export an
// entry point `extern "C" ZygiskModule* zygisk_module(Api*, JNIEnv*)`
// returning a pointer to a heap-allocated instance of a class derived
// from this one.
// ------------------------------------------------------------------
class Module {
public:
    // Called once per module, very early, inside the zygote before any
    // fork has happened. The module can use this to:
    //   - request capabilities via api->setOption
    //   - open its own socket back to zygiskd
    //   - pre-load heavy resources
    virtual void onLoad(Api* api, JNIEnv* env) = 0;

    // Pre-fork callback for app processes. The module sees the
    // forked-inherited fds and may take action that survives the
    // fork (e.g. set up its own hook on libc functions). Returns
    // flags the loader uses to decide whether to call postApp.
    virtual void preAppSpecialize(Api* api, JNIEnv* env) {}

    // Post-fork callback for app processes. The process has now
    // specialized — i.e. setresuid / setresgid has happened, the
    // app's package name and Application object are known. This is
    // the last chance to alter the environment before user code.
    virtual void postAppSpecialize(const char* package_name,
                                    Api* api, JNIEnv* env) {}

    // Pre-fork callback for server processes (system_server).
    // Useful for modules that want to influence the system server's
    // view of the world before any system service starts.
    virtual void preServerSpecialize(Api* api, JNIEnv* env) {}

    // Post-fork callback for server processes.
    virtual void postServerSpecialize(Api* api, JNIEnv* env) {}

    // Module declares which capabilities it wants. The loader uses
    // this to size per-process state.
    virtual uint32_t caps() const { return 0; }

    // Empty virtual dtor for safe deletion through base pointer.
    virtual ~Module() = default;
};

} // namespace zygisk

// Every module .so must export this exact symbol. Signature:
//   extern "C" __attribute__((visibility("default")))
//   zygisk::Module* zygisk_module(zygisk::Api*, JNIEnv*);
#define ZYGISK_MODULE_ENTRY __attribute__((visibility("default")))
