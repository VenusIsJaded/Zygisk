// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/module_dispatch.h
//
// Round 12 — the module dispatch layer ("that feature"):
//
//   Before this round, modules were dlopen'd and constructed in the
//   zygote, then NEVER CALLED. zygisk.hpp's lifecycle (onLoad /
//   preAppSpecialize / postAppSpecialize / preServerSpecialize /
//   postServerSpecialize) existed only as a header comment, the
//   JNIEnv handed to modules was nullptr, and hookJniEnv /
//   connectCompanion were stubs. This file is the real driver.
//
// How each piece is sourced (all without ART-internal hooking —
// see zygisk.hpp for the design rationale):
//
//   JNIEnv    — JNI_GetCreatedJavaVMs (dlsym, libart fallback) +
//               GetEnv / AttachCurrentThreadAsDaemon on the zygote's
//               main thread, lazily at the FIRST fork (the earliest
//               moment the VM exists and we still run pre-fork).
//               Children inherit the pointer; it stays valid on the
//               same thread after fork + specialize.
//   identity  — the setresgid/setresuid arguments the runtime passes
//               during specialization (uid >= 10000 -> app;
//               uid == 1000 -> system_server), plus packages.list for
//               the uid -> package name / app_data_dir mapping.
//   ordering  — pre callbacks at the setresuid/setuid hook ENTRY
//               (child still root; uid/gid WRITES from the module are
//               forwarded to the real calls); post callbacks right
//               AFTER the real privilege drop, before any unmap.
//
// DenyList contract (same as upstream Zygisk): denylisted processes
// do NOT run module callbacks — they take the hide pipeline instead,
// which unmaps the module .so's. setOption(FORCE_DENYLIST_UNMOUNT)
// opts a module into unmounting everywhere; in that case callbacks
// still run, and the unmount happens after the post callback.
#pragma once

#include <sys/types.h>

#include "zygisk.hpp"

namespace zygisk_study {

// One-time: load modules from the daemon list (dlopen + factory) and
// register their .so paths with the hide layer's unmap set. Called
// from payload init (native-bridge initialize time, zygote). Reads
// the daemon's session file first (Round 13) so the module fetch
// connects through the randomized per-boot socket path.
void zs_module_init();

// Round 19 — one lazy-init attempt for every daemon-dependent step:
// the module list fetch ('L') and the spoofed properties_serial file
// send ('P'). Attempted at zs_module_init AND at every ZYGOTE fork
// (from zs_impl_fork) until each latches — on real devices the
// daemon (started by service.sh, late service stage) is never up at
// native-bridge init time, so the Round 12-14 module dispatch was
// dead code on device without this retry. Returns 1 when everything
// is latched (or definitively unavailable), 0 = retry next fork.
int  zs_module_lazy_daemon_init();
// ROUND 39 (C1): 1 when the zygote-context module infrastructure is
// denied by SELinux POLICY (EACCES on the daemon/session socket),
// not merely "daemon not up" (ENOENT). See module_dispatch.cpp.
int  zs_module_env_denied();
// ROUND 39 (C1): one bounded probe (socket connect) + the session
// file read. Trips the gate ONLY on a POLICY denial (EACCES).
// Called at payload init, before any GOT hook is installed.
int  zs_module_env_probe();

// Round 13 — read /data/adb/modules/zygisk_study/session.sock (the
// daemon's randomized per-boot socket path handoff; root-only
// location). On success: switches the module-fetch/companion socket
// to it and registers the random directory with the mount-unmount,
// fd-close, and /proc/net/unix filters. Returns 1 when loaded, 0
// when the file is absent (pre-R13 daemon: fixed path stands).
int  zs_module_load_session_socket();

// Override the daemon socket path (used by the session reader; also
// the hook for test seams).
void zs_module_set_daemon_socket(const char* path);

// Capture the zygote's own argv[0] so the nice-name fallback in
// fill_app_args can recognize "name not rewritten yet" children.
// Called from payload init.
void zs_module_capture_zygote_name();

// Called from the fork GOT hook while we are still the zygote
// (getpid() == origin): acquire the JNIEnv and dispatch onLoad to
// every module exactly once. Cheap after the first call (one atomic
// load). Children inherit the "already ran" state.
void zs_module_on_first_fork();

// ---- per-child dispatch (called from the privilege-drop hooks) ----

// Record the gid the runtime is about to install (from the
// setresgid/setgid hook — it fires BEFORE the uid drop). Used to fill
// AppSpecializeArgs.gid for the pre callback.
void zs_module_record_gid(gid_t gid);

// The gid recorded by the last zs_module_record_gid call in this
// process (0 when the gid-drop hook never fired). entry.cpp uses it
// to detect a module-requested gid override.
gid_t zs_module_recorded_gid();

// Classification of the child, from the uid the runtime is about to
// install. Public for the dispatch tests.
enum ZsChildKind {
    ZS_CHILD_NONE   = 0,   // not a zygote app/server specialization
    ZS_CHILD_APP    = 1,   // uid >= 10000
    ZS_CHILD_SERVER = 2,   // uid == 1000 (system_server)
};

ZsChildKind zs_module_classify(uid_t uid);

// Dispatch preAppSpecialize / preServerSpecialize. Called at the
// setresuid/setuid hook ENTRY — the child is still root.
//
// `uid` is the argument the runtime passed; the module may overwrite
// *out_uid / *out_gid through the args pointers — the caller must
// forward the returned values to the real privilege-drop calls.
// Returns ZS_CHILD_NONE when nothing was dispatched (caller keeps
// the original arguments).
//
// Round 36 — `nice_name_override` (nullable): the isolated-process
// deferral dispatch calls this from the selinux_android_setcontext
// hook, AFTER the uid drop, where the FULL untruncated nice_name is
// finally available (it is not an argument of setresuid, and
// /proc/self/cmdline still holds the zygote's name at that point).
// When non-null it is copied into the module-visible
// AppSpecializeArgs.niceName verbatim ("com.pkg:svc" — the shape
// real Zygisk reports for isolated processes); the package_name
// lookup stays uid-based (isolated uids own no package — the field
// is empty, same as the uid-map path).
ZsChildKind zs_module_pre_specialize(uid_t uid, uid_t* out_uid,
                                     uid_t* out_gid,
                                     const char* nice_name_override = nullptr);

// Dispatch postAppSpecialize / postServerSpecialize. Called right
// after the real privilege drop (the module .so's are still mapped —
// the unmap, if any, runs after this).
void zs_module_post_specialize();

// True when any loaded module called setOption(FORCE_DENYLIST_UNMOUNT)
// (in the zygote — children inherit the flag).
int  zs_module_force_unmount();

// True when at least one loaded module overrode a specialize callback
// or asked for capabilities — lets the hot path skip all dispatch
// work when zero modules are interested. (The common boot with no
// modules installed costs one atomic load per fork.)
// extern "C": resolved by dlsym from the dispatch test.
extern "C" int  zs_module_dispatch_wanted();

// Did onLoad already run (in the zygote)? Exposed for tests.
extern "C" int  zs_module_onload_done();

#ifdef ZS_HOST_TEST
// Test seam: point the daemon-socket client at a different path (the
// production path lives under /data/system and is not writable on the
// host). NULL restores the production path.
extern "C" void zs_test_set_daemon_socket(const char* path);

// Test seam: replace the real privilege-drop thunks with recorders so
// tests can assert that module-modified uid/gid values were forwarded.
struct ZsDropSeam {
    long (*setresgid)(gid_t, gid_t, gid_t);
    long (*setresuid)(uid_t, uid_t, uid_t);
    long (*setgid)(gid_t);
    long (*setuid)(uid_t);
};
extern "C" void zs_test_set_drop_seam(const ZsDropSeam* seam);
extern "C" ZsDropSeam* zs_test_drop_seam();   // entry.cpp consults this

// Test seam: reset the per-child dispatch state between test cases
// (production children get fresh copy-on-write statics for free).
extern "C" void zs_test_reset_child_state();

// Test seam (Round 13): point the session-file reader at a host-
// writable path and drive it directly.
extern "C" void zs_test_set_session_file(const char* path);
extern "C" int  zs_test_load_session();
#endif // ZS_HOST_TEST

} // namespace zygisk_study
