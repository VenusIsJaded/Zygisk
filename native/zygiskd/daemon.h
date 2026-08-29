// zygiskd — from-scratch reimplementation
//
// zygiskd is the Zygisk Next root daemon. It runs as root in the
// post-fs-data stage and lives for the lifetime of the boot.
//
// Responsibilities
// -----------------
//   1. Read/write config under /data/adb/zygisksu/.
//   2. Open a Unix domain socket and accept connections from
//      libzygisk.so (in-zygote), libpayload.so (in-target-process),
//      the WebUI bridge (znctl symlink), and the kernel module
//      (KernelSU/APatch) for action.sh commands.
//   3. ptrace-attach to the zygote process, inject a call to
//      android_dlopen_ext("/data/adb/modules/zygisksu/lib*/libzygisk.so")
//      into zygote's address space, and pass a bridge socket fd
//      via sendmsg+SCM_RIGHTS.
//   4. Manage the module companion .so files (handled by libzn_loader
//      once we inject libzygisk — but we hand off the bridge).
//   5. Handle WebUI commands: status, list-modules, toggle module,
//      view logs, generate bugreport.
//
// Public surface (from the original binary's symbol table):
//   zygiskd has `main` (the C runtime entry), plus internal
//   symbols. The CLI subcommands are:
//
//     zygiskd daemon        — start the long-lived daemon
//     zygiskd service-stage — hook the service stage (called by
//                              service.sh after Zygote has started)
//     zygiskd exit          — drain and exit (called by
//                              emulated-soft-reboot.sh)
//     zygiskd status        — print a status summary (for WebUI)
//     zygiskd <webui-cmd>   — WebUI action commands routed through
//                              the znctl symlink
//
// Architecture (modules within this directory):
//   * main.cpp           — entry, arg parsing, dispatch
//   * daemon.cpp/.h      — main daemon loop (accept + route)
//   * ptrace_inject.cpp/.h — the ptrace-attach-and-inject logic
//   * ipc.cpp/.h         — wire protocol structures + helpers
//   * modules.cpp/.h     — module list cache, scanning
//   * webui_command.cpp/.h — WebUI command handlers
//   * config.cpp/.h      — config file I/O
//   * log.h              — logging macros (klog or stderr)
//
// The injection algorithm
// ------------------------
// 1. Find the zygote PID (parse /proc/*/cmdline for "zygote" or
//    "zygote64").
// 2. ptrace(PTRACE_ATTACH, pid, 0, 0). Wait for the SIGSTOP.
// 3. Save the zygote's register state (PTRACE_GETREGSET).
// 4. Use PTRACE_POKEDATA to write the path string
//    "/data/adb/modules/zygisksu/lib*/libzygisk.so" into zygote's
//    memory at a scratch area (we use the zygote's stack pointer
//    minus a delta, which is safe because the zygote is stopped).
// 5. Construct a remote call to dlopen() — find dlopen's address
//    in zygote's address space by parsing /proc/<pid>/maps for
//    libdl.so or by using linker hooks.
// 6. Set zygote's PC to dlopen's address, set x0/x1 (aarch64) or
//    rdi/rsi (x86_64) to (path, RTLD_NOW).
// 7. PTRACE_CONT, wait for SIGTRAP (the call returned), read
//    return value from x0/rax.
// 8. Find the address of zygisk_entry inside the loaded .so
//    (either by re-reading /proc/<pid>/maps or by using the
//    return value of dlopen + dlsym).
// 9. Construct another remote call to zygisk_entry(bridge_fd).
//    Before calling, we pass the bridge fd via a socketpair and
//    sendmsg+SCM_RIGHTS so that the in-zygote side receives a
//    usable fd.
// 10. Restore zygote's register state (PTRACE_SETREGSET).
// 11. ptrace(PTRACE_DETACH, pid, 0, 0).
//
// The above is a simplified algorithm — real implementations must
// handle multiple corner cases:
//   - SELinux denial of ptrace (we need our sepolicy.rule)
//   - The zygote is multithreaded, so PTRACE_ATTACH only stops
//     one thread; we may need PTRACE_SEIZE
//   - The linker's dlopen may not be callable from arbitrary
//     stopped thread states; we may need to wait for the next
//     syscall boundary.
//   - Remote-call frame setup on each architecture is different.
//
// This implementation handles all 4 ABIs (arm64, arm, x86_64, x86)
// via arch-specific code paths in ptrace_inject.cpp.

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Daemon lifecycle

// Run the main daemon loop. Returns when the daemon should exit
// (e.g. received "exit" command from emulated-soft-reboot.sh).
int daemon_main(void);

// Service-stage entry point. Called by service.sh after Zygote
// has started. Responsible for:
//   * Verifying libzygisk.so is loaded inside zygote
//   * Re-injecting if necessary (e.g. after a zygote restart)
//   * Installing the cleanup hook
int service_stage_main(void);

// Send "exit" to a running daemon. Called by
// emulated-soft-reboot.sh.
int exit_daemon(void);

// Print status summary (used by the WebUI).
int status_main(int argc, char **argv);

// WebUI command router. Called via the znctl symlink for arbitrary
// subcommands.
int webui_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif
