// ptrace-based zygote injection.
//
// This is the core "magic" of zygiskd: it attaches to the zygote
// process via ptrace, makes a remote call to dlopen() inside the
// zygote's address space, then calls zygisk_entry(fd) which we
// passed via sendmsg+SCM_RIGHTS.

#pragma once

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Find the zygote PID by scanning /proc/*/cmdline for "zygote"
// (32-bit) or "zygote64" (64-bit). Returns 0 on failure.
pid_t find_zygote(bool want_64bit);

// Inject libzygisk.so into the zygote and call zygisk_entry(fd).
//   zygote_pid  : target pid
//   lib_path    : absolute path to libzygisk.so (must be readable
//                 by the zygote process's SELinux domain)
//   bridge_fd   : the daemon side of a socketpair; the other end
//                 becomes the bridge fd inside zygote.
// Returns 0 on success, -1 on failure.
int inject_zygote(pid_t zygote_pid, const char *lib_path,
                  int bridge_fd);

#ifdef __cplusplus
}
#endif
