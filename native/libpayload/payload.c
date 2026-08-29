// libpayload.so — from-scratch reimplementation
//
// This is a fresh C reimplementation of the Zygisk Next libpayload
// library. The original ships as a precompiled .so; this source is
// my own work, written from:
//   * the public symbol table (my_execve, my_execveat, my_wait4,
//     daemon_addr — 4 exports, see readelf output)
//   * the Section 1 bootstrap description in the spec, which says:
//       "For each module's companion, libpayload.so exports my_execve,
//        my_execveat, my_wait4 and a daemon_addr global; these are
//        syscall trampolines that allow the root daemon to intercept
//        and rewrite exec requests inside an injected process
//        (e.g. to launch a wrapped binary through zygiskd rather
//        than the original path)."
//   * general knowledge of how unix-domain socket IPC works.
//
// Loaded by libzygisk.so / libzn_loader.so into a target process
// via android_dlopen_ext. Once loaded, libpayload acts as the
// syscall-interception layer for that process. Calls to execve /
// execveat / wait4 are routed through here; if zygiskd says
// "rewrite this exec", libpayload replaces the path/args with
// a zygiskd-managed wrapper binary.
//
// NOTES ON MY GUESSES:
//   * The exact wire format of the IPC messages between libpayload
//     and zygiskd is not documented in the public symbol table or
//     in Section 1 of the spec. I designed a simple TLV-style
//     protocol (see ipc.h). The original may use a different format.
//     I am explicit about where the protocol is "my design" vs.
//     "documented behaviour".
//   * daemon_addr is 116 bytes — that matches sizeof(struct
//     sockaddr_un) on Linux (sa_family_t + 108-byte sun_path + 6
//     bytes padding). So daemon_addr is the zygiskd daemon's
//     AF_UNIX address, populated by zygiskd before the trampolines
//     are installed.
//   * The 3 trampoline functions must preserve the exact syscall
//     semantics: errno, return value, signal-mask inheritance.
//     This implementation does so.

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ------------------------------------------------------------------
// daemon_addr — populated by zygiskd before installing the trampolines.
//
// Size 116 bytes == sizeof(struct sockaddr_un). Stored as raw bytes
// so the layout is ABI-stable across 32/64-bit and arches.
// ------------------------------------------------------------------
__attribute__((visibility("default")))
struct sockaddr_un daemon_addr;

// IPC message format (my design — see notes above).
//
// Every request is:  [opcode:1][body_len:4 LE][body:body_len]
// Every reply is:    [status:1][ret_len:4 LE][ret:ret_len]
//
// status: 0 = proceed with original syscall (don't rewrite)
//         1 = rewrite — caller should execute the returned wrapper
//         2 = deny  — caller should return -ENOEXEC
//         3 = error — caller should fall through to real syscall
enum ipc_op {
    OP_EXECVE   = 1,
    OP_EXECVEAT = 2,
    OP_WAIT4    = 3,
};

enum ipc_status {
    ST_PASS     = 0,  // proceed with original syscall
    ST_REWRITE  = 1,  // execute the returned wrapper
    ST_DENY     = 2,  // return -ENOEXEC
    ST_ERROR    = 3,  // fall through to real syscall
};

// Connect to the zygiskd daemon. Returns fd or -1 on failure.
static int connect_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (const struct sockaddr *)&daemon_addr,
                sizeof(daemon_addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Send an IPC request and read back the status byte + reply payload.
//
// Returns 0 on success (with *out_status and *out_payload populated),
// -1 on transport error. The caller owns *out_payload (caller must
// free).
static int ipc_request(int op,
                       const void *req_body, uint32_t req_len,
                       uint8_t *out_status,
                       void **out_payload, uint32_t *out_len) {
    *out_payload = NULL;
    *out_len = 0;
    *out_status = ST_ERROR;

    int fd = connect_daemon();
    if (fd < 0) return -1;

    // Request header
    uint8_t hdr[5];
    hdr[0] = (uint8_t)op;
    hdr[1] = (uint8_t)(req_len & 0xff);
    hdr[2] = (uint8_t)((req_len >> 8) & 0xff);
    hdr[3] = (uint8_t)((req_len >> 16) & 0xff);
    hdr[4] = (uint8_t)((req_len >> 24) & 0xff);

    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = (void *)req_body;
    iov[1].iov_len  = req_len;
    if (writev(fd, iov, req_len ? 2 : 1) < 0) {
        close(fd);
        return -1;
    }

    // Reply: 1 status + 4 len + body
    uint8_t rpl_hdr[5];
    ssize_t n = recv(fd, rpl_hdr, sizeof(rpl_hdr), MSG_WAITALL);
    if (n != (ssize_t)sizeof(rpl_hdr)) {
        close(fd);
        return -1;
    }
    *out_status = rpl_hdr[0];
    uint32_t len = (uint32_t)rpl_hdr[1]
                 | ((uint32_t)rpl_hdr[2] << 8)
                 | ((uint32_t)rpl_hdr[3] << 16)
                 | ((uint32_t)rpl_hdr[4] << 24);
    if (len > 1u << 20) {  // sanity: >1MB is surely a bug
        close(fd);
        return -1;
    }
    if (len) {
        void *body = malloc(len);
        if (!body) {
            close(fd);
            return -1;
        }
        n = recv(fd, body, len, MSG_WAITALL);
        if (n != (ssize_t)len) {
            free(body);
            close(fd);
            return -1;
        }
        *out_payload = body;
        *out_len = len;
    }
    close(fd);
    return 0;
}

// ------------------------------------------------------------------
// Real syscalls — call these when the daemon says "pass through".
// We use syscall() instead of the libc wrapper so we never recurse
// back into our own trampolines (libpayload does NOT install itself
// as an interposer for libc; it only exports symbols for explicit
// dispatch by libzygisk/libzn_loader).
// ------------------------------------------------------------------
static long real_execve(const char *path, char *const argv[],
                        char *const envp[]) {
    return syscall(SYS_execve, path, argv, envp);
}
static long real_execveat(int dirfd, const char *path,
                          char *const argv[], char *const envp[],
                          int flags) {
    return syscall(SYS_execveat, dirfd, path, argv, envp, flags);
}
static long real_wait4(pid_t pid, int *wstatus, int options,
                       struct rusage *rusage) {
    return syscall(SYS_wait4, pid, wstatus, options, rusage);
}

// ------------------------------------------------------------------
// Helpers for marshalling arg vectors into a flat buffer.
//
// Wire format for OP_EXECVE / OP_EXECVEAT:
//   [path_len:4][path][argv_n:4]
//   for each argv: [arg_len:4][arg]
//   [env_n:4]
//   for each envp: [env_len:4][env]
//
// Wire format for OP_WAIT4:
//   [pid:4][options:4]
//
// Reply format (when status == ST_REWRITE):
//   for EXECVE/EXECVEAT:
//     [path_len:4][path]
//     [argv_n:4]
//     for each argv: [arg_len:4][arg]
//   for WAIT4:
//     [pid:4]   (rebind the pid to wait on)
// ------------------------------------------------------------------
static void put_u32(uint8_t **p, uint32_t v) {
    (*p)[0] = (uint8_t)(v & 0xff);
    (*p)[1] = (uint8_t)((v >> 8) & 0xff);
    (*p)[2] = (uint8_t)((v >> 16) & 0xff);
    (*p)[3] = (uint8_t)((v >> 24) & 0xff);
    *p += 4;
}
static uint32_t get_u32(const uint8_t **p) {
    uint32_t v = (uint32_t)(*p)[0]
               | ((uint32_t)(*p)[1] << 8)
               | ((uint32_t)(*p)[2] << 16)
               | ((uint32_t)(*p)[3] << 24);
    *p += 4;
    return v;
}

// Pack a string vector (NULL-terminated) into the buffer.
// Returns total length or -1 on overflow.
static int pack_vec(const char *path,
                   char *const argv[], char *const envp[],
                   uint8_t *buf, size_t cap) {
    uint8_t *p = buf;
    uint8_t *end = buf + cap;

    // path
    size_t plen = strlen(path);
    if (p + 4 + plen > end) return -1;
    put_u32(&p, (uint32_t)plen);
    memcpy(p, path, plen); p += plen;

    // argv count
    int argc = 0;
    if (argv) while (argv[argc]) argc++;
    if (p + 4 > end) return -1;
    put_u32(&p, (uint32_t)argc);
    for (int i = 0; i < argc; i++) {
        size_t l = strlen(argv[i]);
        if (p + 4 + l > end) return -1;
        put_u32(&p, (uint32_t)l);
        memcpy(p, argv[i], l); p += l;
    }

    // envp count
    int envc = 0;
    if (envp) while (envp[envc]) envc++;
    if (p + 4 > end) return -1;
    put_u32(&p, (uint32_t)envc);
    for (int i = 0; i < envc; i++) {
        size_t l = strlen(envp[i]);
        if (p + 4 + l > end) return -1;
        put_u32(&p, (uint32_t)l);
        memcpy(p, envp[i], l); p += l;
    }
    return (int)(p - buf);
}

// Unpack a returned argv from reply. Returns a malloc'd argv[]
// (NULL-terminated) or NULL on parse error. *out_argv points to
// a single allocation holding both the argv pointer array and the
// string data; caller frees *out_owner.
static char **unpack_argv(const uint8_t *p, const uint8_t *end,
                          void **out_owner) {
    *out_owner = NULL;
    if (p + 4 > end) return NULL;
    uint32_t argc = get_u32(&p);
    if (argc > 65535) return NULL;

    // First pass: compute total size.
    size_t ptrs_size = (argc + 1) * sizeof(char *);
    size_t strs_size = 0;
    const uint8_t *q = p;
    for (uint32_t i = 0; i < argc; i++) {
        if (q + 4 > end) return NULL;
        uint32_t l = get_u32(&q);
        if (q + l > end) return NULL;
        strs_size += l + 1;
        q += l;
    }
    void *owner = malloc(ptrs_size + strs_size);
    if (!owner) return NULL;
    char **argv = (char **)owner;
    char *strs = (char *)owner + ptrs_size;
    char *s = strs;
    for (uint32_t i = 0; i < argc; i++) {
        uint32_t l = get_u32(&p);
        memcpy(s, p, l); s[l] = '\0';
        argv[i] = s;
        s += l + 1;
        p += l;
    }
    argv[argc] = NULL;
    *out_owner = owner;
    return argv;
}

// ------------------------------------------------------------------
// Public API: my_execve
//
// Intercept execve(path, argv, envp). Ask zygiskd whether to
// rewrite this exec. If yes, execute the returned wrapper binary
// instead. If no (or on any IPC error), fall through to the real
// syscall.
// ------------------------------------------------------------------
__attribute__((visibility("default")))
int my_execve(const char *pathname, char *const argv[],
              char *const envp[]) {
    if (!pathname) {
        errno = EFAULT;
        return -1;
    }

    // Build request body.
    uint8_t buf[8192];
    int blen = pack_vec(pathname, argv, envp, buf, sizeof(buf));
    if (blen < 0) {
        // Request too big — just pass through to the kernel.
        return (int)real_execve(pathname, argv, envp);
    }

    uint8_t status;
    void *reply = NULL;
    uint32_t reply_len = 0;
    if (ipc_request(OP_EXECVE, buf, (uint32_t)blen,
                    &status, &reply, &reply_len) < 0) {
        // Daemon unreachable — fall through.
        return (int)real_execve(pathname, argv, envp);
    }

    int rc;
    if (status == ST_REWRITE && reply && reply_len >= 4) {
        // Parse returned (path, argv). Use the caller's envp verbatim.
        const uint8_t *p = (const uint8_t *)reply;
        const uint8_t *end = p + reply_len;
        uint32_t plen = get_u32(&p);
        if (p + plen > end) {
            free(reply);
            return (int)real_execve(pathname, argv, envp);
        }
        // Copy path into a writable buffer (execve requires writable
        // strings on some kernels).
        char *new_path = (char *)malloc(plen + 1);
        if (!new_path) {
            free(reply);
            return (int)real_execve(pathname, argv, envp);
        }
        memcpy(new_path, p, plen); new_path[plen] = '\0';
        p += plen;

        void *owner = NULL;
        char **new_argv = unpack_argv(p, end, &owner);
        if (!new_argv) {
            free(new_path);
            free(reply);
            return (int)real_execve(pathname, argv, envp);
        }

        rc = (int)real_execve(new_path, new_argv, envp);
        // Only reach here if execve failed.
        int saved_errno = errno;
        free(new_path);
        free(owner);
        free(reply);
        errno = saved_errno;
    } else {
        // Pass-through or deny.
        free(reply);
        if (status == ST_DENY) {
            errno = ENOEXEC;
            return -1;
        }
        rc = (int)real_execve(pathname, argv, envp);
    }
    return rc;
}

// ------------------------------------------------------------------
// Public API: my_execveat
//
// Same logic as my_execve but with dirfd + flags.
// Wire format adds dirfd (4 bytes) and flags (4 bytes) at the start.
// ------------------------------------------------------------------
__attribute__((visibility("default")))
int my_execveat(int dirfd, const char *pathname,
                char *const argv[], char *const envp[],
                int flags) {
    if (!pathname) {
        errno = EFAULT;
        return -1;
    }

    // Pack: [dirfd][flags][path][argv][envp]
    uint8_t buf[8192];
    uint8_t *p = buf;
    uint8_t *end = buf + sizeof(buf);
    put_u32(&p, (uint32_t)dirfd);
    put_u32(&p, (uint32_t)flags);
    int blen = pack_vec(pathname, argv, envp, p, (size_t)(end - p));
    if (blen < 0) {
        return (int)real_execveat(dirfd, pathname, argv, envp, flags);
    }
    blen += 8;

    uint8_t status;
    void *reply = NULL;
    uint32_t reply_len = 0;
    if (ipc_request(OP_EXECVEAT, buf, (uint32_t)blen,
                    &status, &reply, &reply_len) < 0) {
        return (int)real_execveat(dirfd, pathname, argv, envp, flags);
    }

    int rc;
    if (status == ST_REWRITE && reply && reply_len >= 4) {
        // Parse: [path][argv]. The returned path is absolute, so
        // dirfd is ignored on the rewrite (we still pass AT_FDCWD).
        const uint8_t *p2 = (const uint8_t *)reply;
        const uint8_t *end2 = p2 + reply_len;
        uint32_t plen = get_u32(&p2);
        if (p2 + plen > end2) {
            free(reply);
            return (int)real_execveat(dirfd, pathname, argv, envp, flags);
        }
        char *new_path = (char *)malloc(plen + 1);
        if (!new_path) {
            free(reply);
            return (int)real_execveat(dirfd, pathname, argv, envp, flags);
        }
        memcpy(new_path, p2, plen); new_path[plen] = '\0';
        p2 += plen;

        void *owner = NULL;
        char **new_argv = unpack_argv(p2, end2, &owner);
        if (!new_argv) {
            free(new_path);
            free(reply);
            return (int)real_execveat(dirfd, pathname, argv, envp, flags);
        }

        // Rewrite always uses AT_FDCWD + same flags.
        rc = (int)real_execveat(AT_FDCWD, new_path, new_argv, envp, flags);
        int saved_errno = errno;
        free(new_path);
        free(owner);
        free(reply);
        errno = saved_errno;
    } else {
        free(reply);
        if (status == ST_DENY) {
            errno = ENOEXEC;
            return -1;
        }
        rc = (int)real_execveat(dirfd, pathname, argv, envp, flags);
    }
    return rc;
}

// ------------------------------------------------------------------
// Public API: my_wait4
//
// zygiskd sometimes needs to redirect a wait4() to wait on a
// different pid (e.g. the wrapped binary's child rather than the
// original target). Wire format: [pid:4][options:4].
// Reply (when rewrite): [new_pid:4].
// ------------------------------------------------------------------
__attribute__((visibility("default")))
pid_t my_wait4(pid_t pid, int *wstatus, int options,
               struct rusage *rusage) {
    // Build request.
    uint8_t req[8];
    uint8_t *p = req;
    put_u32(&p, (uint32_t)pid);
    put_u32(&p, (uint32_t)options);

    uint8_t status;
    void *reply = NULL;
    uint32_t reply_len = 0;
    if (ipc_request(OP_WAIT4, req, sizeof(req),
                    &status, &reply, &reply_len) < 0) {
        return (pid_t)real_wait4(pid, wstatus, options, rusage);
    }

    pid_t rc;
    if (status == ST_REWRITE && reply && reply_len >= 4) {
        const uint8_t *q = (const uint8_t *)reply;
        uint32_t new_pid = get_u32(&q);
        free(reply);
        rc = (pid_t)real_wait4((pid_t)new_pid, wstatus, options, rusage);
    } else if (status == ST_DENY) {
        free(reply);
        errno = ECHILD;
        return -1;
    } else {
        free(reply);
        rc = (pid_t)real_wait4(pid, wstatus, options, rusage);
    }
    return rc;
}

// ------------------------------------------------------------------
// Library init. Note: this is loaded via android_dlopen_ext, not
// via libc's normal dlopen. The .init_array entry below runs at
// load time. We use it to ensure daemon_addr is zeroed (zygiskd
// will overwrite it before installing any trampoline).
// ------------------------------------------------------------------
__attribute__((constructor))
static void payload_init(void) {
    memset(&daemon_addr, 0, sizeof(daemon_addr));
}
