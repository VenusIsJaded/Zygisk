// SPDX-License-Identifier: Apache-2.0
// native/common/daemon_sock.h
//
// ROUND 34 — bounded daemon sockets.
//
// THE BUG this header exists for: every client socket to the daemon
// was created plain blocking, with no SO_RCVTIMEO/SO_SNDTIMEO and a
// potentially-blocking connect(). Two of the callers
// (fetch_module_list_from_daemon and send_props_file_to_daemon) run
// on the ZYGOTE'S MAIN THREAD inside the fork hook: a daemon that
// accepts a connection and then stalls (wedged handler, full accept
// backlog) froze the zygote's fork() — every subsequent app launch
// on the device blocked. A daemon CRASH is safe (the kernel closes
// the socket, recv returns 0); a HANG is not.
//
// Verified (not guessed):
//   * SO_RCVTIMEO/SO_SNDTIMEO are honored by AF_UNIX stream reads
//     and writes — kernel net/unix/af_unix.c routes both through
//     sock_rcvtimeo (checked at torvalds/linux master, lines ~2584
//     and ~2946).
//   * A non-blocking connect(2) on a unix stream socket returns
//     EINPROGRESS (queued) or EAGAIN (transient backlog full); both
//     are then resolvable through poll(POLLOUT) + SO_ERROR.
//
// Usage contract:
//   zs_daemon_connect_bounded(path, connect_ms, io_ms)
//     connect_ms > 0 always — bounds the handshake;
//     io_ms == 0    — do NOT install SO_RCVTIMEO/SO_SNDTIMEO (for
//                     LONG-LIVED sockets the caller hands to a module:
//                     the module owns the I/O timing after the
//                     handshake; installing our timeout would break
//                     its blocking semantics);
//     io_ms > 0     — bounds every subsequent send/recv (single-shot
//                     request/response sockets only).
// Returns a connected BLOCKING socket, or -1 (callers already treat
// connect failure as "daemon not up, retry later").
#pragma once

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static inline int zs_daemon_connect_bounded(const char* path,
                                            int connect_ms, int io_ms) {
    if (!path || path[0] == '\0' || connect_ms <= 0) return -1;

    int sock = socket(AF_UNIX,
                      SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int rc = connect(sock, (struct sockaddr*)&addr, sizeof addr);
    if (rc != 0) {
        // EINPROGRESS: queued; EAGAIN: unix-stream backlog transiently
        // full — both resolve through poll. Anything else failed for
        // good (ENOENT = daemon not up yet, EACCES = path rules...).
        if (errno != EINPROGRESS && errno != EAGAIN) {
            close(sock);
            return -1;
        }
        struct pollfd pfd;
        memset(&pfd, 0, sizeof pfd);
        pfd.fd = sock;
        pfd.events = POLLOUT;
        int pr = poll(&pfd, 1, connect_ms);
        if (pr <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            close(sock);
            return -1;   // timeout or hard error — same as "not up"
        }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 ||
            soerr != 0) {
            close(sock);
            return -1;
        }
    }

    // Back to blocking mode for the exchange (callers do plain
    // send/recv loops).
    int fl = fcntl(sock, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(sock, F_SETFL, fl & ~O_NONBLOCK);

    if (io_ms > 0) {
        struct timeval tv;
        tv.tv_sec = io_ms / 1000;
        tv.tv_usec = (io_ms % 1000) * 1000;
        (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }
    return sock;
}
