// The daemon loop: open the bridge socket, accept connections
// from libzygisk.so (in-zygote), libpayload.so (in-target-process),
// and the znctl WebUI bridge; route messages to handlers.

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "daemon.h"
#include "ipc.h"
#include "log.h"
#include "modules.h"
#include "ptrace_inject.h"

// The daemon's listening socket path. We use an abstract
// namespace Unix domain socket so it's invisible on the
// filesystem and survives across pivot_root.
//
// Real Zygisk Next uses the path "@/data/adb/zygisksu/zn_ctx"
// (abstract namespace) — but the name is opaque to clients.
// We follow the same convention.
#define DAEMON_SOCK_NAME "zygisksu_daemon"

// PID file — used by `zygiskd exit` to find us.
#define PID_FILE "/data/adb/zygisksu/daemon.pid"

static int g_listen_fd = -1;
static volatile sig_atomic_t g_should_exit = 0;

static void on_sigterm(int sig) {
    (void)sig;
    g_should_exit = 1;
    if (g_listen_fd >= 0) {
        shutdown(g_listen_fd, SHUT_RDWR);
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

// Set up an abstract-namespace Unix domain socket.
static int make_listen_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    // Abstract namespace — first byte is \0
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, DAEMON_SOCK_NAME,
            sizeof(addr.sun_path) - 1 - 1);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) + 1
                   + strlen(DAEMON_SOCK_NAME);
    if (bind(fd, (struct sockaddr *)&addr, alen) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Send a reply on a client socket. Returns 0 on success.
static int send_reply(int fd, uint32_t op, uint32_t status,
                     const void *body, uint32_t len) {
    struct ReplyHdr hdr = {
        .op = op,
        .status = status,
        .len = len,
    };
    struct iovec iov[2] = {
        { .iov_base = &hdr,    .iov_len = sizeof(hdr) },
        { .iov_base = (void*)body, .iov_len = len },
    };
    return writev(fd, iov, len ? 2 : 1) >= 0 ? 0 : -1;
}

// Receive a request from a client. Returns 0 on success, fills in
// op + body. Caller must free *body_out.
static int recv_request(int fd, uint32_t *op_out,
                       void **body_out, uint32_t *len_out) {
    *body_out = NULL;
    *len_out = 0;
    struct MsgHdr hdr;
    ssize_t n = recv(fd, &hdr, sizeof(hdr), MSG_WAITALL);
    if (n != (ssize_t)sizeof(hdr)) return -1;
    uint32_t op = hdr.op;
    uint32_t len = hdr.len;
    if (len > 1u << 24) return -1;
    void *body = NULL;
    if (len) {
        body = malloc(len);
        if (!body) return -1;
        if (recv(fd, body, len, MSG_WAITALL) != (ssize_t)len) {
            free(body);
            return -1;
        }
    }
    *op_out = op;
    *body_out = body;
    *len_out = len;
    return 0;
}

// Handler for a libzygisk (in-zygote) bridge connection.
static void handle_bridge_client(int fd) {
    // The bridge is a single long-lived connection from inside
    // zygote. We just stay on this connection and route messages.
    while (!g_should_exit) {
        uint32_t op;
        void *body;
        uint32_t len;
        if (recv_request(fd, &op, &body, &len) < 0) break;
        switch (op) {
        case BO_PING:
            send_reply(fd, BO_PING, 0, NULL, 0);
            break;
        case BO_GET_MODULE_LIST: {
            size_t n;
            struct ModuleInfo *mods = modules_list(&n);
            // Build a simple text body:
            //   <id>\t<name>\t<version>\n
            // per module.
            char *buf = NULL;
            size_t buf_cap = 0, buf_len = 0;
            FILE *mem = open_memstream(&buf, &buf_cap);
            for (size_t i = 0; i < n; i++) {
                fprintf(mem, "%s\t%s\t%s\n",
                        mods[i].id, mods[i].name, mods[i].version);
            }
            fclose(mem);
            send_reply(fd, BO_GET_MODULE_LIST, 0, buf, (uint32_t)buf_len);
            free(buf);
            free(mods);
            break;
        }
        case BO_CONNECT_COMPANION: {
            // Create a fresh socketpair, send one end via SCM_RIGHTS,
            // keep the other end for talking to the module's
            // companion (a per-module fork of zygiskd).
            int pair[2];
            if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
                send_reply(fd, BO_CONNECT_COMPANION, 1, NULL, 0);
                break;
            }
            send_reply(fd, BO_CONNECT_COMPANION, 0, NULL, 0);
            // Send the client end via ancillary data.
            char dummy = 'c';
            struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
            struct msghdr msg = {};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            char cbuf[CMSG_SPACE(sizeof(int))];
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type  = SCM_RIGHTS;
            cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cmsg), &pair[1], sizeof(int));
            if (sendmsg(fd, &msg, 0) < 0) {
                close(pair[0]);
                close(pair[1]);
                break;
            }
            close(pair[1]);
            // We now own pair[0]. In a real implementation, we'd
            // spawn a per-module companion thread/process here to
            // handle messages on this fd. For the minimal impl,
            // we just close it (modules that need this will fall
            // back to BO_LOG only).
            close(pair[0]);
            break;
        }
        case BO_LOG: {
            // Forward to klog if enabled.
            if (len > 0 && body) {
                klog_write("[zygote] %.*s", (int)len, (char*)body);
            }
            send_reply(fd, BO_LOG, 0, NULL, 0);
            break;
        }
        case BO_REQUEST_REWRITE: {
            // We don't have a real rewrite policy in this minimal
            // implementation — always pass through.
            send_reply(fd, BO_REQUEST_REWRITE, 0, NULL, 0);
            break;
        }
        default:
            send_reply(fd, op, 1, NULL, 0);
        }
        free(body);
    }
}

// Handler for a libpayload (in-target-process) client.
//
// libpayload sends execve/wait4 trampoline requests. We decide
// whether to rewrite them (e.g. to launch a wrapped binary via
// zygiskd instead of the original path).
static void handle_payload_client(int fd) {
    // Same wire format as the bridge. Different opcodes range:
    //   1 = OP_EXECVE
    //   2 = OP_EXECVEAT
    //   3 = OP_WAIT4
    while (!g_should_exit) {
        uint32_t op;
        void *body;
        uint32_t len;
        if (recv_request(fd, &op, &body, &len) < 0) break;
        // Pass-through for all requests in this minimal impl.
        // A real implementation would:
        //   1. Parse the execve request body
        //   2. Check if path matches a denylist entry or a
        //      module-wrapped binary
        //   3. Reply with ST_REWRITE + new (path, argv) if so,
        //      or ST_PASS otherwise.
        send_reply(fd, op, 0 /* ST_PASS */, NULL, 0);
        free(body);
    }
}

// Handler for the znctl WebUI bridge client.
//
// WebUI commands are short: receive a single request, send a
// single reply, close.
static void handle_webui_client(int fd) {
    uint32_t op;
    void *body;
    uint32_t len;
    if (recv_request(fd, &op, &body, &len) < 0) return;
    switch (op) {
    case WO_STATUS: {
        char buf[512];
        int n = snprintf(buf, sizeof(buf),
            "Zygisk: %s\nDaemon pid: %d\nModules: see list\n",
            config_get_zygisk_enabled() ? "enabled" : "disabled",
            (int)getpid());
        send_reply(fd, WO_STATUS, 0, buf, (uint32_t)n);
        break;
    }
    case WO_LIST_MODULES: {
        size_t n;
        struct ModuleInfo *mods = modules_list(&n);
        char *out = NULL;
        size_t out_cap = 0;
        FILE *mem = open_memstream(&out, &out_cap);
        for (size_t i = 0; i < n; i++) {
            fprintf(mem, "%s\t%s\t%s\t%s\n",
                    mods[i].id, mods[i].name, mods[i].version,
                    mods[i].enabled ? "enabled" : "disabled");
        }
        fclose(mem);
        send_reply(fd, WO_LIST_MODULES, 0, out, (uint32_t)out_cap);
        free(out);
        free(mods);
        break;
    }
    case WO_TOGGLE_MODULE: {
        if (len < 1 || !body) {
            send_reply(fd, WO_TOGGLE_MODULE, 1, NULL, 0);
            break;
        }
        // body is module id (null-terminated)
        char *id = (char *)body;
        size_t n;
        struct ModuleInfo *mods = modules_list(&n);
        bool found = false, new_state = false;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(mods[i].id, id) == 0) {
                found = true;
                new_state = !mods[i].enabled;
                break;
            }
        }
        free(mods);
        if (!found) {
            send_reply(fd, WO_TOGGLE_MODULE, 2, NULL, 0);
            break;
        }
        if (modules_toggle(id, new_state) != 0) {
            send_reply(fd, WO_TOGGLE_MODULE, 3, NULL, 0);
            break;
        }
        send_reply(fd, WO_TOGGLE_MODULE, 0, NULL, 0);
        break;
    }
    case WO_ENABLE_ZYGISK:
        config_set_zygisk_enabled(true);
        send_reply(fd, WO_ENABLE_ZYGISK, 0, NULL, 0);
        break;
    case WO_DISABLE_ZYGISK:
        config_set_zygisk_enabled(false);
        send_reply(fd, WO_DISABLE_ZYGISK, 0, NULL, 0);
        break;
    case WO_VERSION: {
        const char *v = "1.5.0 (843-5217106-release)";
        send_reply(fd, WO_VERSION, 0, v, (uint32_t)strlen(v));
        break;
    }
    case WO_VIEW_LOG: {
        // Stream the bugreport log file.
        // For minimal impl, return empty.
        send_reply(fd, WO_VIEW_LOG, 0, NULL, 0);
        break;
    }
    default:
        send_reply(fd, op, 1, NULL, 0);
    }
    free(body);
}

// Classify an incoming client based on the first message's
// opcode. Bridge clients send BO_PING first; payload clients
// send OP_EXECVE/OP_EXECVEAT/OP_WAIT4 (1/2/3); WebUI clients
// send WO_STATUS (100) or other WO_* opcodes.
enum ClientType { CT_BRIDGE, CT_PAYLOAD, CT_WEBUI, CT_UNKNOWN };

static enum ClientType classify(uint32_t op) {
    if (op == BO_PING || (op >= BO_REGISTER_MODULE && op <= BO_GET_FLAGS))
        return CT_BRIDGE;
    if (op >= 1 && op <= 3)
        return CT_PAYLOAD;
    if (op >= 100 && op <= 200)
        return CT_WEBUI;
    return CT_UNKNOWN;
}

// Main daemon loop. Listens on the abstract-namespace socket,
// accepts connections, dispatches by client type.
int daemon_main(void) {
    // Signal handlers for clean shutdown.
    struct sigaction sa = {};
    sa.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    // SIGPIPE — ignore so writes to dead clients return EPIPE.
    signal(SIGPIPE, SIG_IGN);

    // Make sure config dir exists.
    mkdir("/data/adb/zygisksu", 0700);

    // Write pid file.
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", (int)getpid());
        fclose(pf);
    }

    g_listen_fd = make_listen_socket();
    if (g_listen_fd < 0) {
        LOGE("failed to create listen socket");
        return 1;
    }

    LOGI("zygiskd daemon started (pid=%d)", (int)getpid());

    // Pre-load the module list cache.
    modules_refresh_cache();

    while (!g_should_exit) {
        int cfd = accept4(g_listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Peek at the first message to classify the client.
        // We do this by reading the first 8 bytes (op + len) and
        // then pushing them back via recv-MSG_PEEK.
        uint32_t op = 0;
        // Simpler: read one MsgHdr via MSG_PEEK.
        struct MsgHdr hdr;
        ssize_t n = recv(cfd, &hdr, sizeof(hdr), MSG_PEEK);
        if (n != (ssize_t)sizeof(hdr)) {
            close(cfd);
            continue;
        }
        op = hdr.op;
        enum ClientType ct = classify(op);

        switch (ct) {
        case CT_BRIDGE:
            handle_bridge_client(cfd);
            break;
        case CT_PAYLOAD:
            handle_payload_client(cfd);
            break;
        case CT_WEBUI:
            handle_webui_client(cfd);
            break;
        default:
            // Unknown — close.
            (void)recv(cfd, &hdr, sizeof(hdr), 0);  // consume
            break;
        }
        close(cfd);
    }

    LOGI("zygiskd daemon exiting");
    unlink(PID_FILE);
    close(g_listen_fd);
    g_listen_fd = -1;
    return 0;
}

// Tell the running daemon to exit. Reads the pid file, sends
// SIGTERM.
int exit_daemon(void) {
    FILE *pf = fopen(PID_FILE, "r");
    if (!pf) {
        fprintf(stderr, "no pid file — daemon not running?\n");
        return 1;
    }
    pid_t pid = 0;
    if (fscanf(pf, "%d", &pid) != 1) {
        fclose(pf);
        return 1;
    }
    fclose(pf);
    if (kill(pid, SIGTERM) < 0) {
        perror("kill");
        return 1;
    }
    return 0;
}

// Service-stage entry. Called by service.sh after Zygote is up.
// We check whether the injection already happened (post-fs-data
// stage should have done it). If not, do it now.
int service_stage_main(void) {
    if (!config_get_zygisk_enabled()) {
        // Zygisk is disabled — nothing to do. The zygote is not
        // running our libzygisk; this is the intended state.
        return 0;
    }
    // In a real implementation, we'd verify the injection by
    // sending a PING on the bridge and waiting for a reply. For
    // the minimal impl, we just log and exit.
    LOGI("service-stage: zygisk is enabled");
    return 0;
}

// Print status summary (used by the WebUI and by the `zygiskd
// status` CLI command).
int status_main(int argc, char **argv) {
    (void)argc; (void)argv;
    bool zygisk_enabled = config_get_zygisk_enabled();
    bool klog_enabled   = config_get_klog_enabled();
    bool daemon_running = (access(PID_FILE, F_OK) == 0);

    printf("Zygisk: %s\n", zygisk_enabled ? "enabled" : "disabled");
    printf("Klog: %s\n",   klog_enabled   ? "enabled" : "disabled");
    printf("Daemon: %s\n", daemon_running ? "running" : "not running");
    size_t n;
    struct ModuleInfo *mods = modules_list(&n);
    printf("Modules: %zu\n", n);
    for (size_t i = 0; i < n; i++) {
        printf("  %s (%s) — %s\n", mods[i].name, mods[i].version,
                mods[i].enabled ? "enabled" : "disabled");
    }
    free(mods);
    return 0;
}
