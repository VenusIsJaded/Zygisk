// Simple logging macros. When KLOG_ENABLED is set, log to
// /dev/kmsg as well as stderr.

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

#define LOG_TAG "zygiskd"

static inline void klog_write(const char *fmt, ...) {
    if (!config_get_klog_enabled()) return;
    int fd = open("/dev/kmsg", O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return;
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "%s: ", LOG_TAG);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + n, sizeof(buf) - n - 1, fmt, ap);
    va_end(ap);
    strlcat(buf, "\n", sizeof(buf));
    write(fd, buf, strlen(buf));
    close(fd);
}

#define LOGI(...) do { \
    fprintf(stderr, "[I] " __VA_ARGS__); fputc('\n', stderr); \
    klog_write("[I] " __VA_ARGS__); \
} while (0)

#define LOGE(...) do { \
    fprintf(stderr, "[E] " __VA_ARGS__); fputc('\n', stderr); \
    klog_write("[E] " __VA_ARGS__); \
} while (0)

#define LOGW(...) do { \
    fprintf(stderr, "[W] " __VA_ARGS__); fputc('\n', stderr); \
    klog_write("[W] " __VA_ARGS__); \
} while (0)

#define LOGD(...) do { \
    fprintf(stderr, "[D] " __VA_ARGS__); fputc('\n', stderr); \
    klog_write("[D] " __VA_ARGS__); \
} while (0)
