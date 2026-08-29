// Config file I/O.

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

#define CONFIG_DIR "/data/adb/zygisksu"

static int ensure_config_dir(void) {
    return mkdir(CONFIG_DIR, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

// Read a flag file (1 byte content "1" or "0").
static bool read_flag(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", CONFIG_DIR, name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[16];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return buf[0] == '1';
}

static int write_flag(const char *name, bool value) {
    ensure_config_dir();
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", CONFIG_DIR, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0600);
    if (fd < 0) return -1;
    write(fd, value ? "1\n" : "0\n", 2);
    close(fd);
    return 0;
}

bool config_get_zygisk_enabled(void) {
    return read_flag("zygisk_enabled");
}
int config_set_zygisk_enabled(bool enabled) {
    return write_flag("zygisk_enabled", enabled);
}
bool config_get_klog_enabled(void) {
    return read_flag("klog");
}
int config_set_klog_enabled(bool enabled) {
    return write_flag("klog", enabled);
}

const char *config_get_log_dir(void) {
    return CONFIG_DIR "/bugreports";
}
