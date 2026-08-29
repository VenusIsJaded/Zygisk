// Module list cache. Scans /data/adb/modules to discover enabled
// Zygisk modules.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "modules.h"

#define MODULES_DIR "/data/adb/modules"
#define CACHE_FILE "/data/adb/zygisksu/modules_info"

// Read a key=value line from a module.prop file.
static int read_kv(const char *path, const char *key,
                  char *out, size_t out_sz) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    size_t klen = strlen(key);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
            char *v = line + klen + 1;
            char *nl = strchr(v, '\n');
            if (nl) *nl = '\0';
            strncpy(out, v, out_sz - 1);
            out[out_sz - 1] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

// Check whether a module is enabled (no "disable" or "remove" file).
static bool module_is_enabled(const char *id) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", id);
    if (access(path, F_OK) == 0) return false;
    snprintf(path, sizeof(path), MODULES_DIR "/%s/remove", id);
    if (access(path, F_OK) == 0) return false;
    return true;
}

// Check whether a module has a companion .so for the current arch.
static bool module_has_companion(const char *id) {
    char path[PATH_MAX];
#if defined(__aarch64__)
    const char *arch = "arm64-v8a";
#elif defined(__arm__)
    const char *arch = "armeabi-v7a";
#elif defined(__x86_64__)
    const char *arch = "x86_64";
#elif defined(__i386__)
    const char *arch = "x86";
#else
    return false;
#endif
    snprintf(path, sizeof(path), MODULES_DIR "/%s/zygisk/%s.so",
             id, arch);
    return access(path, R_OK) == 0;
}

struct ModuleInfo *modules_list(size_t *count_out) {
    *count_out = 0;
    DIR *d = opendir(MODULES_DIR);
    if (!d) return NULL;

    size_t cap = 16;
    struct ModuleInfo *arr = (struct ModuleInfo *)calloc(cap, sizeof(*arr));
    if (!arr) { closedir(d); return NULL; }

    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char prop[PATH_MAX];
        snprintf(prop, sizeof(prop), MODULES_DIR "/%s/module.prop",
                 e->d_name);
        if (access(prop, R_OK) != 0) continue;

        if (*count_out == cap) {
            cap *= 2;
            arr = (struct ModuleInfo *)realloc(arr, cap * sizeof(*arr));
            if (!arr) { closedir(d); return NULL; }
        }
        struct ModuleInfo *m = &arr[*count_out];
        memset(m, 0, sizeof(*m));
        strncpy(m->id, e->d_name, sizeof(m->id) - 1);
        read_kv(prop, "name", m->name, sizeof(m->name));
        read_kv(prop, "version", m->version, sizeof(m->version));
        m->enabled = module_is_enabled(m->id);
        m->has_companion = module_has_companion(m->id);
        (*count_out)++;
    }
    closedir(d);
    return arr;
}

void modules_refresh_cache(void) {
    size_t n;
    struct ModuleInfo *mods = modules_list(&n);
    FILE *f = fopen(CACHE_FILE, "w");
    if (f) {
        for (size_t i = 0; i < n; i++) {
            fprintf(f, "%s\n", mods[i].id);
        }
        fclose(f);
    }
    free(mods);
}

int modules_toggle(const char *id, bool enabled) {
    char path[PATH_MAX];
    if (enabled) {
        // Remove the "disable" file (if any).
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", id);
        unlink(path);
    } else {
        // Create the "disable" file.
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", id);
        int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
        if (fd < 0) {
            LOGE("could not create %s: %s", path, strerror(errno));
            return -1;
        }
        close(fd);
    }
    return 0;
}
