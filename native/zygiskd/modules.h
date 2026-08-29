// Module list cache. We periodically scan /data/adb/modules to
// refresh this; the in-zygote libzn_loader asks for it via the
// BO_GET_MODULE_LIST bridge op.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ModuleInfo {
    char id[256];
    char name[256];
    char version[64];
    bool enabled;
    bool has_companion;
};

// Returns a malloc'd array (caller frees) of ModuleInfo entries.
// *count_out is set to the number of modules.
struct ModuleInfo *modules_list(size_t *count_out);

// Refresh the on-disk cache file. The file format is a simple
// newline-separated list of module ids (one per line).
void modules_refresh_cache(void);

// Toggle a module's enable/disable flag.
int modules_toggle(const char *id, bool enabled);

#ifdef __cplusplus
}
#endif
