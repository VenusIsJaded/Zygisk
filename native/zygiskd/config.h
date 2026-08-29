// Config files under /data/adb/zygisksu/.
//
// Files we own:
//   klog          — 1 byte: "1" or "0" — enable kernel log
//   znctx         — opaque context blob, rotated on each boot
//   modules_info  — list of enabled modules, used by libzn_loader
//   tango         — legacy flag (removed in 1.5.0; customize.sh
//                    deletes it if present)
//   auto_umount   — legacy flag (removed in 1.5.0)
//
// All these files are stored under /data/adb/zygisksu/, owned by
// root, mode 0600.

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Read the "ZYGISK_ENABLED" flag from config. Set by the WebUI
// toggle. When false, the service-stage script will skip the
// zygote injection (Zygisk won't be active).
bool config_get_zygisk_enabled(void);
int  config_set_zygisk_enabled(bool enabled);

// Read the "KLOG_ENABLED" flag. When true, the daemon will log
// to /dev/kmsg as well as to the bugreport log file.
bool config_get_klog_enabled(void);
int  config_set_klog_enabled(bool enabled);

// Path to the daemon's bugreport log directory.
//   /data/adb/zygisksu/bugreports/
const char *config_get_log_dir(void);

#ifdef __cplusplus
}
#endif
