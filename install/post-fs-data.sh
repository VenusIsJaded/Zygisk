#!/system/bin/sh
# post-fs-data.sh — start zygiskd as a background daemon.
#
# This runs at the post-fs-data boot stage. /data is mounted.
# We launch zygiskd in daemon mode; it ptrace-attaches to the
# zygote process (which starts later) at the service stage.

MODDIR=/data/adb/modules/zygisksu

# Don't start the daemon if Zygisk is disabled in config.
if [ ! -f /data/adb/zygisksu/zygisk_enabled ] \
   || [ "$(cat /data/adb/zygisksu/zygisk_enabled 2>/dev/null)" != "1" ]; then
  exit 0
fi

# Launch zygiskd in the background. It will keep running for the
# lifetime of this boot.
nohup "$MODDIR/bin/zygiskd" daemon >/dev/null 2>&1 &
