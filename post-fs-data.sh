#!/system/bin/sh
# post-fs-data.sh — runs very early in the boot, after /data is mounted.
#
# At this point we can:
#   - Set up the daemon's working directory under /data/system/zygisk_study
#     (deliberately NOT under /data/adb/ — that path is a known
#     Zygisk signature and would shout "this is a Zygisk loader" to
#     anyone reading /proc/mounts)
#   - Pre-stage any per-app DenyList configuration the user has dropped
#   - Make the socket directory with the right permissions
#
# We deliberately do NOT do anything that requires multiuser awareness
# here (per-user data isn't available yet). Per-user bookkeeping happens
# in the daemon after it starts.

MODDIR=${0%/*}
WORKDIR=/data/system/zygisk_study
SOCKDIR=$WORKDIR/sock

mkdir -p "$WORKDIR"
mkdir -p "$SOCKDIR"
chmod 0700 "$WORKDIR"
chmod 0700 "$SOCKDIR"

# Leave a marker so the daemon can detect "first boot after install".
if [ ! -f "$WORKDIR/.installed" ]; then
  date +%s > "$WORKDIR/.installed"
fi

# Default DenyList is empty. The user can populate this file at runtime
# from the WebUI (or by hand). Format: one package name per line.
if [ ! -f "$WORKDIR/denylist" ]; then
  : > "$WORKDIR/denylist"
fi

# Module registry. The daemon reads this on startup. Format:
#   <module_dir>;<compat_flag>
# where <module_dir> is relative to /data/adb/modules.
if [ ! -f "$WORKDIR/modules" ]; then
  : > "$WORKDIR/modules"
fi
