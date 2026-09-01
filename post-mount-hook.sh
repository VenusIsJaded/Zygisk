#!/system/bin/sh
# zygisk_study-mount.sh — Round 31: the /data/adb/post-mount.d hook.
#
# Installed by customize.sh on every root manager; only KernelSU and
# APatch actually RUN /data/adb/post-mount.d (their "post-mount"
# stage, verified from ksud/src/init_event.rs and apd/src/event.rs:
# run_stage("post-mount") -> exec_common_scripts("post-mount.d")),
# AFTER metamodule mounting and still BEFORE zygote start. Magisk
# ignores the directory (a dead file there is harmless), because on
# Magisk the magic mount already made the loader visible before
# post-fs-data.sh ran.
#
# What it does: if post-fs-data.sh left a .mount_pending flag (the
# loader was not visible at /system/lib[64] yet), try to resolve it —
# either the metamodule has now mounted it, or our own overlayfs
# self-mount takes over. If nothing works, roll the property swap
# back so the boot never references a missing library, and stand the
# daemon's property guard down.

# /data/adb remap for the host script tests (verify_scripts.py).
ZS_ADB_ROOT="${ZS_TEST_ADB_ROOT:-/data/adb}"
MODDIR_REAL="$ZS_ADB_ROOT/modules/zygisk_study"
ZS_SYS_ROOT="${ZS_TEST_ROOT:-/data/system}"
WORKDIR="$ZS_SYS_ROOT/zygisk_study"

# Only act when the flag exists (nothing pending -> exit fast: this
# file runs on EVERY post-mount event on KernelSU, e.g. also after
# soft reboots / emulated-soft-reboot).
[ -f "$WORKDIR/.mount_pending" ] || exit 0

# Guard against a disabled or removed module.
[ -f "$MODDIR_REAL/disable" ] && exit 0
[ -d "$MODDIR_REAL" ] || exit 0

. "$MODDIR_REAL/zs_compat.sh"
MODDIR="$MODDIR_REAL"
zs_compat_init

if zs_ensure_loader_mounted; then
  log -t ZygiskStudy "post-mount: loader resolved at /system ($ZS_BRIDGE_NAME)"
else
  zs_rollback_bridge
  rm -f "$WORKDIR/.mount_pending" 2>/dev/null
  log -t ZygiskStudy "post-mount: loader could not be made visible; bridge rolled back"
fi
exit 0
