#!/system/bin/sh
# emulated-soft-reboot.sh — drain the daemon before a soft reboot.
#
# The KernelSU/APatch WebUI invokes this when the user clicks
# "Restart Zygisk". We tell the daemon to exit cleanly so the
# next boot can re-inject.

MODDIR=/data/adb/modules/zygisksu
"$MODDIR/bin/zygiskd" exit 2>/dev/null
