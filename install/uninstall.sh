#!/system/bin/sh
# uninstall.sh — clean up /data/adb/zygisksu/ on uninstall.
#
# Magisk calls this when the user uninstalls the module. We kill
# any running zygiskd, then remove the config directory.

MODDIR=/data/adb/modules/zygisksu
"$MODDIR/bin/zygiskd" exit 2>/dev/null
rm -rf /data/adb/zygisksu
exit 0
