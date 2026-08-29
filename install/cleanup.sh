#!/system/bin/sh
# cleanup.sh — invoked after a soft-reboot or before re-injection.
#
# This script restores the module.prop.orig file if it was patched
# (e.g. when the user toggled Zygisk off, we rename module.prop to
# module.prop.orig and substitute a disabled version).

MODDIR=/data/adb/modules/zygisksu
if [ -f "$MODDIR/module.prop.orig" ]; then
  mv "$MODDIR/module.prop.orig" "$MODDIR/module.prop"
fi
exit 0
