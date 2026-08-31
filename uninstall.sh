#!/system/bin/sh
# uninstall.sh — runs when the module is removed (Magisk).
#
# Round 7: restore the native-bridge property we changed in
# post-fs-data.sh. The systemless /system files disappear with the
# module automatically; the property would otherwise keep pointing at
# a library that no longer exists, which makes ART log errors (and on
# some builds marks the runtime as degraded) on every boot.

WORKDIR=/data/system/zygisk_study
RESETPROP="$(command -v resetprop || true)"
[ -z "$RESETPROP" ] && [ -x /data/adb/magisk/resetprop ] && RESETPROP=/data/adb/magisk/resetprop

if [ -n "$RESETPROP" ]; then
  if [ -f "$WORKDIR/.native_bridge_backup" ]; then
    OLD="$(cat "$WORKDIR/.native_bridge_backup")"
    if [ -n "$OLD" ]; then
      "$RESETPROP" ro.dalvik.vm.native.bridge "$OLD"
    else
      # It was empty before we touched it.
      "$RESETPROP" --delete ro.dalvik.vm.native.bridge 2>/dev/null
      "$RESETPROP" ro.dalvik.vm.native.bridge ""
    fi
  fi
fi

# Remove the working directory (socket, denylist, markers).
rm -rf "$WORKDIR" 2>/dev/null
exit 0
