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

# Round 13: remove the randomized per-boot socket dir + session
# handoff file. The session file lives in the module dir (which the
# Magisk uninstaller removes wholesale), but the RANDOM dir under
# /data/system must be cleaned explicitly, or the next boot inherits
# a stale directory with no daemon behind it.
SESSION="$MODDIR/session.sock"
if [ -f "$SESSION" ]; then
  RANDSOCK=$(cat "$SESSION" 2>/dev/null | tr -d ' \r\n')
  case "$RANDSOCK" in
    /data/system/.????????/*)
      RANDDIR=${RANDSOCK%/*}
      rm -rf "$RANDDIR" 2>/dev/null
      ;;
  esac
  rm -f "$SESSION" 2>/dev/null
fi
exit 0
