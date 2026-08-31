#!/system/bin/sh
# uninstall.sh — runs when the module is removed (Magisk).
#
# Round 7: restore the native-bridge property we changed in
# post-fs-data.sh. The systemless /system files disappear with the
# module automatically; the property would otherwise keep pointing at
# a library that no longer exists, which makes ART log errors (and on
# some builds marks the runtime as degraded) on every boot.

# Round 28 bug fix: this script previously referenced $MODDIR without
# defining it (unlike post-fs-data.sh/service.sh, which derive it via
# ${0%/*}). If the Magisk environment does not export MODDIR, SESSION
# became "/session.sock", the randomized-socket cleanup below never
# matched, and a stale /data/system/.<hex> directory survived the
# uninstall forever — with no daemon left to clean it at next boot.
# Derive it the same way the other scripts do.
MODDIR=${0%/*}

# Round 29: /data/system prefix overridable for the host script tests
# (scripts/verify_scripts.py); unset on a real device.
ZS_SYS_ROOT="${ZS_TEST_ROOT:-/data/system}"
WORKDIR="$ZS_SYS_ROOT/zygisk_study"
RESETPROP="$(command -v resetprop || true)"
[ -z "$RESETPROP" ] && [ -x /data/adb/magisk/resetprop ] && RESETPROP=/data/adb/magisk/resetprop

if [ -n "$RESETPROP" ]; then
  if [ -f "$WORKDIR/.native_bridge_backup" ]; then
    OLD="$(cat "$WORKDIR/.native_bridge_backup")"
    if [ -n "$OLD" ]; then
      "$RESETPROP" ro.dalvik.vm.native.bridge "$OLD"
    else
      # It was empty before we touched it. Delete the prop outright —
      # Round 28: the previous sequence ran --delete AND THEN set the
      # prop to "", which re-created it as an empty-value property.
      # No stock device has an empty ro.dalvik.vm.native.bridge ENTRY
      # (stock is either absent or "0"), so the leftover empty entry
      # was visible via getprop after uninstall. ART treats absent and
      # empty identically (same ALOGW path in AndroidRuntime.cpp at
      # 5.0 and 16.0 — verified), so deleting is the correct restore.
      # The empty-value fallback runs only when --delete is not
      # supported by an old resetprop binary.
      if ! "$RESETPROP" --delete ro.dalvik.vm.native.bridge 2>/dev/null; then
        "$RESETPROP" ro.dalvik.vm.native.bridge ""
      fi
    fi
  fi
fi

# Round 13: remove the randomized per-boot socket dir + session
# handoff file. The session file lives in the module dir (which the
# Magisk uninstaller removes wholesale), but the RANDOM dir under
# /data/system must be cleaned explicitly, or the next boot inherits
# a stale directory with no daemon behind it. Round 29: the daemon
# also writes its record into the workdir (session.sock) — when the
# module-dir record is missing/unreadable, that copy still names the
# random dir (the daemon's own next-boot cleanup reads it the same
# way). The record must be read BEFORE the workdir removal below —
# the fallback copy lives inside it.
SESSION="$MODDIR/session.sock"
if [ ! -f "$SESSION" ] && [ -f "$WORKDIR/session.sock" ]; then
  SESSION="$WORKDIR/session.sock"
fi
RANDSOCK=""
if [ -f "$SESSION" ]; then
  RANDSOCK=$(cat "$SESSION" 2>/dev/null | tr -d ' \r\n')
  # Round 29: the second alternative is the host-test remap; with
  # ZS_TEST_ROOT unset it is identical to the first (ZS_SYS_ROOT
  # defaults to /data/system), so device behavior is unchanged.
  case "$RANDSOCK" in
    /data/system/.????????/*|"$ZS_SYS_ROOT"/.????????/*)
      RANDDIR=${RANDSOCK%/*}
      rm -rf "$RANDDIR" 2>/dev/null
      ;;
  esac
  rm -f "$SESSION" 2>/dev/null
fi

# Remove the working directory (socket, denylist, markers) — AFTER
# the session read above (the Round 29 fallback record lives here).
rm -rf "$WORKDIR" 2>/dev/null
exit 0
