#!/system/bin/sh
# uninstall.sh — runs when the module is removed.
#
# WHEN this runs (verified from the managers' own sources, Round 38):
#   * Magisk (master native/src/core/module.rs): the manager only
#     creates a `remove` marker; at the NEXT BOOT magiskd runs
#     uninstall.sh (BBEXEC: busybox `sh <full-path>`), then deletes
#     the module dir immediately.
#   * KernelSU (userspace/ksud/src/module.rs) and APatch
#     (apd/src/module.rs): identical remove-marker flow at boot.
#   * `magisk --remove-modules` (native/src/core/module.rs
#     remove_modules()) and a manual `sh uninstall.sh` run the script
#     AT RUNTIME with the daemon STILL ALIVE.
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

# ---------------------------------------------------------------------------
# ROUND 38 (U1 — the live-daemon uninstall): terminate the daemon
# BEFORE anything else. On the runtime removal paths
# (`magisk --remove-modules`, manual script run) the daemon is still
# running while this script executes, and a live daemon carries:
#
#   a) an ARMED property guard (Round 30) holding the applied loader
#      name in memory. If the zygote restarts after we restore the
#      stock value — crash, `stop/start zygote`, a soft reboot — the
#      guard RE-SETS ro.dalvik.vm.native.bridge to our loader name on
#      a device where the module is being removed: `getprop` then
#      shows the randomized soname (an identifying artifact) and ART
#      logs the missing-library warning at every zygote start, for
#      the rest of the boot.
#   b) the daemon process itself (mlockall'd, root, running until
#      reboot) and the denylist hiding it still serves.
#
# Killing it FIRST makes the property restore below the last write
# that ever lands. Pid-reuse safety: a pid from the file is only
# killed when /proc/<pid>/comm matches our process name. The
# /proc scan fallback covers a daemon whose pid file was lost; it
# matches ONLY the cloak name ("subsysd" — deliberately not used by
# any real Android service or other root tool, so no collateral
# damage; ReZygisk's daemon, for example, runs as "zygiskd" and is
# never touched). ZS_TEST_DAEMON_COMM overrides the expected name for
# the host script E2E.
ZS_DAEMON_COMM="${ZS_TEST_DAEMON_COMM:-subsysd}"
if [ -f "$WORKDIR/zygiskd.pid" ]; then
  _dpid="$(cat "$WORKDIR/zygiskd.pid" 2>/dev/null | tr -d ' \r\n')"
  case "$_dpid" in
    *[!0-9]* | "") ;;
    *)
      if [ -r "/proc/$_dpid/comm" ] && \
         [ "$(cat "/proc/$_dpid/comm" 2>/dev/null)" = "$ZS_DAEMON_COMM" ]; then
        kill -TERM "$_dpid" 2>/dev/null && {
          # Give it a moment to die; SIGKILL as the last resort.
          sleep 1
          kill -KILL "$_dpid" 2>/dev/null
        }
      fi
      ;;
  esac
fi
# Comm-scan fallback (pid file missing/stale but the daemon lives).
for _p in /proc/[0-9]*; do
  [ -r "$_p/comm" ] || continue
  read -r _c < "$_p/comm" 2>/dev/null
  [ "$_c" = "$ZS_DAEMON_COMM" ] || continue
  _dp="${_p#/proc/}"
  kill -TERM "$_dp" 2>/dev/null
  # never SIGKILL from the blind scan: an unverified pid gets one
  # clean TERM, nothing more.
done

# ROUND 31: use the compat layer's property chain so the uninstall
# also works on KernelSU / APatch (no resetprop binary there — the
# daemon's built-in engine does the write).
. "$MODDIR/zs_compat.sh" 2>/dev/null || true
zs_compat_init 2>/dev/null || {
  # Module dir already half-removed (defensive): fall back to the
  # binary chain alone.
  ZS_DAEMON="$MODDIR/zygiskd"
  # ROUND 34 (B4 — the broken fallback): with zs_compat.sh missing,
  # zs_compat_init / zs_prop_set / zs_prop_delete are UNDEFINED
  # commands (exit 127), so the property restore below — this
  # script's PRIMARY purpose — silently failed exactly in the
  # degraded scenario the fallback was written for. Define inline
  # fallbacks for the two writers used here.
  zs_prop_set() {
    if command -v resetprop >/dev/null 2>&1; then
      resetprop "$1" "$2" 2>/dev/null && return 0
    fi
    for _c in /data/adb/magisk/resetprop /system/bin/resetprop; do
      if [ -x "$_c" ]; then
        "$_c" "$1" "$2" 2>/dev/null && return 0
      fi
    done
    if [ -x "$ZS_DAEMON" ]; then
      "$ZS_DAEMON" prop set "$1" "$2" 2>/dev/null && return 0
    fi
    return 1
  }
  zs_prop_delete() {
    if command -v resetprop >/dev/null 2>&1; then
      resetprop --delete "$1" 2>/dev/null && return 0
    fi
    for _c in /data/adb/magisk/resetprop /system/bin/resetprop; do
      if [ -x "$_c" ]; then
        "$_c" --delete "$1" 2>/dev/null && return 0
      fi
    done
    if [ -x "$ZS_DAEMON" ]; then
      "$ZS_DAEMON" prop delete "$1" 2>/dev/null && return 0
    fi
    return 1
  }
  # zs_log is referenced by nothing here yet, but define a silent
  # stub so a future edit cannot break on a missing function.
  zs_log() { return 0; }
}

# ROUND 31: remove the post-mount.d hook customize.sh installed (only
# if it is OURS — check the header marker, never blindly delete a
# name that another package could own).
ZS_ADB_ROOT="${ZS_TEST_ADB_ROOT:-/data/adb}"
for hook in "$ZS_ADB_ROOT/post-mount.d/zygisk_study-mount.sh"; do
  if [ -f "$hook" ] && head -n 3 "$hook" 2>/dev/null | grep -q "zygisk_study-mount"; then
    rm -f "$hook" 2>/dev/null
  fi
done

if [ -f "$WORKDIR/.native_bridge_backup" ]; then
  OLD="$(cat "$WORKDIR/.native_bridge_backup")"
  if [ -n "$OLD" ]; then
    zs_prop_set ro.dalvik.vm.native.bridge "$OLD"
  else
    # It was empty before we touched it. Delete the prop outright —
    # Round 28: the previous sequence ran --delete AND THEN set the
    # prop to "", which re-created it as an empty-value property.
    # No stock device has an empty ro.dalvik.vm.native.bridge ENTRY
    # (stock is either absent or "0"), so the leftover empty entry
    # was visible via getprop after uninstall. ART treats absent and
    # empty identically (same ALOGW path in AndroidRuntime.cpp at
    # 5.0 and 16.0 — verified), so deleting is the correct restore.
    zs_prop_delete ro.dalvik.vm.native.bridge
  fi
else
  # ROUND 38 (U3 — the backup-less restore gap): no backup record
  # (workdir partially wiped by the user, a denied write, an
  # interrupted first boot), but the LIVE value may still be OUR
  # applied name. Leaving it set means the prop points at a library
  # that no longer exists until reboot — the exact leftover class
  # this script exists to prevent. When the live value matches our
  # recorded applied name, restore the documented no-bridge default
  # "0" (169 of 173 real devices in the
  # getActivity/AndroidSystemPropertyCollect firmware collection ship
  # exactly "0"; ART treats "0" and absent identically — the
  # `zygote && strcmp(propBuf, "0")` path verified at 5.0.0_r1,
  # 16.0.0_r1 and android16-qpr2-release). A live value that is
  # neither ours nor a no-bridge default is a foreign bridge: same
  # rule as post-fs-data.sh — never touch it.
  if [ -f "$WORKDIR/.native_bridge_applied" ]; then
    _applied="$(cat "$WORKDIR/.native_bridge_applied" 2>/dev/null | tr -d ' \r\n')"
    if [ -n "$_applied" ]; then
      _live="$(zs_prop_get ro.dalvik.vm.native.bridge 2>/dev/null)"
      if [ "$_live" = "$_applied" ]; then
        zs_prop_set ro.dalvik.vm.native.bridge "0"
      fi
    fi
  fi
fi

# ROUND 34 (B8 — uninstall hygiene): undo what zs_ensure_loader_mounted
# recorded in the manifest — our self-mounted overlays (unmount, then
# drop the randomized scratch) and the DIRECT COPIES into a RW
# /system (emulators, some custom ROMs): those files do NOT vanish
# with the module dir, and a leftover lib<rand>.so in the real
# /system is both an orphan and an identifying artifact. Order
# matters: unmount the overlay FIRST (the copies under it are
# shadowed by the lowerdir once it is gone anyway), then remove
# direct copies recorded outside any overlay.
if [ -f "$WORKDIR/.uninstall_manifest" ]; then
  _ovl_root=""
  if [ -f "$WORKDIR/.ovl_root" ]; then
    _ovl_root="$(cat "$WORKDIR/.ovl_root" 2>/dev/null | tr -d ' \r\n')"
  fi
  while IFS= read -r _line; do
    [ -n "$_line" ] || continue
    case "$_line" in
      "overlay "*)
        _dir="${_line#overlay }"
        _dir="${_dir%% *}"
        # ROUND 38 (U4 — EBUSY on the runtime-removal path): while the
        # zygote still maps files through the overlay, plain umount
        # fails EBUSY and the mount line stays in /proc/mounts
        # (world-readable) until reboot. Fall back to a LAZY detach:
        # the line disappears immediately and already-mapped files
        # keep working. (busybox and toybox umount both support -l;
        # verified from Magisk's busybox applet list and toybox
        # umount.c.)
        umount "$_dir" 2>/dev/null || umount -l "$_dir" 2>/dev/null
        ;;
      "copy "*)
        _f="${_line#copy }"
        # Only remove a recorded file that still matches OUR naming
        # (defense in depth: never rm -f a path we do not recognize).
        case "$_f" in
          /system/lib*/lib*.so) rm -f "$_f" 2>/dev/null ;;
        esac
        ;;
    esac
  done < "$WORKDIR/.uninstall_manifest"
  # Drop the randomized overlay scratch (verified to be OURS by the
  # recorded root, then by the name class).
  if [ -n "$_ovl_root" ]; then
    case "$_ovl_root" in
      "$ZS_SYS_ROOT"/.*.o) rm -rf "$_ovl_root" 2>/dev/null ;;
    esac
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
