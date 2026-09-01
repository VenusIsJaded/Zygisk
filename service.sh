#!/system/bin/sh
# service.sh — runs after the boot is "mostly" done (after `class_start main`
# from init). The daemon goes here.

MODDIR=${0%/*}
# Round 29: /data/system prefix overridable for the host script tests
# (scripts/verify_scripts.py); unset on a real device.
ZS_SYS_ROOT="${ZS_TEST_ROOT:-/data/system}"
WORKDIR="$ZS_SYS_ROOT/zygisk_study"

# ROUND 34: source the compat layer up front so zs_log (the gated
# diagnostics) is defined on EVERY path — the socket-check tail used
# it while zs_compat.sh was only sourced inside the .mount_pending
# branch. `|| true`: a missing file must not take the daemon launch
# down (the property chain degrades to resetprop-only there).
. "$MODDIR/zs_compat.sh" 2>/dev/null || true
zs_compat_init 2>/dev/null || true

# ROUND 34 (B1): gated diagnostics usable BEFORE zs_compat.sh is
# sourced (the daemon-not-found path exits first). Same opt-in rule
# as zs_log: silent unless <module>/.debug exists.
zs_log_note() {
  if [ -f "$MODDIR/.debug" ] && command -v log >/dev/null 2>&1; then
    log -t ZygiskStudy "$@"
  fi
  return 0
}

# Spawn the daemon. We use `setsid` + `&` so it survives this script's
# exit. We use `exec` style trickery: setsid forks the child, then we
# background it.

DAEMON=$MODDIR/zygiskd
if [ ! -x "$DAEMON" ]; then
  # Round 29: the primary path is the $MODPATH/zygiskd symlink that
  # customize.sh creates. For manual/legacy layouts (a module dir
  # built by hand following the README without re-running
  # customize.sh), fall back to the ABI directory the artifacts
  # actually live in.
  #
  # ROUND 34 (B7 - the wrong-ABI fallback): the zip ships ALL FOUR
  # ABIs, so the old fixed probe order (arm64 first) picked the
  # arm64 binary on every x86/x86_64 device with a missing symlink
  # - exactly the layout this fallback exists for - and setsid
  # failed to exec it: daemon dead on the ABI it was supposed to
  # rescue. Derive the device's ABI FIRST (getprop, the
  # customize.sh-written arch= record) and probe that directory;
  # any-executable is the last resort (single-ABI installs).
  _abi="$(getprop ro.product.cpu.abi 2>/dev/null | tr -d ' \r\n')"
  if [ -z "$_abi" ] && [ -f "$MODDIR/.zygisk_study_info" ]; then
    _abi="$(sed -n 's/^arch=//p' "$MODDIR/.zygisk_study_info" 2>/dev/null | head -n1 | tr -d ' \r\n')"
  fi
  case "$_abi" in
    arm64-v8a|x86_64|armeabi-v7a|x86) ;;
    aarch64) _abi=arm64-v8a ;;
    armeabi*) _abi=armeabi-v7a ;;
    i686) _abi=x86 ;;
    *) _abi="" ;;
  esac
  if [ -n "$_abi" ] && [ -x "$MODDIR/libs/$_abi/zygiskd" ]; then
    DAEMON="$MODDIR/libs/$_abi/zygiskd"
  else
    for cand in "$MODDIR"/libs/*/zygiskd; do
      if [ -x "$cand" ]; then
        DAEMON="$cand"
        break
      fi
    done
  fi
fi
if [ ! -x "$DAEMON" ]; then
  zs_log_note "daemon not found at $MODDIR/zygiskd (or libs/<abi>/)"
  exit 0
fi

# The ro.dalvik.vm.native.bridge swap is done in post-fs-data.sh
# (Round 7, Round 29). This script only starts the daemon.

# ROUND 31: last-resort mount resolution. On KernelSU/APatch the
# post-mount.d hook (see post-mount-hook.sh) normally resolves the
# pending mount BEFORE zygote start. If we get here with the flag
# still set, either the hook is missing (older manager, manual
# install) or every mount strategy failed. Resolve-or-roll-back now:
# a resolved mount revives the module on the next zygote restart (the
# Round 30 property guard re-applies on zygote death), a failure
# rolls the property back so nothing references a missing file.
if [ -f "$WORKDIR/.mount_pending" ]; then
  . "$MODDIR/zs_compat.sh"
  zs_compat_init
  if zs_ensure_loader_mounted; then
    zs_log "service: loader resolved late; armed for next zygote start"
  else
    zs_rollback_bridge
    rm -f "$WORKDIR/.mount_pending" 2>/dev/null
    zs_log "service: loader unresolvable; bridge rolled back (module inert this boot)"
  fi
fi

# ROUND 33 (bug): the old `echo $! > zygiskd.pid` recorded the PID of
# the setsid WRAPPER — which forks (and exits) whenever the backgrounded
# job is already a process-group leader, exactly what shell job control
# produces on Android — so the file named a dead pid from the first
# millisecond. The daemon now writes its own pid AFTER the socket bind
# (native/zygiskd/src/main.rs), so the file only ever exists for a
# fully-started daemon.
# ROUND 34 (B10): guard the setsid call. Magisk runs module scripts
# under busybox ash standalone mode (docs/guides.md - "the full suite
# of commands no matter which Android version"), so setsid exists
# there; KernelSU/APatch environments vary. A missing setsid must not
# take the daemon down with it - the daemon does not need a ctty, a
# plain background launch is enough (the shell exits, the daemon is
# reparented to init).
if command -v setsid >/dev/null 2>&1; then
  setsid "$DAEMON" --workdir "$WORKDIR" >/dev/null 2>&1 &
else
  "$DAEMON" --workdir "$WORKDIR" >/dev/null 2>&1 &
fi

# Give it a moment to come up, then sanity-check the socket. Round 13:
# the socket path is randomized per boot — the daemon hands it to the
# payload via the session file inside our module dir, so the check
# reads that file (falling back to the legacy fixed path). Round 29:
# the daemon also writes the same record into its /data/system workdir
# (session.sock there) — a second source for exactly the same path.
SESSION=$MODDIR/session.sock
SOCK=""
if [ -f "$SESSION" ]; then
  SOCK=$(cat "$SESSION" 2>/dev/null | tr -d ' \r\n')
fi
if [ -z "$SOCK" ] && [ -f "$WORKDIR/session.sock" ]; then
  SOCK=$(cat "$WORKDIR/session.sock" 2>/dev/null | tr -d ' \r\n')
fi
if [ -z "$SOCK" ]; then
  SOCK=$WORKDIR/sock/sock
fi
sleep 1
if [ -S "$SOCK" ]; then
  zs_log "daemon ready"
else
  zs_log "daemon did not open socket; check logcat for errors"
fi
