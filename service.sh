#!/system/bin/sh
# service.sh — runs after the boot is "mostly" done (after `class_start main`
# from init). The daemon goes here.

MODDIR=${0%/*}
# Round 29: /data/system prefix overridable for the host script tests
# (scripts/verify_scripts.py); unset on a real device.
ZS_SYS_ROOT="${ZS_TEST_ROOT:-/data/system}"
WORKDIR="$ZS_SYS_ROOT/zygisk_study"

# Spawn the daemon. We use `setsid` + `&` so it survives this script's
# exit. We use `exec` style trickery: setsid forks the child, then we
# background it.

DAEMON=$MODDIR/zygiskd
if [ ! -x "$DAEMON" ]; then
  # Round 29: the primary path is the $MODPATH/zygiskd symlink that
  # customize.sh creates. For manual/legacy layouts (a module dir
  # built by hand following the README without re-running
  # customize.sh), fall back to the ABI directory the artifacts
  # actually live in. The first match wins; arm64 is listed first
  # because that is the layout customize.sh builds for 64-bit
  # devices (IS64BIT=true).
  for cand in "$MODDIR"/libs/arm64-v8a/zygiskd \
              "$MODDIR"/libs/x86_64/zygiskd \
              "$MODDIR"/libs/armeabi-v7a/zygiskd \
              "$MODDIR"/libs/x86/zygiskd; do
    if [ -x "$cand" ]; then
      DAEMON="$cand"
      break
    fi
  done
fi
if [ ! -x "$DAEMON" ]; then
  log -t ZygiskStudy "daemon not found at $MODDIR/zygiskd (or libs/<abi>/)"
  exit 0
fi

# The ro.dalvik.vm.native.bridge swap is done in post-fs-data.sh
# (Round 7, Round 29). This script only starts the daemon.
setsid "$DAEMON" --workdir "$WORKDIR" >/dev/null 2>&1 &
echo $! > "$WORKDIR/zygiskd.pid"

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
  log -t ZygiskStudy "daemon ready"
else
  log -t ZygiskStudy "daemon did not open socket; check logcat for errors"
fi
