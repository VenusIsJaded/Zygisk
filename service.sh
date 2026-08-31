#!/system/bin/sh
# service.sh — runs after the boot is "mostly" done (after `class_start main`
# from init). The daemon goes here.

MODDIR=${0%/*}
WORKDIR=/data/system/zygisk_study

# Spawn the daemon. We use `setsid` + `&` so it survives this script's
# exit. We use `exec` style trickery: setsid forks the child, then we
# background it.

DAEMON=$MODDIR/zygiskd
if [ ! -x "$DAEMON" ]; then
  # Path on some 32-bit devices is different — fall back to module dir.
  # The actual binary name comes from customize.sh which sets it to
  # $MODPATH/libs/<abi>/zygiskd. We expect the layout:
  #   $MODDIR/zygiskd -> symlink to the real binary
  # If that's missing, we abort cleanly rather than crash zygote.
  log -t ZygiskStudy "daemon not found at $DAEMON"
  exit 0
fi

# Disable prop-based preload trick (avoids double-launch).
# The actual ro.dalvik.vm.native.bridge swap is done from the daemon
# itself on supported platforms. We just start the companion here.
setsid "$DAEMON" --workdir "$WORKDIR" >/dev/null 2>&1 &
echo $! > "$WORKDIR/zygiskd.pid"

# Give it a moment to come up, then sanity-check the socket. Round 13:
# the socket path is randomized per boot — the daemon hands it to the
# payload via the session file inside our module dir, so the check
# reads that file (falling back to the legacy fixed path).
SESSION=$MODDIR/session.sock
SOCK=""
if [ -f "$SESSION" ]; then
  SOCK=$(cat "$SESSION" 2>/dev/null | tr -d ' \r\n')
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
