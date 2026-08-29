#!/system/bin/sh
# action.sh — WebUI bug-report action.
#
# Invoked by the WebUI when the user clicks "Generate Bug Report".
# Generates a tarball of /data/adb/zygisksu/ + recent klog + logcat
# and prints the path on stdout.

MODDIR=/data/adb/modules/zygisksu

OUTDIR=/data/adb/zygisksu/bugreports
mkdir -p "$OUTDIR"

TS=$(date +%Y%m%d_%H%M%S)
OUT="$OUTDIR/zygisksu_bugreport_$TS.tar.gz"

# Collect: daemon status, module list, klog (last 1000 lines),
# logcat (last -d), and config files.
TMPDIR=$(mktemp -d)
"$MODDIR/bin/zygiskd" status > "$TMPDIR/status.txt" 2>&1
"$MODDIR/bin/zygiskd" list    > "$TMPDIR/modules.txt" 2>&1
dmesg | tail -1000 > "$TMPDIR/dmesg.txt" 2>&1
logcat -d -t 5000 > "$TMPDIR/logcat.txt" 2>&1
cp -r /data/adb/zygisksu/*.txt "$TMPDIR/" 2>/dev/null
cp -r /data/adb/zygisksu/zygisk_enabled "$TMPDIR/" 2>/dev/null
cp -r /data/adb/zygisksu/klog "$TMPDIR/" 2>/dev/null

tar -czf "$OUT" -C "$TMPDIR" .
rm -rf "$TMPDIR"

# Print the path on stdout (the WebUI reads this).
echo "$OUT"
exit 0
