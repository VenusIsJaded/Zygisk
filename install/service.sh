#!/system/bin/sh
# service.sh — service-stage hook.
#
# At this stage zygote is up. zygiskd (started in post-fs-data.sh)
# has already ptrace-attached to zygote and injected libzygisk.so.
# This script invokes `zygiskd service-stage` which verifies the
# injection worked; if not, it logs an error but does not block
# boot.

MODDIR=/data/adb/modules/zygisksu

# Install the cleanup hook — on next shutdown, restore module.prop.orig
# if we patched it (this is for the ZYGISK_ENABLED=0 path; see the
# emulated-soft-reboot.sh script).
"$MODDIR/bin/zygiskd" service-stage 2>/dev/null

exit 0
