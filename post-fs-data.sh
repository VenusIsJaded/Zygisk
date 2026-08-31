#!/system/bin/sh
# post-fs-data.sh — runs very early in the boot, after /data is mounted.
#
# At this point we can:
#   - Set up the daemon's working directory under /data/system/zygisk_study
#     (deliberately NOT under /data/adb/ — that path is a known
#     Zygisk signature and would shout "this is a Zygisk loader" to
#     anyone reading /proc/mounts)
#   - Pre-stage any per-app DenyList configuration the user has dropped
#   - Make the socket directory with the right permissions
#
# We deliberately do NOT do anything that requires multiuser awareness
# here (per-user data isn't available yet). Per-user bookkeeping happens
# in the daemon after it starts.

MODDIR=${0%/*}
# Round 29: the /data/system prefix is overridable for the host script
# tests (scripts/verify_scripts.py). Unset on a real device — the
# expanded path is then byte-identical to the old hard-coded one.
ZS_SYS_ROOT="${ZS_TEST_ROOT:-/data/system}"
WORKDIR="$ZS_SYS_ROOT/zygisk_study"
SOCKDIR=$WORKDIR/sock

mkdir -p "$WORKDIR"
mkdir -p "$SOCKDIR"
chmod 0700 "$WORKDIR"
chmod 0700 "$SOCKDIR"

# Leave a marker so the daemon can detect "first boot after install".
if [ ! -f "$WORKDIR/.installed" ]; then
  date +%s > "$WORKDIR/.installed"
fi

# Default DenyList is empty. The user can populate this file at runtime
# from the WebUI (or by hand). Format: one package name per line.
if [ ! -f "$WORKDIR/denylist" ]; then
  : > "$WORKDIR/denylist"
fi

# Module registry. The daemon reads this on startup. Format:
#   <module_dir>;<compat_flag>
# where <module_dir> is relative to /data/adb/modules.
if [ ! -f "$WORKDIR/modules" ]; then
  : > "$WORKDIR/modules"
fi

# ---------------------------------------------------------------------------
# Round 7: the native-bridge property swap.
#
# This is the missing load step. ART reads ro.dalvik.vm.native.bridge
# once at zygote start and dlopen()s the named library from
# /system/lib[64]/ (the systemless copies customize.sh installed).
# post-fs-data runs before zygote starts, so the property is in place
# in time.
#
# Guards:
#   - resetprop must exist (Magisk environment).
#   - We only set the property when it currently means "no bridge".
#     ROUND 29 (the biggest device-side bug this module ever had):
#     the guard used to swap only when the value was EMPTY — but
#     ART treats BOTH empty and "0" as "no bridge" (verified from
#     AOSP frameworks/base/core/jni/AndroidRuntime.cpp at
#     android-5.0.0_r1:862-871 and android-16.0.0_r1:1109-1117:
#     "" logs a warning and loads nothing, "0" is documented as
#     "native bridge is disabled", anything else is dlopen()ed), and
#     a 173-device real-firmware collection
#     (github.com/getActivity/AndroidSystemPropertyCollect — Samsung
#     OneUI 1.0-8.0, Xiaomi MIUI/HyperOS, OPPO/OnePlus ColorOS,
#     Huawei EMUI/HarmonyOS, vivo OriginOS, realme, Meizu, ...) shows
#     169 devices ship the value "0" and 4 ship it ABSENT — zero
#     devices ship a real bridge. The old guard therefore left the
#     module dead on ~98% of real devices while every host test
#     stayed green. Both "free" values now swap.
#   - Devices that already run a real native bridge (x86 ARM
#     translation, ChromeOS-style bridges) must never be overridden —
#     breaking translation would break the whole device. Any non-empty
#     value other than "0" means a real bridge: refuse.
#   - The previous value is saved so uninstall.sh can restore it
#     exactly (a "0" device restores "0"; an absent-prop device
#     deletes the prop — see uninstall.sh).
# ---------------------------------------------------------------------------
BRIDGE_LIB="libzygisk.so"
RESETPROP="$(command -v resetprop || true)"
if [ -z "$RESETPROP" ]; then
  # Magisk's resetprop lives in the busybox dir on some installs.
  for cand in /data/adb/magisk/resetprop /system/bin/resetprop; do
    [ -x "$cand" ] && RESETPROP="$cand" && break
  done
fi

if [ -n "$RESETPROP" ]; then
  CURRENT="$($RESETPROP ro.dalvik.vm.native.bridge 2>/dev/null)"
  # Round 29: "" and "0" are the two documented no-bridge values.
  if [ -z "$CURRENT" ] || [ "$CURRENT" = "0" ]; then
    if [ ! -f "$WORKDIR/.native_bridge_backup" ]; then
      printf '%s' "$CURRENT" > "$WORKDIR/.native_bridge_backup" 2>/dev/null
    fi
    "$RESETPROP" ro.dalvik.vm.native.bridge "$BRIDGE_LIB"
    log -t ZygiskStudy "native.bridge set to $BRIDGE_LIB (was: ${CURRENT:-<absent>})"
  else
    # A real bridge is in use — do not touch it.
    log -t ZygiskStudy "native.bridge already set ($CURRENT); leaving it alone"
  fi
else
  log -t ZygiskStudy "resetprop not found; cannot set native.bridge"
fi
