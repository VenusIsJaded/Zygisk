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
# Round 30: the bridge's SONAME is randomized per install (see
# customize.sh) and recorded in $MODDIR/.loader_names. The fallback
# covers manual/legacy layouts without the file.
BRIDGE_LIB="libzygisk.so"
if [ -f "$MODDIR/.loader_names" ]; then
  LOADER_BRIDGE="$(sed -n 's/^bridge=//p' "$MODDIR/.loader_names" 2>/dev/null | head -n1)"
  case "$LOADER_BRIDGE" in
    lib*.so) BRIDGE_LIB="$LOADER_BRIDGE" ;;
  esac
fi
RESETPROP="$(command -v resetprop || true)"
if [ -z "$RESETPROP" ]; then
  # Magisk's resetprop lives in the busybox dir on some installs.
  for cand in /data/adb/magisk/resetprop /system/bin/resetprop; do
    [ -x "$cand" ] && RESETPROP="$cand" && break
  done
fi

# Round 31: the compat layer (zs_compat.sh) provides the property
# write chain (resetprop binary -> our daemon's built-in engine) and
# the loader-visibility/mount chain. Sourcing it does nothing by
# itself; zs_compat_init reads .loader_names and sets ZS_* state.
. "$MODDIR/zs_compat.sh"
zs_compat_init

if [ -n "$RESETPROP" ] || [ -x "$ZS_DAEMON" ]; then
  CURRENT="$(zs_prop_get ro.dalvik.vm.native.bridge)"
  # ROUND 34 (B9 — the update-flash edge): a live value that equals
  # OUR previous install's applied name is OURS (the daemon's guard
  # had not restored stock yet, or the module was live-flashed
  # without a reboot), not a "real bridge": treat it as swappable.
  # resetprop changes are memory-only (verified from Magisk
  # native/src/core/resetprop — file persistence is a separate,
  # --persist-only path our scripts never use), so a REBOOT always
  # reloads the stock value; this check covers the live window.
  _ours_prev=""
  if [ -f "$WORKDIR/.native_bridge_applied" ]; then
    _ours_prev="$(cat "$WORKDIR/.native_bridge_applied" 2>/dev/null | tr -d ' \r\n')"
  fi
  _swap_ok=0
  # Round 29: "" and "0" are the two documented no-bridge values.
  if [ -z "$CURRENT" ] || [ "$CURRENT" = "0" ]; then
    _swap_ok=1
  elif [ -n "$_ours_prev" ] && [ "$CURRENT" = "$_ours_prev" ]; then
    _swap_ok=1
  fi
  if [ "$_swap_ok" = "1" ]; then
    # ROUND 34 (B6 — fail CLOSED): the swap previously proceeded even
    # when the backup write failed silently (full disk, SELinux
    # denial of the script context writing system_data_file on
    # KernelSU/APatch) — leaving no rollback record, no uninstall
    # restore, and (with .mount_pending also unwritable) no rollback
    # trigger. Verify the backup BEFORE touching the property; if it
    # cannot be written, this boot stays stock.
    if [ ! -f "$WORKDIR/.native_bridge_backup" ]; then
      printf '%s' "$CURRENT" > "$WORKDIR/.native_bridge_backup" 2>/dev/null
      if [ ! -f "$WORKDIR/.native_bridge_backup" ]; then
        zs_log "backup unwritable; skipping the swap this boot (fail-closed)"
        return 0 2>/dev/null || exit 0
      fi
    fi
    zs_prop_set ro.dalvik.vm.native.bridge "$BRIDGE_LIB"
    # Round 30: record the value we just installed so the daemon's
    # property guard can (a) restore the stock value once the zygote
    # has consumed it and (b) re-apply this exact value after a
    # zygote crash-restart. Written ONLY on a successful swap — its
    # absence (or a mismatch with the live value) means the guard
    # stays inert.
    if [ "$(zs_prop_get ro.dalvik.vm.native.bridge)" = "$BRIDGE_LIB" ]; then
      printf '%s' "$BRIDGE_LIB" > "$WORKDIR/.native_bridge_applied" 2>/dev/null
    fi
    zs_log "native.bridge swapped (was: ${CURRENT:-<absent>}; name withheld)"
    # ROUND 31 (KernelSU / APatch / metamodule-less environments):
    # on Magisk the root manager has ALREADY magic-mounted
    # $MODPATH/system over /system, so the loader is visible right
    # now. On KernelSU (ksud runs module post-fs-data scripts BEFORE
    # the metamodule mount, verified from init_event.rs) it is NOT —
    # and without any metamodule it never will be by itself. Mark the
    # mount as pending; the post-mount.d hook (KernelSU/APatch run it
    # AFTER their metamodule mounting, still before zygote) and
    # service.sh (last resort) resolve it or roll the swap back.
    if zs_loader_visible; then
      rm -f "$WORKDIR/.mount_pending" 2>/dev/null
    else
      : > "$WORKDIR/.mount_pending" 2>/dev/null
      zs_log "loader not visible at /system yet; mount check deferred"
    fi
  else
    # A real bridge is in use — do not touch it. Magisk's own Zygisk
    # (if enabled) sets exactly "libzygisk.so" here.
    if [ "$CURRENT" = "libzygisk.so" ]; then
      zs_log "Magisk's own Zygisk is active; refusing to double-inject"
    else
      zs_log "native.bridge already set to a foreign bridge; leaving it alone"
    fi
  fi
else
  zs_log "no property writer available (resetprop / zygiskd); cannot set native.bridge"
fi
