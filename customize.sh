#!/system/bin/sh
# customize.sh — runs at Magisk module installation time.
#
# This script chooses the right native libraries for the device's ABI
# and copies them into $MODPATH. It also writes a small marker file that
# the runtime uses to know which build is present.

# Magisk-provided variables:
#   MODPATH       — module install directory
#   ARCH          — device primary arch (arm64-v8a / armeabi-v7a / x86_64 / x86)
#   IS64BIT       — "true" if 64-bit
#   API           — Android API level
#   ZYGISK_*      — Magisk Zygisk state vars (we don't depend on these)

set -e

# Round 27/28: minimum supported Android version gate. The property
# area (trie format + contexts), the native-bridge interface and the
# fork hook points were all verified from AOSP sources for
# 5.0.0_r1/5.1.1_r37 upward. Below 5.0 the load mechanism does not
# exist AT ALL (Round 28, verified from AOSP at android-4.3_r1,
# 4.3.1_r1 and 4.4.2_r1): system/core has no libnativebridge (the
# library first ships in L), Dalvik has no bridge-loading path (the
# only dlopen in the VM is the per-app System.loadLibrary loader, and
# AndroidRuntime@4.3's complete dalvik.vm.* property surface carries
# no native-bridge key), and the pre-L /dev/__properties__ file uses
# the old flat-TOC format (version 0x45434f76, fixed-size prop_info
# records, no contexts). Refuse cleanly instead of shipping something
# that would misbehave at boot.
if [ -n "$API" ] && [ "$API" -lt 21 ] 2>/dev/null; then
  ui_print "- This Android version (API $API) is below the minimum (21 / Android 5.0)."
  abort "! Zygisk Study requires Android 5.0 or newer."
fi

# Pick the right subdirectory for our prebuilt .so files. The user is
# expected to build these themselves from the source in this repo (see
# README.md) and place them under libs/<abi>/ before packaging the
# module. We do NOT ship binaries here.

case "$ARCH" in
  arm64-v8a)
    NATIVE_DIR="$MODPATH/libs/arm64-v8a"
    DAEMON_BIN="$MODPATH/libs/arm64-v8a/zygiskd"
    LIBZYGISK="$MODPATH/libs/arm64-v8a/libzygisk.so"
    LIBPAYLOAD="$MODPATH/libs/arm64-v8a/libpayload.so"
    LIBLOADER="$MODPATH/libs/arm64-v8a/libzn_loader.so"
    ;;
  armeabi-v7a)
    NATIVE_DIR="$MODPATH/libs/armeabi-v7a"
    DAEMON_BIN="$MODPATH/libs/armeabi-v7a/zygiskd"
    LIBZYGISK="$MODPATH/libs/armeabi-v7a/libzygisk.so"
    LIBPAYLOAD="$MODPATH/libs/armeabi-v7a/libpayload.so"
    LIBLOADER="$MODPATH/libs/armeabi-v7a/libzn_loader.so"
    ;;
  x86_64)
    NATIVE_DIR="$MODPATH/libs/x86_64"
    DAEMON_BIN="$MODPATH/libs/x86_64/zygiskd"
    LIBZYGISK="$MODPATH/libs/x86_64/libzygisk.so"
    LIBPAYLOAD="$MODPATH/libs/x86_64/libpayload.so"
    LIBLOADER="$MODPATH/libs/x86_64/libzn_loader.so"
    ;;
  x86)
    NATIVE_DIR="$MODPATH/libs/x86"
    DAEMON_BIN="$MODPATH/libs/x86/zygiskd"
    LIBZYGISK="$MODPATH/libs/x86/libzygisk.so"
    LIBPAYLOAD="$MODPATH/libs/x86/libpayload.so"
    LIBLOADER="$MODPATH/libs/x86/libzn_loader.so"
    ;;
  *)
    ui_print "- Unsupported ABI: $ARCH"
    abort "! Zygisk Study does not support $ARCH"
    ;;
esac

ui_print "- Target ABI: $ARCH"

# Sanity check: the user must have built and packaged the .so files
# themselves. We never ship binaries from upstream.
for f in "$LIBZYGISK" "$LIBPAYLOAD" "$LIBLOADER" "$DAEMON_BIN"; do
  if [ ! -f "$f" ]; then
    ui_print "! Missing artifact: $f"
    abort "! Build the binaries from source first (see README)."
  fi
done

ui_print "- Native artifacts present"

# Set executable bits.
chmod 0755 "$DAEMON_BIN"
chmod 0644 "$LIBZYGISK" "$LIBPAYLOAD" "$LIBLOADER"

# Round 7: systemless /system layout. Magisk magic-mounts
# $MODPATH/system over /system, so placing the two libraries here
# makes them appear at /system/lib[64]/libzygisk.so — the path
# ro.dalvik.vm.native.bridge must name for ART to dlopen them.
# (Before Round 7 the property swap was entirely stubbed: nothing
# ever put libzygisk.so where ART could load it.)
if [ "$IS64BIT" = "true" ]; then
  SYS_LIB_DIR="$MODPATH/system/lib64"
else
  SYS_LIB_DIR="$MODPATH/system/lib"
fi
mkdir -p "$SYS_LIB_DIR"
# ROUND 30 (STEALTH): the two libraries are installed under
# PER-INSTALL RANDOMIZED names — lib<8-hex>.so (bridge) and
# lib<8-hex>-p.so (payload). A fixed "libzygisk.so" / "libpayload.so"
# in every process's /proc/self/maps is a trivial string signature
# for name-based Zygisk detectors; a random name per install defeats
# that whole class of scan. The payload discovers its own path and
# the bridge's via dladdr at runtime (libzygisk's
# derive_payload_path, hide.cpp's discover_own_paths), so nothing
# else needs the names. They are recorded in .loader_names for
# post-fs-data.sh (the property value) and the daemon (the crash
# re-apply value).
RAND_STEM="$(head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')"
# Fallback for environments without /dev/urandom or od: derive from
# the install time + pid (still unique per install).
if [ -z "$RAND_STEM" ] || [ "${#RAND_STEM}" -ne 8 ]; then
  RAND_STEM="$(printf '%08x' $(( ($(date +%s 2>/dev/null || echo 0) + $$) % 2147483647 )) )"
  RAND_STEM="${RAND_STEM:0:8}"
fi
BRIDGE_NAME="lib${RAND_STEM}.so"
PAYLOAD_NAME="lib${RAND_STEM}-p.so"
cp "$LIBZYGISK"  "$SYS_LIB_DIR/$BRIDGE_NAME"
cp "$LIBPAYLOAD" "$SYS_LIB_DIR/$PAYLOAD_NAME"
chmod 0644 "$SYS_LIB_DIR/$BRIDGE_NAME" "$SYS_LIB_DIR/$PAYLOAD_NAME"
printf 'bridge=%s\npayload=%s\n' "$BRIDGE_NAME" "$PAYLOAD_NAME"   > "$MODPATH/.loader_names"
ui_print "- Systemless bridge layout at $SYS_LIB_DIR ($BRIDGE_NAME)"

# ROUND 31 (custom-ROM / dual-arch compatibility): on a 64-bit device
# that ALSO runs a 32-bit zygote (most pre-2018 SoCs, still common on
# LineageOS-class custom ROMs), the 32-bit zygote resolves the SAME
# property value through ITS search path (/system/lib) and dlopens a
# 32-bit build. Verified from AOSP main this round: ART validates the
# bridge name with NativeBridgeNameAcceptable (no slashes — a bare
# soname), then dlopens it via the exported "system" linker namespace
# whose search paths are per-bitness (/system/${LIB}). The two
# zygotes each search their own directory, so the SAME soname must
# exist in both. Install the 32-bit pair when the device's abilist
# includes a 32-bit ABI AND the user built the 32-bit artifacts.
if [ "$IS64BIT" = "true" ]; then
  ABILIST="$(getprop ro.product.cpu.abilist 2>/dev/null)"
  ZS32_SRC=""
  case "$ABILIST" in
    *armeabi-v7a*) ZS32_SRC="$MODPATH/libs/armeabi-v7a" ;;
    *x86*)         ZS32_SRC="$MODPATH/libs/x86" ;;
    *)             ZS32_SRC="" ;;
  esac
  # ROUND 31 hardening: verify the 32-bit artifacts are actually
  # ELF32 (EI_CLASS byte 1 at offset 4). A 64-bit build dropped in
  # libs/armeabi-v7a would install a bridge the 32-bit zygote can
  # never load — the dlopen would fail silently at boot.
  ZS32_OK=0
  if [ -n "$ZS32_SRC" ] && [ -f "$ZS32_SRC/libzygisk.so" ] && \
     [ -f "$ZS32_SRC/libpayload.so" ]; then
    ZS32_OK=1
    for f in "$ZS32_SRC/libzygisk.so" "$ZS32_SRC/libpayload.so"; do
      CLS="$(od -An -tu1 -j4 -N1 "$f" 2>/dev/null | tr -d ' \t')"
      if [ "$CLS" != "1" ]; then
        ui_print "! $f is not a 32-bit ELF (EI_CLASS=$CLS); skipping 32-bit install"
        ZS32_OK=0
        break
      fi
    done
  fi
  if [ "$ZS32_OK" = "1" ]; then
    mkdir -p "$MODPATH/system/lib"
    cp "$ZS32_SRC/libzygisk.so"  "$MODPATH/system/lib/$BRIDGE_NAME"
    cp "$ZS32_SRC/libpayload.so" "$MODPATH/system/lib/$PAYLOAD_NAME"
    chmod 0644 "$MODPATH/system/lib/$BRIDGE_NAME" "$MODPATH/system/lib/$PAYLOAD_NAME"
    ui_print "- Dual-arch install: 32-bit bridge also placed in system/lib"
  elif [ -n "$ZS32_SRC" ]; then
    ui_print "- NOTE: device is dual-arch but no 32-bit artifacts in $ZS32_SRC"
    ui_print "- 32-bit zygote apps will NOT be injected (64-bit side works)"
  fi
fi

# ROUND 31 (conflict detection — all markers verified online):
#   * Magisk's own Zygisk sets ZYGISK_ENABLED=1 in the installer env
#     (Magisk docs/guides.md) and sets the property to "libzygisk.so".
#   * ZygiskNext / NeoZygisk: module id "zygisksu" (NeoZygisk
#     build.gradle.kts: moduleId by extra("zygisksu")), work dir
#     /data/adb/neozygisk.
#   * ReZygisk: module id "rezygisk", work dir /data/adb/rezygisk.
# Double injection is undefined behavior (two zygote injection
# frameworks fighting over the same processes) — refuse cleanly.
# ZS_TEST_ADB_ROOT remaps /data/adb for the host script tests.
ZS_ADB_ROOT="${ZS_TEST_ADB_ROOT:-/data/adb}"
CONFLICT=""
[ "$ZYGISK_ENABLED" = "1" ] && CONFLICT="Magisk's built-in Zygisk (disable it in Magisk settings)"
for mid in zygisksu zygisk_next rezygisk neozygisk; do
  [ -d "$ZS_ADB_ROOT/modules/$mid" ] && [ -z "$CONFLICT" ] && \
    CONFLICT="the $mid module (remove it or this one)"
done
for wd in "$ZS_ADB_ROOT/neozygisk" "$ZS_ADB_ROOT/rezygisk"; do
  [ -d "$wd" ] && [ -z "$CONFLICT" ] && CONFLICT="$wd (another zygisk implementation)"
done
if [ -z "$CONFLICT" ]; then
  LIVE_BRIDGE="$(getprop ro.dalvik.vm.native.bridge 2>/dev/null)"
  if [ "$LIVE_BRIDGE" = "libzygisk.so" ]; then
    CONFLICT="the live native-bridge value libzygisk.so (Magisk Zygisk or a fixed-name loader)"
  fi
fi
if [ -n "$CONFLICT" ]; then
  ui_print "! CONFLICT: $CONFLICT"
  ui_print "! Two zygote-injection frameworks cannot run at once."
  abort "! Resolve the conflict, then reinstall."
fi
ui_print "- No conflicting zygisk implementation detected"

# ROUND 31 (root-manager compatibility): install the post-mount.d
# hook. KernelSU and APatch run /data/adb/post-mount.d scripts AFTER
# their metamodule mounting (ksud init_event.rs / apd event.rs
# run_stage("post-mount")) and before zygote start — exactly where a
# pending loader mount gets resolved. Magisk ignores the directory
# (harmless dead file; on Magisk magic mount already handles us).
# ReZygisk uses the same mechanism for the same reason.
POSTMOUNT_DIR="$ZS_ADB_ROOT/post-mount.d"
if mkdir -p "$POSTMOUNT_DIR" 2>/dev/null && \
   cp "$MODPATH/post-mount-hook.sh" "$POSTMOUNT_DIR/zygisk_study-mount.sh" 2>/dev/null; then
  chmod 0755 "$POSTMOUNT_DIR/zygisk_study-mount.sh" 2>/dev/null
  ui_print "- post-mount.d hook installed (KernelSU / APatch mount resolution)"
else
  ui_print "- NOTE: post-mount.d not writable; KernelSU mount resolution deferred to service.sh"
fi
# Root-manager messaging (detection is behavior-neutral; the boot
# scripts work identically on all managers).
if [ "$KSU" = "true" ]; then
  ui_print "- KernelSU detected: mount fallback chain active (metamodule or self-overlay)"
elif [ "$APATCH" = "true" ]; then
  ui_print "- APatch detected: mount fallback chain active (metamodule or self-overlay)"
else
  ui_print "- Magisk (or compatible) detected: magic mount + built-in property engine"
fi

# Round 29: service.sh launches the daemon from $MODPATH/zygiskd.
# Before this round NOBODY created that path — customize.sh only
# ever placed the binary at libs/<abi>/zygiskd, so service.sh's
# [ -x "$MODDIR/zygiskd" ] failed on EVERY real install ("daemon not
# found", exit 0) and the daemon never started: no socket, no
# session file, no 'P'/'I'/'C' handlers. Host tests never caught it
# because the fake daemon there is started by the test harness, not
# by service.sh. Create the expected symlink (relative, so it stays
# valid wherever Magisk mounts the module dir).
ln -sfn "libs/$ARCH/zygiskd" "$MODPATH/zygiskd"
ui_print "- Daemon launcher: $MODPATH/zygiskd -> libs/$ARCH/zygiskd"

# Pick the right libzygisk.so for the system property trick (see
# service.sh). Magisk's standard pattern is to swap ro.dalvik.vm.native.bridge
# to point at libzygisk.so on platforms where that property is honored.
ZYGISK_STUDY_LIB="$LIBZYGISK"

# Write a small marker the daemon will read at runtime.
cat > "$MODPATH/.zygisk_study_info" <<EOF
arch=$ARCH
api=$API
libzygisk=$LIBZYGISK
libpayload=$LIBPAYLOAD
libloader=$LIBLOADER
daemon=$DAEMON_BIN
version=v0.1.0
EOF

ui_print "- Zygisk Study installed"
ui_print "- NOTE: This is an educational reimplementation."
ui_print "-       It is NOT a successor to any other Zygisk project."
