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
cp "$LIBZYGISK"  "$SYS_LIB_DIR/libzygisk.so"
cp "$LIBPAYLOAD" "$SYS_LIB_DIR/libpayload.so"
chmod 0644 "$SYS_LIB_DIR/libzygisk.so" "$SYS_LIB_DIR/libpayload.so"
ui_print "- Systemless bridge layout at $SYS_LIB_DIR"

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
