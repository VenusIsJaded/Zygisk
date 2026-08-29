#!/system/bin/sh
#
# customize.sh — from-scratch reimplementation
#
# This is invoked by Magisk/KernelSU/APatch during module installation.
# It picks the right per-arch binaries, installs them, and sets up
# the WebUI symlink.
#
# Differences from the upstream customize.sh:
#   * Does NOT install machikado.<arch> / mazoku blobs — our
#     reimplementation's zygiskd does not consume them.
#   * Otherwise mirrors the original install structure exactly.

MODDIR="$MODPATH"
# Output dirs inside the module zip:
#   bin/        — zygiskd (one per arch)
#   lib/<arch>/ — the three .so files (one set per arch)
#   webroot/    — built WebUI (index.html + assets/)
#
# At install time we copy:
#   $MODDIR/bin/zygiskd -> /data/adb/modules/zygisksu/bin/zygiskd
#   $MODDIR/lib/<arch>/* -> /data/adb/modules/zygisksu/lib/<arch>/

ARCH=
case "$ARCH" in
  arm64)  ARCH=arm64-v8a ;;
  arm)    ARCH=armeabi-v7a ;;
  x64)    ARCH=x86_64 ;;
  x86)    ARCH=x86 ;;
esac

ui_print "- Installing Zygisk Next (from-scratch reimplementation) for $ARCH"

# Sanity: per-arch binaries must exist in the module zip.
if [ ! -f "$MODDIR/bin/zygiskd.$ARCH" ]; then
  abort "zygiskd.$ARCH not found in module zip — aborting"
fi
if [ ! -f "$MODDIR/lib/$ARCH/libzygisk.so" ]; then
  abort "lib/$ARCH/libzygisk.so not found in module zip"
fi
if [ ! -f "$MODDIR/lib/$ARCH/libzn_loader.so" ]; then
  abort "lib/$ARCH/libzn_loader.so not found in module zip"
fi
if [ ! -f "$MODDIR/lib/$ARCH/libpayload.so" ]; then
  abort "lib/$ARCH/libpayload.so not found in module zip"
fi

# Move per-arch zygiskd into place.
mkdir -p "/data/adb/modules/zygisksu/bin"
cp "$MODDIR/bin/zygiskd.$ARCH" "/data/adb/modules/zygisksu/bin/zygiskd"
chmod 755 "/data/adb/modules/zygisksu/bin/zygiskd"

# Install per-arch libraries.
mkdir -p "/data/adb/modules/zygisksu/lib/$ARCH"
cp "$MODDIR/lib/$ARCH/libzygisk.so"    "/data/adb/modules/zygisksu/lib/$ARCH/"
cp "$MODDIR/lib/$ARCH/libzn_loader.so" "/data/adb/modules/zygisksu/lib/$ARCH/"
cp "$MODDIR/lib/$ARCH/libpayload.so"   "/data/adb/modules/zygisksu/lib/$ARCH/"
chmod 644 "/data/adb/modules/zygisksu/lib/$ARCH"/*.so

# Symlink lib64 -> arm64-v8a, lib -> armeabi-v7a, etc. so the
# in-zygote libzygisk.so can find its siblings via the canonical
# path /data/adb/modules/zygisksu/lib{,64}/<lib>.so
case "$ARCH" in
  arm64-v8a)  ln -sf "$ARCH" "/data/adb/modules/zygisksu/lib64" ;;
  armeabi-v7a) ln -sf "$ARCH" "/data/adb/modules/zygisksu/lib" ;;
esac

# Install the WebUI (built Vue SPA). The KernelSU/APatch manager
# looks for /data/adb/modules/<id>/webroot/index.html.
mkdir -p "/data/adb/modules/zygisksu/webroot/assets"
cp "$MODDIR/webroot/index.html" "/data/adb/modules/zygisksu/webroot/" 2>/dev/null
cp "$MODDIR/webroot/assets/"* "/data/adb/modules/zygisksu/webroot/assets/" 2>/dev/null

# Install the znctl WebUI bridge symlink. The manager app invokes
# the module's webroot/index.html; when the SPA needs to talk to
# zygiskd, it shells out via `ksu.exec('zygiskd ...')`, which is
# resolved by the manager via PATH lookup. The znctl symlink lets
# the SPA call `znctl status` etc.
ln -sf "/data/adb/modules/zygisksu/bin/zygiskd" \
       "/data/adb/modules/zygisksu/bin/znctl"

# Create the config directory.
mkdir -p "/data/adb/zygisksu"
# Default: Zygisk enabled, klog disabled.
[ -f "/data/adb/zygisksu/zygisk_enabled" ] || \
  echo "1" > "/data/adb/zygisksu/zygisk_enabled"
[ -f "/data/adb/zygisksu/klog" ] || \
  echo "0" > "/data/adb/zygisksu/klog"

# Set perms: everything under /data/adb/zygisksu/ is root:root, 0700
# for dirs, 0600 for files. Module dir is root:root 0755.
chown -R 0:0 "/data/adb/zygisksu" "/data/adb/modules/zygisksu"
find "/data/adb/zygisksu" -type d -exec chmod 0700 {} \;
find "/data/adb/zygisksu" -type f -exec chmod 0600 {} \;
chmod 0755 "/data/adb/zygisksu"
chmod 755 "/data/adb/modules/zygisksu/bin/zygiskd"

ui_print "- Installation complete"
ui_print "- Zygisk will activate on next boot"
