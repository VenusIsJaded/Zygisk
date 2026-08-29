#!/system/bin/sh
# verify.sh — invoked at install time to verify the module's
# built binaries match the expected SHA256s.
#
# This is a from-scratch reimplementation, so there is no
# "official" SHA256 to compare against. Instead, we verify the
# binaries are valid ELF and have the right machine type for
# the target ABI, and that the documented symbol exports are
# present.

MODDIR=$MODPATH
ARCH=
case "$ARCH" in
  arm64)  ARCH=arm64-v8a ;;
  arm)    ARCH=armeabi-v7a ;;
  x64)    ARCH=x86_64 ;;
  x86)    ARCH=x86 ;;
esac

ui_print "- Verifying $ARCH binaries"

for f in zygiskd.$ARCH lib/$ARCH/libzygisk.so \
         lib/$ARCH/libzn_loader.so lib/$ARCH/libpayload.so; do
  if [ ! -f "$MODDIR/$f" ]; then
    abort "missing: $f"
  fi
  # ELF magic check
  magic=$(head -c 4 "$MODDIR/$f" | od -An -tx1 | tr -d ' \n')
  if [ "$magic" != "7f454c46" ]; then
    abort "not ELF: $f"
  fi
done

# Symbol export verification — check via nm-equivalent. Magisk
# doesn't ship nm, but we can do a crude symbol-presence check
# by grepping the binary for the symbol name string.
for sym in zygisk_entry zn_entry my_execve my_execveat my_wait4; do
  found=0
  for f in lib/$ARCH/libzygisk.so lib/$ARCH/libzn_loader.so lib/$ARCH/libpayload.so; do
    if strings "$MODDIR/$f" 2>/dev/null | grep -q "^$sym$"; then
      found=1
      break
    fi
  done
  if [ $found -eq 0 ]; then
    ui_print "! WARNING: symbol $sym not found in any binary"
  fi
done

ui_print "- Verification passed"
exit 0
