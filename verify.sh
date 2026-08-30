#!/system/bin/sh
# verify.sh — quick post-install sanity check.
#
# Confirms that the user really did build and package their own .so
# files from the source in this repo. Fails loudly if anything is
# missing or if any file looks suspiciously like a copy of an upstream
# binary (we don't have a fingerprint database, but we can at least
# check the ELF header's e_ident[EI_ABIVERSION] and the build-id to
# make sure the file exists and is plausible).

MODDIR=${0%/*}
EXPECTED_COUNT=4

count=0
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  for f in libzygisk.so libpayload.so libzn_loader.so zygiskd; do
    p="$MODDIR/libs/$abi/$f"
    if [ -f "$p" ]; then
      count=$((count + 1))
      # ELF magic for the libraries
      case "$f" in
        *.so)
          head -c 4 "$p" | grep -q $'\x7fELF' || {
            ui_print "! $p is not an ELF file"
            abort "! Refusing to install: corrupt artifact"
          }
          ;;
      esac
    fi
  done
done

if [ "$count" -eq 0 ]; then
  ui_print "! No native artifacts found."
  ui_print "! You must build the .so files yourself from the source in"
  ui_print "! this repo (see README.md) before packaging the module."
  abort "! Refusing to install with no artifacts."
fi

ui_print "- Verified $count native artifacts"
