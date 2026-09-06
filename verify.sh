#!/system/bin/sh
# verify.sh — quick post-install sanity check.
# Run with sh, or source with MODPATH (installer) / MODDIR set.
# Checks bundle completeness and ELF headers, not provenance, build IDs,
# or whether a binary will actually load on a device.

# Keep helpers, variables, shell options and positional arguments out of
# the installer shell when this script is sourced.
(
set -f
IFS=$(printf '\n\t ')
MODDIR=${MODPATH:-${MODDIR:-}}
if [ -z "$MODDIR" ]; then
  case "$0" in
    */*) MODDIR=${0%/*} ;;
    *) MODDIR=. ;;
  esac
fi

zs_verify_print() {
  if command -v ui_print >/dev/null 2>&1; then
    ui_print "$@"
  else
    printf '%s\n' "$*"
  fi
}

zs_verify_fail() {
  zs_verify_print "$*"
  if command -v abort >/dev/null 2>&1; then
    abort "$*" || :
  fi
  # Some installer/test abort helpers return instead of exiting.
  exit 1
}

zs_verify_elf() {
  # Read bytes numerically: no bash-only $'...' quoting, binary shell
  # strings, host-endian integer decoding or external readelf required.
  if ! zs_header=$(od -An -v -tu1 -N64 < "$1"); then
    zs_verify_fail "! Cannot read ELF header: $1"
  fi
  set -- $zs_header
  if [ "$#" -lt 4 ] || [ "$1 $2 $3 $4" != "127 69 76 70" ]; then
    zs_verify_fail "! $p is not an ELF file"
  fi
  if [ "$#" -lt 5 ] || [ "$5" != "$elf_class" ]; then
    zs_verify_fail "! Wrong ELF class for $abi: $p"
  fi
  if [ "$#" -lt "$header_size" ]; then
    zs_verify_fail "! Truncated ELF header: $p"
  fi
  # All four supported Android ABIs are little-endian. Compare both
  # e_machine bytes, so same-width ARM/x86 mixups cannot pass.
  if [ "$6" != 1 ]; then
    zs_verify_fail "! Unsupported ELF byte order: $p"
  fi
  [ "$7" = 1 ] || zs_verify_fail "! Unsupported ELF identification version: $p"
  # Libraries must be ET_DYN. The daemon may be PIE (ET_DYN) or ET_EXEC.
  if [ "${18}" != 0 ] || { [ "${17}" != 3 ] &&
       { [ "$f" != zygiskd ] || [ "${17}" != 2 ]; }; }; then
    zs_verify_fail "! Unsupported ELF object type: $p"
  fi
  shift 18
  if [ "$1" != "$elf_machine" ] || [ "$2" != 0 ]; then
    zs_verify_fail "! Wrong ELF machine for $abi: $p"
  fi
  shift 2
  [ "$1 $2 $3 $4" = "1 0 0 0" ] ||
    zs_verify_fail "! Unsupported ELF header version: $p"
  if [ "$elf_class" = 2 ]; then shift 32; else shift 20; fi
  [ "$1" = "$header_size" ] && [ "$2" = 0 ] ||
    zs_verify_fail "! Invalid declared ELF header size: $p"
}

# A valid subset must not conceal misspelled/unsupported ABI entries.
# Enable expansion locally even when the sourcing shell has noglob enabled.
set +f
for zs_entry in "$MODDIR"/libs/* "$MODDIR"/libs/.[!.]* "$MODDIR"/libs/..?*; do
  [ -e "$zs_entry" ] || [ -L "$zs_entry" ] || continue
  case "${zs_entry##*/}" in
    arm64-v8a|armeabi-v7a|x86_64|x86) ;;
    *) zs_verify_fail "! Unsupported ABI entry: $zs_entry" ;;
  esac
done
set -f

count=0
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  # Subset builds are supported, but every present ABI must be complete.
  [ -e "$MODDIR/libs/$abi" ] || [ -L "$MODDIR/libs/$abi" ] || continue
  case "$abi" in
    arm64-v8a)   elf_class=2; header_size=64; elf_machine=183 ;;
    armeabi-v7a) elf_class=1; header_size=52; elf_machine=40 ;;
    x86_64)      elf_class=2; header_size=64; elf_machine=62 ;;
    x86)         elf_class=1; header_size=52; elf_machine=3 ;;
  esac
  for f in libzygisk.so libpayload.so libzn_loader.so zygiskd; do
    p="$MODDIR/libs/$abi/$f"
    [ -f "$p" ] || zs_verify_fail "! Missing native artifact: $p"
    zs_verify_elf "$p"
    count=$((count + 1))
  done
done

if [ "$count" -eq 0 ]; then
  zs_verify_fail "! No native artifacts found. Build the binaries from source before packaging the module (see README.md)."
fi

zs_verify_print "- Verified $count native artifacts"
)
