#!/system/bin/sh
# verify.sh — structural checks for packaged native artifacts.
# Accept ABI subsets, but require every present ABI to contain all four files.
# ELF headers establish format/architecture only, not provenance or safety.

# Magisk sources scripts with MODPATH set; $0 then names the installer.
MODDIR=${MODPATH:-${MODDIR:-$(dirname "$0")}}

if ! command -v ui_print >/dev/null 2>&1; then
  ui_print() { printf '%s\n' "$*"; }
fi
if ! command -v abort >/dev/null 2>&1; then
  abort() { ui_print "$*"; exit 1; }
fi

verify_fail() {
  abort "! $*"
  exit 1
}

verify_elf() {
  # od is available in Android's toybox/busybox and POSIX host shells.
  # Check all four magic bytes, class, little-endian encoding and e_machine.
  # No Bash-only $'...' quoting, binary shell variables, or SIGPIPE pipeline.
  set -- $(LC_ALL=C od -An -v -tu1 -N20 "$1")
  [ "$#" -eq 20 ] || verify_fail "$p has a truncated ELF header"
  [ "$1 $2 $3 $4" = "127 69 76 70" ] || verify_fail "$p is not an ELF file"
  [ "$5" = "$expected_class" ] || verify_fail "$p has the wrong ELF class for $abi"
  [ "$6" = 1 ] || verify_fail "$p is not a little-endian ELF"
  shift 18
  [ "$1" = "$expected_machine" ] && [ "$2" = 0 ] ||
    verify_fail "$p has the wrong ELF machine for $abi"
}

count=0
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
  [ -d "$MODDIR/libs/$abi" ] || continue
  case "$abi" in
    arm64-v8a)   expected_class=2; expected_machine=183 ;;
    armeabi-v7a) expected_class=1; expected_machine=40 ;;
    x86_64)      expected_class=2; expected_machine=62 ;;
    x86)         expected_class=1; expected_machine=3 ;;
  esac
  for f in libzygisk.so libpayload.so libzn_loader.so zygiskd; do
    p="$MODDIR/libs/$abi/$f"
    [ -f "$p" ] || verify_fail "Missing required artifact: $p"
    verify_elf "$p"
    count=$((count + 1))
  done
done

[ "$count" -gt 0 ] || verify_fail "No native artifacts found; build and package them first."
ui_print "- Verified $count native artifacts"
