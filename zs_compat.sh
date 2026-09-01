#!/system/bin/sh
# zs_compat.sh — Round 31: the root-manager / custom-ROM compatibility
# layer. Sourced (not executed) by post-fs-data.sh, the post-mount.d
# hook, service.sh and uninstall.sh.
#
# WHY THIS EXISTS (all verified online this round, nothing guessed):
#
#   * Magisk mounts a module's system/ directory over /system with
#     magic mount BEFORE post-fs-data scripts run — our loader is
#     already visible at /system/lib[64]/ when our script starts.
#
#   * KernelSU (current ksud, read from
#     userspace/ksud/src/init_event.rs) runs module post-fs-data
#     scripts BEFORE the metamodule that mounts module system/ dirs:
#     at our script's time the loader is NOT visible, and WITHOUT a
#     metamodule (kernelsu.org module guide: "KernelSU uses a
#     metamodule architecture for mounting the system directory.
#     Only if your module needs to modify /system files ... do you
#     need to install a metamodule") it never becomes visible at all.
#
#   * APatch (apd/src/event.rs) delegates to metamodules too, and
#     both KernelSU and APatch run a "post-mount" stage (their
#     run_stage("post-mount") -> /data/adb/post-mount.d scripts)
#     AFTER metamodule mounting and still BEFORE zygote start — the
#     perfect retry point.
#
#   * ART's loader chain (verified from AOSP main this round):
#     AndroidRuntime.cpp passes the property value as
#     -XX:NativeBridge=<value>; art's LoadNativeBridge validates the
#     name with NativeBridgeNameAcceptable (chars [a-zA-Z0-9._-], a
#     leading letter, NO slashes — absolute paths are impossible) and
#     dlopens it through the exported "system" linker namespace,
#     whose search paths (system/linkerconfig contents/namespace/
#     system.cc) are /system/${LIB} and /system_ext/${LIB}. The
#     bridge library therefore MUST be visible by soname in the
#     zygote's mount namespace at /system/lib[64] — there is no other
#     location and no other spelling.
#
#   * Every bionic linker version since 7 also honors /system/lib
#     (32-bit) for the 32-bit zygote on dual-arch devices, so a
#     dual-arch install needs the same soname in BOTH directories.
#
# The functions below implement the write chain for the property
# (resetprop binary -> our daemon's built-in engine, which implements
# bionic's own mutation protocol) and the mount chain for the loader
# (root manager's mount -> direct copy on RW /system -> our own
# overlayfs bind over /system/lib[64] -> fail closed with a clean
# rollback so the boot never depends on a missing file).

# --- property write chain -------------------------------------------------

# zs_prop_get NAME -> prints value (empty if absent)
zs_prop_get() {
  if command -v resetprop >/dev/null 2>&1; then
    resetprop "$1" 2>/dev/null
    return
  fi
  if [ -x "$ZS_DAEMON" ]; then
    "$ZS_DAEMON" prop get "$1" 2>/dev/null
    return
  fi
  getprop "$1" 2>/dev/null
}

# zs_prop_set NAME VALUE -> 0 on success
zs_prop_set() {
  if command -v resetprop >/dev/null 2>&1; then
    resetprop "$1" "$2" 2>/dev/null && return 0
  fi
  for cand in /data/adb/magisk/resetprop /system/bin/resetprop; do
    if [ -x "$cand" ]; then
      "$cand" "$1" "$2" 2>/dev/null && return 0
    fi
  done
  # Round 31: our daemon's built-in engine (props.rs) — the
  # resetprop-equivalent that works on KernelSU / APatch where no
  # resetprop binary exists on PATH.
  if [ -x "$ZS_DAEMON" ]; then
    "$ZS_DAEMON" prop set "$1" "$2" 2>/dev/null && return 0
  fi
  return 1
}

# zs_prop_delete NAME -> 0 on success
zs_prop_delete() {
  if command -v resetprop >/dev/null 2>&1; then
    resetprop --delete "$1" 2>/dev/null && return 0
  fi
  for cand in /data/adb/magisk/resetprop /system/bin/resetprop; do
    if [ -x "$cand" ]; then
      "$cand" --delete "$1" 2>/dev/null && return 0
    fi
  done
  if [ -x "$ZS_DAEMON" ]; then
    "$ZS_DAEMON" prop delete "$1" 2>/dev/null && return 0
  fi
  return 1
}

# --- loader visibility + mount chain --------------------------------------

# zs_lib_dirs -> prints the /system lib dirs THIS device needs
# (one per line). 64-bit always on 64-bit devices; the 32-bit dir
# only when the device is dual-arch AND we installed a 32-bit loader.
zs_lib_dirs() {
  [ "$ZS_IS64" = "1" ] && printf '%s\n' /system/lib64
  if [ "$ZS_IS32" = "1" ]; then
    printf '%s\n' /system/lib
  fi
}

# zs_loader_visible -> 0 if every needed dir has our bridge file
zs_loader_visible() {
  for d in $(zs_lib_dirs); do
    [ -f "$d/$ZS_BRIDGE_NAME" ] || return 1
  done
  return 0
}

# zs_have_overlayfs -> 0 if the kernel supports overlayfs
zs_have_overlayfs() {
  grep -qw overlay /proc/filesystems 2>/dev/null
}

# zs_self_mount_dir DIR -> 0 if OUR overlay over DIR is (now) active.
# Mounts an overlayfs with lowerdir=DIR and an upper/work pair under
# the module dir (the same approach KernelSU's official meta-overlayfs
# metamodule uses, scoped to only the lib dir we need). Idempotent:
# skips when /proc/mounts already shows our upperdir on DIR.
zs_self_mount_dir() {
  _dir="$1"
  _tag="$MODDIR/.ovl$(echo "$_dir" | tr '/' '_')"
  # already mounted?
  if grep -q " $_dir overlay " /proc/mounts 2>/dev/null; then
    if grep -q "upperdir=$_tag/upper" /proc/mounts 2>/dev/null; then
      return 0
    fi
    # someone else's overlay sits there (a metamodule mounted over
    # the whole /system); re-check the file through it before doing
    # anything.
    [ -f "$_dir/$ZS_BRIDGE_NAME" ] && return 0
    return 1
  fi
  zs_have_overlayfs || return 1
  mkdir -p "$_tag/upper" "$_tag/work" 2>/dev/null || return 1
  # A file in the module dir is the upper source: copy it in AFTER the
  # overlay is up so it lands in the upper layer.
  _src="$MODDIR/system${_dir#/system}"
  [ -f "$_src/$ZS_BRIDGE_NAME" ] || return 1
  mount -t overlay overlay \
    -o "lowerdir=$_dir,upperdir=$_tag/upper,workdir=$_tag/work" \
    "$_dir" 2>/dev/null || return 1
  cp "$_src/$ZS_BRIDGE_NAME" "$_dir/$ZS_BRIDGE_NAME" 2>/dev/null || return 1
  # The payload lives beside the bridge under the same soname family.
  if [ -f "$_src/$ZS_PAYLOAD_NAME" ]; then
    cp "$_src/$ZS_PAYLOAD_NAME" "$_dir/$ZS_PAYLOAD_NAME" 2>/dev/null
  fi
  [ -f "$_dir/$ZS_BRIDGE_NAME" ]
}

# zs_ensure_loader_mounted -> 0 if the loader is visible by any means.
# Chain: root-manager mount (already visible) -> direct copy (RW
# /system, rare but free) -> our own overlayfs -> give up.
# The module's own skip_mount flag is honored: it means the USER
# opted this module out of /system modification, so no self-mount.
zs_ensure_loader_mounted() {
  zs_loader_visible && { rm -f "$WORKDIR/.mount_pending" 2>/dev/null; return 0; }
  if [ -f "$MODDIR/skip_mount" ]; then
    log -t ZygiskStudy "skip_mount set; not self-mounting the loader"
    return 1
  fi
  # Direct copy: works only when the /system mount is RW (some custom
  # ROM setups and emulators). Harmless when it fails.
  for d in $(zs_lib_dirs); do
    _src="$MODDIR/system${d#/system}"
    if [ -f "$_src/$ZS_BRIDGE_NAME" ] && [ ! -f "$d/$ZS_BRIDGE_NAME" ]; then
      cp "$_src/$ZS_BRIDGE_NAME" "$d/$ZS_BRIDGE_NAME" 2>/dev/null
      [ -f "$_src/$ZS_PAYLOAD_NAME" ] && \
        cp "$_src/$ZS_PAYLOAD_NAME" "$d/$ZS_PAYLOAD_NAME" 2>/dev/null
    fi
  done
  zs_loader_visible && { rm -f "$WORKDIR/.mount_pending" 2>/dev/null; return 0; }
  # Overlay self-mount per directory.
  for d in $(zs_lib_dirs); do
    zs_self_mount_dir "$d" || true
  done
  if zs_loader_visible; then
    rm -f "$WORKDIR/.mount_pending" 2>/dev/null
    log -t ZygiskStudy "loader self-mounted via overlayfs ($ZS_BRIDGE_NAME)"
    return 0
  fi
  return 1
}

# zs_rollback_bridge -> restore the stock property + stand the guard
# down. Used when the loader cannot be made visible: the module fails
# CLOSED (no property pointing at a file ART cannot load — that would
# only produce a warning + a dead module).
zs_rollback_bridge() {
  if [ -f "$WORKDIR/.native_bridge_backup" ]; then
    _old="$(cat "$WORKDIR/.native_bridge_backup" 2>/dev/null)"
    if [ -n "$_old" ]; then
      zs_prop_set ro.dalvik.vm.native.bridge "$_old"
    else
      zs_prop_delete ro.dalvik.vm.native.bridge
    fi
  fi
  rm -f "$WORKDIR/.native_bridge_applied" 2>/dev/null
}

# --- shared state ----------------------------------------------------------

# zs_compat_init — sets ZS_BRIDGE_NAME / ZS_PAYLOAD_NAME / arch flags
# / ZS_DAEMON. Call at the top of each script AFTER MODDIR/WORKDIR.
zs_compat_init() {
  ZS_BRIDGE_NAME="libzygisk.so"
  ZS_PAYLOAD_NAME="libpayload.so"
  if [ -f "$MODDIR/.loader_names" ]; then
    _b="$(sed -n 's/^bridge=//p' "$MODDIR/.loader_names" 2>/dev/null | head -n1)"
    _p="$(sed -n 's/^payload=//p' "$MODDIR/.loader_names" 2>/dev/null | head -n1)"
    case "$_b" in lib*.so) ZS_BRIDGE_NAME="$_b" ;; esac
    case "$_p" in lib*.so) ZS_PAYLOAD_NAME="$_p" ;; esac
  fi
  ZS_IS64=1
  ZS_IS32=0
  if [ -d "$MODDIR/system/lib64" ]; then
    ZS_IS64=1
  fi
  # Dual-arch: only when we actually installed a 32-bit copy.
  if [ -d "$MODDIR/system/lib" ] && \
     [ -f "$MODDIR/system/lib/$ZS_BRIDGE_NAME" ]; then
    ZS_IS32=1
  fi
  # 32-bit-only devices: no lib64 dir at all.
  if [ ! -d "$MODDIR/system/lib64" ]; then
    ZS_IS64=0
    ZS_IS32=1
  fi
  ZS_DAEMON="$MODDIR/zygiskd"
  if [ ! -x "$ZS_DAEMON" ]; then
    for _c in "$MODDIR"/libs/arm64-v8a/zygiskd "$MODDIR"/libs/x86_64/zygiskd \
              "$MODDIR"/libs/armeabi-v7a/zygiskd "$MODDIR"/libs/x86/zygiskd; do
      if [ -x "$_c" ]; then ZS_DAEMON="$_c"; break; fi
    done
  fi
}
