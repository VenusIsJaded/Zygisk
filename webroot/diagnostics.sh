#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Read-only snapshot. No property writes, daemon commands, policy changes or
# test injection. Fields are base64 encoded to keep module metadata inert.
# ZS_DIAG_ROOT is a host-test filesystem prefix, never supplied by the WebUI.
ROOT=${ZS_DIAG_ROOT:-}
MODDIR="${0%/*}/.."
[ -z "$ROOT" ] || MODDIR="$ROOT/data/adb/modules/zygisk_study"
WORKDIR="$ROOT/data/system/zygisk_study"
MODULES="$ROOT/data/adb/modules"
export LC_ALL=C
command -v base64 >/dev/null 2>&1 || { echo 'base64 is required' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Root access is required. Open this page in a compatible module WebUI manager.' >&2; exit 1; }
row() {
  printf '%s' "$1"; shift
  for field in "$@"; do
    printf '\t'
    printf '%s' "$field" | base64 | tr -d '\r\n'
  done
  printf '\n'
}
prop() { getprop "$1" 2>/dev/null; }
value() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1 | cut -c 1-1024 | tr -d '\r'; }
check() { row check "$@"; }
row meta protocol 1
row meta collected "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
row meta model "$(prop ro.product.model)"
row meta android "$(prop ro.build.version.release)"
row meta kernel "$(uname -r)"
row meta version "$(value "$MODDIR/module.prop" version)"
ABI=$(prop ro.product.cpu.abi)
case "$ABI" in arm64-v8a|armeabi-v7a|x86|x86_64) ;; *) ABI=unknown ;; esac
row meta abi "$ABI"
row meta selinux "$(getenforce 2>/dev/null)"
check root pass 'Root access' 'Collector is running with UID 0.' 'No action needed.'
if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
  check enabled fail 'Loader enabled' 'The loader is disabled or scheduled for removal.' 'Review the module state in your root manager, then reboot when safe.'
else
  check enabled pass 'Loader enabled' 'No disable or remove marker is present.' 'This is an installation check, not proof of injection.'
fi
if [ "$(prop sys.boot_completed)" = 1 ]; then
  check boot pass 'Android boot' 'Android reports that boot has completed.' 'No action needed.'
else
  check boot warn 'Android boot' 'Boot completion has not been reported.' 'Wait for boot to finish, then run diagnostics again.'
fi
BRIDGE=$(value "$MODDIR/.loader_names" bridge)
[ -n "$BRIDGE" ] || BRIDGE=libzygisk.so
case "$BRIDGE" in *[!a-zA-Z0-9_.-]*|.|..) BRIDGE=libzygisk.so ;; esac
CURRENT=$(prop ro.dalvik.vm.native.bridge)
if [ "$CURRENT" = "$BRIDGE" ]; then
  check bridge pass 'Native bridge property' 'The native bridge property matches the installed loader.' 'A matching property does not prove ART loaded it; check debug logs.'
else
  check bridge fail 'Native bridge property' 'The native bridge property does not point to this loader.' 'Inspect post-fs-data and mount resolution. An existing translation bridge must not be overwritten.'
fi
case "$ABI" in *64*) LIB=lib64 ;; *) LIB=lib ;; esac
if [ "$ABI" = unknown ]; then
  check mount unknown 'System loader visibility' 'Device ABI could not be read.' 'Check root permissions and getprop availability.'
elif [ -r "$ROOT/system/$LIB/$BRIDGE" ]; then
  check mount pass 'System loader visibility' 'The loader is readable in the collector mount namespace.' 'The zygote mount namespace may differ; this is not proof of loading.'
else
  check mount fail 'System loader visibility' 'The system loader library is not readable here.' 'Check your manager mount support and the post-mount hook. Do not manually overwrite system libraries.'
fi
if [ -f "$WORKDIR/.mount_pending" ]; then
  check pending warn 'Mount handoff' 'The mount-pending marker is still present.' 'Inspect post-mount-hook.sh and service logs for mount resolution or rollback.'
else
  check pending pass 'Mount handoff' 'No pending mount marker was found.' 'Absence of the marker does not prove a successful mount.'
fi
PID=$(head -n 1 "$WORKDIR/zygiskd.pid" 2>/dev/null | tr -d '\r\n')
case "$PID" in ''|*[!0-9]*) PID=0 ;; esac
EXE=$(readlink "$ROOT/proc/$PID/exe" 2>/dev/null)
case "$EXE" in
  "$MODULES/zygisk_study/zygiskd"|"$MODULES/zygisk_study/libs/"*/zygiskd)
    check daemon pass 'Companion daemon process' 'The recorded PID belongs to the installed daemon.' 'Process identity is confirmed; protocol responsiveness is not tested.' ;;
  *)
    check daemon unknown 'Companion daemon process' 'The recorded PID is missing, stale, or its executable cannot be verified.' 'Inspect service.sh, daemon binary ABI and permissions. A hidden process is not automatically a failed process.' ;;
esac
SOCK=$(head -n 1 "$MODDIR/session.sock" 2>/dev/null | tr -d ' \r\n')
[ -n "$SOCK" ] || SOCK=$(head -n 1 "$WORKDIR/session.sock" 2>/dev/null | tr -d ' \r\n')
[ -n "$SOCK" ] || SOCK=/data/system/zygisk_study/sock/sock
case "$SOCK" in /data/system/zygisk_study/*) case "$SOCK" in *"/../"*|*"/./"*|*"//"*|*/..|*/.) SOCKET_PATH='' ;; *) SOCKET_PATH="$ROOT$SOCK" ;; esac ;; *) SOCKET_PATH='' ;; esac
if [ -n "$SOCKET_PATH" ] && [ -S "$SOCKET_PATH" ]; then
  check socket pass 'Companion socket' 'A Unix socket exists at the session endpoint.' 'Socket presence does not verify IPC or connectCompanion(). Session paths are omitted from reports.'
else
  check socket fail 'Companion socket' 'The session endpoint is missing or invalid.' 'Check daemon startup, session records and SELinux denials. Re-run after boot completes.'
fi
if [ -r "$WORKDIR/denylist" ]; then
  COUNT=$(grep -c '^[^#[:space:]]' "$WORKDIR/denylist" 2>/dev/null) || COUNT=0
  check denylist pass 'DenyList configuration' "$COUNT non-comment entries; configuration is readable." 'Reading the file does not verify enforcement. Package names are excluded from the snapshot.'
else
  check denylist warn 'DenyList configuration' 'The DenyList configuration cannot be read.' 'Check whether post-fs-data.sh initialized the working directory.'
fi
if [ -f "$MODDIR/.debug" ]; then
  check debug pass 'Boot-script logging' 'The .debug marker is enabled.' 'Native Release builds compile out logs; .debug only enables shell diagnostics.'
else
  check debug warn 'Boot-script logging' 'Optional boot-script diagnostics are off.' 'For shell logs, create .debug in the module directory before a controlled reboot. Native logs require a Debug build.'
fi
if [ ! -r "$MODULES" ] || [ ! -x "$MODULES" ]; then
  check inventory unknown 'Module inventory' 'The module directory cannot be enumerated.' 'Check root access and SELinux policy; an unreadable directory is not an empty inventory.'
else
  check inventory pass 'Module inventory' 'The installed module directory is accessible.' 'Discovery is based on disk layout, not a daemon registry query or proof of onLoad execution.'
  N=0
  for DIR in "$MODULES"/*; do
    [ -d "$DIR/zygisk" ] || continue
    N=$((N + 1))
    if [ "$N" -gt 256 ]; then
      check inventory_limit warn 'Inventory limit' 'Only the first 256 Zygisk module directories are shown.' 'Inspect additional directories manually.'
      break
    fi
    ID=${DIR##*/}
    NAME=$(value "$DIR/module.prop" name); [ -n "$NAME" ] || NAME=$ID
    ABIS=''; LAYOUT='none'; ELIGIBLE=no
    for A in arm64-v8a armeabi-v7a x86_64 x86; do
      if [ -f "$DIR/zygisk/$A.so" ] || [ -f "$DIR/zygisk/$A/libzygisk-module.so" ]; then
        ABIS="${ABIS}${ABIS:+, }$A"
      fi
    done
    if [ -f "$DIR/zygisk/$ABI/libzygisk-module.so" ]; then LAYOUT=study; ELIGIBLE=yes
    elif [ -f "$DIR/zygisk/$ABI.so" ]; then LAYOUT=standard
    fi
    FLAGS=enabled
    [ ! -f "$DIR/disable" ] || FLAGS=disabled
    [ ! -f "$DIR/remove" ] || FLAGS=removing
    row module "$ID" "$NAME" "$(value "$DIR/module.prop" version)" "$(value "$DIR/module.prop" author)" "$(value "$DIR/module.prop" description)" "$ABIS" "$LAYOUT" "$FLAGS" "$ELIGIBLE"
  done
fi
# Finite, tag-filtered log read. No log clearing, continuous process or full
# device log export. Native Release builds may legitimately return no lines.
if command -v logcat >/dev/null 2>&1; then
  if LOGS=$(logcat -d -t 150 -v threadtime -s 'ZygiskStudy:*' '*:S' 2>/dev/null); then
    row meta logStatus available
    printf '%s\n' "$LOGS" | tail -n 150 | while IFS= read -r LINE; do
      [ -z "$LINE" ] || row log "$(printf '%s' "$LINE" | cut -c 1-1024)"
    done
  else
    row meta logStatus denied
  fi
else
  row meta logStatus unavailable
fi
row meta complete 1
