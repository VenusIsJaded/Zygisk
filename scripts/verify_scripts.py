#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Round 29 — E2E verification of the module's shell scripts.

Until this round every device-side shell script (post-fs-data.sh,
service.sh, customize.sh, uninstall.sh) ran ONLY on a phone: the host
test suite exercised the C++ payload and the Rust daemon, but nothing
executed the scripts that actually wire them into a boot. That is how
the two worst install-path bugs survived 28 rounds:

  1. post-fs-data.sh only swapped ro.dalvik.vm.native.bridge when the
     value was EMPTY, but 169 of 173 devices in the real-firmware
     collection (getActivity/AndroidSystemPropertyCollect) ship "0"
     and 4 ship it absent — the module was dead on ~98% of real
     devices. ART treats "" and "0" identically (AndroidRuntime.cpp
     at 5.0.0_r1:862-871 and 16.0.0_r1:1109-1117).
  2. service.sh looked for $MODDIR/zygiskd, a path NOBODY created —
     customize.sh only ever installed libs/<abi>/zygiskd, so the
     daemon never started on any real install.

This harness runs the REAL scripts against a fake Magisk environment
(temp module dir + PATH-injected fake resetprop/log + ZS_TEST_ROOT
remap of /data/system — the same seam the daemon uses). Every check
below failed against the pre-Round-29 scripts or guards the fixed
behavior.

Exit codes: 0 all pass, 1 any failure.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

failures = []
skips = []    # Round 34: optional-toolchain skips (cargo absent, etc.)

FAKE_RESETPROP = """#!/bin/sh
# Fake resetprop for script E2E. Read mode prints the CURRENT value
# (the configured one, or the last value a SET wrote — Round 30's
# post-fs-data read-back depends on realistic get-after-set
# semantics); every invocation is recorded to
# $ZS_FAKE_RESETPROP_LOG.
LOG="${ZS_FAKE_RESETPROP_LOG:?}"
STATE="${ZS_FAKE_PROP_STATE:?}"
if [ "$#" -eq 1 ]; then
  if [ -f "$STATE" ]; then
    cat "$STATE"
  else
    printf '%s\\n' "$ZS_FAKE_PROP_VALUE"
  fi
  exit 0
fi
printf '%s\\n' "$*" >> "$LOG.raw"
if [ "$ZS_REQUIRE_NO_SERVICE" = "1" ] && [ "$1" != "-n" ] && [ "$1" != "--delete" ]; then
  echo "property service blocked during post-fs-data" >&2
  exit 1
fi
# Preserve raw argv for the boot-stage regression; legacy checks below
# intentionally compare normalized NAME VALUE operations.
if [ "$1" = "-n" ]; then shift; fi
printf '%s\\n' "$*" >> "$LOG"
if [ "$1" = "--delete" ]; then
  [ -n "$ZS_FAKE_DELETE_FAIL" ] && exit 1
  : > "$STATE"
elif [ "$#" -ge 2 ]; then
  printf '%s\\n' "$2" > "$STATE"
fi
exit 0
"""

FAKE_LOG = """#!/bin/sh
# Fake Android `log` — silently succeed.
exit 0
"""

FAKE_GETPROP = """#!/bin/sh
# Fake Android `getprop` — the compat layer's last-resort read and the
# customize.sh detections use it. Values come from ZS_FAKE_GETPROP_*.
case "$1" in
  ro.dalvik.vm.native.bridge)
    if [ -n "${ZS_FAKE_PROP_STATE:-}" ] && [ -f "$ZS_FAKE_PROP_STATE" ]; then
      cat "$ZS_FAKE_PROP_STATE"; exit 0
    fi
    printf '%s\\n' "${ZS_FAKE_GETPROP_BRIDGE:-0}"; exit 0 ;;
  ro.product.cpu.abilist)
    printf '%s\\n' "${ZS_FAKE_GETPROP_ABILIST:-arm64-v8a}"; exit 0 ;;
  *) printf '%s\\n' "" ; exit 0 ;;
esac
"""

STUB_DAEMON = """#!/bin/sh
# Stub zygiskd: records its argv and exits 0.
printf '%s\\n' "$*" >> "${ZS_STUB_DAEMON_LOG:?}"
exit 0
"""


def check(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(f"{name}: {detail}")


def skip(name, reason=""):
    # Round 34: a SKIP is neither pass nor fail — used when an optional
    # toolchain (cargo) is genuinely absent. Previously a missing cargo
    # was reported as a FAIL ("cargo build failed"), which misreported
    # a toolchain-absent host as a code regression. See find_real_daemon.
    print(f"  [SKIP] {name}" + (f"  ({reason})" if reason else ""))
    skips.append(f"{name}: {reason}")


def write_exec(path, contents):
    with open(path, "w") as fp:
        fp.write(contents)
    os.chmod(path, 0o755)


class FakeMagisk:
    """A temp module dir + fake tool PATH + remapped /data/system."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="zs_scripts_")
        self.moddir = os.path.join(self.root, "module")
        self.sysroot = os.path.join(self.root, "data", "system")
        self.workdir = os.path.join(self.sysroot, "zygisk_study")
        self.bindir = os.path.join(self.root, "bin")
        os.makedirs(self.moddir)
        os.makedirs(self.sysroot)
        os.makedirs(self.bindir)
        for script in ("post-fs-data.sh", "service.sh", "uninstall.sh",
                       "customize.sh", "zs_compat.sh", "post-mount-hook.sh"):
            shutil.copy(os.path.join(REPO_ROOT, script),
                        os.path.join(self.moddir, script))
        write_exec(os.path.join(self.bindir, "resetprop"), FAKE_RESETPROP)
        write_exec(os.path.join(self.bindir, "log"), FAKE_LOG)
        write_exec(os.path.join(self.bindir, "getprop"), FAKE_GETPROP)
        # Model the documented installer helper, not host SELinux/root.
        # Record all arguments so tests can assert context + ownership.
        write_exec(os.path.join(self.bindir, "set_perm"), '''#!/bin/sh
printf '%s\\n' "$*" >> "${MODPATH:?}/permissions.log"
[ "$5" = u:object_r:system_file:s0 ] || exit 1
[ "$2:$3" = 0:0 ] || exit 1
case "$1" in
  *"${ZS_FAIL_PERM:-__never__}"*) exit 1 ;;
esac
chmod "$4" "$1"
''')
        self.resetprop_log = os.path.join(self.root, "resetprop.log")
        self.stub_daemon_log = os.path.join(self.root, "stub_daemon.log")
        self.prop_value = "0"
        self.delete_fail = ""
        self.prop_state = os.path.join(self.root, "prop_state")

    def env(self, extra=None):
        env = dict(os.environ)
        env["PATH"] = self.bindir + os.pathsep + env.get("PATH", "")
        env["ZS_TEST_ROOT"] = self.sysroot
        env["ZS_TEST_ADB_ROOT"] = self.root
        env["ZS_FAKE_RESETPROP_LOG"] = self.resetprop_log
        env["ZS_FAKE_PROP_VALUE"] = self.prop_value
        env["ZS_FAKE_PROP_STATE"] = self.prop_state
        env["ZS_STUB_DAEMON_LOG"] = self.stub_daemon_log
        if self.delete_fail:
            env["ZS_FAKE_DELETE_FAIL"] = self.delete_fail
        if extra:
            env.update(extra)
        return env

    def run_script(self, name, extra_env=None):
        proc = subprocess.run(
            ["sh", os.path.join(self.moddir, name)],
            env=self.env(extra_env),
            capture_output=True, text=True, timeout=60)
        return proc

    def resetprop_calls(self):
        if not os.path.exists(self.resetprop_log):
            return []
        with open(self.resetprop_log) as fp:
            return [line.rstrip("\n") for line in fp]

    def backup_value(self):
        p = os.path.join(self.workdir, ".native_bridge_backup")
        if not os.path.exists(p):
            return None
        with open(p) as fp:
            return fp.read()

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def installed_layout(mk, abi="arm64-v8a", with_symlink=True):
    """Create the on-device module layout customize.sh produces (or
    the legacy one, without the Round 29 symlink)."""
    libs = os.path.join(mk.moddir, "libs", abi)
    os.makedirs(libs, exist_ok=True)
    for f in ("libzygisk.so", "libpayload.so", "libzn_loader.so"):
        with open(os.path.join(libs, f), "wb") as fp:
            fp.write(b"\x7fELF" + b"\x00" * 64)
    write_exec(os.path.join(libs, "zygiskd"), STUB_DAEMON)
    if with_symlink:
        os.symlink(f"libs/{abi}/zygiskd",
                   os.path.join(mk.moddir, "zygiskd"))


# ---------------------------------------------------------------------------
# post-fs-data.sh — the Round 29 "0" guard.
# ---------------------------------------------------------------------------

def test_swap_value_zero(mk):
    mk.prop_value = "0"
    proc = mk.run_script("post-fs-data.sh", {"ZS_REQUIRE_NO_SERVICE": "1"})
    with open(mk.resetprop_log + ".raw") as fp:
        raw_calls = fp.read().splitlines()
    check("post-fs-data bypasses the blocked property service",
          "-n ro.dalvik.vm.native.bridge libzygisk.so" in raw_calls,
          repr(raw_calls))
    check("post-fs-data with current=0 exits 0", proc.returncode == 0,
          proc.stderr[-200:])
    calls = mk.resetprop_calls()
    check("post-fs-data with current=0 SWAPS the bridge",
          "ro.dalvik.vm.native.bridge libzygisk.so" in calls, str(calls))
    check("post-fs-data backup records the original 0",
          mk.backup_value() == "0", repr(mk.backup_value()))
    check("workdir created 0700",
          stat.S_IMODE(os.stat(mk.workdir).st_mode) == 0o700)


def test_swap_value_absent(mk):
    mk.prop_value = ""
    proc = mk.run_script("post-fs-data.sh")
    calls = mk.resetprop_calls()
    check("post-fs-data with absent prop SWAPS the bridge",
          proc.returncode == 0
          and "ro.dalvik.vm.native.bridge libzygisk.so" in calls,
          str(calls))
    check("post-fs-data backup records the empty original",
          mk.backup_value() == "", repr(mk.backup_value()))


def test_swap_refuses_real_bridge(mk):
    for real in ("libhoudini.so", "libndk_translation.so",
                 "libndk_translation_arm64.so"):
        mk2 = FakeMagisk()
        mk2.prop_value = real
        proc = mk2.run_script("post-fs-data.sh")
        calls = mk2.resetprop_calls()
        check(f"post-fs-data refuses to override {real}",
              proc.returncode == 0 and calls == [], str(calls))
        check(f"no backup written for {real}", mk2.backup_value() is None)
        mk2.cleanup()


def test_backup_not_overwritten(mk):
    mk.prop_value = "0"
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("0")
    mk.run_script("post-fs-data.sh")
    check("existing backup is preserved on re-run",
          mk.backup_value() == "0", repr(mk.backup_value()))
    # The swap still happened (upgrade path).
    check("swap still happens when backup exists",
          "ro.dalvik.vm.native.bridge libzygisk.so" in mk.resetprop_calls())


def test_round30_random_name_swap_and_applied_record(mk):
    """Round 30: with .loader_names present, the swap uses the
    randomized bridge name and records it in .native_bridge_applied
    (the daemon's crash re-apply value); without a swap, no applied
    record is written."""
    # (a) the randomized-name swap.
    mk.prop_value = "0"
    with open(os.path.join(mk.moddir, ".loader_names"), "w") as fp:
        fp.write("bridge=lib3fa2b81c.so\npayload=lib3fa2b81c-p.so\n")
    proc = mk.run_script("post-fs-data.sh")
    calls = mk.resetprop_calls()
    check("post-fs-data swaps the RANDOMIZED bridge name",
          proc.returncode == 0
          and "ro.dalvik.vm.native.bridge lib3fa2b81c.so" in calls,
          str(calls))
    applied = os.path.join(mk.workdir, ".native_bridge_applied")
    check(".native_bridge_applied records the installed name",
          os.path.exists(applied)
          and open(applied).read() == "lib3fa2b81c.so",
          open(applied).read() if os.path.exists(applied) else "<missing>")

    # (b) a garbage .loader_names falls back to the fixed name.
    mk2 = FakeMagisk()
    mk2.prop_value = "0"
    with open(os.path.join(mk2.moddir, ".loader_names"), "w") as fp:
        fp.write("bridge=../../evil/path\npayload=x\n")
    mk2.run_script("post-fs-data.sh")
    check("garbage .loader_names falls back to libzygisk.so",
          "ro.dalvik.vm.native.bridge libzygisk.so"
          in mk2.resetprop_calls(), str(mk2.resetprop_calls()))
    mk2.cleanup()

    # (c) no swap (real bridge): no applied record.
    mk3 = FakeMagisk()
    mk3.prop_value = "libhoudini.so"
    mk3.run_script("post-fs-data.sh")
    check("real bridge: no .native_bridge_applied written",
          not os.path.exists(
              os.path.join(mk3.workdir, ".native_bridge_applied")))
    mk3.cleanup()


def test_no_resetprop_is_survivable(mk):
    # A real Android always has `log` (system/core/logcat) even when
    # resetprop is unavailable — keep the fake log, drop resetprop.
    logonly = os.path.join(mk.root, "bin_logonly")
    os.makedirs(logonly, exist_ok=True)
    write_exec(os.path.join(logonly, "log"), FAKE_LOG)
    env = mk.env()
    parts = [p for p in env["PATH"].split(os.pathsep) if p != mk.bindir]
    env["PATH"] = os.pathsep.join([logonly] + parts)
    proc = subprocess.run(
        ["sh", os.path.join(mk.moddir, "post-fs-data.sh")],
        env=env, capture_output=True, text=True, timeout=60)
    check("missing resetprop: script still exits 0",
          proc.returncode == 0, proc.stderr[-200:])
    check("missing resetprop: no swap attempted",
          mk.resetprop_calls() == [])


def test_installed_marker_and_denylist(mk):
    mk.prop_value = "0"
    mk.run_script("post-fs-data.sh")
    check(".installed marker written",
          os.path.exists(os.path.join(mk.workdir, ".installed")))
    check("denylist file initialized empty",
          os.path.exists(os.path.join(mk.workdir, "denylist")))
    check("modules registry initialized",
          os.path.exists(os.path.join(mk.workdir, "modules")))


# ---------------------------------------------------------------------------
# customize.sh — the Round 29 launcher symlink.
# ---------------------------------------------------------------------------

def run_customize(mk, arch="arm64", abi=None, api="30", is64="true",
                  make_libs=True, missing_artifact=False, extra_env=None):
    """Run customize.sh the way a REAL installer does.

    ROUND 32: `arch` is the value Magisk/KernelSU/APatch actually set
    (arm64 | arm | x86 | x64 — verified from their api_level_arch_detect
    functions); `abi` is the NDK-style directory name under libs/ (for
    arm64 that is arm64-v8a). The two are DIFFERENT names: the old test
    harness passed "arm64-v8a" as ARCH, which no installer ever does —
    the exact bug that made customize.sh abort on every real device
    while the host tests stayed green.
    """
    if abi is None:
        abi = {"arm64": "arm64-v8a", "arm": "armeabi-v7a",
               "x64": "x86_64", "x86": "x86"}[arch]
    modpath = os.path.join(mk.root, "modpath")
    shutil.rmtree(modpath, ignore_errors=True)
    os.makedirs(modpath)
    if make_libs:
        libs = os.path.join(modpath, "libs", abi)
        os.makedirs(libs)
        for f in ("libzygisk.so", "libpayload.so", "libzn_loader.so"):
            with open(os.path.join(libs, f), "wb") as fp:
                fp.write(b"\x7fELF" + b"\x00" * 64)
        write_exec(os.path.join(libs, "zygiskd"), STUB_DAEMON)
    if missing_artifact and make_libs:
        os.unlink(os.path.join(modpath, "libs", abi, "libpayload.so"))
    wrapper = (
        "ui_print() { echo \"$*\"; }\n"
        "abort() { echo \"ABORT:$*\"; exit 1; }\n"
        f". {os.path.join(mk.moddir, 'customize.sh')}\n")
    env = mk.env({"MODPATH": modpath, "ARCH": arch, "API": api,
                  "IS64BIT": is64})
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        ["sh", "-c", wrapper],
        env=env,
        capture_output=True, text=True, timeout=60)
    return proc, modpath


def test_customize_creates_launcher(mk):
    proc, modpath = run_customize(mk)
    check("customize.sh (arm64, API 30) exits 0", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    link = os.path.join(modpath, "zygiskd")
    check("customize.sh creates $MODPATH/zygiskd",
          os.path.islink(link), link)
    if os.path.islink(link):
        target = os.readlink(link)
        check("launcher symlink points at the abi dir",
              target == "libs/arm64-v8a/zygiskd", target)
        check("launcher target is executable",
              os.access(os.path.join(modpath, target), os.X_OK))
    sysdir = os.path.join(modpath, "system", "lib64")
    # Round 30: the libraries are installed under randomized names
    # recorded in .loader_names (STEALTH — fixed names are map-scan
    # signatures).
    names_p = os.path.join(modpath, ".loader_names")
    bridge = payload = None
    if os.path.exists(names_p):
        with open(names_p) as fp:
            for line in fp:
                if line.startswith("bridge="):
                    bridge = line.strip()[len("bridge="):]
                elif line.startswith("payload="):
                    payload = line.strip()[len("payload="):]
    check(".loader_names records both names",
          bool(bridge and payload and bridge != payload
               and bridge.startswith("lib") and bridge.endswith(".so")
               and payload.startswith("lib") and payload.endswith(".so")
               and payload[:-3].endswith(bridge[:-len(".so")] + "-p")
               or (bridge and payload and payload == bridge[:-3] + "-p.so")),
          f"bridge={bridge} payload={payload}")
    check("randomized bridge name is not the fixed signature",
          bridge not in ("libzygisk.so", "libpayload.so"), str(bridge))
    check("systemless /system/lib64 layout created (random names)",
          bridge is not None and payload is not None
          and os.path.exists(os.path.join(sysdir, bridge))
          and os.path.exists(os.path.join(sysdir, payload)))
    check("no fixed-name libraries left in the systemless tree",
          not os.path.exists(os.path.join(sysdir, "libzygisk.so"))
          and not os.path.exists(os.path.join(sysdir, "libpayload.so")))
    if bridge and os.path.exists(os.path.join(sysdir, bridge)):
        with open(os.path.join(sysdir, bridge), "rb") as fp:
            check("randomized bridge file has ELF content",
                  fp.read(4) == b"\x7fELF")


def test_customize_32bit_layout(mk):
    proc, modpath = run_customize(mk, arch="arm", abi="armeabi-v7a",
                                  is64="false")
    check("customize.sh (ARCH=arm, 32-bit) exits 0", proc.returncode == 0,
          proc.stdout[-200:])
    sysdir = os.path.join(modpath, "system", "lib")
    names_p = os.path.join(modpath, ".loader_names")
    bridge = None
    if os.path.exists(names_p):
        with open(names_p) as fp:
            for line in fp:
                if line.startswith("bridge="):
                    bridge = line.strip()[len("bridge="):]
    check("32-bit systemless layout at /system/lib (random name)",
          bridge is not None
          and os.path.exists(os.path.join(sysdir, bridge)),
          f"bridge={bridge}")


def test_customize_real_installer_arch_values(mk):
    """ROUND 32 regression test: the installer-provided $ARCH values.

    Magisk's api_level_arch_detect() (scripts/util_functions.sh) and the
    identical logic in KernelSU's ksud installer.sh and APatch's
    installer.sh set ARCH to arm64/arm/x86/x64 — never the NDK-style
    names. Every entry must install from its matching libs/<abi> dir.
    """
    for arch, abi, is64 in (("arm64", "arm64-v8a", "true"),
                            ("x64", "x86_64", "true"),
                            ("x86", "x86", "false")):
        proc, modpath = run_customize(mk, arch=arch, abi=abi, is64=is64)
        ok = proc.returncode == 0
        check(f"customize.sh accepts real ARCH={arch}", ok,
              (proc.stdout[-200:] + proc.stderr[-200:]))
        link = os.path.join(modpath, "zygiskd")
        if ok:
            check(f"ARCH={arch}: launcher points at libs/{abi}",
                  os.path.islink(link)
                  and os.readlink(link) == f"libs/{abi}/zygiskd",
                  str(os.readlink(link)) if os.path.islink(link) else "no link")
    # riscv64: Magisk can report it (util_functions.sh api_level_arch_detect)
    # but we ship no build for it — must refuse cleanly, not install garbage.
    proc, _ = run_customize(mk, arch="riscv64", abi="x86", make_libs=False)
    check("customize.sh refuses riscv64 cleanly",
          proc.returncode != 0 and "ABORT:" in proc.stdout
          and "riscv64" in proc.stdout, proc.stdout[-200:])


def test_customize_no_getprop_on_path(mk):
    """ROUND 32 regression test: plain-recovery install (no getprop).

    customize.sh runs under `set -e`; before the zs_getprop fix a missing
    getprop binary made `X=$(getprop ...)` exit 127 and abort the whole
    install mid-way (after the 64-bit libs were copied, before the
    conflict checks / launcher / marker). With no getprop AND no readable
    build.prop the abilist is simply empty — 32-bit pairing is skipped
    and the install must still complete.
    """
    # Populate the module path exactly like run_customize does (libs,
    # artifacts, stub daemon) but run with a PATH that contains NO fake
    # getprop — the plain-recovery environment.
    modpath = os.path.join(mk.root, "modpath")
    shutil.rmtree(modpath, ignore_errors=True)
    libs = os.path.join(modpath, "libs", "arm64-v8a")
    os.makedirs(libs)
    for f in ("libzygisk.so", "libpayload.so", "libzn_loader.so"):
        with open(os.path.join(libs, f), "wb") as fp:
            fp.write(b"\x7fELF" + b"\x00" * 64)
    write_exec(os.path.join(libs, "zygiskd"), STUB_DAEMON)
    proc = subprocess.run(
        ["sh", "-c",
         "ui_print() { echo \"$*\"; }\n"
         "abort() { echo \"ABORT:$*\"; exit 1; }\n"
         f"set_perm() {{ '{mk.bindir}/set_perm' \"$@\"; }}\n"
         f". {os.path.join(mk.moddir, 'customize.sh')}\n"],
        env={"PATH": "/usr/bin:/bin",
             "MODPATH": modpath,
             "ARCH": "arm64", "IS64BIT": "true", "API": "30",
             "ZS_TEST_ADB_ROOT": str(mk.root)},
        capture_output=True, text=True, timeout=60)
    check("no-getprop install completes (no set -e death)",
          proc.returncode == 0,
          (proc.stdout[-300:] + proc.stderr[-300:]))
    check("no-getprop: nothing fatal in the output",
          "ABORT:" not in proc.stdout, proc.stdout[-300:])
    # The install must have gotten all the way through: launcher symlink
    # is one of the LAST steps (after the getprop call sites) — its
    # presence proves the script survived the property lookups.
    check("no-getprop: launcher symlink created (script ran to the end)",
          os.path.islink(os.path.join(modpath, "zygiskd")),
          "no launcher symlink")


def test_customize_buildprop_fallback(mk):
    """ROUND 32: zs_getprop's build.prop fallback (the grep_get_prop
    pattern from Magisk's util_functions.sh). getprop is absent, the
    abilist comes from build.prop instead — including CRLF line ends
    (some OEM images ship Windows-ended build.prop files). The proof is
    behavioral: with a dual-arch abilist in build.prop AND 32-bit
    artifacts present (EI_CLASS=1 stubs), the 32-bit pair must be
    installed into system/lib."""
    modpath = os.path.join(mk.root, "modpath")
    shutil.rmtree(modpath, ignore_errors=True)
    for abi, elf_cls in (("arm64-v8a", 2), ("armeabi-v7a", 1)):
        libs = os.path.join(modpath, "libs", abi)
        os.makedirs(libs)
        for f in ("libzygisk.so", "libpayload.so", "libzn_loader.so"):
            with open(os.path.join(libs, f), "wb") as fp:
                # ELF magic + EI_CLASS (offset 4): 2 = ELF64, 1 = ELF32
                fp.write(b"\x7fELF" + bytes([elf_cls]) + b"\x00" * 59)
        write_exec(os.path.join(libs, "zygiskd"), STUB_DAEMON)
    propdir = os.path.join(mk.root, "props")
    os.makedirs(propdir, exist_ok=True)
    bp = os.path.join(propdir, "build.prop")
    with open(bp, "wb") as fp:
        fp.write(b"ro.build.version.sdk=30\r\n"
                 b"ro.product.cpu.abilist=arm64-v8a,armeabi-v7a\r\n"
                 b"ro.dalvik.vm.native.bridge=0\r\n")
    proc = subprocess.run(
        ["sh", "-c",
         "ui_print() { echo \"$*\"; }\n"
         "abort() { echo \"ABORT:$*\"; exit 1; }\n"
         f"set_perm() {{ '{mk.bindir}/set_perm' \"$@\"; }}\n"
         f". {os.path.join(mk.moddir, 'customize.sh')}\n"],
        env={"PATH": "/usr/bin:/bin",
             "MODPATH": modpath,
             "ARCH": "arm64", "IS64BIT": "true", "API": "30",
             "ZS_TEST_ADB_ROOT": str(mk.root),
             "ZS_PROP_FILES": bp},
        capture_output=True, text=True, timeout=60)
    check("build.prop fallback: install completes",
          proc.returncode == 0,
          (proc.stdout[-300:] + proc.stderr[-300:]))
    # The abilist came from build.prop (no getprop exists): the 32-bit
    # pair must have been installed under system/lib with the randomized
    # names from .loader_names.
    names_p = os.path.join(modpath, ".loader_names")
    bridge = None
    if os.path.exists(names_p):
        with open(names_p) as fp:
            for line in fp:
                if line.startswith("bridge="):
                    bridge = line.strip()[len("bridge="):]
    lib32 = os.path.join(modpath, "system", "lib")
    check("build.prop fallback: dual-arch pair installed via abilist",
          bridge is not None and os.path.exists(os.path.join(lib32, bridge)),
          f"bridge={bridge}")
    check("build.prop fallback: CRLF stripped from the parsed value",
          # If CRLF leaked, abilist would not match the case patterns and
          # the 32-bit branch would have printed the NOTE instead.
          "32-bit zygote apps will NOT be injected" not in proc.stdout,
          proc.stdout[-300:])


def test_customize_refuses_old_android(mk):
    proc, _ = run_customize(mk, api="19")
    check("customize.sh refuses API 19 (pre-5.0)",
          proc.returncode != 0 and "ABORT:" in proc.stdout,
          proc.stdout[-200:])


def test_customize_refuses_bad_abi(mk):
    proc, _ = run_customize(mk, abi="mips")
    check("customize.sh refuses unsupported ABI",
          proc.returncode != 0 and "ABORT:" in proc.stdout,
          proc.stdout[-200:])


def test_customize_refuses_missing_artifacts(mk):
    proc, _ = run_customize(mk, missing_artifact=True)
    check("customize.sh refuses missing artifacts",
          proc.returncode != 0 and "ABORT:" in proc.stdout,
          proc.stdout[-200:])


# ---------------------------------------------------------------------------
# service.sh — the Round 29 daemon path resolution.
# ---------------------------------------------------------------------------

def test_service_starts_symlink_daemon(mk):
    # Real boot order: post-fs-data.sh creates the workdir first.
    installed_layout(mk, with_symlink=True)
    mk.prop_value = "0"
    pre = mk.run_script("post-fs-data.sh")
    check("prior post-fs-data run (workdir setup) exits 0",
          pre.returncode == 0)
    proc = mk.run_script("service.sh")
    check("service.sh exits 0 with the symlink layout",
          proc.returncode == 0, proc.stderr[-200:])
    if os.path.exists(mk.stub_daemon_log):
        with open(mk.stub_daemon_log) as fp:
            argv = fp.read().strip()
        check("daemon launched with --workdir",
              argv == "--workdir " + mk.workdir, argv)
    else:
        check("daemon launched with --workdir", False, "stub not invoked")
    # Round 33: the script NO LONGER writes zygiskd.pid — the old
    # `echo $!` recorded the setsid wrapper's pid, which forks+exits
    # under shell job control (a dead pid from the first millisecond).
    # The real daemon writes its own pid after the socket bind; that
    # contract is E2E-verified in scripts/verify_daemon.py ("zygiskd.pid
    # names the LIVE daemon pid"). With the stub daemon (which does not
    # self-write), the file must simply be absent.
    check("no dead-pid file written by the script",
          not os.path.exists(os.path.join(mk.workdir, "zygiskd.pid")))


def test_service_finds_legacy_layout(mk):
    installed_layout(mk, with_symlink=False)
    proc = mk.run_script("service.sh")
    check("service.sh finds the legacy libs/<abi>/zygiskd",
          proc.returncode == 0
          and os.path.exists(mk.stub_daemon_log),
          proc.stderr[-200:])


def test_service_survives_missing_daemon(mk):
    proc = mk.run_script("service.sh")
    check("service.sh exits 0 with no daemon present",
          proc.returncode == 0, proc.stderr[-200:])
    check("no daemon started", not os.path.exists(mk.stub_daemon_log))


# ---------------------------------------------------------------------------
# uninstall.sh — restore semantics.
# ---------------------------------------------------------------------------

def test_uninstall_restores_zero(mk):
    mk.prop_value = "libzygisk.so"  # value after the swap
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("0")
    proc = mk.run_script("uninstall.sh")
    calls = mk.resetprop_calls()
    check("uninstall restores the 0 value verbatim",
          proc.returncode == 0
          and calls == ["ro.dalvik.vm.native.bridge 0"], str(calls))
    check("uninstall removes the workdir", not os.path.exists(mk.workdir))


def test_uninstall_deletes_when_backup_empty(mk):
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("")
    proc = mk.run_script("uninstall.sh")
    calls = mk.resetprop_calls()
    check("uninstall --deletes an absent-original prop",
          proc.returncode == 0 and calls == ["--delete ro.dalvik.vm.native.bridge"],
          str(calls))


def test_uninstall_empty_fallback_on_old_resetprop(mk):
    mk.delete_fail = "1"
    # The compat layer's last resort is the module's own daemon binary
    # — the stub records its argv (on a real device the built-in
    # property engine performs the actual deletion).
    installed_layout(mk, with_symlink=True)
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("")
    proc = mk.run_script("uninstall.sh")
    calls = mk.resetprop_calls()
    # Round 31: the resetprop --delete failure now falls through to the
    # daemon's built-in engine (the stub records the CLI invocation).
    stub_calls = []
    if os.path.exists(mk.stub_daemon_log):
        with open(mk.stub_daemon_log) as fp:
            stub_calls = [l.strip() for l in fp if l.strip()]
    check("uninstall --delete failure falls back to the built-in engine",
          proc.returncode == 0
          and calls == ["--delete ro.dalvik.vm.native.bridge"]
          and stub_calls == ["prop delete ro.dalvik.vm.native.bridge"],
          f"resetprop={calls} stub={stub_calls}")


def test_uninstall_cleans_random_session_dir(mk):
    # The R13 randomized socket dir under (the remapped) /data/system.
    randdir = os.path.join(mk.sysroot, ".1a2b3c4d")
    os.makedirs(randdir, exist_ok=True)
    sock = os.path.join(randdir, "sock")
    with open(sock, "w") as fp:
        fp.write("")
    with open(os.path.join(mk.moddir, "session.sock"), "w") as fp:
        fp.write(sock)
    proc = mk.run_script("uninstall.sh")
    check("uninstall removes the randomized socket dir",
          proc.returncode == 0 and not os.path.exists(randdir))
    check("uninstall removes the session file",
          not os.path.exists(os.path.join(mk.moddir, "session.sock")))


def test_uninstall_workdir_record_fallback(mk):
    # Round 29: the module-dir session record is gone (module tree
    # removed by hand / unreadable), but the daemon's workdir copy
    # still names the random dir. Uninstall must clean it via the
    # fallback record — and must read it BEFORE removing $WORKDIR
    # (the copy lives inside the workdir).
    randdir = os.path.join(mk.sysroot, ".9f8e7d6c")
    os.makedirs(randdir, exist_ok=True)
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(randdir, "sock"), "w") as fp:
        fp.write("")
    with open(os.path.join(mk.workdir, "session.sock"), "w") as fp:
        fp.write(os.path.join(randdir, "sock"))
    proc = mk.run_script("uninstall.sh")
    check("uninstall cleans the random dir via the workdir record",
          proc.returncode == 0 and not os.path.exists(randdir))
    check("workdir removed too", not os.path.exists(mk.workdir))


def test_uninstall_leaves_foreign_paths_alone(mk):
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.moddir, "session.sock"), "w") as fp:
        fp.write("/data/adb/evil/path/sock")   # does not match the pattern
    proc = mk.run_script("uninstall.sh")
    check("uninstall ignores a session file naming a foreign path",
          proc.returncode == 0)


# ---------------------------------------------------------------------------
# ROUND 38 — the live-daemon uninstall (U1), the backup-less restore
# (U3), the lazy-umount fallback (U4).
# ---------------------------------------------------------------------------

FAKE_DAEMON_PY = """\
import signal, sys, time
log = sys.argv[1]
def on_term(sig, frame):
    with open(log, "a") as f:
        f.write("DAEMON_TERM\\n")
    sys.exit(0)
signal.signal(signal.SIGTERM, on_term)
with open(log, "a") as f:
    f.write("DAEMON_START\\n")
while True:
    time.sleep(0.5)
"""


def spawn_fake_daemon(mk, name="fakedaemon"):
    """A live process whose /proc/<pid>/comm is a UNIQUE name, so the
    uninstall's kill logic can be exercised without endangering any
    real process. Executing a symlink to python named `fakedaemon`
    gives comm=fakedaemon (the kernel derives comm from the executed
    dentry name) — verified on this host before the test was written.
    The comm-scan in uninstall.sh matches by exact name, so only this
    process can ever be a victim."""
    exe = os.path.join(mk.root, name)
    if not os.path.exists(exe):
        os.symlink(sys.executable, exe)
    log = os.path.join(mk.root, "fake_daemon.log")
    proc = subprocess.Popen(
        [exe, "-c", FAKE_DAEMON_PY, log],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 5
    while time.time() < deadline:
        if os.path.exists(log):
            break
        time.sleep(0.05)
    return proc, log


def test_uninstall_kills_daemon_and_restores_after(mk):
    """U1: a LIVE daemon at uninstall time (the `magisk
    --remove-modules` / manual-run path) must die BEFORE the property
    restore — the restore has to be the last write that lands (the
    guard would otherwise re-arm on the next zygote restart)."""
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("0")
    proc, dlog = spawn_fake_daemon(mk)
    try:
        with open(os.path.join(mk.workdir, "zygiskd.pid"), "w") as fp:
            fp.write(f"{proc.pid}\\n")
        # The fake resetprop calls and the daemon's TERM marker share
        # ONE log so the ORDER is assertable.
        p = mk.run_script("uninstall.sh", extra_env={
            "ZS_TEST_DAEMON_COMM": "fakedaemon",
            "ZS_FAKE_RESETPROP_LOG": dlog,
        })
        check("uninstall exits 0 with a live daemon present",
              p.returncode == 0)
        deadline = time.time() + 5
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        check("uninstall killed the live daemon (pid-file path)",
              proc.poll() is not None)
        with open(dlog) as fp:
            lines = [l.strip() for l in fp if l.strip()]
        ok = False
        try:
            t = lines.index("DAEMON_TERM")
            r = next(i for i, l in enumerate(lines)
                     if l == "ro.dalvik.vm.native.bridge 0")
            ok = t < r
        except (ValueError, StopIteration):
            ok = False
        check("property restore lands AFTER the daemon death", ok,
              repr(lines))
    finally:
        if proc.poll() is None:
            proc.kill()


def test_uninstall_comm_scan_kills_orphan_daemon(mk):
    """U1 fallback: the pid file is gone but the daemon lives — the
    /proc comm scan must find and terminate it."""
    os.makedirs(mk.workdir, exist_ok=True)
    proc, _ = spawn_fake_daemon(mk)
    try:
        # NO zygiskd.pid: only the comm scan can find it.
        p = mk.run_script("uninstall.sh",
                          extra_env={"ZS_TEST_DAEMON_COMM": "fakedaemon"})
        check("uninstall exits 0 (comm-scan path)", p.returncode == 0)
        deadline = time.time() + 5
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        check("comm-scan fallback killed the orphan daemon",
              proc.poll() is not None)
    finally:
        if proc.poll() is None:
            proc.kill()


def test_uninstall_pid_reuse_safety(mk):
    """U1 safety: a pid-file pid whose comm does NOT match ours (pid
    reuse, foreign process) must never be killed."""
    os.makedirs(mk.workdir, exist_ok=True)
    exe = os.path.join(mk.root, "otherproc")
    if not os.path.exists(exe):
        os.symlink(sys.executable, exe)
    proc = subprocess.Popen(
        [exe, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.3)
        with open(os.path.join(mk.workdir, "zygiskd.pid"), "w") as fp:
            fp.write(f"{proc.pid}\\n")
        p = mk.run_script("uninstall.sh",
                          extra_env={"ZS_TEST_DAEMON_COMM": "fakedaemon"})
        time.sleep(0.3)
        check("wrong-comm pid is NOT killed (pid-reuse safety)",
              proc.poll() is None)
        check("uninstall still exits 0", p.returncode == 0)
    finally:
        if proc.poll() is None:
            proc.kill()


def test_uninstall_backup_missing_restores_zero(mk):
    """U3: no backup record, but the LIVE value is our applied name —
    restore the documented stock "0" instead of leaving the prop
    pointing at a deleted library until reboot."""
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_applied"), "w") as fp:
        fp.write("libtest1234.so")
    with open(mk.prop_state, "w") as fp:
        fp.write("libtest1234.so\n")
    p = mk.run_script("uninstall.sh")
    calls = mk.resetprop_calls()
    check("backup-less restore sets the documented stock 0",
          "ro.dalvik.vm.native.bridge 0" in calls, repr(calls))
    check("uninstall exits 0", p.returncode == 0)
    check("workdir removed", not os.path.exists(mk.workdir))


def test_uninstall_backup_missing_leaves_foreign_bridge(mk):
    """U3 guard: no backup, and the live value is a FOREIGN bridge —
    never touch it (same rule as post-fs-data.sh)."""
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_applied"), "w") as fp:
        fp.write("libtest1234.so")
    with open(mk.prop_state, "w") as fp:
        fp.write("librealbridge.so\n")
    p = mk.run_script("uninstall.sh")
    calls = mk.resetprop_calls()
    check("foreign bridge untouched when backup is missing",
          not any("ro.dalvik.vm.native.bridge" in c for c in calls),
          repr(calls))


def test_uninstall_lazy_umount_fallback(mk):
    """U4: a live overlay mount umounts EBUSY at runtime-uninstall
    time — the lazy `-l` fallback must run after the plain attempt
    fails."""
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".uninstall_manifest"), "w") as fp:
        fp.write("overlay /system/lib64 /data/system/.abcd1234.o_system_lib64\n")
    fake_umount = os.path.join(mk.bindir, "umount")
    ulog = os.path.join(mk.root, "umount.log")
    with open(fake_umount, "w") as fp:
        fp.write(f'#!/bin/sh\necho "$*" >> {ulog}\n'
                 'if [ "$1" = "-l" ]; then exit 0; fi\nexit 1\n')
    os.chmod(fake_umount, 0o755)
    p = mk.run_script("uninstall.sh")
    lines = []
    if os.path.exists(ulog):
        with open(ulog) as fp:
            lines = [l.strip() for l in fp if l.strip()]
    check("plain umount attempted first",
          "/system/lib64" in lines, repr(lines))
    check("lazy umount -l fallback used",
          "-l /system/lib64" in lines, repr(lines))
    check("uninstall exits 0", p.returncode == 0)


# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Round 31 — root-manager / custom-ROM compatibility scenarios
# ---------------------------------------------------------------------------

def build_prop_area_file(path, props, a10=True, total=8192):
    """Build a bionic-shaped property area file (independent of the
    Rust engine: this is the same format the fixture builder in
    props.rs emits, written again here in Python so the E2E exercises
    the engine against a THIRD implementation of the format)."""
    import struct
    buf = bytearray(total)
    struct.pack_into("<IIII", buf, 0, 0, 0, 0x504f5250, 0xfc6ed0ab)
    used = 20 + (92 if a10 else 0)

    def alloc_node(frag):
        nonlocal used
        off = used
        span = 20 + len(frag) + 1
        buf[128 + off:128 + off + span] = b"\0" * span
        struct.pack_into("<I", buf, 128 + off, len(frag))
        buf[128 + off + 20:128 + off + 20 + len(frag)] = frag.encode()
        used += (span + 3) & ~3
        return off

    def bst_insert(root_off, frag):
        cur = root_off
        while True:
            namelen = struct.unpack_from("<I", buf, 128 + cur)[0]
            name = bytes(buf[128 + cur + 20:128 + cur + 20 + namelen]).decode()
            if (len(frag), frag) == (len(name), name):
                return cur
            field = 8 if (len(frag), frag) < (len(name), name) else 12  # ROUND 34: bionic cmp_prop_name is (len, bytes)
            child = struct.unpack_from("<I", buf, 128 + cur + field)[0]
            if child:
                cur = child
                continue
            off = alloc_node(frag)
            struct.pack_into("<I", buf, 128 + cur + field, off)
            return off

    for name, value in props:
        current = 0
        frags = name.split(".")
        for i, frag in enumerate(frags):
            children = struct.unpack_from("<I", buf, 128 + current + 16)[0]
            if children == 0:
                off = alloc_node(frag)
                struct.pack_into("<I", buf, 128 + current + 16, off)
                child_root = off
            else:
                child_root = children
            current = bst_insert(child_root, frag)
            if i == len(frags) - 1:
                pi = used
                total_pi = 96 + len(name) + 1
                buf[128 + pi:128 + pi + total_pi] = b"\0" * total_pi
                struct.pack_into("<I", buf, 128 + pi, len(value) << 24)
                buf[128 + pi + 4:128 + pi + 4 + len(value)] = value.encode()
                buf[128 + pi + 96:128 + pi + 96 + len(name)] = name.encode()
                used += (total_pi + 3) & ~3
                struct.pack_into("<I", buf, 128 + current + 4, pi)
    struct.pack_into("<I", buf, 0, used)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True)
    path.write_bytes(bytes(buf))


def read_prop_from_area(path, name):
    """Third implementation of the trie reader for verification."""
    import struct
    buf = path.read_bytes()
    magic, version = struct.unpack_from("<II", buf, 8)
    if magic != 0x504f5250 or version != 0xfc6ed0ab:
        return None

    def node(off):
        namelen = struct.unpack_from("<I", buf, 128 + off)[0]
        nm = bytes(buf[128 + off + 20:128 + off + 20 + namelen]).decode()
        prop, left, right, children = struct.unpack_from("<IIII", buf, 128 + off + 4)
        return nm, prop, left, right, children

    def find_bst(root, frag):
        scan = root
        while scan:
            nm2, prop2, left2, right2, children2 = node(scan)
            if nm2 == frag:
                return scan, prop2
            scan = left2 if (len(frag), frag) < (len(nm2), nm2) else right2  # ROUND 34: bionic cmp_prop_name is (len, bytes)
        return None, 0

    cur = 0
    rest = name
    prop = 0
    while True:
        nm, prop, left, right, children = node(cur)
        frag, sep, tail = rest.partition(".")
        if children == 0:
            return None
        scan, prop = find_bst(children, frag)
        if scan is None:
            return None
        cur = scan
        if not sep:
            break
        rest = tail
    if prop == 0:
        return None
    serial = struct.unpack_from("<I", buf, 128 + prop)[0]
    if serial & (1 << 16):
        long_off = struct.unpack_from("<I", buf, 128 + prop + 60)[0]
        base = 128 + prop + long_off
        end = buf.index(0, base)
        return buf[base:end].decode()
    ln = serial >> 24
    return bytes(buf[128 + prop + 4:128 + prop + 4 + ln]).decode()


REAL_DAEMON = None
# Round 34: distinguishes "toolchain absent" (SKIP) from "toolchain
# present but the build actually failed" (FAIL — a real regression).
REAL_DAEMON_ABSENT_TOOLCHAIN = None


def find_real_daemon():
    """Build (once) the real zygiskd for the property-engine E2E."""
    global REAL_DAEMON, REAL_DAEMON_ABSENT_TOOLCHAIN
    if REAL_DAEMON is not None:
        return REAL_DAEMON
    # Share toolchain selection and output lookup with the daemon harness;
    # otherwise CARGO_TARGET_DIR or a configured Android target selects a
    # missing/stale binary only in this second, release-profile harness.
    from verify_daemon import cargo_build
    REAL_DAEMON_ABSENT_TOOLCHAIN = False
    try:
        REAL_DAEMON, _ = cargo_build(release=True)
    except SystemExit as exc:
        REAL_DAEMON = ""
        REAL_DAEMON_ABSENT_TOOLCHAIN = exc.code == 77
    except (OSError, subprocess.SubprocessError) as exc:
        print("daemon build failed:", exc)
        REAL_DAEMON = ""
    return REAL_DAEMON


def _populate_modpath(modpath, abis=("arm64-v8a",), with_daemon=None):
    for abi in abis:
        d = os.path.join(modpath, "libs", abi)
        os.makedirs(d, exist_ok=True)
        for f in ("libzygisk.so", "libpayload.so", "libzn_loader.so"):
            with open(os.path.join(d, f), "wb") as fp:
                # EI_CLASS (byte 4) = 1 = ELF32 — customize.sh's
                # Round 31 dual-arch gate validates this byte.
                fp.write(b"\x7fELF\x01" + b"A" * 40)
        if with_daemon:
            shutil.copy(with_daemon, os.path.join(d, "zygiskd"))
            os.chmod(os.path.join(d, "zygiskd"), 0o755)
        else:
            write_exec(os.path.join(d, "zygiskd"), "#!/bin/sh\nexit 0\n")
    # the hook source customize.sh copies
    shutil.copy(os.path.join(REPO_ROOT, "post-mount-hook.sh"),
                os.path.join(modpath, "post-mount-hook.sh"))


FAKE_UI = """#!/bin/sh
echo "ui: $*"
"""

FAKE_ABORT = """#!/bin/sh
echo "ABORT: $*"
exit 1
"""


def test_real_engine_swap_without_resetprop(mk):
    """KernelSU/APatch scenario: NO resetprop binary exists; the module's
    own daemon engine performs the swap against a real (fixture)
    property area."""
    daemon = find_real_daemon()
    if not daemon:
        if REAL_DAEMON_ABSENT_TOOLCHAIN:
            skip("real daemon built (cargo absent on host)",
                 "no Rust toolchain: engine E2E skipped, not failed")
        else:
            check("real daemon built (cargo available)", False,
                  "cargo build failed")
        return
    check("real daemon built (cargo available)", True)
    # Remove resetprop from PATH: only log/getprop fakes remain.
    os.unlink(os.path.join(mk.bindir, "resetprop"))
    # The real daemon installed as the module launcher (customize.sh
    # creates a relative symlink; the test copies the binary).
    installed_layout(mk, with_symlink=False)
    os.unlink(os.path.join(mk.moddir, "libs", "arm64-v8a", "zygiskd"))
    shutil.copy(daemon, os.path.join(mk.moddir, "zygiskd"))
    os.chmod(os.path.join(mk.moddir, "zygiskd"), 0o755)
    # A randomized loader name + a fixture property area with stock "0".
    names = os.path.join(mk.moddir, ".loader_names")
    with open(names, "w") as fp:
        fp.write("bridge=lib0123abcd.so\npayload=lib0123abcd-p.so\n")
    proot = os.path.join(mk.root, "props")
    os.makedirs(proot, exist_ok=True)
    area = os.path.join(proot, "u:object_r:dalvik_config_prop:s0")
    build_prop_area_file(__import__("pathlib").Path(area),
                         [("ro.dalvik.vm.native.bridge", "0"),
                          ("ro.build.version.sdk", "34")])
    build_prop_area_file(__import__("pathlib").Path(
        os.path.join(proot, "properties_serial")), [])
    proc = subprocess.run(
        ["sh", os.path.join(mk.moddir, "post-fs-data.sh")],
        env=mk.env({"ZS_PROP_ROOT": proot}),
        capture_output=True, text=True, timeout=120)
    check("no-resetprop post-fs-data exits 0", proc.returncode == 0,
          proc.stderr[-300:])
    val = read_prop_from_area(__import__("pathlib").Path(area),
                              "ro.dalvik.vm.native.bridge")
    check("engine swapped the bridge in the fixture area",
          val == "lib0123abcd.so", str(val))
    check("other props untouched by the engine",
          read_prop_from_area(__import__("pathlib").Path(area),
                              "ro.build.version.sdk") == "34")
    check("backup file records stock 0", mk.backup_value() == "0")
    applied = os.path.join(mk.workdir, ".native_bridge_applied")
    if os.path.exists(applied):
        with open(applied) as fp:
            check(".native_bridge_applied records the engine swap",
                  fp.read() == "lib0123abcd.so")
    else:
        check(".native_bridge_applied records the engine swap", False, "missing")


def test_mount_pending_and_post_mount_hook(mk):
    """KernelSU order: post-fs-data runs BEFORE module mounting, so the
    loader is invisible; the flag is set. The post-mount hook then
    rolls back cleanly (the host cannot see /system, so the resolution
    branch is device-only; the ROLLBACK branch is fully testable)."""
    installed_layout(mk, with_symlink=True)
    with open(os.path.join(mk.moddir, ".loader_names"), "w") as fp:
        fp.write("bridge=lib5566ffee.so\npayload=lib5566ffee-p.so\n")
    os.makedirs(os.path.join(mk.moddir, "system", "lib64"), exist_ok=True)
    with open(os.path.join(mk.moddir, "system", "lib64", "lib5566ffee.so"), "wb") as fp:
        fp.write(b"\x7fELF")
    mk.prop_value = "0"
    proc = mk.run_script("post-fs-data.sh")
    check("KSU-order post-fs-data exits 0", proc.returncode == 0, proc.stderr[-300:])
    pend = os.path.join(mk.workdir, ".mount_pending")
    check("mount pending flag set (loader invisible)", os.path.exists(pend))
    # Install the hook where the manager would run it from, with a
    # remapped /data/adb pointing at the module dir (the hook's
    # MODDIR_REAL). On the host /system/lib64 stays invisible, so the
    # expected branch is the rollback.
    adbroot = os.path.join(mk.root, "adb")
    os.makedirs(os.path.join(adbroot, "modules"), exist_ok=True)
    shutil.copytree(mk.moddir, os.path.join(adbroot, "modules", "zygisk_study"),
                    dirs_exist_ok=True)
    hook = os.path.join(adbroot, "post-mount.d", "zygisk_study-mount.sh")
    os.makedirs(os.path.dirname(hook), exist_ok=True)
    shutil.copy(os.path.join(mk.moddir, "post-mount-hook.sh"), hook)
    os.chmod(hook, 0o755)
    proc2 = subprocess.run(["sh", hook], capture_output=True, text=True,
                           env=mk.env({"ZS_TEST_ADB_ROOT": adbroot}),
                           timeout=120)
    check("post-mount hook exits 0 (rollback branch on host)",
          proc2.returncode == 0, proc2.stderr[-300:])
    check("hook rolled the bridge back (stock 0 restored)",
          "ro.dalvik.vm.native.bridge 0" in mk.resetprop_calls(),
          str(mk.resetprop_calls()))
    check("hook cleared the pending flag", not os.path.exists(pend))
    check("hook stood the guard down",
          not os.path.exists(os.path.join(mk.workdir, ".native_bridge_applied")))


def test_post_mount_noop_without_pending(mk):
    """The hook runs on EVERY post-mount event; with nothing pending it
    must exit 0 fast and never touch the property."""
    installed_layout(mk, with_symlink=True)
    mk.prop_value = "0"
    mk.run_script("post-fs-data.sh")
    # Simulate the Magisk case: the loader WAS visible, so post-fs-data
    # cleared the flag itself.
    pend = os.path.join(mk.workdir, ".mount_pending")
    if os.path.exists(pend):
        os.unlink(pend)
    hook = os.path.join(mk.moddir, "post-mount-hook.sh")
    adbroot = os.path.join(mk.root, "adb")
    os.makedirs(os.path.join(adbroot, "modules"), exist_ok=True)
    shutil.copytree(mk.moddir, os.path.join(adbroot, "modules", "zygisk_study"),
                    dirs_exist_ok=True)
    n_before = len(mk.resetprop_calls())
    proc = subprocess.run(["sh", hook], capture_output=True, text=True,
                          env=mk.env({"ZS_TEST_ADB_ROOT": adbroot}),
                          timeout=120)
    check("hook no-ops without a pending flag",
          proc.returncode == 0 and len(mk.resetprop_calls()) == n_before,
          str(mk.resetprop_calls()))


def test_service_late_resolution(mk):
    """service.sh with a still-pending mount and skip_mount: it rolls
    back (the module boots inert) instead of leaving a dangling
    reference."""
    installed_layout(mk, with_symlink=True)
    with open(os.path.join(mk.moddir, ".loader_names"), "w") as fp:
        fp.write("bridge=lib11223344.so\npayload=lib11223344-p.so\n")
    os.makedirs(os.path.join(mk.moddir, "system", "lib64"), exist_ok=True)
    with open(os.path.join(mk.moddir, "system", "lib64", "lib11223344.so"), "wb") as fp:
        fp.write(b"\x7fELF")
    with open(os.path.join(mk.moddir, "skip_mount"), "w") as fp:
        fp.write("")
    mk.prop_value = "0"
    mk.run_script("post-fs-data.sh")
    check("pending before service", os.path.exists(
        os.path.join(mk.workdir, ".mount_pending")))
    proc = mk.run_script("service.sh")
    check("service.sh exits 0 with pending rollback", proc.returncode == 0,
          proc.stderr[-300:])
    check("service rollback restored 0",
          "ro.dalvik.vm.native.bridge 0" in mk.resetprop_calls(),
          str(mk.resetprop_calls()))
    check("service rollback cleared pending", not os.path.exists(
        os.path.join(mk.workdir, ".mount_pending")))


def _run_customize(mk, modpath, extra_env=None, abilist=None, bridge="0", arch="arm64"):
    """Shared customize.sh runner with a remapped /data/adb."""
    env = mk.env(extra_env or {})
    env["MODPATH"] = str(modpath)
    # ROUND 32: the REAL installer value (Magisk/KSU/APatch
    # api_level_arch_detect), not the NDK-style ABI name.
    env["ARCH"] = arch
    env["IS64BIT"] = "true"
    env["API"] = "30"
    env["ZS_TEST_ADB_ROOT"] = str(mk.root)  # remap /data/adb
    if abilist is not None:
        env["ZS_FAKE_GETPROP_ABILIST"] = abilist
    env["ZS_FAKE_GETPROP_BRIDGE"] = bridge
    write_exec(os.path.join(mk.bindir, "ui_print"), FAKE_UI)
    write_exec(os.path.join(mk.bindir, "abort"), FAKE_ABORT)
    proc = subprocess.run(["sh", os.path.join(mk.moddir, "customize.sh")],
                          env=env, capture_output=True, text=True, timeout=120)
    return proc


def test_customize_installs_post_mount_hook(mk):
    modpath = os.path.join(mk.root, "modpath")
    os.makedirs(modpath, exist_ok=True)
    _populate_modpath(modpath)
    proc = _run_customize(mk, modpath)
    check("customize (clean env) exits 0", proc.returncode == 0,
          proc.stdout[-400:] + proc.stderr[-200:])
    hook = os.path.join(mk.root, "post-mount.d", "zygisk_study-mount.sh")
    check("post-mount.d hook installed", os.path.exists(hook))
    check("post-mount.d hook executable",
          os.path.exists(hook) and os.access(hook, os.X_OK))


def test_customize_conflict_detection(mk):
    # 1. Magisk's own Zygisk enabled
    modpath = os.path.join(mk.root, "modpath1")
    os.makedirs(modpath, exist_ok=True)
    _populate_modpath(modpath)
    proc = _run_customize(mk, modpath, {"ZYGISK_ENABLED": "1"})
    check("customize aborts when Magisk Zygisk is enabled",
          proc.returncode != 0 and "CONFLICT" in proc.stdout, proc.stdout[-200:])
    # 2. zygisksu module present
    modpath = os.path.join(mk.root, "modpath2")
    os.makedirs(modpath, exist_ok=True)
    _populate_modpath(modpath)
    os.makedirs(os.path.join(mk.root, "modules", "zygisksu"), exist_ok=True)
    proc = _run_customize(mk, modpath)
    check("customize aborts when zygisksu module is installed",
          proc.returncode != 0 and "zygisksu" in proc.stdout, proc.stdout[-200:])
    # 3. rezygisk work dir present
    mk2 = FakeMagisk()
    modpath = os.path.join(mk2.root, "modpath3")
    os.makedirs(modpath, exist_ok=True)
    _populate_modpath(modpath)
    os.makedirs(os.path.join(mk2.root, "rezygisk"), exist_ok=True)
    proc = _run_customize(mk2, modpath)
    check("customize aborts when rezygisk workdir exists",
          proc.returncode != 0 and "rezygisk" in proc.stdout, proc.stdout[-200:])
    mk2.cleanup()
    # 4. live property = libzygisk.so
    mk3 = FakeMagisk()
    modpath = os.path.join(mk3.root, "modpath4")
    os.makedirs(modpath, exist_ok=True)
    _populate_modpath(modpath)
    proc = _run_customize(mk3, modpath, bridge="libzygisk.so")
    check("customize aborts when live bridge is libzygisk.so",
          proc.returncode != 0 and "libzygisk.so" in proc.stdout, proc.stdout[-200:])
    mk3.cleanup()


def test_customize_dual_arch(mk):
    # Dual-arch device with 32-bit artifacts: both lib dirs populated.
    modpath = os.path.join(mk.root, "modpath1")
    os.makedirs(modpath, exist_ok=True)
    _populate_modpath(modpath, ("arm64-v8a", "armeabi-v7a"))
    proc = _run_customize(mk, modpath, abilist="arm64-v8a,armeabi-v7a")
    check("dual-arch customize exits 0", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-200:])
    names_file = os.path.join(modpath, ".loader_names")
    with open(names_file) as fp:
        lines = dict(l.split("=", 1) for l in fp.read().splitlines())
    bridge = lines["bridge"]
    check("32-bit bridge placed in system/lib",
          os.path.exists(os.path.join(modpath, "system", "lib", bridge)))
    check("64-bit bridge placed in system/lib64",
          os.path.exists(os.path.join(modpath, "system", "lib64", bridge)))
    # Dual-arch device WITHOUT 32-bit artifacts: warns, still succeeds.
    mk2 = FakeMagisk()
    modpath2 = os.path.join(mk2.root, "modpath2")
    os.makedirs(modpath2, exist_ok=True)
    _populate_modpath(modpath2, ("arm64-v8a",))
    proc2 = _run_customize(mk2, modpath2, abilist="arm64-v8a,armeabi-v7a")
    check("dual-arch without 32-bit artifacts still installs",
          proc2.returncode == 0 and "32-bit zygote" in proc2.stdout,
          proc2.stdout[-300:])
    check("no system/lib created without 32-bit artifacts",
          not os.path.exists(os.path.join(modpath2, "system", "lib")))
    mk2.cleanup()
    # A 64-bit (EI_CLASS=2) artifact in the 32-bit dir is REFUSED —
    # the 32-bit zygote could never load it (Round 31 gate).
    mk3 = FakeMagisk()
    modpath3 = os.path.join(mk3.root, "modpath3")
    os.makedirs(modpath3, exist_ok=True)
    _populate_modpath(modpath3, ("arm64-v8a", "armeabi-v7a"))
    bad = os.path.join(modpath3, "libs", "armeabi-v7a", "libzygisk.so")
    with open(bad, "wb") as fp:
        fp.write(b"\x7fELF\x02" + b"A" * 40)   # EI_CLASS = 2 = ELF64
    proc3 = _run_customize(mk3, modpath3, abilist="arm64-v8a,armeabi-v7a")
    check("64-bit artifact in 32-bit dir is refused",
          proc3.returncode == 0
          and "not a 32-bit ELF" in proc3.stdout
          and not os.path.exists(
              os.path.join(modpath3, "system", "lib")),
          proc3.stdout[-200:])
    mk3.cleanup()

    # Complete ABI tokens, constrained to the native CPU family. Give
    # every package all four ABIs so wrong selections cannot hide behind
    # missing files; distinct contents prove which ISA was copied.
    for arch, abilist, expected in (
        ("x64", "x86_64", None),
        ("x64", "x86_64,x86", "x86"),
        ("x64", "x86_64,armeabi-v7a,x86", "x86"),
        ("x64", "x86_64,armeabi-v7a", None),
        ("arm64", "arm64-v8a", None),
        ("arm64", "arm64-v8a,armeabi-v7a,armeabi", "armeabi-v7a"),
        ("arm64", "arm64-v8a,x86", None),
    ):
        fixture = FakeMagisk()
        try:
            mod = os.path.join(fixture.root, "abi_module")
            _populate_modpath(mod, ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"))
            for abi in ("armeabi-v7a", "x86"):
                for lib in ("libzygisk.so", "libpayload.so"):
                    with open(os.path.join(mod, "libs", abi, lib), "ab") as fp:
                        fp.write(abi.encode())
            result = _run_customize(fixture, mod, abilist=abilist, arch=arch)
            check(f"ABI matrix {arch}/{abilist} installs", result.returncode == 0,
                  result.stderr[-200:])
            libdir = os.path.join(mod, "system", "lib")
            if expected is None:
                check(f"ABI matrix {arch}/{abilist} skips foreign or absent ISA",
                      not os.path.exists(libdir))
            else:
                with open(os.path.join(mod, ".loader_names")) as fp:
                    names = dict(line.strip().split("=", 1) for line in fp)
                for key, lib in (("bridge", "libzygisk.so"), ("payload", "libpayload.so")):
                    with open(os.path.join(libdir, names[key]), "rb") as fp:
                        actual = fp.read()
                    with open(os.path.join(mod, "libs", expected, lib), "rb") as fp:
                        check(f"ABI matrix {arch}/{abilist} selects {expected} {key}",
                              actual == fp.read())
        finally:
            fixture.cleanup()


def test_customize_root_manager_envs(mk):
    for env_name, label in (("KSU", "KernelSU"), ("APATCH", "APatch")):
        mkx = FakeMagisk()
        modpath = os.path.join(mkx.root, "modpath_x")
        os.makedirs(modpath, exist_ok=True)
        _populate_modpath(modpath)
        proc = _run_customize(mkx, modpath, {env_name: "true"})
        check(f"customize runs clean under {label} env",
              proc.returncode == 0 and label in proc.stdout,
              proc.stdout[-200:])
        mkx.cleanup()


def test_uninstall_removes_hook(mk):
    installed_layout(mk, with_symlink=True)
    hook_dir = os.path.join(mk.root, "post-mount.d")
    os.makedirs(hook_dir, exist_ok=True)
    hook = os.path.join(hook_dir, "zygisk_study-mount.sh")
    shutil.copy(os.path.join(REPO_ROOT, "post-mount-hook.sh"), hook)
    foreign = os.path.join(hook_dir, "other-module-hook.sh")
    with open(foreign, "w") as fp:
        fp.write("#!/system/bin/sh\nexit 0\n")
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("0")
    proc = mk.run_script("uninstall.sh", {"ZS_TEST_ADB_ROOT": mk.root})
    check("uninstall exits 0 with hook present", proc.returncode == 0,
          proc.stderr[-200:])
    check("uninstall removes OUR post-mount hook", not os.path.exists(hook))
    check("uninstall leaves FOREIGN hooks alone", os.path.exists(foreign))


def test_ci_script_hygiene(mk):  # noqa: ARG001 — signature per harness
    """Round 33 — the permission-denied CI bug can never return.

    The first live GitHub Actions run of the flashable-zip workflow
    (Round 32's push) died at './scripts/build_module.sh: Permission
    denied': the script had been committed with git mode 100644, and a
    runner checkout faithfully reproduced the missing exec bit. The
    workflow now invokes it through `bash` (immune to the bit), but
    these checks make the repository itself fail loudly if the mode
    ever regresses.
    """
    # 1. Git modes (the thing the runner reproduces).
    want = {
        "scripts/build_module.sh": "100755",
        "scripts/installer/update-binary": "100755",
    }
    if os.path.isdir(os.path.join(REPO_ROOT, ".git")):
        out = subprocess.run(
            ["git", "ls-files", "-s"] + list(want),
            cwd=REPO_ROOT, capture_output=True, text=True)
        listed = {}
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                listed[parts[3]] = parts[0]
        for path, mode in want.items():
            check(f"git mode of {path} is {mode}",
                  listed.get(path) == mode,
                  f"got {listed.get(path)!r} — run: "
                  f"git update-index --chmod=+x {path}")
            # 2. The on-disk bit in a real checkout follows the index.
            full = os.path.join(REPO_ROOT, path)
            if os.path.exists(full):
                check(f"{path} is executable on disk",
                      os.access(full, os.X_OK),
                      "on-disk mode lost the exec bit")
    # 3. The workflow must keep the bash- invocation (belt and braces
    #    for any future exec-bit loss, e.g. a zip round-trip).
    wf = os.path.join(REPO_ROOT, ".github", "workflows", "build.yml")
    if os.path.exists(wf):
        body = open(wf, encoding="utf-8").read()
        check("build.yml invokes the build script through bash",
              "bash ./scripts/build_module.sh" in body,
              "the workflow must not execute ./scripts/build_module.sh "
              "directly — a lost exec bit kills CI at that line")


def make_gate_fixture(mk, program):
    """Run the real Makefile with tiny sources and a deterministic compiler.

    This tests build/exit-status handling without depending on sanitizer
    runtime support (TSan cannot start on some otherwise valid hosts).
    """
    root = os.path.join(mk.root, "make-gate")
    testdir = os.path.join(root, "tests")
    os.makedirs(testdir)
    shutil.copy(os.path.join(REPO_ROOT, "tests", "Makefile"), testdir)
    for path in ("tests/test_obfstr.cpp", "tests/test_framework.h",
                 "tests/test_race.cpp", "tests/race_fixture.c",
                 "native/common/obfstr.h", "native/common/log.h",
                 "native/libpayload/src/hide_advanced.cpp",
                 "native/libpayload/src/hide.cpp"):
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w"):
            pass
    write_exec(os.path.join(testdir, "plain"),
               '#!/bin/sh\necho plain >> "$FAKE_RUN_LOG"\n')
    write_exec(os.path.join(testdir, "instrumented"), program)
    write_exec(os.path.join(testdir, "compiler"), '''#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_BUILD_LOG"
input=plain
case " $* " in
  *-fsanitize=*)
    if [ -n "$FAKE_BUILD_ERROR" ]; then
      echo "$FAKE_BUILD_ERROR" >&2
      exit 1
    fi
    input=instrumented ;;
esac
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; break; fi
  shift
done
cp "$input" "$output" && chmod +x "$output"
''')
    env = os.environ.copy()
    # A parent `make verify-scripts` may export -j, -n, or command-line
    # overrides; the isolated fixture must not inherit those settings.
    for key in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"):
        env.pop(key, None)
    env.update(FAKE_BUILD_LOG=os.path.join(testdir, "build.log"),
               FAKE_RUN_LOG=os.path.join(testdir, "run.log"),
               FAKE_BUILD_ERROR="")
    return testdir, env


def run_make_gate(testdir, env, target):
    return subprocess.run(
        ["make", "--no-print-directory", target, "CXX=./compiler",
         "CC=./compiler", "SAN_TESTS=test_obfstr"],
        cwd=testdir, env=env, capture_output=True, text=True, timeout=30)


def test_sanitize_gate(mk):
    testdir, env = make_gate_fixture(mk, '''#!/bin/sh
echo instrumented >> "$FAKE_RUN_LOG"
case "$UBSAN_OPTIONS" in
  *halt_on_error=1*) exit 0 ;;
  *) echo 'UBSan must fail the gate on undefined behavior' >&2; exit 1 ;;
esac
''')
    # First create an up-to-date, ordinary build. Changing only compiler
    # flags must still rebuild it when run-sanitize is requested.
    plain = run_make_gate(testdir, env, "test_obfstr")
    check("sanitizer fixture ordinary build succeeds", plain.returncode == 0,
          plain.stdout + plain.stderr)
    proc = run_make_gate(testdir, env, "run-sanitize")
    with open(env["FAKE_BUILD_LOG"]) as fp:
        builds = fp.read()
    runs = ""
    if os.path.exists(env["FAKE_RUN_LOG"]):
        with open(env["FAKE_RUN_LOG"]) as fp:
            runs = fp.read()
    check("run-sanitize rebuilds with ASan and UBSan",
          "-fsanitize=address,undefined" in builds, builds)
    check("run-sanitize executes only the instrumented binary",
          runs == "instrumented\n", runs)
    check("run-sanitize enables fatal UBSan errors", proc.returncode == 0,
          proc.stdout + proc.stderr)

    # A failed rebuild must not fall back to a previously passing binary.
    run_make_gate(testdir, env, "test_obfstr")
    os.unlink(env["FAKE_RUN_LOG"])
    env["FAKE_BUILD_ERROR"] = "deliberate compiler failure"
    proc = run_make_gate(testdir, env, "run-sanitize")
    check("run-sanitize fails on compiler errors", proc.returncode != 0,
          proc.stdout + proc.stderr)
    check("failed sanitizer builds never execute stale binaries",
          not os.path.exists(env["FAKE_RUN_LOG"]))
    check("failed sanitizer builds still clean up",
          not os.path.exists(os.path.join(testdir, "test_obfstr")))


def test_tsan_gate(mk):
    testdir, env = make_gate_fixture(mk, '''#!/bin/sh
echo instrumented >> "$FAKE_RUN_LOG"
printf '%s\\n' "$FAKE_DIAGNOSTIC" >&2
exit "$FAKE_STATUS"
''')
    cases = [
        ("clean execution", "", "0", "", True, "TSAN: no data races"),
        ("runtime initialization failure",
         "FATAL: ThreadSanitizer: unexpected memory mapping", "66", "",
         False, "RUN FAILED"),
        ("test assertion failure", "assertion failed", "1", "",
         False, "RUN FAILED"),
        ("signal-style exit", "Segmentation fault", "139", "",
         False, "RUN FAILED"),
        ("race warning with zero exit", "WARNING: ThreadSanitizer: data race",
         "0", "", False, "DATA RACES FOUND"),
        ("missing toolchain", "", "0", "cannot find -ltsan",
         True, "toolchain absent"),
        ("compiler regression", "", "0", "error: invalid source",
         False, "BUILD FAILED"),
    ]
    for name, diagnostic, status, build_error, success, message in cases:
        env.update(FAKE_DIAGNOSTIC=diagnostic, FAKE_STATUS=status,
                   FAKE_BUILD_ERROR=build_error)
        proc = run_make_gate(testdir, env, "race")
        output = proc.stdout + proc.stderr
        check(f"TSan {name}: exit status",
              (proc.returncode == 0) == success, output)
        check(f"TSan {name}: diagnostic", message in output, output)
        if name != "clean execution":
            check(f"TSan {name}: never reported as clean",
                  "TSAN: no data races" not in output, output)
        if diagnostic:
            check(f"TSan {name}: preserves runtime output",
                  diagnostic in output, output)
        check(f"TSan {name}: temporary logs removed",
              not any(p.startswith(".zs_tsan.") for p in os.listdir(testdir)))


def test_build_ndk_discovery(mk):
    """Exercise real build-script discovery without a cross-compilation toolchain."""
    sdk = os.path.join(mk.root, "Android SDK")

    def fake_ndk(path, tag="linux-x86_64"):
        bindir = os.path.join(path, "toolchains", "llvm", "prebuilt", tag, "bin")
        os.makedirs(bindir)
        # Discovery only checks executability; no compiler should run here.
        write_exec(os.path.join(bindir, "clang"), "#!/bin/sh\nexit 99\n")
        cmake_dir = os.path.join(path, "build", "cmake")
        os.makedirs(cmake_dir)
        with open(os.path.join(cmake_dir, "android.toolchain.cmake"), "w"):
            pass
        return path

    older = fake_ndk(os.path.join(sdk, "ndk", "9.0.0"))
    newest = fake_ndk(os.path.join(sdk, "ndk", "27.3.13750724"))
    # Keep the host deterministic, even when this suite runs on macOS.
    write_exec(os.path.join(mk.bindir, "uname"), "#!/bin/sh\necho Linux\n")
    alternate = fake_ndk(os.path.join(mk.root, "alternate NDK"), "linux-aarch64")
    foreign = fake_ndk(os.path.join(sdk, "ndk", "99.0.0"), "darwin-x86_64")
    # An unrelated prebuilt directory must not hide the usable toolchain.
    os.makedirs(os.path.join(alternate, "toolchains", "llvm", "prebuilt", "aaa-empty"))
    missing = os.path.join(mk.root, "missing NDK")
    os.makedirs(missing)
    write_exec(os.path.join(mk.bindir, "cmake"), "#!/bin/sh\nexit 99\n")
    env = mk.env()
    for key in ("NDK", "NDK_VERSION", "ANDROID_NDK_HOME",
                "ANDROID_NDK_LATEST_HOME", "ANDROID_NDK_ROOT"):
        env.pop(key, None)
    env["ANDROID_HOME"] = sdk

    cases = [
        ("SDK newest version", {}, newest),
        ("empty NDK_VERSION", {"NDK_VERSION": ""}, newest),
        ("pinned NDK_VERSION", {"NDK_VERSION": "9.0.0"}, older),
        ("explicit NDK", {"NDK": older}, older),
        ("environment NDK override", {"ANDROID_NDK_HOME": older}, older),
        ("alternate same-OS toolchain", {"NDK": alternate}, alternate),
        ("foreign preferred NDK falls through to SDK", {"ANDROID_NDK_HOME": foreign}, newest),
        ("foreign preferred NDK falls through to next environment candidate",
         {"ANDROID_NDK_HOME": foreign, "ANDROID_NDK_LATEST_HOME": older}, older),
        ("foreign latest NDK falls through to classic environment candidate",
         {"ANDROID_NDK_LATEST_HOME": foreign, "ANDROID_NDK_ROOT": older}, older),
        ("explicit foreign NDK fails instead of silently switching", {"NDK": foreign}, None),
        ("missing clang rejected", {"NDK": missing}, None),
    ]
    for index, (name, overrides, expected) in enumerate(cases):
        out = os.path.join(mk.root, f"build-{index}")
        proc = subprocess.run(
            ["bash", os.path.join(REPO_ROOT, "scripts", "build_module.sh"),
             "--skip-cpp", "--skip-rust", "--skip-zip", "--out", out],
            env={**env, **overrides}, capture_output=True, text=True, timeout=30)
        if expected is None:
            check(f"build: {name}", proc.returncode != 0 and
                  "ERROR: clang not found" in proc.stderr,
                  proc.stdout + proc.stderr)
        else:
            check(f"build: {name}", proc.returncode == 0 and
                  f"== NDK: {expected}" in proc.stdout.splitlines() and
                  os.path.isfile(os.path.join(out, "module", "module.prop")),
                  proc.stdout + proc.stderr)


def test_build_regressions(mk):
    """Exercise the real build driver with fake compilers and real ELF/zip tools.

    No Android NDK or Rust installation is needed. The compiler doubles only
    produce fixtures; path handling, strip, assembly and verification are real.
    """
    import struct
    import zipfile

    root = os.path.join(mk.root, "build fixture")
    os.makedirs(os.path.join(root, "scripts", "installer"))
    os.makedirs(os.path.join(root, "native", "zygiskd"))
    for name in ("build_module.sh", "installer/update-binary",
                 "installer/updater-script"):
        shutil.copy(os.path.join(REPO_ROOT, "scripts", name),
                    os.path.join(root, "scripts", name))
    for name in ("customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh",
                 "zs_compat.sh", "post-mount-hook.sh", "verify.sh", "LICENSE"):
        shutil.copy(os.path.join(REPO_ROOT, name), root)
    shutil.copytree(os.path.join(REPO_ROOT, "webroot"), os.path.join(root, "webroot"))
    ndk = os.path.join(root, "Android NDK")
    toolbin = os.path.join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
    os.makedirs(toolbin)
    os.makedirs(os.path.join(ndk, "build", "cmake"))
    with open(os.path.join(ndk, "build", "cmake", "android.toolchain.cmake"), "w"):
        pass
    write_exec(os.path.join(toolbin, "clang"), "#!/bin/sh\nexit 99\n")
    os.symlink(shutil.which("strip"), os.path.join(toolbin, "llvm-strip"))
    os.symlink(shutil.which("readelf"), os.path.join(toolbin, "llvm-readelf"))

    seed = os.path.join(root, "fixture.so")
    subprocess.run(["cc", "-shared", "-fPIC", "-s", "-Wl,-z,max-page-size=16384",
                    "-x", "c", "-", "-o", seed], input="int fixture(void){return 0;}\n",
                   text=True, capture_output=True, check=True, timeout=30)
    with open(seed, "rb") as fp:
        valid_elf = fp.read()

    write_exec(os.path.join(mk.bindir, "cmake"), r'''#!/usr/bin/env python3
import json, os, shutil, sys
args = sys.argv[1:]
with open(os.environ["BUILD_CALLS"], "a") as fp:
    fp.write("cmake " + json.dumps(args) + "\n")
if args[0] == "--build":
    out = args[1]
    for name in ("libzygisk", "libpayload", "libzn_loader"):
        dest = os.path.join(out, name) if os.environ.get("NESTED_OUTPUT") else out
        os.makedirs(dest, exist_ok=True)
        shutil.copy(os.environ["BUILD_SEED"], os.path.join(dest, name + ".so"))
else:
    path = next(a.split("=", 1)[1] for a in args if a.startswith("-DCMAKE_TOOLCHAIN_FILE="))
    # CMake resolves a relative toolchain path from its build/source tree,
    # not from the shell's cwd. Require the unambiguous absolute form.
    if not os.path.isabs(path) or not os.path.isfile(path):
        sys.exit("invalid CMake toolchain path: " + path)
''')
    write_exec(os.path.join(mk.bindir, "cargo"), r'''#!/usr/bin/env python3
import json, os, shutil, sys
args = sys.argv[1:]
target = args[args.index("--target") + 1]
prefix = "CARGO_TARGET_" + target.upper().replace("-", "_")
# Cargo's documented precedence: encoded, generic, then target flags.
if "CARGO_ENCODED_RUSTFLAGS" in os.environ:
    flags = os.environ["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
elif "RUSTFLAGS" in os.environ:
    flags = os.environ["RUSTFLAGS"].split()
else:
    flags = os.environ.get(prefix + "_RUSTFLAGS", "").split()
with open(os.environ["BUILD_CALLS"], "a") as fp:
    fp.write("cargo " + json.dumps(flags) + "\n")
if os.environ.get("CHECK_RUST_FLAGS"):
    required = ["link-arg=--target=x86_64-linux-android21",
                "link-arg=--sysroot=" + os.environ["NDK"] + "/toolchains/llvm/prebuilt/linux-x86_64/sysroot",
                "link-arg=-Wl,-z,max-page-size=16384",
                "link-arg=-Wl,-z,common-page-size=16384",
                "--remap-path-prefix=" + os.environ["BUILD_REPO"] + "=.", "opt-level=2"]
    if not all(arg in flags for arg in required):
        sys.exit("required or caller Rust flags were lost: " + repr(flags))
out = (args[args.index("--target-dir") + 1] if "--target-dir" in args
       else os.environ.get("CARGO_TARGET_DIR", "target"))
dest = os.path.join(out, target, "release")
os.makedirs(dest, exist_ok=True)
shutil.copy(os.environ["BUILD_SEED"], os.path.join(dest, "zygiskd"))
''')
    env = mk.env()
    for key in list(env):
        if key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
                   "OUT_ROOT", "ABIS", "API_LEVEL", "BUILD_TYPE") or key.startswith("CARGO_TARGET_"):
            env.pop(key, None)
    env.update(NDK=ndk, BUILD_REPO=root, BUILD_SEED=seed,
               BUILD_CALLS=os.path.join(root, "calls.log"))
    script = os.path.join(root, "scripts", "build_module.sh")
    run_index = 0

    def run(args=(), extra=None):
        nonlocal run_index
        run_index += 1
        out = os.path.join(root, "out " + str(run_index))
        with open(env["BUILD_CALLS"], "w"):
            pass
        proc = subprocess.run(["bash", script, "--abis", "x86_64", "--out", out, *args],
                              cwd=root, env={**env, **(extra or {})},
                              capture_output=True, text=True, timeout=30)
        return proc, out

    def passed(label, proc):
        check(label, proc.returncode == 0, proc.stdout + proc.stderr)

    # 1. Missing values must be diagnosed, not nounset crashes or swallowed options.
    for option in ("--ndk", "--api", "--abis", "--out", "--type"):
        for args in ((option,), (option, "--skip-zip")):
            proc, _ = run(args)
            check("build: missing value " + repr(args),
                  proc.returncode == 2 and "requires a value" in proc.stderr,
                  proc.stdout + proc.stderr)

    # 2. Invalid/empty ABI lists must fail before invoking compilers or assembly.
    for abis in ("", "   ", "mips", "x86_64 mips", "*"):
        proc, out = run(("--abis", abis, "--skip-cpp", "--skip-rust", "--skip-zip"))
        with open(env["BUILD_CALLS"]) as fp:
            calls = fp.read()
        check("build: invalid ABI list rejected " + repr(abis),
              proc.returncode == 2 and not calls and not os.path.exists(out),
              proc.stdout + proc.stderr)

    # 3. A relative output path must still work after cd into the module tree.
    proc, _ = run(("--out", "relative output"))
    passed("build: relative output creates a complete archive", proc)
    outdir = os.path.join(root, "relative output", "out")
    archives = os.listdir(outdir) if os.path.isdir(outdir) else []
    check("build: relative archive is at the requested location", len(archives) == 1)
    if len(archives) == 1:
        with zipfile.ZipFile(os.path.join(outdir, archives[0])) as archive:
            check("build: archive contains all four ABI artifacts",
                  all("libs/x86_64/" + f in archive.namelist() for f in
                      ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")))

    # 4. A relative NDK path must be normalized before CMake/Cargo change cwd.
    proc, _ = run(("--ndk", "Android NDK", "--skip-rust", "--skip-zip"))
    passed("build: relative NDK path survives cross-build configuration", proc)

    # 5. Documented quick/partial builds must not try to ship incomplete zips.
    for option, artifact in (("--skip-rust", "libzygisk.so"), ("--skip-cpp", "zygiskd")):
        proc, out = run((option,))
        passed("build: partial mode succeeds " + option, proc)
        check("build: partial mode keeps the built artifact " + option,
              os.path.isfile(os.path.join(out, "module", "libs", "x86_64", artifact)))
        check("build: partial mode never emits an installable zip " + option,
              not os.path.isdir(os.path.join(out, "out")))

    # 6. Per-target CMake layouts must be flattened before strip is invoked.
    proc, _ = run(("--skip-rust", "--skip-zip"), {"NESTED_OUTPUT": "1"})
    passed("build: nested CMake artifacts are found before stripping", proc)

    # 7. Cargo's target directory must agree with strip and assembly paths.
    # Remove the default outputs so a stale successful build cannot mask this.
    shutil.rmtree(os.path.join(root, "native", "zygiskd", "target"), ignore_errors=True)
    for cargo_dir in (os.path.join(root, "cargo cache"), "relative cargo cache"):
        proc, out = run(("--skip-cpp", "--skip-zip"), {"CARGO_TARGET_DIR": cargo_dir})
        passed("build: custom Cargo output directory " + cargo_dir, proc)
        check("build: custom Cargo output is packaged",
              os.path.isfile(os.path.join(out, "module", "libs", "x86_64", "zygiskd")))

    # 8. Global/encoded flags must not override required Android linker options.
    for flags in ({"RUSTFLAGS": "-C opt-level=2"},
                  {"CARGO_ENCODED_RUSTFLAGS": "-C\x1fopt-level=2"},
                  {"CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS": "-C opt-level=2"},
                  {"CARGO_ENCODED_RUSTFLAGS": "-C\x1fopt-level=2",
                   "RUSTFLAGS": "-C opt-level=0"}):
        proc, _ = run(("--skip-cpp", "--skip-zip"), {**flags, "CHECK_RUST_FLAGS": "1"})
        passed("build: preserves required and caller flags " + next(iter(flags)), proc)

    # 9. Every PT_LOAD must meet the page-size floor, not only the first one.
    elf = bytearray(valid_elf)
    endian = "<" if elf[5] == 1 else ">"
    if elf[4] == 2:
        phoff = struct.unpack_from(endian + "Q", elf, 32)[0]
        phsize, phnum = struct.unpack_from(endian + "HH", elf, 54)
        align_offset, align_fmt = 48, "Q"
    else:
        phoff = struct.unpack_from(endian + "I", elf, 28)[0]
        phsize, phnum = struct.unpack_from(endian + "HH", elf, 42)
        align_offset, align_fmt = 28, "I"
    loads = [phoff + i * phsize for i in range(phnum)
             if struct.unpack_from(endian + "I", elf, phoff + i * phsize)[0] == 1]
    assert len(loads) > 1, "ELF fixture must have multiple load segments"
    struct.pack_into(endian + align_fmt, elf, loads[1] + align_offset, 0x1000)
    with open(seed, "wb") as fp:
        fp.write(elf)
    proc, _ = run()
    check("build: rejects underaligned later LOAD segments",
          proc.returncode != 0 and "alignment" in proc.stderr,
          proc.stdout + proc.stderr)
    with open(seed, "wb") as fp:
        fp.write(valid_elf)
    proc, _ = run()
    passed("build: valid complete archive still passes all verification", proc)


# Release-tooling regressions. Each numbered group covers one distinct bug.
def test_verify_artifact_regressions(mk):
    import struct

    script = os.path.join(mk.moddir, "verify.sh")
    shutil.copy(os.path.join(REPO_ROOT, "verify.sh"), script)
    libs = os.path.join(mk.moddir, "libs")
    names = ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")
    machines = {"arm64-v8a": (2, 183), "armeabi-v7a": (1, 40),
                "x86_64": (2, 62), "x86": (1, 3)}

    def layout(abi="x86_64"):
        shutil.rmtree(libs, ignore_errors=True)
        dest = os.path.join(libs, abi)
        os.makedirs(dest)
        cls, machine = machines[abi]
        elf = bytearray(64)
        elf[:7] = b"\x7fELF" + bytes((cls, 1, 1))
        struct.pack_into("<H", elf, 16, 3)
        struct.pack_into("<H", elf, 18, machine)
        struct.pack_into("<I", elf, 20, 1)
        struct.pack_into("<H", elf, 52 if cls == 2 else 40, 64 if cls == 2 else 52)
        for name in names:
            with open(os.path.join(dest, name), "wb") as fp:
                fp.write(elf)
        return dest

    def run(shell="bash", helpers=True, sourced=False):
        env = mk.env()
        env.pop("MODDIR", None)
        env.pop("MODPATH", None)
        if not helpers:
            return subprocess.run([shell, script], env=env, capture_output=True,
                                  text=True, timeout=10)
        body = 'ui_print(){ printf "%s\\n" "$*"; }; abort(){ ui_print "$*"; exit 1; }; '
        if sourced:
            env["MODPATH"] = mk.moddir
            body += '. "$1"'
            args = [shell, "-c", body, "recovery-installer", script]
        else:
            # Executing through a shell with helpers mirrors Magisk's functions,
            # while giving the verifier its original $0 (unlike sourcing).
            with open(script) as fp:
                body += fp.read()
            args = [shell, "-c", body, script]
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=10)

    # 1: standalone verification must not depend on Magisk-only shell functions.
    layout()
    proc = run(helpers=False)
    check("bug 01: verifier works standalone", proc.returncode == 0,
          proc.stdout + proc.stderr)
    shutil.rmtree(libs)
    proc = run(helpers=False)
    check("bug 01: standalone empty layout fails cleanly", proc.returncode != 0
          and "not found" not in proc.stderr, proc.stdout + proc.stderr)

    # 2: /system/bin/sh scripts must not need Bash's ANSI-C quoting extension.
    layout()
    proc = run(shell="sh")
    check("bug 02: valid ELF accepted by POSIX sh", proc.returncode == 0,
          proc.stdout + proc.stderr)

    # 3: a present ABI must have all four artifacts, not just one file anywhere.
    for missing in names:
        dest = layout()
        os.unlink(os.path.join(dest, missing))
        proc = run()
        check("bug 03: incomplete ABI rejected: " + missing, proc.returncode != 0,
              proc.stdout + proc.stderr)
    layout()
    os.makedirs(os.path.join(libs, "x86"))
    proc = run()
    check("bug 03: empty secondary ABI rejected", proc.returncode != 0,
          proc.stdout + proc.stderr)

    # 4: the daemon is an ELF too, not an arbitrary file that counts as present.
    dest = layout()
    with open(os.path.join(dest, "zygiskd"), "wb") as fp:
        fp.write(b"not an executable\n")
    proc = run()
    check("bug 04: corrupt daemon rejected", proc.returncode != 0,
          proc.stdout + proc.stderr)

    # 5: reject wrong bitness even when the ELF magic is valid.
    dest = layout()
    with open(os.path.join(dest, "libpayload.so"), "r+b") as fp:
        fp.seek(4)
        fp.write(b"\x01")
    proc = run()
    check("bug 05: wrong ELF class rejected", proc.returncode != 0,
          proc.stdout + proc.stderr)

    # 6: arm64 and x86_64 share ELFCLASS64, but cannot run each other's code.
    dest = layout()
    with open(os.path.join(dest, "libzygisk.so"), "r+b") as fp:
        fp.seek(18)
        fp.write(struct.pack("<H", 183))
    proc = run()
    check("bug 06: wrong ELF machine rejected", proc.returncode != 0,
          proc.stdout + proc.stderr)
    for abi in machines:
        layout(abi)
        proc = run()
        check("verify: valid ABI accepted: " + abi, proc.returncode == 0,
              proc.stdout + proc.stderr)

    # 7: when sourced, $0 belongs to the installer, not to verify.sh.
    layout()
    proc = run(sourced=True)
    check("bug 07: sourced verifier honors MODPATH", proc.returncode == 0,
          proc.stdout + proc.stderr)


def test_publish_regressions(mk):
    import json

    write_exec(os.path.join(mk.bindir, "git"), r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['PUBLISH_CALLS'], 'a') as fp:
    fp.write(json.dumps(args) + '\n')
state = os.environ['PUBLISH_REMOTE']
if args[:2] == ['rev-parse', '--is-inside-work-tree']:
    print('true')
elif args[:2] in (['rev-parse', 'HEAD'], ['rev-parse', '--verify']):
    print('0123456789abcdef')
elif args[:1] == ['symbolic-ref']:
    if os.environ.get('PUBLISH_DETACHED'):
        sys.exit(1)
    print('study-fixes')
elif args[:2] == ['remote', 'get-url']:
    with open(state) as fp:
        url = fp.read()
    if not url:
        sys.exit(2)
    print(url)
elif args[:2] in (['remote', 'set-url'], ['remote', 'add'], ['config', '--replace-all']):
    with open(state, 'w') as fp:
        fp.write(args[-1])
elif args[:1] == ['check-ref-format']:
    pass
elif args[:2] in (['config', 'user.email'], ['config', '--get-all'], ['config', '--local'], ['config', '--bool']):
    sys.exit(1)
elif args[:1] != ['push']:
    sys.exit('unexpected git command: ' + repr(args))
''')
    env = mk.env({"PUBLISH_CALLS": os.path.join(mk.root, "publish.log"),
                  "PUBLISH_REMOTE": os.path.join(mk.root, "remote.url")})

    def run(args=(), remote="https://github.com/example/study.git", extra=None):
        with open(env["PUBLISH_CALLS"], "w"):
            pass
        with open(env["PUBLISH_REMOTE"], "w") as fp:
            fp.write(remote)
        proc = subprocess.run(["bash", os.path.join(REPO_ROOT, "publish.sh"), *args],
                              env={**env, **(extra or {})}, capture_output=True,
                              text=True, timeout=10)
        with open(env["PUBLISH_CALLS"]) as fp:
            calls = [json.loads(line) for line in fp]
        with open(env["PUBLISH_REMOTE"]) as fp:
            url = fp.read()
        return proc, calls, url

    # 8: option values cannot be missing, empty, or another switch.
    for opt in ("--repo", "--remote", "--branch"):
        for args in ((opt,), (opt, ""), (opt, "--ssh")):
            proc, calls, _ = run(args)
            check("bug 08: publish validates " + repr(args), proc.returncode == 2
                  and "requires a value" in proc.stderr and not calls,
                  proc.stdout + proc.stderr)

    # 9: the default push should publish the branch actually being worked on.
    proc, calls, _ = run()
    check("bug 09: publish defaults to the current branch", proc.returncode == 0
          and ["push", "--no-follow-tags", "-u", "origin", "refs/heads/study-fixes:refs/heads/study-fixes"] in calls, repr(calls))
    proc, calls, _ = run(extra={"PUBLISH_DETACHED": "1"})
    check("bug 09: detached HEAD requires an explicit branch", proc.returncode != 0
          and not any(c[0] == "push" for c in calls), proc.stdout + proc.stderr)
    proc, calls, _ = run(("--branch", "release"), extra={"PUBLISH_DETACHED": "1"})
    check("publish: explicit branch works detached", proc.returncode == 0
          and ["push", "--no-follow-tags", "-u", "origin", "refs/heads/release:refs/heads/release"] in calls, repr(calls))

    # 10: --repo must not silently push to the existing, different repository.
    proc, calls, url = run(("--repo", "owner/new-study"))
    check("bug 10: explicit repository updates existing remote", proc.returncode == 0
          and url == "https://github.com/owner/new-study.git", repr(calls))

    # 11: explicit transport switches apply to existing GitHub remotes too.
    for args, remote, expected in (
        (("--ssh",), "https://github.com/example/study.git", "git@github.com:example/study.git"),
        (("--https",), "git@github.com:example/study.git", "https://github.com/example/study.git"),
        (("--https",), "ssh://git@github.com/example/study.git", "https://github.com/example/study.git"),
    ):
        proc, calls, url = run(args, remote)
        check("bug 11: transport switch " + repr(args) + " from " + remote,
              proc.returncode == 0 and url == expected, repr(calls))
    proc, calls, url = run(("--ssh",), "https://example.org/team/study.git")
    check("publish: transport conversion cannot redirect a non-GitHub remote",
          proc.returncode != 0 and not any(c[0] == "push" for c in calls), repr(calls))

    # 12: missing git user.email must not suppress the missing-remote diagnostic.
    proc, calls, _ = run(remote="")
    check("bug 12: missing remote diagnostic without configured email",
          proc.returncode != 0 and "pass --repo" in proc.stderr,
          proc.stdout + proc.stderr)


def test_build_input_regressions(mk):
    sdk = os.path.join(mk.root, "sdk")
    valid = os.path.join(sdk, "ndk", "26.0")
    toolbin = os.path.join(valid, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
    os.makedirs(toolbin)
    write_exec(os.path.join(toolbin, "clang"), "#!/bin/sh\nexit 99\n")
    os.makedirs(os.path.join(valid, "build", "cmake"))
    with open(os.path.join(valid, "build", "cmake", "android.toolchain.cmake"), "w"):
        pass
    broken = os.path.join(sdk, "ndk", "99.0")
    os.makedirs(broken)
    write_exec(os.path.join(mk.bindir, "cmake"), "#!/bin/sh\nexit 99\n")
    env = mk.env()
    for key in ("NDK", "NDK_VERSION", "ANDROID_NDK_HOME", "ANDROID_NDK_LATEST_HOME",
                "ANDROID_NDK_ROOT", "API_LEVEL", "ABIS"):
        env.pop(key, None)
    env["ANDROID_HOME"] = sdk
    index = 0

    def run(args=(), extra=None):
        nonlocal index
        index += 1
        out = os.path.join(mk.root, "input-build-" + str(index))
        proc = subprocess.run(["bash", os.path.join(REPO_ROOT, "scripts", "build_module.sh"),
                               "--skip-cpp", "--skip-rust", "--out", out, *args],
                              env={**env, **(extra or {})}, capture_output=True,
                              text=True, timeout=15)
        return proc, out

    # 13: an explicit missing NDK is an error, not permission to use another one.
    proc, out = run(("--ndk", os.path.join(mk.root, "missing")),
                    {"ANDROID_NDK_HOME": valid})
    check("bug 13: explicit nonexistent NDK is rejected", proc.returncode != 0
          and not os.path.exists(out), proc.stdout + proc.stderr)

    # 14: automatic discovery must skip incomplete/stale NDK installations.
    for extra in ({}, {"ANDROID_NDK_HOME": broken}, {"NDK_VERSION": "99.0"}):
        proc, _ = run(extra=extra)
        check("bug 14: discovery skips incomplete NDK " + repr(extra), proc.returncode == 0
              and f"== NDK: {valid}" in proc.stdout.splitlines(), proc.stdout + proc.stderr)

    # 15: invalid or unsupported API values must fail before output/compilers.
    for api in ("", "abc", "20", "-1", "21;echo bad", "021"):
        proc, out = run(("--ndk", valid, "--api", api))
        check("bug 15: invalid API rejected: " + repr(api), proc.returncode == 2
              and not os.path.exists(out), proc.stdout + proc.stderr)
    for api in ("21", "35"):
        proc, _ = run(("--ndk", valid, "--api", api))
        check("build: supported API accepted: " + api, proc.returncode == 0,
              proc.stdout + proc.stderr)


def test_recovery_installer_regressions(mk):
    # Rewrite only the absolute device path in a private copy; all decisions and
    # exit handling still come from the production installer. Never mount /data.
    with open(os.path.join(REPO_ROOT, "scripts", "installer", "update-binary")) as fp:
        source = fp.read()
    util = os.path.join(mk.root, "util_functions.sh")
    script = os.path.join(mk.root, "update-binary")
    with open(script, "w") as fp:
        fp.write(source.replace("/data/adb/magisk/util_functions.sh", '"' + util + '"'))
    write_exec(os.path.join(mk.bindir, "mount"), "#!/bin/sh\nexit 0\n")
    marker = os.path.join(mk.root, "installed")

    def run(version="20400", status=0):
        if os.path.exists(marker):
            os.unlink(marker)
        with open(util, "w") as fp:
            fp.write("MAGISK_VER_CODE='" + version + "'\n"
                     + "install_module(){ touch '" + marker + "'; return " + str(status) + "; }\n")
        archive = os.path.join(mk.root, "module.zip")
        with open(archive, "wb") as fp:
            fp.write(b"fixture")
        return subprocess.run(["sh", script, "3", "", archive], env=mk.env(),
                              capture_output=True, text=True, timeout=10)

    # 16: preserve Magisk install_module's nonzero return code.
    proc = run(status=42)
    check("bug 16: recovery propagates installation failure", proc.returncode == 42,
          proc.stdout + proc.stderr)
    proc = run()
    check("recovery: successful installation returns zero", proc.returncode == 0
          and os.path.exists(marker), proc.stdout + proc.stderr)

    # 17: a malformed version must not bypass the minimum-version check.
    for version in ("garbage", "20400x", "", "20300", "999999999999999999999999999999999"):
        proc = run(version)
        check("bug 17: recovery rejects invalid/old version " + repr(version),
              proc.returncode != 0 and not os.path.exists(marker), proc.stdout + proc.stderr)


def test_make_cleanup_regressions(mk):
    # 18: header probes must not share predictable source files across builds.
    proc = subprocess.run(["make", "-n", "-C", os.path.join(REPO_ROOT, "tests"),
                           "verify-public-header"], capture_output=True, text=True, timeout=10)
    check("bug 18: public-header probes do not share /tmp source files", proc.returncode == 0
          and "/tmp/zs_api_" not in proc.stdout, proc.stdout + proc.stderr)

    # 19: clean must remove both ordinary and TSan race-suite artifacts.
    testdir = os.path.join(mk.root, "tests")
    os.makedirs(testdir)
    shutil.copy(os.path.join(REPO_ROOT, "tests", "Makefile"), testdir)
    for name in ("race_fixture.so", "test_race_tsan", "test_race"):
        with open(os.path.join(testdir, name), "w"):
            pass
    proc = subprocess.run(["make", "-C", testdir, "clean"], capture_output=True,
                          text=True, timeout=10)
    check("bug 19: clean removes race fixtures and sanitizer binary", proc.returncode == 0
          and all(not os.path.exists(os.path.join(testdir, name)) for name in
                  ("race_fixture.so", "test_race_tsan", "test_race")), proc.stdout + proc.stderr)


def test_verify_pr8_regressions(mk):
    """Nine post-install verifier bugs; header fixtures need no Android NDK.

    These are deliberately only ELF headers, not runnable binaries: the
    device-side checker promises header sanity, not loader/provenance checks.
    """
    import struct

    moddir = os.path.join(mk.root, "verification module with spaces")
    os.makedirs(moddir)
    script = os.path.join(moddir, "verify.sh")
    shutil.copy(os.path.join(REPO_ROOT, "verify.sh"), script)
    artifacts = ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")
    formats = {"arm64-v8a": (2, 183, 64), "armeabi-v7a": (1, 40, 52),
               "x86_64": (2, 62, 64), "x86": (1, 3, 52)}

    def header(abi):
        cls, machine, size = formats[abi]
        data = bytearray(size)
        data[:7] = b"\x7fELF" + bytes((cls, 1, 1))
        struct.pack_into("<HHI", data, 16, 3, machine, 1)
        struct.pack_into("<H", data, 52 if cls == 2 else 40, size)
        return data

    def put(abi, name, data):
        folder = os.path.join(moddir, "libs", abi)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, name), "wb") as fp:
            fp.write(data)

    def bundle(abis=("x86_64",)):
        shutil.rmtree(os.path.join(moddir, "libs"), ignore_errors=True)
        for abi in abis:
            for name in artifacts:
                put(abi, name, header(abi))

    def run(shell="sh", mode="standalone", helpers="exit", module_var="MODPATH"):
        env = mk.env()
        env.pop("MODPATH", None)
        env.pop("MODDIR", None)
        if mode == "standalone":
            argv = [shell, script]
        elif mode == "bare":
            argv = [shell, "verify.sh"]
        else:
            env[module_var] = moddir
            setup = 'ui_print() { printf "UI:%s\\n" "$*"; }; '
            if helpers == "exit":
                setup += 'abort() { exit 1; }; '
            elif helpers != "absent":
                setup += 'abort() { return ' + helpers + '; }; '
            # Correct legacy argv[0] isolates format bugs from path resolution.
            argv0 = script if mode == "legacy" else "/installer/update-binary"
            argv = [shell, "-c", setup + '. "$1"', argv0, script]
        return subprocess.run(argv, cwd=moddir, env=env, capture_output=True,
                              text=True, timeout=10)

    def accept(label, proc, count=4):
        check(label, proc.returncode == 0
              and f"Verified {count} native artifacts" in proc.stdout,
              proc.stdout + proc.stderr)

    def reject(label, proc, diagnostic):
        check(label, proc.returncode != 0 and "Verified" not in proc.stdout
              and diagnostic in proc.stdout + proc.stderr,
              proc.stdout + proc.stderr)

    # 1. Standalone execution must not depend on installer-only functions.
    bundle()
    accept("verify #1: standalone valid bundle", run("bash"))
    bundle(())
    reject("verify #1: standalone empty bundle has a useful error",
           run("bash"), "No native artifacts")

    # 2. A sourced script's $0 belongs to its caller, not the module.
    bundle()
    for variable in ("MODPATH", "MODDIR"):
        proc = run("bash", "sourced", module_var=variable)
        accept("verify #2: sourced module location via " + variable, proc)
        check("verify #2: preserves installer ui_print " + variable,
              "UI:- Verified" in proc.stdout, proc.stdout + proc.stderr)

    # 3. POSIX sh does not understand bash's ANSI-C string quoting.
    for abi in formats:
        bundle((abi,))
        accept("verify #3: POSIX shell accepts " + abi, run("sh", "legacy"))
        accept("verify: standalone POSIX shell accepts " + abi, run())
    accept("verify: bare filename invocation", run(mode="bare"))

    # 4. A returning/missing abort helper must never allow success afterward.
    for helper in ("0", "1", "absent"):
        bundle()
        put("x86_64", artifacts[0], b"BAD!")
        reject("verify #4: fail closed with abort=" + helper,
               run("bash", "legacy", helper), "not an ELF")

    # 5. A nonzero global count does not imply a complete per-ABI bundle.
    for abi in formats:
        for missing in artifacts:
            bundle((abi,))
            os.unlink(os.path.join(moddir, "libs", abi, missing))
            reject("verify #5: missing " + abi + "/" + missing,
                   run("bash", "legacy"), "Missing native artifact")
    bundle()
    os.makedirs(os.path.join(moddir, "libs", "x86"))
    reject("verify #5: empty ABI next to a complete ABI",
           run("bash", "legacy"), "Missing native artifact")
    bundle(formats)
    accept("verify: all four complete ABIs", run(), 16)

    # 6. The daemon is an ELF executable too, not an arbitrary existing file.
    for data in (b"", b"#!/bin/sh\nexit 0\n", b"not an executable"):
        bundle()
        put("x86_64", "zygiskd", data)
        reject("verify #6: rejects corrupt daemon " + repr(data),
               run("bash", "legacy"), "not an ELF")

    # 7. Each ABI has a fixed ELF class, for both libraries and the daemon.
    for abi in formats:
        for name in (artifacts[0], "zygiskd"):
            bundle((abi,))
            data = header(abi)
            data[4] = 3 - data[4]
            put(abi, name, data)
            reject("verify #7: wrong ELF class " + abi + "/" + name,
                   run("bash", "legacy"), "ELF class")

    # 8. Same-width ARM/x86 binaries are not interchangeable. Check the
    # high byte and the encoding too, rather than host-endian od -tu2.
    for abi, other in (("arm64-v8a", "x86_64"), ("x86_64", "arm64-v8a"),
                       ("armeabi-v7a", "x86"), ("x86", "armeabi-v7a")):
        for name in (artifacts[0], "zygiskd"):
            bundle((abi,))
            put(abi, name, header(other))
            reject("verify #8: wrong CPU " + abi + "/" + name,
                   run("bash", "legacy"), "ELF machine")
    for offset, value, diagnostic in ((19, 1, "ELF machine"),
                                      (5, 2, "byte order")):
        bundle()
        data = header("x86_64")
        data[offset] = value
        put("x86_64", artifacts[0], data)
        reject("verify #8: validates machine high byte/endianness " + str(offset),
               run("bash", "legacy"), diagnostic)

    # 9. Magic, class and machine can all survive a truncated download.
    for abi in formats:
        for length in (20, len(header(abi)) - 1):
            for name in (artifacts[0], "zygiskd"):
                bundle((abi,))
                put(abi, name, header(abi)[:length])
                reject("verify #9: truncated " + abi + "/" + name + " " + str(length),
                       run("bash", "legacy"), "Truncated ELF header")

    # Sourcing must not leak the verifier's variables, arguments or options.
    bundle()
    proc = subprocess.run(
        ["sh", "-eu", "-c", 'MODPATH=$1; MODDIR=sentinel; count=sentinel; '
         'before=$-; set -- caller args; . "$MODPATH/verify.sh"; '
         '[ "$MODDIR/$count/$*/$-" = "sentinel/sentinel/caller args/$before" ]',
         "installer", moddir], cwd=moddir, env=mk.env(), capture_output=True,
        text=True, timeout=10)
    accept("verify: sourced shell state is unchanged under errexit/nounset", proc)



def test_nineteen_validation_regressions(mk):
    """Nineteen independently reproduced failures relative to main at aa34cfe.

    Only host fixtures are used; no Android execution or network pushes.
    Archive tests invoke the real verification function with deterministic
    readelf output, keeping structural checks independent of toolchain support.
    """
    import struct
    import zipfile

    names = ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")
    script = os.path.join(REPO_ROOT, "verify.sh")
    libs = os.path.join(mk.moddir, "libs")

    def header(cls=2, machine=62):
        data = bytearray(64 if cls == 2 else 52)
        data[:7] = b"\x7fELF" + bytes((cls, 1, 1))
        struct.pack_into("<HHI", data, 16, 3, machine, 1)
        struct.pack_into("<H", data, 52 if cls == 2 else 40, len(data))
        return data

    def bundle(cls=2, machine=62, abi="x86_64"):
        shutil.rmtree(libs, ignore_errors=True)
        os.makedirs(os.path.join(libs, abi))
        for name in names:
            with open(os.path.join(libs, abi, name), "wb") as fp:
                fp.write(header(cls, machine))
        return os.path.join(libs, abi, names[0])

    def verify(setup="", tail="", extra=None):
        return subprocess.run(
            ["sh", "-c", setup + '. "$1"' + tail, "installer", script],
            env=mk.env({"MODPATH": mk.moddir, **(extra or {})}),
            capture_output=True, text=True, timeout=10)

    def result(number, label, proc, ok):
        check(f"nineteen {number:02d}: {label}", ok, proc.stdout + proc.stderr)

    bundle()
    proc = verify('count=original; abi=original; ',
                  '; [ "$count/$abi" = original/original ]')
    result(1, "sourcing preserves caller variables", proc, proc.returncode == 0)
    proc = verify('IFS=:; ')
    result(2, "caller IFS does not corrupt byte parsing", proc, proc.returncode == 0)

    for cls, machine, abi in ((2, 62, "x86_64"), (1, 3, "x86")):
        path = bundle(cls, machine, abi)
        with open(path, "wb") as fp:
            fp.write(header(cls, machine)[:-1])
        proc = verify()
        result(3, "rejects truncated " + abi + " headers", proc, proc.returncode != 0)

    bundle()
    # A broken reader can emit plausible bytes before reporting I/O failure.
    fake_od = os.path.join(mk.bindir, "od")
    import shlex
    write_exec(fake_od, '#!/bin/sh\n' + shlex.quote(shutil.which("od")) +
               ' "$@"\nexit 1\n')
    proc = verify()
    result(4, "reader failure cannot pass on partial output", proc, proc.returncode != 0)
    os.unlink(fake_od)

    bundle()
    with open(os.path.join(libs, "x86"), "w") as fp:
        fp.write("not a directory")
    proc = verify()
    result(5, "malformed secondary ABI entry is not skipped", proc, proc.returncode != 0)
    bundle()
    os.makedirs(os.path.join(libs, "x86_typo"))
    proc = verify()
    result(6, "unknown ABI directory is not silently ignored", proc, proc.returncode != 0)

    for number, offset, value, label in (
            (7, 6, b"\x00", "ELF identification version"),
            (8, 20, b"\x00\x00\x00\x00", "ELF header version"),
            (9, 16, b"\x01\x00", "relocatable object masquerading as library"),
            (10, 52, b"\x00\x00", "declared ELF header size")):
        path = bundle()
        with open(path, "r+b") as fp:
            fp.seek(offset)
            fp.write(value)
        proc = verify()
        result(number, "rejects " + label, proc, proc.returncode != 0)
    # Positive controls: ELF32, ELF64 and a non-PIE executable daemon.
    for cls, machine, abi in ((1, 40, "armeabi-v7a"), (2, 183, "arm64-v8a")):
        bundle(cls, machine, abi)
        daemon = os.path.join(libs, abi, "zygiskd")
        with open(daemon, "r+b") as fp:
            fp.seek(16)
            fp.write(b"\x02\x00")
        proc = verify()
        check("nineteen control: valid " + abi + " executable", proc.returncode == 0,
              proc.stdout + proc.stderr)

    # The staged tree remains valid while the ZIP is independently mutated.
    bundle()
    toolchain = os.path.join(mk.root, "archive tools")
    os.makedirs(os.path.join(toolchain, "bin"))
    write_exec(os.path.join(toolchain, "bin", "llvm-readelf"),
               '#!/bin/sh\ncase "$1" in -lW) echo " LOAD 0 0 0 0 0 R 0x4000";; esac\n')
    write_exec(os.path.join(toolchain, "bin", "llvm-strings"), '#!/bin/sh\nexit 0\n')
    with open(os.path.join(REPO_ROOT, "scripts", "build_module.sh")) as fp:
        build = fp.read()
    function = build[build.index("verify_zip() {"):build.index("# Drive the build")]
    prop = ("id=zygisk_study\nname=Study\nversion=1\nversionCode=1\n"
            "author=Study\ndescription=Educational\n")
    base = {f: b"fixture" for f in (
        "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh", "verify.sh",
        "zs_compat.sh", "post-mount-hook.sh", "LICENSE",
        "webroot/index.html", "webroot/app.js", "webroot/styles.css", "webroot/diagnostics.sh",
        "META-INF/com/google/android/update-binary")}
    base.update({"module.prop": prop.encode(),
                 "META-INF/com/google/android/updater-script": b"#MAGISK\n"})
    base.update({"libs/x86_64/" + name: bytes(release_elf_fixture()) for name in names})

    def archive_run(entries):
        archive = os.path.join(mk.root, "module.zip")
        with zipfile.ZipFile(archive, "w") as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return subprocess.run(
            ["bash", "-c", 'set -euo pipefail; ABI_LIST=(x86_64); ' +
             function + '\nverify_zip "$1"', "verify-archive", archive],
            env=mk.env({"REPO_ROOT": REPO_ROOT, "MODULE_DIR": mk.moddir,
                        "TOOLCHAIN": toolchain}), capture_output=True, text=True, timeout=20)

    proc = archive_run(base)
    check("nineteen control: valid archive", proc.returncode == 0, proc.stdout + proc.stderr)
    mutations = []
    entries = dict(base)
    del entries["verify.sh"]
    mutations.append((11, "missing packaged verifier", entries))
    entries = dict(base)
    entries["customizeXsh"] = entries.pop("customize.sh")
    mutations.append((12, "regex lookalike required filename", entries))
    entries = dict(base)
    entries["libs/x86_64/libpayload.so"] = bytes(header(2, 183))
    mutations.append((13, "same-width wrong CPU in archive", entries))
    entries = dict(base)
    entries["libs/x86_64/zygiskd"] = b"not an ELF executable"
    mutations.append((14, "corrupt daemon in archive", entries))
    entries = dict(base)
    entries["module.prop"] = prop.replace("name=Study", "name=").encode()
    mutations.append((15, "empty required metadata", entries))
    entries = dict(base)
    entries["module.prop"] = (prop + "id=another_module\n").encode()
    mutations.append((16, "conflicting duplicate metadata", entries))
    for number, label, entries in mutations:
        proc = archive_run(entries)
        result(number, "rejects " + label, proc, proc.returncode != 0)

    # Real local Git repositories exercise ref ambiguity and pushurl semantics.
    repo = os.path.join(mk.root, "publish repo")
    remote = os.path.join(mk.root, "remote.git")
    os.makedirs(repo)
    real_git = shutil.which("git")
    def git(*args):
        return subprocess.run([real_git, *args], cwd=repo, capture_output=True,
                              text=True, check=True, timeout=10)
    git("init", "-q")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit",
        "--allow-empty", "-qm", "fixture")
    git("checkout", "-qb", "topic")
    git("tag", "topic")
    git("init", "--bare", "-q", remote)
    git("remote", "add", "origin", remote)
    publisher = os.path.join(repo, "publish.sh")
    shutil.copy(os.path.join(REPO_ROOT, "publish.sh"), publisher)
    def publish(*args, extra=None):
        return subprocess.run(["bash", publisher, *args], cwd=repo,
                              env=mk.env(extra), capture_output=True, text=True, timeout=15)
    proc = publish("--branch", "topic")
    result(17, "branch/tag name collision publishes the branch", proc, proc.returncode == 0)
    if proc.returncode == 0:
        check("nineteen control: destination branch exists",
              bool(git("--git-dir=" + remote, "rev-parse", "refs/heads/topic").stdout.strip()))

    # Block actual network pushes; ask real Git which URL it would use instead.
    import shlex
    write_exec(os.path.join(mk.bindir, "git"), '#!/bin/sh\nif [ "$1" = push ]; then\n'
               '  ' + shlex.quote(real_git) + ' remote get-url --push --all origin\n'
               '  exit 0\nfi\nexec ' + shlex.quote(real_git) + ' "$@"\n')
    git("config", "remote.origin.pushurl", "https://github.com/wrong/destination.git")
    proc = publish("--repo", "study/intended")
    result(18, "explicit destination cannot be overridden by pushurl", proc,
           proc.returncode == 0 and "wrong/destination" not in proc.stdout
           and "https://github.com/study/intended.git" in proc.stdout)
    if "pushurl" in git("config", "--get-regexp", "remote.origin").stdout:
        git("config", "--unset-all", "remote.origin.pushurl")
    proc = publish("--repo", "study/intended.git")
    result(19, "repository suffix is not duplicated", proc,
           proc.returncode == 0 and ".git.git" not in proc.stdout)


def test_build_lifecycle_regressions(mk):
    """Nine build-driver failures, using compiler doubles and real shell tools."""
    root = os.path.join(mk.root, "build lifecycle")
    os.makedirs(os.path.join(root, "scripts", "installer"))
    os.makedirs(os.path.join(root, "native", "zygiskd"))
    for name in ("build_module.sh", "installer/update-binary", "installer/updater-script"):
        shutil.copy(os.path.join(REPO_ROOT, "scripts", name),
                    os.path.join(root, "scripts", name))
    for name in ("customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh",
                 "zs_compat.sh", "post-mount-hook.sh", "verify.sh", "LICENSE"):
        shutil.copy(os.path.join(REPO_ROOT, name), root)
    shutil.copytree(os.path.join(REPO_ROOT, "webroot"), os.path.join(root, "webroot"))
    ndk = os.path.join(root, "ndk")
    toolbin = os.path.join(ndk, "toolchains/llvm/prebuilt/linux-x86_64/bin")
    os.makedirs(toolbin)
    os.makedirs(os.path.join(ndk, "build/cmake"))
    with open(os.path.join(ndk, "build/cmake/android.toolchain.cmake"), "w"):
        pass
    for tool in ("clang", "llvm-strip"):
        write_exec(os.path.join(toolbin, tool), "#!/bin/sh\nexit 0\n")
    write_exec(os.path.join(mk.bindir, "cmake"), r'''#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
if [ "$1" = --build ]; then
  dest=$2
  case "$LAYOUT" in
    config) dest="$dest/Debug" ;;
    nested) dest="$dest/libpayload" ;;
  esac
  mkdir -p "$dest"
  for name in libzygisk.so libpayload.so libzn_loader.so; do
    printf 'fresh\n' > "$dest/$name"
  done
fi
''')
    script = os.path.join(root, "scripts/build_module.sh")
    env = mk.env({"NDK": ndk, "CALLS": os.path.join(root, "calls"), "LAYOUT": "flat"})
    for key in ("CARGO_TARGET_DIR", "OUT_ROOT", "ABIS", "API_LEVEL", "BUILD_TYPE"):
        env.pop(key, None)
    index = 0

    def run(args=(), extra=None):
        nonlocal index
        index += 1
        out = os.path.join(root, "out" + str(index))
        with open(env["CALLS"], "w"):
            pass
        proc = subprocess.run(["bash", script, "--abis", "x86_64", "--out", out,
                               "--skip-rust", "--skip-zip", *args],
                              env={**env, **(extra or {})}, capture_output=True,
                              text=True, timeout=15)
        with open(env["CALLS"]) as fp:
            calls = fp.read()
        return proc, out, calls

    # 01: empty path options must not fall back to discovery or the repository.
    for option in ("--ndk", "--out"):
        proc, _, calls = run((option, ""))
        check("lifecycle 01: reject empty " + option,
              proc.returncode == 2 and not calls, proc.stdout + proc.stderr)

    # 02: CMake silently accepts misspelled types with no optimization flags.
    for value in ("", "Releaze", "../outside"):
        proc, _, calls = run(("--type", value))
        check("lifecycle 02: reject invalid build type " + repr(value),
              proc.returncode == 2 and not calls, proc.stdout + proc.stderr)

    proc, _, calls = run(("--type", "Release"))
    check("lifecycle 03: select configuration when building multi-config generators",
          proc.returncode == 0 and "--config Release" in calls, proc.stdout + proc.stderr)

    proc, _, _ = run(("--type", "Debug"), {"LAYOUT": "config"})
    check("lifecycle 04: collect configuration-specific CMake outputs",
          proc.returncode == 0, proc.stdout + proc.stderr)

    out = os.path.join(root, "stale")
    flat = os.path.join(out, "cpp/x86_64")
    os.makedirs(flat)
    for name in ("libzygisk.so", "libpayload.so", "libzn_loader.so"):
        with open(os.path.join(flat, name), "w") as fp:
            fp.write("stale\n")
    # Classic per-target directories, including a stale flattened copy.
    with open(os.path.join(mk.bindir, "cmake")) as fp:
        cmake = fp.read()
    write_exec(os.path.join(mk.bindir, "cmake"), cmake.replace(
        "printf 'fresh\\n' > \"$dest/$name\"",
        'mkdir -p "$2/${name%.so}"\nprintf \'fresh\\n\' > "$2/${name%.so}/$name"'))
    proc, _, _ = run(("--out", out), {"LAYOUT": "nested"})
    path = os.path.join(out, "module/libs/x86_64/libpayload.so")
    with open(path) as fp:
        contents = fp.read()
    check("lifecycle 05: refreshed nested artifacts replace stale flattened copies",
          proc.returncode == 0 and contents == "fresh\n", proc.stdout + proc.stderr)
    write_exec(os.path.join(mk.bindir, "cmake"), cmake)

    # 06: a present but incomplete preferred toolchain must not mask a usable one.
    alternate = os.path.join(ndk, "toolchains/llvm/prebuilt/linux-aarch64/bin")
    os.makedirs(alternate)
    for tool in ("clang", "llvm-strip"):
        shutil.copy(os.path.join(toolbin, tool), alternate)
    os.unlink(os.path.join(toolbin, "clang"))
    proc, _, _ = run()
    check("lifecycle 06: incomplete preferred prebuilt does not block fallback",
          proc.returncode == 0, proc.stdout + proc.stderr)
    shutil.copy(os.path.join(alternate, "clang"), toolbin)

    # 07/08: a controlled PATH proves missing dependencies cannot be masked by CI.
    tools = os.path.join(root, "tools")
    os.makedirs(tools)
    for name in ("bash", "dirname", "mkdir", "cp", "chmod", "rm", "sed", "git",
                 "cat", "find", "sort", "basename", "getconf", "tr", "uname"):
        source = shutil.which(name)
        if source:
            os.symlink(source, os.path.join(tools, name))
    os.symlink(os.path.join(mk.bindir, "cmake"), os.path.join(tools, "cmake"))
    proc, _, calls = run(extra={"PATH": tools})
    check("lifecycle 07: missing nproc uses a bounded portable job count",
          proc.returncode == 0 and "not found" not in proc.stderr
          and not any(line.endswith(" -j") for line in calls.splitlines()),
          proc.stdout + proc.stderr + calls)
    with open(env["CALLS"], "w"):
        pass
    proc = subprocess.run([shutil.which("bash"), script, "--abis", "x86_64",
                           "--out", os.path.join(root, "missing-cargo"), "--skip-zip"],
                          env={**env, "PATH": tools}, capture_output=True, text=True, timeout=15)
    with open(env["CALLS"]) as fp:
        calls = fp.read()
    check("lifecycle 08: missing Cargo fails before C++ compilation",
          proc.returncode != 0 and not calls, proc.stdout + proc.stderr + calls)

    # 09: a failed rebuild must preserve the last verified archive byte-for-byte.
    with open(script) as fp:
        source = fp.read()
    function = source[source.index("make_zip() {"):source.index("# Self-verification")]
    zipdir = os.path.join(root, "archives")
    os.makedirs(zipdir)
    archive = os.path.join(zipdir, "zygisk_study-vtest-1.zip")
    with open(archive, "wb") as fp:
        fp.write(b"previous verified release")
    proc = subprocess.run(
        ["bash", "-c", 'set -euo pipefail; ' + function +
         '\nverify_zip(){ return 1; }; make_zip'],
        env=mk.env({"ZIP_DIR": zipdir, "MODULE_DIR": mk.moddir,
                    "VERSION_NAME": "vtest", "VERSION_CODE": "1"}),
        capture_output=True, text=True, timeout=15)
    with open(archive, "rb") as fp:
        contents = fp.read()
    check("lifecycle 09: failed verification preserves the published archive",
          proc.returncode != 0 and contents == b"previous verified release",
          proc.stdout + proc.stderr)


def test_publish_preflight_regressions(mk):
    """Three publishing preflight errors; all Git operations stay local."""
    repo = os.path.join(mk.root, "publisher")
    os.makedirs(repo)
    real_git = shutil.which("git")

    def git(*args):
        return subprocess.run([real_git, *args], cwd=repo, check=True,
                              text=True, capture_output=True, timeout=10)

    git("init", "-q")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "--allow-empty", "-qm", "fixture")
    git("remote", "add", "origin", "https://github.com/study/original.git")
    script = os.path.join(repo, "publish.sh")
    shutil.copy(os.path.join(REPO_ROOT, "publish.sh"), script)
    import shlex
    write_exec(os.path.join(mk.bindir, "git"), '#!/bin/sh\n'
               'if [ "$1" = push ]; then echo attempted >> "$PUSH_LOG"; exit 0; fi\n'
               'exec ' + shlex.quote(real_git) + ' "$@"\n')
    log = os.path.join(repo, "push.log")
    for number, label, args in (
            (10, "missing source branch", ("--branch", "missing", "--repo", "study/new")),
            (12, "repository path traversal", ("--repo", "../other"))):
        before = git("config", "--local", "--list").stdout
        proc = subprocess.run(["bash", script, *args], env=mk.env({"PUSH_LOG": log}),
                              capture_output=True, text=True, timeout=10)
        after = git("config", "--local", "--list").stdout
        check(f"lifecycle {number:02d}: {label} rejected before mutation/push",
              proc.returncode != 0 and before == after and not os.path.exists(log),
              proc.stdout + proc.stderr)
        if os.path.exists(log):
            os.unlink(log)
        git("remote", "set-url", "origin", "https://github.com/study/original.git")

    # A repository named original.git has a clone URL ending in .git.git.
    git("remote", "set-url", "origin", "https://github.com/study/original.git.git")
    proc = subprocess.run(["bash", script, "--ssh"], env=mk.env({"PUSH_LOG": log}),
                          capture_output=True, text=True, timeout=10)
    check("lifecycle 11: transport conversion removes exactly one clone suffix",
          proc.returncode == 0 and git("remote", "get-url", "origin").stdout.strip()
          == "git@github.com:study/original.git.git", proc.stdout + proc.stderr)


def test_daemon_harness_regressions(mk):
    """Seven harness failures, using controlled processes/sockets, not Android."""
    import importlib.util
    from unittest.mock import Mock, patch

    spec = importlib.util.spec_from_file_location(
        "verify_daemon", os.path.join(REPO_ROOT, "scripts/verify_daemon.py"))
    daemon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(daemon)
    cargo_dir = os.path.join(mk.root, "cargo outputs")
    host = "x86_64-unknown-linux-gnu"
    os.makedirs(os.path.join(cargo_dir, host, "debug"))
    binary = os.path.join(cargo_dir, host, "debug/zygiskd")
    with open(binary, "w"):
        pass
    completed = subprocess.CompletedProcess([], 0, "host: " + host + "\n", "")
    with patch.dict(os.environ, {"CARGO_TARGET_DIR": cargo_dir}), \
            patch.object(daemon.shutil, "which", return_value="/selected/cargo"), \
            patch.object(daemon.subprocess, "run", return_value=completed):
        try:
            found, _ = daemon.cargo_build()
        except SystemExit:
            found = None
        check("lifecycle 13: daemon verifier honors Cargo target directory", found == binary)

    with patch.object(daemon.shutil, "which", return_value="/selected/cargo"), \
            patch.object(daemon.os.path, "exists", return_value=True), \
            patch.object(daemon.subprocess, "run", return_value=completed) as run:
        before = os.environ.get("PATH", "")
        daemon.cargo_build()
        argv, kwargs = run.call_args
        check("lifecycle 14: selected Cargo is not shadowed by HOME toolchain",
              argv[0][0] == "/selected/cargo" and kwargs["env"]["PATH"] == before)

    sock = Mock()
    sock.connect.side_effect = OSError("connection refused")
    with patch.object(daemon.socket, "socket", return_value=sock):
        try:
            daemon.connect("fixture.sock")
        except OSError:
            pass
    check("lifecycle 15: connection failures close their socket", sock.close.called)

    sock = Mock()
    sock.recv.side_effect = [b"a" * 4096, b"b" * 12, b""]
    with patch.object(daemon, "connect", return_value=sock):
        reply = daemon.ask("fixture.sock", b"L")
    check("lifecycle 16: stream replies are read through EOF",
          reply == b"a" * 4096 + b"b" * 12 and sock.close.called)

    tree = Mock(root=mk.root, workdir=mk.workdir,
                session_file=os.path.join(mk.root, "session"))
    proc = Mock()
    proc.poll.return_value = None
    with patch.object(daemon.subprocess, "Popen", return_value=proc), \
            patch.object(daemon.os.path, "exists", return_value=True), \
            patch.object(daemon, "read_session_path", side_effect=[OSError(), "socket", "socket", "socket"]), \
            patch.object(daemon, "connect", side_effect=[OSError(), OSError(), Mock()]) as connect, \
            patch.object(daemon.time, "sleep"):
        daemon.start_daemon("binary", tree, {})
    check("lifecycle 17: session publication waits for a usable socket",
          connect.call_count == 3)

    proc = Mock()
    proc.poll.return_value = None
    with patch.object(daemon.subprocess, "Popen", return_value=proc), \
            patch.object(daemon.os.path, "exists", return_value=False), \
            patch.object(daemon.time, "time", side_effect=[0, 6]), \
            patch.object(daemon.time, "monotonic", side_effect=[0, 6]):
        try:
            daemon.start_daemon("binary", tree, {})
        except (SystemExit, RuntimeError):
            pass
    check("lifecycle 18: startup timeout reaps the child", proc.wait.called)

    with patch.object(daemon, "cargo_build", return_value=("binary", {})), \
            patch.object(daemon.tempfile, "mkdtemp", return_value=mk.root), \
            patch.object(daemon, "Tree", return_value=tree), \
            patch.object(daemon, "start_daemon", side_effect=RuntimeError("startup failed")), \
            patch.object(daemon.shutil, "rmtree") as cleanup:
        try:
            daemon.main()
        except (RuntimeError, SystemExit):
            pass
    check("lifecycle 19: startup failure still cleans the temporary tree", cleanup.called)


def test_nine_followup_regressions(mk):
    """Nine additional PR #11 bugs; fixtures never contact a remote service."""
    import importlib.util
    import shlex
    from pathlib import Path
    from unittest.mock import patch

    # 1/2: use real Git configuration; intercept only the network-facing push.
    repo = Path(mk.root) / "publish-extra"
    repo.mkdir()
    real_git = shutil.which("git")

    def git(*args):
        return subprocess.run([real_git, *args], cwd=repo, check=True,
                              capture_output=True, text=True, timeout=10)

    git("init", "-q")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "--allow-empty", "-qm", "fixture")
    shutil.copy(os.path.join(REPO_ROOT, "publish.sh"), repo)
    git("remote", "add", "origin", "https://github.com/study/old.git")
    git("config", "--add", "remote.origin.url", "https://github.com/study/other.git")
    log = repo / "push.log"
    write_exec(os.path.join(mk.bindir, "git"), '#!/bin/sh\n'
               'if [ "$1" = push ]; then echo push >> "$PUSH_LOG"; exit 0; fi\n'
               'exec ' + shlex.quote(real_git) + ' "$@"\n')
    env = mk.env({"PUSH_LOG": str(log)})
    proc = subprocess.run(["bash", str(repo / "publish.sh"), "--repo", "study/new"],
                          env=env, capture_output=True, text=True, timeout=10)
    destinations = git("remote", "get-url", "--push", "--all", "origin").stdout.splitlines()
    check("additional 01: explicit publishing destination replaces ALL URLs",
          proc.returncode == 0 and destinations == ["https://github.com/study/new.git"],
          repr(destinations) + proc.stderr)
    log.unlink(missing_ok=True)
    # Isolate the mirror failure from the independent multi-URL failure.
    git("config", "--replace-all", "remote.origin.url", "https://github.com/study/new.git")
    git("config", "remote.origin.mirror", "true")
    before = git("config", "--local", "--list").stdout
    proc = subprocess.run(["bash", str(repo / "publish.sh"), "--repo", "study/repoint"],
                          env=env, capture_output=True, text=True, timeout=10)
    check("additional 02: mirror remote rejected before mutation or push",
          proc.returncode != 0 and not log.exists()
          and before == git("config", "--local", "--list").stdout, proc.stderr)

    # 3: both scripts change cwd before reading their help from argv[0].
    for script in ("publish.sh", "scripts/build_module.sh"):
        proc = subprocess.run(["bash", "../" + script, "--help"],
                              cwd=os.path.join(REPO_ROOT, "tests"),
                              capture_output=True, text=True, timeout=10)
        check("additional 03: relative invocation help: " + script,
              proc.returncode == 0 and "USAGE:" in proc.stdout, proc.stderr)

    # 4: a single-leading-dash output directory is a valid path, not mkdir flags.
    root = Path(mk.root) / "build-extra"
    (root / "scripts/installer").mkdir(parents=True)
    for name in ("build_module.sh", "installer/update-binary", "installer/updater-script"):
        shutil.copy(Path(REPO_ROOT) / "scripts" / name, root / "scripts" / name)
    for name in ("customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh",
                 "zs_compat.sh", "post-mount-hook.sh", "verify.sh", "LICENSE"):
        shutil.copy(Path(REPO_ROOT) / name, root / name)
    shutil.copytree(Path(REPO_ROOT) / "webroot", root / "webroot")
    ndk = root / "ndk"
    toolbin = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    toolbin.mkdir(parents=True)
    (ndk / "build/cmake").mkdir(parents=True)
    (ndk / "build/cmake/android.toolchain.cmake").touch()
    write_exec(toolbin / "clang", "#!/bin/sh\nexit 0\n")
    proc = subprocess.run(["bash", str(root / "scripts/build_module.sh"),
                           "--ndk", str(ndk), "--out", "-output", "--abis", "x86_64",
                           "--skip-cpp", "--skip-rust"], cwd=root, env=mk.env(),
                          capture_output=True, text=True, timeout=10)
    check("additional 04: leading-dash output path is treated as a directory",
          proc.returncode == 0 and (root / "-output/module/module.prop").is_file(),
          proc.stderr)

    # 5/6: Cargo doubles emulate real output layouts, including a cross default.
    spec = importlib.util.spec_from_file_location(
        "verify_daemon", os.path.join(REPO_ROOT, "scripts/verify_daemon.py"))
    daemon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(daemon)
    crate = root / "native/zygiskd"
    crate.mkdir(parents=True)
    write_exec(os.path.join(mk.bindir, "rustc"),
               "#!/bin/sh\nprintf 'rustc fixture\nhost: x86_64-unknown-linux-gnu\n'\n")
    write_exec(os.path.join(mk.bindir, "cargo"), '''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
target = args[args.index('--target') + 1] if '--target' in args else os.getenv('CARGO_BUILD_TARGET', '')
out = args[args.index('--target-dir') + 1] if '--target-dir' in args else os.getenv('CARGO_TARGET_DIR', 'target')
profile = 'release' if '--release' in args else 'debug'
path = pathlib.Path(out) / target / profile / 'zygiskd'
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text('native' if target in ('', 'x86_64-unknown-linux-gnu') else 'cross')
path.chmod(0o755)
''')
    for target_dir in (str(root / "cargo cache"), "relative cache"):
        with patch.dict(os.environ, mk.env({"CARGO_TARGET_DIR": target_dir}), clear=True), \
                patch.dict(sys.modules, {"verify_daemon": daemon}), \
                patch.object(daemon, "DAEMON_DIR", str(crate)), \
                patch.dict(globals(), REPO_ROOT=str(root), REAL_DAEMON=None,
                           REAL_DAEMON_ABSENT_TOOLCHAIN=None):
            found = find_real_daemon()
        expected = os.path.abspath(os.path.join(crate, target_dir))
        check("additional 05: property harness honors Cargo output " + target_dir,
              bool(found) and os.path.commonpath([found, expected]) == expected,
              repr(found))
    stale = crate / "target/debug/zygiskd"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale host binary")
    with patch.dict(os.environ, mk.env({"CARGO_BUILD_TARGET": "aarch64-linux-android",
                                       "CARGO_TARGET_DIR": str(crate / "target")}), clear=True), \
            patch.object(daemon, "DAEMON_DIR", str(crate)):
        try:
            found, _ = daemon.cargo_build()
        except SystemExit:
            found = ""
    check("additional 06: daemon E2E builds the host despite cross-target defaults",
          bool(found) and Path(found).read_text() == "native", repr(found))

    # 7: an empty or deleted property must not resurrect the initial value.
    for operation in (("property", ""), ("--delete", "property")):
        subprocess.run([os.path.join(mk.bindir, "resetprop"), *operation],
                       env=mk.env(), check=True, timeout=10)
        for reader, key in (("resetprop", "property"), ("getprop", "ro.dalvik.vm.native.bridge")):
            proc = subprocess.run([os.path.join(mk.bindir, reader), key], env=mk.env(),
                                  capture_output=True, text=True, timeout=10)
            check("additional 07: fake property reads preserve empty/deleted state "
                  + repr(operation) + " via " + reader,
                  proc.returncode == 0 and not proc.stdout.strip(), repr(proc.stdout))

    # 8/9: lightweight Make fixtures reproduce stale and partially-written builds.
    make_root = Path(mk.root) / "make-extra"
    tests = make_root / "tests"
    tests.mkdir(parents=True)
    shutil.copy(Path(REPO_ROOT) / "tests/Makefile", tests)
    for subtree in ("tests", "native/common", "native/libpayload/src"):
        for source in (Path(REPO_ROOT) / subtree).iterdir():
            if source.suffix in (".h", ".cpp", ".S"):
                dest = make_root / subtree / source.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.touch()
                os.utime(dest, (100, 100))
    binary = tests / "test_hide"
    binary.touch()
    os.utime(binary, (200, 200))
    os.utime(make_root / "native/libpayload/src/hide.h", (300, 300))
    proc = subprocess.run(["make", "-n", "test_hide"], cwd=tests,
                          capture_output=True, text=True, timeout=10)
    check("additional 08: included header changes trigger recompilation",
          proc.returncode == 0 and "-o test_hide" in proc.stdout, proc.stdout + proc.stderr)
    compiler = tests / "failing-cxx"
    write_exec(compiler, '''#!/bin/sh
while [ "$1" != -o ]; do shift; done
shift
printf 'partial executable' > "$1"
exit 1
''')
    args = ["make", "test_obfstr", "CXX=" + str(compiler)]
    first = subprocess.run(args, cwd=tests, capture_output=True, text=True, timeout=10)
    second = subprocess.run(args, cwd=tests, capture_output=True, text=True, timeout=10)
    check("additional 09: failed compilers cannot leave up-to-date partial binaries",
          first.returncode != 0 and second.returncode != 0
          and not (tests / "test_obfstr").exists(), second.stdout + second.stderr)


def test_pr11_completion_regressions(mk):
    """Nine new follow-up bugs, separate from the nine already in PR #11."""
    import importlib.util
    import shlex
    import zipfile
    from pathlib import Path
    from unittest.mock import Mock, patch

    root = Path(mk.root)
    repo = root / "publisher"
    repo.mkdir()
    real_git = shutil.which("git")
    env = mk.env({"GIT_CONFIG_GLOBAL": str(root / "global.gitconfig"),
                  "GIT_CONFIG_NOSYSTEM": "1"})
    # Prevent the user's Git identity or config overrides leaking into fixtures.
    for key in list(env):
        if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            env.pop(key)
    env.pop("GIT_CONFIG_COUNT", None)
    (root / "global.gitconfig").touch()

    def git(*args):
        return subprocess.run([real_git, *args], cwd=repo, env=env,
                              check=True, capture_output=True, text=True, timeout=10)

    git("init", "-q", "-b", "main")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    git("commit", "--allow-empty", "-qm", "fixture")
    shutil.copy(Path(REPO_ROOT) / "publish.sh", repo)
    (repo / "scripts").mkdir()
    shutil.copy(Path(REPO_ROOT) / "scripts/build_module.sh", repo / "scripts")

    # 1: cd prints its destination when CDPATH is used, corrupting $(cd && pwd).
    for script in ("publisher/publish.sh", "publisher/scripts/build_module.sh"):
        proc = subprocess.run(["bash", script, "--help"], cwd=root,
                              env={**env, "CDPATH": str(root)},
                              capture_output=True, text=True, timeout=10)
        check("completion 01: CDPATH cannot corrupt script roots: " + script,
              proc.returncode == 0 and "USAGE:" in proc.stdout, proc.stderr)

    log = root / "push.log"
    write_exec(Path(mk.bindir) / "git", '#!/bin/sh\n'
               'if [ "$1" = push ]; then echo push >> "$PUSH_LOG"; exit 0; fi\n'
               'exec ' + shlex.quote(real_git) + ' "$@"\n')
    env["PUSH_LOG"] = str(log)

    def publish(*args):
        return subprocess.run(["bash", str(repo / "publish.sh"), *args], env=env,
                              capture_output=True, text=True, timeout=10)

    # 2: converting transport must use the fork's push URL, not upstream fetch.
    git("remote", "add", "origin", "https://github.com/upstream/study.git")
    git("config", "remote.origin.pushurl", "https://github.com/fork/study.git")
    proc = publish("--ssh")
    dest = git("remote", "get-url", "--push", "origin").stdout.strip()
    check("completion 02: transport conversion preserves the push repository",
          proc.returncode == 0 and dest == "git@github.com:fork/study.git", dest + proc.stderr)

    # 3: an explicit branch-only push must not publish annotated release tags.
    git("remote", "remove", "origin")
    bare = root / "destination.git"
    git("init", "--bare", "-q", str(bare))
    git("remote", "add", "origin", str(bare))
    git("config", "push.followTags", "true")
    git("tag", "-am", "local release", "v-local")
    (Path(mk.bindir) / "git").unlink()  # Real local push, never a network request.
    proc = publish()
    tags = git("--git-dir=" + str(bare), "tag", "--list").stdout.strip()
    check("completion 03: branch-only publishing does not follow release tags",
          proc.returncode == 0 and not tags, repr(tags) + proc.stderr)
    git("config", "--unset", "push.followTags")

    # 4: inherited push URLs cannot be removed by a local git config --unset.
    write_exec(Path(mk.bindir) / "git", '#!/bin/sh\n'
               'if [ "$1" = push ]; then echo push >> "$PUSH_LOG"; exit 0; fi\n'
               'exec ' + shlex.quote(real_git) + ' "$@"\n')
    log.unlink(missing_ok=True)
    git("config", "--global", "remote.origin.pushurl", "https://github.com/other/study.git")
    before = git("config", "--local", "--list").stdout
    proc = publish("--repo", "requested/study")
    check("completion 04: inherited push overrides fail before mutating local config",
          proc.returncode != 0 and not log.exists()
          and before == git("config", "--local", "--list").stdout, proc.stderr)
    git("config", "--global", "--unset", "remote.origin.pushurl")
    (Path(mk.bindir) / "git").unlink()

    # 5: assembly deletes module/ recursively; Cargo outputs inside it are unsafe.
    ndk = repo / "ndk"
    toolbin = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    toolbin.mkdir(parents=True)
    (ndk / "build/cmake").mkdir(parents=True)
    (ndk / "build/cmake/android.toolchain.cmake").touch()
    write_exec(toolbin / "clang", "#!/bin/sh\nexit 0\n")
    marker = root / "cargo-ran"
    write_exec(Path(mk.bindir) / "cargo", '#!/bin/sh\ntouch "$CARGO_MARKER"\nexit 1\n')
    (repo / "native/zygiskd").mkdir(parents=True)
    unsafe = repo / "output/module/cargo"
    unsafe.mkdir(parents=True)
    sentinel = unsafe / "previous-build"
    sentinel.write_text("keep")
    proc = subprocess.run(["bash", str(repo / "scripts/build_module.sh"),
                           "--ndk", str(ndk), "--out", str(repo / "output"),
                           "--abis", "x86_64", "--skip-cpp"], cwd=repo,
                          env={**env, "CARGO_TARGET_DIR": str(unsafe),
                               "CARGO_MARKER": str(marker)},
                          capture_output=True, text=True, timeout=10)
    check("completion 05: reject Cargo cache inside disposable module staging",
          proc.returncode != 0 and not marker.exists() and sentinel.read_text() == "keep",
          proc.stderr)

    # 6: all archived entries need CRC verification, including scripts/LICENSE.
    verifier = root / "zip-verifier"
    verifier.mkdir()
    write_exec(verifier / "verify.sh", "#!/bin/sh\nexit 0\n")
    source = (Path(REPO_ROOT) / "scripts/build_module.sh").read_text()
    function = source.split("verify_zip() {", 1)[1].split("\n}\n", 1)[0]
    archive = verifier / "fixture.zip"
    required = ("customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh "
                "webroot/index.html webroot/app.js webroot/styles.css webroot/diagnostics.sh post-mount-hook.sh verify.sh LICENSE META-INF/com/google/android/update-binary").split()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as z:
        for name in required:
            z.writestr(name, "fixture content")
        z.writestr("module.prop", "id=zygisk_study\nname=Study\nversion=1\n"
                   "versionCode=1\nauthor=Test\ndescription=Fixture\n")
        z.writestr("META-INF/com/google/android/updater-script", "#MAGISK\n")
    runner = ('set -euo pipefail\nABI_LIST=()\nREPO_ROOT=' + shlex.quote(str(verifier))
              + '\nTOOLCHAIN=' + shlex.quote(str(ndk)) + '\nMODULE_DIR=' + shlex.quote(str(verifier))
              + '\nverify_zip() {' + function + '\n}\nverify_zip "$1" || exit 1\n')
    valid = subprocess.run(["bash", "-c", runner, "verify", str(archive)], env=env,
                           capture_output=True, text=True, timeout=10)
    with zipfile.ZipFile(archive) as z:
        info = z.getinfo("LICENSE")
        offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    content = bytearray(archive.read_bytes())
    content[offset] ^= 1  # Keep the central directory/listing intact; corrupt data only.
    archive.write_bytes(content)
    corrupt = subprocess.run(["bash", "-c", runner, "verify", str(archive)], env=env,
                             capture_output=True, text=True, timeout=10)
    check("completion 06: archive CRC errors in non-ELF files are rejected",
          valid.returncode == 0 and corrupt.returncode != 0, corrupt.stdout + corrupt.stderr)

    # 7: merely mentioning -fsanitize=thread is not proof of a missing toolchain.
    testdir, make_env = make_gate_fixture(mk, "#!/bin/sh\nexit 0\n")
    make_env["FAKE_BUILD_ERROR"] = "error: static assertion failed: -fsanitize=thread regression"
    proc = run_make_gate(testdir, make_env, "race")
    check("completion 07: sanitizer source errors cannot masquerade as toolchain skips",
          proc.returncode != 0 and "SKIP" not in proc.stdout, proc.stdout + proc.stderr)

    spec = importlib.util.spec_from_file_location(
        "completion_daemon", Path(REPO_ROOT) / "scripts/verify_daemon.py")
    daemon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(daemon)
    crate = root / "crate"
    crate.mkdir()
    # 8: CARGO_BUILD_RUSTC is Cargo's supported compiler selector too.
    compiler = root / "selected-rustc"
    write_exec(compiler, "#!/bin/sh\nprintf 'host: selected-host-target\\n'\n")
    write_exec(Path(mk.bindir) / "rustc", "#!/bin/sh\nprintf 'host: wrong-host-target\\n'\n")
    write_exec(Path(mk.bindir) / "cargo", '''#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
target = args[args.index('--target') + 1]
out = pathlib.Path(args[args.index('--target-dir') + 1]) / target / 'debug' / 'zygiskd'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(target)
out.chmod(0o755)
''')
    cargo_env = {**env, "CARGO_BUILD_RUSTC": str(compiler), "CARGO_TARGET_DIR": str(crate / "target")}
    cargo_env.pop("RUSTC", None)
    with patch.dict(os.environ, cargo_env, clear=True), patch.object(daemon, "DAEMON_DIR", str(crate)):
        binary, _ = daemon.cargo_build()
    check("completion 08: host harness honors CARGO_BUILD_RUSTC",
          Path(binary).read_text() == "selected-host-target", binary)

    # 9: a live previous daemon's socket is not evidence that a new child is ready.
    tree = daemon.Tree(str(root / "daemon-tree"))
    Path(tree.session_file).write_text("old-socket")
    child = Mock()
    child.poll.return_value = None
    connection = Mock()
    times = iter((0, 0, 6))  # One probe, then expire the startup deadline.
    with patch.object(daemon.subprocess, "Popen", return_value=child), \
            patch.object(daemon, "connect", return_value=connection), \
            patch.object(daemon.time, "monotonic", side_effect=lambda: next(times)), \
            patch.object(daemon.time, "sleep"), patch.object(daemon, "stop_daemon") as stop:
        try:
            daemon.start_daemon("fixture-daemon", tree, {})
            rejected = False
        except RuntimeError:
            rejected = True
        check("completion 09: stale live session cannot satisfy startup readiness",
              rejected and stop.call_count == 1)


def test_final_nine_regressions(mk):
    """Nine distinct bugs found after the existing completion regressions."""
    import importlib.util
    import shlex
    import warnings
    import zipfile
    from pathlib import Path
    from unittest.mock import Mock, patch

    root = Path(mk.root)
    real_git = shutil.which("git")
    env = mk.env({"GIT_CONFIG_GLOBAL": str(root / "gitconfig"),
                  "GIT_CONFIG_NOSYSTEM": "1"})
    for key in list(env):
        if key.startswith("GIT_CONFIG_") and key not in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"):
            env.pop(key)
    repo = root / "publisher"
    repo.mkdir()

    def git(*args):
        return subprocess.run([real_git, *args], cwd=repo, env=env, check=True,
                              capture_output=True, text=True, timeout=10)

    git("init", "-q", "-b", "main")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "--allow-empty", "-qm", "fixture")
    git("remote", "add", "origin", "https://github.com/local/study.git")
    git("config", "--global", "remote.origin.url", "https://github.com/other/study.git")
    shutil.copy(Path(REPO_ROOT) / "publish.sh", repo)
    log = root / "push.log"
    write_exec(Path(mk.bindir) / "git", '#!/bin/sh\n'
               'if [ "$1" = push ]; then echo push >> "$PUSH_LOG"; exit 0; fi\n'
               'exec ' + shlex.quote(real_git) + ' "$@"\n')
    before = git("config", "--local", "--list").stdout
    proc = subprocess.run(["bash", str(repo / "publish.sh"), "--repo", "requested/study"],
                          env={**env, "PUSH_LOG": str(log)}, capture_output=True, text=True, timeout=10)
    check("final 01: inherited fetch URLs cannot silently add push destinations",
          proc.returncode != 0 and not log.exists()
          and git("config", "--local", "--list").stdout == before, proc.stderr)
    (Path(mk.bindir) / "git").unlink()

    source = (Path(REPO_ROOT) / "scripts/build_module.sh").read_text()
    make_zip = source[source.index("make_zip() {"):source.index("# Self-verification")]
    staging = root / "staging"
    staging.mkdir()
    (staging / "payload").write_text("preserve staging")
    zipdir = root / "archives"
    zipdir.mkdir()
    zip_env = {**env, "MODULE_DIR": str(staging), "ZIP_DIR": str(zipdir),
               "VERSION_NAME": "fixture", "VERSION_CODE": "1"}
    runner = 'set -euo pipefail\n' + make_zip + '\nverify_zip(){ return 0; }; make_zip\n'
    proc = subprocess.run(["bash", "-c", runner], env={**zip_env, "ZIPOPT": "-m"},
                          capture_output=True, text=True, timeout=10)
    check("final 02: inherited ZIPOPT cannot delete the staging tree",
          proc.returncode == 0 and (staging / "payload").is_file(), proc.stdout + proc.stderr)
    # Recreate the tree on the unfixed implementation so this remains independent.
    staging.mkdir(exist_ok=True)
    (staging / "payload").write_text("preserve staging")
    archive = zipdir / "zygisk_study-fixture-1.zip"
    archive.unlink(missing_ok=True)
    archive.mkdir()
    proc = subprocess.run(["bash", "-c", runner], env=zip_env,
                          capture_output=True, text=True, timeout=10)
    check("final 03: publishing refuses a directory at the release ZIP path",
          proc.returncode != 0 and not list(archive.iterdir()), proc.stdout + proc.stderr)

    # A legitimate checkout named module under --out would otherwise be rm -rf'd.
    output = root / "build-root"
    checkout = output / "module"
    (checkout / "scripts").mkdir(parents=True)
    shutil.copy(Path(REPO_ROOT) / "scripts/build_module.sh", checkout / "scripts")
    sentinel = checkout / "source-sentinel"
    sentinel.write_text("source, not staging")
    ndk = root / "ndk"
    toolbin = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    toolbin.mkdir(parents=True)
    (ndk / "build/cmake").mkdir(parents=True)
    (ndk / "build/cmake/android.toolchain.cmake").touch()
    write_exec(toolbin / "clang", "#!/bin/sh\nexit 0\n")
    proc = subprocess.run(["bash", str(checkout / "scripts/build_module.sh"),
                           "--out", str(output), "--ndk", str(ndk),
                           "--skip-cpp", "--skip-rust"], env=env,
                          capture_output=True, text=True, timeout=10)
    check("final 04: assembly cannot recursively delete its own checkout",
          proc.returncode != 0 and sentinel.is_file(), proc.stderr)

    verifier = root / "verifier"
    verifier.mkdir()
    write_exec(verifier / "verify.sh", "#!/bin/sh\nexit 0\n")
    function = source.split("verify_zip() {", 1)[1].split("\n}\n", 1)[0]
    runner = ('set -euo pipefail\nABI_LIST=()\nREPO_ROOT=' + shlex.quote(str(verifier))
              + '\nTOOLCHAIN=' + shlex.quote(str(ndk)) + '\nMODULE_DIR=' + shlex.quote(str(verifier))
              + '\nverify_zip() {' + function + '\n}\nverify_zip "$1" || exit 1\n')
    fixture = verifier / "fixture.zip"
    required = ("customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh "
                "webroot/index.html webroot/app.js webroot/styles.css webroot/diagnostics.sh post-mount-hook.sh verify.sh LICENSE META-INF/com/google/android/update-binary").split()

    def verify(extra=None):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # Deliberate duplicate ZIP member.
            with zipfile.ZipFile(fixture, "w") as z:
                for name in required:
                    z.writestr(name, "fixture content")
                z.writestr("module.prop", "id=zygisk_study\nname=Study\nversion=1\n"
                           "versionCode=1\nauthor=Test\ndescription=Fixture\n")
                z.writestr("META-INF/com/google/android/updater-script", "#MAGISK\n")
                if extra:
                    z.writestr(extra, "unexpected content")
        return subprocess.run(["bash", "-c", runner, "verify", str(fixture)], env=env,
                              capture_output=True, text=True, timeout=10)

    valid = verify()
    check("final archive control: valid ZIP still verifies", valid.returncode == 0, valid.stderr)
    proc = verify("customize.sh")
    check("final 05: duplicate archive members cannot pass verification",
          proc.returncode != 0, proc.stdout + proc.stderr)
    for name in ("../outside", "/absolute", "libs/../../outside", "./customize.sh"):
        proc = verify(name)
        check("final 06: unsafe or aliased archive paths rejected: " + name,
              proc.returncode != 0, proc.stdout + proc.stderr)

    spec = importlib.util.spec_from_file_location(
        "final_daemon", Path(REPO_ROOT) / "scripts/verify_daemon.py")
    daemon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(daemon)
    sock = Mock()
    sock.recv.side_effect = [b"a", b"b", b""]
    # Time advances while the peer keeps sending, so a per-recv timeout never fires.
    with patch.object(daemon, "connect", return_value=sock), \
            patch.object(daemon.time, "monotonic", side_effect=[0, 0, 1, 6, 7, 8]):
        try:
            daemon.ask("fixture.sock", b"L")
            expired = False
        except TimeoutError:
            expired = True
    check("final 07: trickling replies cannot extend the total response deadline",
          expired and sock.close.called)
    sock = Mock()
    sock.recv.side_effect = [b"a" * 4096] * 4 + [b""]
    with patch.object(daemon, "connect", return_value=sock), \
            patch.object(daemon, "MAX_RESPONSE_BYTES", 8192, create=True):
        try:
            daemon.ask("fixture.sock", b"L")
            bounded = False
        except ValueError:
            bounded = True
    check("final 08: oversized replies are bounded and close their socket",
          bounded and sock.close.called)

    testdir = root / "missing-python"
    testdir.mkdir()
    shutil.copy(Path(REPO_ROOT) / "tests/Makefile", testdir)
    tools = testdir / "tools"
    tools.mkdir()
    make_env = {**env, "PATH": str(tools)}
    for key in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"):
        make_env.pop(key, None)
    for target in ("verify-scripts", "verify-trampolines", "verify-daemon"):
        proc = subprocess.run([shutil.which("make"), target], cwd=testdir, env=make_env,
                              capture_output=True, text=True, timeout=10)
        check("final 09: missing Python cannot report a successful gate: " + target,
              proc.returncode != 0 and "python3" in proc.stdout, proc.stdout + proc.stderr)


def test_assertion_and_build_regressions(mk):
    """Assertion/build regressions, including PR #12's three additional fixes."""
    import json
    import shlex
    import struct
    import zipfile
    from pathlib import Path

    root = Path(mk.root)
    compiler = shlex.split(os.environ.get("CXX", "c++"))

    def cpp(label, body):
        source = root / "assertion.cpp"
        binary = root / "assertion"
        source.write_text('#include "test_framework.h"\n' + body)
        proc = subprocess.run([*compiler, "-std=c++17", "-Wall", "-Wextra",
                               "-I" + str(Path(REPO_ROOT) / "tests"), str(source),
                               "-o", str(binary)], capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            proc = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        check(label, proc.returncode == 0, proc.stdout + proc.stderr)

    cpp("audit 01: equality supports strings and pointers", r'''
int main() {
    std::string a = "same", b = "same";
    ZS_CHECK_EQ(a, b);
    int value = 1;
    ZS_CHECK_EQ(&value, &value);
    try { ZS_CHECK_EQ(a, std::string("different")); }
    catch (const zstest::CheckFailed& e) {
        return e.msg.find("same") != std::string::npos ? 0 : 1;
    }
    return 2;
}
''')
    cpp("audit 02: comparison does not copy noncopyable operands", r'''
struct Value {
    int n;
    explicit Value(int value) : n(value) {}
    Value(const Value&) = delete;
    bool operator!=(const Value& other) const { return n != other.n; }
};
int main() { Value a(1), b(2); ZS_CHECK_NE(a, b); }
''')
    cpp("audit 03: assertion macros do not capture caller variable names", r'''
int main() {
    int _a = 1, _b = 2;
    ZS_CHECK_NE(_a, _b);
    ZS_CHECK_EQ(_a, 1);
    std::string _h = "hello", _n = "ell";
    ZS_CHECK_STR_CONTAINS(_h, _n);
    ZS_CHECK_STR_ABSENT(_h, "absent");
    ZS_CHECK_STR_EQ(_h, "hello");
    int calls = 0;
    ZS_CHECK_EQ(++calls, 1);
    return calls != 1;
}
''')
    cpp("audit 04: null strings report assertion failures without undefined behavior", r'''
int main() {
    const char* missing = nullptr;
    int failures = 0;
    auto expect = [&](auto fn) {
        try { fn(); }
        catch (const zstest::CheckFailed& e) {
            if (e.msg.find("assertion.cpp:") != std::string::npos) ++failures;
        }
        catch (...) {}
    };
    expect([&] { ZS_CHECK_STR_EQ(missing, ""); });
    expect([&] { ZS_CHECK_STR_EQ("", missing); });
    expect([&] { ZS_CHECK_STR_CONTAINS(missing, ""); });
    expect([&] { ZS_CHECK_STR_CONTAINS("", missing); });
    expect([&] { ZS_CHECK_STR_ABSENT(missing, ""); });
    expect([&] { ZS_CHECK_STR_ABSENT("", missing); });
    return failures == 6 ? 0 : 1;
}
''')

    cpp("audit 10: pointer diagnostics never read character buffers", r'''
#include <sys/mman.h>
#include <unistd.h>
int main() {
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 2;
    void* mapping = mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 3;
    char* buffer = static_cast<char*>(mapping);
    if (mprotect(buffer + page, page, PROT_NONE) != 0) {
        munmap(mapping, 2 * page);
        return 4;
    }
    buffer[page - 1] = 'x'; // A valid single character, not a C string.
    int failures = 0;
    auto expect = [&](auto pointer) {
        decltype(pointer) missing = nullptr;
        for (bool reverse : {false, true}) {
            try {
                if (reverse) { ZS_CHECK_EQ(missing, pointer); }
                else { ZS_CHECK_EQ(pointer, missing); }
            } catch (const zstest::CheckFailed& e) {
                if (e.msg.find("assertion.cpp:") != std::string::npos &&
                    e.msg.find(" != ") != std::string::npos) ++failures;
            }
        }
    };
    expect(buffer + page);
    expect(static_cast<const char*>(buffer + page));
    expect(reinterpret_cast<signed char*>(buffer + page));
    expect(reinterpret_cast<unsigned char*>(buffer + page));
    expect(static_cast<volatile char*>(buffer + page));
    expect(buffer + page - 1);
    munmap(mapping, 2 * page);
    return failures == 12 ? 0 : 1;
}
''')

    checkout = root / "checkout"
    (checkout / "scripts/installer").mkdir(parents=True)
    (checkout / "native/zygiskd").mkdir(parents=True)
    for name in ("build_module.sh", "installer/update-binary", "installer/updater-script"):
        shutil.copy(Path(REPO_ROOT) / "scripts" / name, checkout / "scripts" / name)
    for name in ("customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh",
                 "zs_compat.sh", "post-mount-hook.sh", "verify.sh", "LICENSE"):
        shutil.copy(Path(REPO_ROOT) / name, checkout / name)
    shutil.copytree(Path(REPO_ROOT) / "webroot", checkout / "webroot")
    ndk = root / "ndk"
    (ndk / "build/cmake").mkdir(parents=True)
    (ndk / "build/cmake/android.toolchain.cmake").touch()
    for tag in ("linux-x86_64", "darwin-x86_64"):
        tools = ndk / "toolchains/llvm/prebuilt" / tag / "bin"
        tools.mkdir(parents=True)
        for tool in ("clang", "llvm-strip"):
            write_exec(tools / tool, "#!/bin/sh\nexit 0\n")
    log = root / "cargo.json"
    write_exec(Path(mk.bindir) / "cargo", '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
target = args[args.index('--target') + 1]
profile = 'release' if '--release' in args else 'debug'
out = pathlib.Path(args[args.index('--target-dir') + 1]) / target / profile / 'zygiskd'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(profile)
key = 'CARGO_TARGET_' + target.upper().replace('-', '_') + '_LINKER'
pathlib.Path(os.environ['AUDIT_CARGO_LOG']).write_text(json.dumps([os.environ[key], profile]))
''')
    uname = shutil.which("uname")
    write_exec(Path(mk.bindir) / "uname", '#!/bin/sh\n'
               'if [ "$1" = -s ]; then echo "$AUDIT_HOST"; else exec '
               + shlex.quote(uname) + ' "$@"; fi\n')
    env = mk.env({"AUDIT_CARGO_LOG": str(log), "NDK": str(ndk),
                  "CARGO_TARGET_DIR": str(root / "cargo-target")})
    for number, host, build_type, expected_profile in (
            (5, "Darwin", "Release", "release"),
            (6, "Linux", "Debug", "debug")):
        out = root / ("out-" + str(number))
        proc = subprocess.run(["bash", str(checkout / "scripts/build_module.sh"),
                               "--abis", "x86_64", "--skip-cpp", "--out", str(out),
                               "--type", build_type], env={**env, "AUDIT_HOST": host},
                              capture_output=True, text=True, timeout=30)
        selected = json.loads(log.read_text()) if log.exists() else []
        expected_tag = "darwin-x86_64" if host == "Darwin" else "linux-x86_64"
        check(f"audit {number:02d}: host toolchain / Rust profile {host}/{build_type}",
              proc.returncode == 0 and len(selected) == 2
              and expected_tag in selected[0] and selected[1] == expected_profile
              and (out / "module/libs/x86_64/zygiskd").read_text() == expected_profile,
              repr(selected) + proc.stdout + proc.stderr)
        log.unlink(missing_ok=True)
    (Path(mk.bindir) / "uname").unlink()

    # Inspect the real archive verifier with deterministic ELF program headers.
    # A valid staging copy must not mask different bytes inside the ZIP.
    tools = ndk / "bin"
    tools.mkdir()
    write_exec(tools / "llvm-readelf", '''#!/usr/bin/env python3
import pathlib, sys
if sys.argv[1] == '-lW':
    alignment = '0x1000' if pathlib.Path(sys.argv[-1]).read_bytes().endswith(b'bad-alignment') else '0x4000'
    print('LOAD 0x000000 0x000000 0x000000 0x001000 0x001000 R E ' + alignment)
''')
    write_exec(tools / "llvm-strings", "#!/bin/sh\nexit 0\n")
    data = release_elf_fixture()
    names = ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")
    staging = root / "staging"
    (staging / "libs/x86_64").mkdir(parents=True)
    for name in names:
        (staging / "libs/x86_64" / name).write_bytes(data)
    source = (Path(REPO_ROOT) / "scripts/build_module.sh").read_text()
    function = source.split("verify_zip() {", 1)[1].split("\n}\n", 1)[0]
    runner = ('set -euo pipefail\nABI_LIST=(x86_64)\nverify_zip() {' + function
              + '\n}\nverify_zip "$1" || exit 1\n')
    env = mk.env({"REPO_ROOT": REPO_ROOT, "MODULE_DIR": str(staging), "TOOLCHAIN": str(ndk)})
    fixture = root / "fixture.zip"

    def archive(extra=None, marker="#MAGISK\n", corrupt=False, symlink=None):
        def member(name):
            if name != symlink:
                return name
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            return info

        with zipfile.ZipFile(fixture, "w") as z:
            for name in ("customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh "
                         "webroot/index.html webroot/app.js webroot/styles.css webroot/diagnostics.sh post-mount-hook.sh verify.sh LICENSE "
                         "META-INF/com/google/android/update-binary").split():
                z.writestr(member(name), "fixture")
            z.writestr("module.prop", "id=zygisk_study\nname=Study\nversion=1\n"
                       "versionCode=1\nauthor=Test\ndescription=Fixture\n")
            z.writestr("META-INF/com/google/android/updater-script", marker)
            for name in names:
                z.writestr(member("libs/x86_64/" + name),
                           data + (b"bad-alignment" if corrupt and name == "libpayload.so" else b""))
            if extra:
                z.writestr(member(extra), "unexpected ABI")
        return subprocess.run(["bash", "-c", runner, "verify", str(fixture)], env=env,
                              capture_output=True, text=True, timeout=30)

    proc = archive()
    check("audit archive control: valid package is accepted", proc.returncode == 0,
          proc.stdout + proc.stderr)
    for extra in ("libs/riscv64/zygiskd", "libs/x86/zygiskd"):
        proc = archive(extra=extra)
        check("audit 07: unrequested/unverified ABI rejected: " + extra,
              proc.returncode != 0, proc.stdout + proc.stderr)
    for marker in ("#MAG\nISK\n", "#MA\rGISK\n"):
        proc = archive(marker=marker)
        check("audit 08: split recovery marker is not silently concatenated",
              proc.returncode != 0, proc.stdout + proc.stderr)
    proc = archive(corrupt=True)
    check("audit 09: archived ELF alignment is checked, not the staging copy",
          proc.returncode != 0, proc.stdout + proc.stderr)
    for symlink in ("customize.sh", "META-INF/com/google/android/update-binary",
                    "libs/x86_64/libpayload.so", "optional-link"):
        proc = archive(symlink=symlink,
                       extra=symlink if symlink == "optional-link" else None)
        check("audit 12: symlink archive member rejected: " + symlink,
              proc.returncode != 0 and "symlink archive member" in proc.stderr,
              proc.stdout + proc.stderr)
    # NDK discovery regressions (audit 11) live in test_build_ndk_discovery.
    proc = archive()
    check("audit archive control: regular members remain valid after link rejection",
          proc.returncode == 0, proc.stdout + proc.stderr)


def release_elf_fixture(cls=2, machine=62):
    """Small structural ELF control, not executable code or a loadability claim.

    Older archive tests mocked inspection tools and used only an ELF header.
    Give those controls real LOAD/dynamic tables so they still reach the
    particular tool/ZIP failure they are meant to test.
    """
    import struct
    data = bytearray(512)
    data[:7] = b"\x7fELF" + bytes((cls, 1, 1))
    struct.pack_into("<HHI", data, 16, 3, machine, 1)
    wide = cls == 2
    ehsize, phsize, word = (64, 56, 8) if wide else (52, 32, 4)
    struct.pack_into("<Q" if wide else "<I", data, 32 if wide else 28, ehsize)
    struct.pack_into("<HHH", data, 52 if wide else 40, ehsize, phsize, 2)
    if wide:
        struct.pack_into("<IIQQQQQQ", data, ehsize, 1, 5, 0, 0, 0, len(data), len(data), 0x4000)
        struct.pack_into("<IIQQQQQQ", data, ehsize + phsize, 2, 4, 256, 256, 256, 96, 96, 8)
    else:
        struct.pack_into("<IIIIIIII", data, ehsize, 1, 0, 0, 0, len(data), len(data), 5, 0x4000)
        struct.pack_into("<IIIIIIII", data, ehsize + phsize, 2, 256, 256, 256, 48, 48, 4, 4)
    for i, (tag, value) in enumerate(((5, 480), (10, 1), (6, 384),
                                     (11, 24 if wide else 16), (4, 416), (0, 0))):
        struct.pack_into("<QQ" if wide else "<II", data, 256 + i * word * 2, tag, value)
    struct.pack_into("<IIII", data, 416, 1, 1, 0, 0)  # one empty SysV bucket
    return data


def test_release_and_recovery_nineteen(mk):
    """Nineteen release/installer/publisher failures, using only local fixtures."""
    import shlex
    import struct
    import zipfile
    from pathlib import Path

    root = Path(mk.root)
    source = (Path(REPO_ROOT) / "scripts/build_module.sh").read_text()
    function = source.split("verify_zip() {", 1)[1].split("\n}\n", 1)[0]
    toolchain = root / "toolchain"
    tools = toolchain / "bin"
    tools.mkdir(parents=True)
    readelf = tools / "llvm-readelf"
    strings = tools / "llvm-strings"
    write_exec(readelf, '''#!/bin/sh
case "$1" in
  -lW) printf 'LOAD 0x0 0x0 0x0 0x40 0x40 R E %s\\n' "${AUDIT_ALIGN:-0x4000}" ;;
  -SW) [ "${AUDIT_ERROR:-}" != sections ] || exit 1 ;;
  -d) [ "${AUDIT_ERROR:-}" != dynamic ] || exit 1 ;;
esac
exit 0
''')
    write_exec(strings, '#!/bin/sh\n[ "${AUDIT_ERROR:-}" != strings ]\n')
    data = release_elf_fixture()
    names = ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")
    scripts = ("customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh "
               "webroot/index.html webroot/app.js webroot/styles.css webroot/diagnostics.sh post-mount-hook.sh verify.sh LICENSE "
               "META-INF/com/google/android/update-binary").split()
    prop = b"id=zygisk_study\nname=Study\nversion=1\nversionCode=1\nauthor=Test\ndescription=Fixture\n"
    archive = root / "fixture.zip"
    runner = ('set -euo pipefail\nABI_LIST=(x86_64)\n'
              # A missing fallback is simulated without hiding awk/unzip/sh.
              'command(){ if [ "$1" = -v ] && [ "$2" = "${AUDIT_MISSING:-}" ]; '
              'then return 1; fi; builtin command "$@"; }\n'
              'verify_zip() {' + function + '\n}\nverify_zip "$1" || exit 1\n')
    env = mk.env({"REPO_ROOT": REPO_ROOT, "TOOLCHAIN": str(toolchain),
                  "MODULE_DIR": str(root)})

    def verify(extra=None, props=prop, empty=None, error="", align="0x4000", missing=""):
        with zipfile.ZipFile(archive, "w") as z:
            for name in scripts:
                z.writestr(name, b"" if name == empty else b"fixture\n")
            z.writestr("module.prop", props)
            z.writestr("META-INF/com/google/android/updater-script", "#MAGISK\n")
            for name in names:
                z.writestr("libs/x86_64/" + name, data)
            if extra is not None:
                z.writestr(extra, "extra")
        disabled = tools / ("llvm-" + missing)
        if missing:
            disabled.rename(str(disabled) + ".disabled")
        try:
            return subprocess.run(["bash", "-c", runner, "audit", str(archive)],
                                  env={**env, "AUDIT_ERROR": error, "AUDIT_ALIGN": align,
                                       "AUDIT_MISSING": missing},
                                  capture_output=True, text=True, timeout=15)
        finally:
            if missing:
                Path(str(disabled) + ".disabled").rename(disabled)

    def reject(number, label, proc, condition=True):
        check(f"release19 {number:02d}: {label}", proc.returncode != 0 and condition,
              proc.stdout + proc.stderr)

    proc = verify()
    check("release19 archive control: valid input", proc.returncode == 0, proc.stderr)
    reject(1, "missing readelf cannot verify a release", verify(missing="readelf"))
    reject(2, "section inspection failures propagate", verify(error="sections"))
    reject(3, "dynamic inspection failures propagate", verify(error="dynamic"))
    reject(4, "missing strings cannot verify a release", verify(missing="strings"))
    reject(5, "string inspection failures propagate", verify(error="strings"))
    reject(6, "LOAD alignment must be a power of two", verify(align="0x6000"))
    reject(7, "LOAD alignment cannot wrap shell arithmetic", verify(align="0x10000000000004000"))
    reject(8, "a regular file cannot also be an archive parent", verify(extra="LICENSE/child"))
    info = zipfile.ZipInfo("optional-fifo")
    info.create_system = 3
    info.external_attr = (stat.S_IFIFO | 0o600) << 16
    reject(9, "special archive members are refused", verify(extra=info))
    reject(10, "control characters cannot alias archive names", verify(extra="optional\tname"))
    reject(11, "empty required boot scripts are refused", verify(empty="service.sh"))
    reject(12, "versionCode must fit Android's signed int", verify(props=prop.replace(
        b"versionCode=1", b"versionCode=2147483648")))
    reject(13, "NUL bytes cannot disappear from module metadata", verify(props=prop.replace(
        b"id=zygisk_study", b"id=zygisk_\x00study")))
    # Boundaries and canonical directory entries remain accepted.
    for value in (b"0", b"2147483647"):
        proc = verify(props=prop.replace(b"versionCode=1", b"versionCode=" + value), extra="extras/")
        check("release19 archive control: version boundary " + value.decode(),
              proc.returncode == 0, proc.stdout + proc.stderr)

    # Recovery uses a private util file and a no-op mount; no device paths run.
    util = root / "util_functions.sh"
    installer = root / "update-binary"
    original = (Path(REPO_ROOT) / "scripts/installer/update-binary").read_text()
    installer.write_text(original.replace("/data/adb/magisk/util_functions.sh", shlex.quote(str(util))))
    mount_log = root / "mount.log"
    write_exec(Path(mk.bindir) / "mount", '#!/bin/sh\nprintf mount >> "$AUDIT_MOUNT_LOG"\n')
    marker = root / "installed"
    zipfile_path = root / "module.zip"
    zipfile_path.write_bytes(b"fixture")
    elsewhere = root / "elsewhere"
    elsewhere.mkdir()
    recovery_env = mk.env({"AUDIT_MOUNT_LOG": str(mount_log), "AUDIT_MARKER": str(marker),
                           "AUDIT_ELSEWHERE": str(elsewhere)})
    recovery_env.pop("ZIPFILE", None)
    recovery_env.pop("OUTFD", None)

    def recover(body, args=None):
        marker.unlink(missing_ok=True)
        mount_log.unlink(missing_ok=True)
        util.write_text("MAGISK_VER_CODE=20400\n" + body)
        return subprocess.run(["sh", str(installer), *(args if args is not None else
                              ["3", "1", str(zipfile_path)])], cwd=root, env=recovery_env,
                              capture_output=True, text=True, timeout=10)

    body = 'install_module(){ touch "$AUDIT_MARKER"; }\n'
    proc = recover(body + 'false\n')
    reject(14, "failed Magisk utility loading stops installation", proc, not marker.exists())
    proc = recover('install_module(){ sh -c \'[ -n "$ZIPFILE" ] && [ "$OUTFD" = 1 ]\'; }\n')
    check("release19 15: recovery exports ZIPFILE and OUTFD", proc.returncode == 0, proc.stderr)
    proc = recover(body, ["3"])
    reject(16, "missing recovery arguments fail before mount/install", proc,
           not marker.exists() and not mount_log.exists())
    proc = recover('cd "$AUDIT_ELSEWHERE"\ninstall_module(){ [ -f "$ZIPFILE" ]; }\n',
                   ["3", "1", "module.zip"])
    check("release19 17: relative ZIP path survives utility directory changes",
          proc.returncode == 0, proc.stdout + proc.stderr)
    proc = recover(body, ["3", "1", str(root / "missing.zip")])
    reject(18, "missing ZIP fails before installation", proc, not marker.exists())
    proc = recover(body)
    check("release19 recovery control: valid invocation installs", proc.returncode == 0
          and marker.exists(), proc.stdout + proc.stderr)

    # No network pushes: the conflicting Git context points at a local fixture.
    git = shutil.which("git")
    repo = root / "publisher"
    foreign = root / "foreign"
    repo.mkdir()
    foreign.mkdir()
    git_env = mk.env({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    for key in list(git_env):
        if key.startswith("GIT_") and key not in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"):
            git_env.pop(key)
    for path in (repo, foreign):
        subprocess.run([git, "init", "-q", "-b", "main", str(path)], env=git_env, check=True)
        subprocess.run([git, "-C", str(path), "-c", "user.name=Test", "-c",
                        "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "fixture"],
                       env=git_env, check=True)
        subprocess.run([git, "-C", str(path), "remote", "add", "origin", "https://github.com/test/study.git"],
                       env=git_env, check=True)
    publisher = repo / "publish.sh"
    shutil.copy(Path(REPO_ROOT) / "publish.sh", publisher)
    push_log = root / "push.log"
    write_exec(Path(mk.bindir) / "git", '#!/bin/sh\n'
               'if [ "$1" = push ]; then echo push >> "$AUDIT_PUSH_LOG"; exit 0; fi\n'
               'exec ' + shlex.quote(git) + ' "$@"\n')
    proc = subprocess.run(["bash", str(publisher)],
                          env={**git_env, "GIT_DIR": str(foreign / ".git"),
                               "GIT_WORK_TREE": str(foreign), "AUDIT_PUSH_LOG": str(push_log)},
                          capture_output=True, text=True, timeout=10)
    reject(19, "foreign Git environment cannot publish a different checkout", proc,
           not push_log.exists())


def test_pr13_additional_forty_four(mk):
    """44 separately corrupted release fixtures; real readelf, strings and unzip.

    Never execute an archived script or ELF. The healthy control is compiled on
    the host; mutations retain CRC-correct ZIPs to reach the release checks.
    """
    import struct
    import zipfile
    from pathlib import Path

    root = Path(mk.root)
    seed = root / "seed.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-s", "-Wl,-z,max-page-size=16384",
                    "-x", "c", "-", "-o", str(seed)],
                   input='#include <stdio.h>\nint fixture(void){return puts("fixture");}\n',
                   text=True, capture_output=True, check=True, timeout=30)
    original = seed.read_bytes()
    assert original[4:6] == b"\x02\x01", "these mutation offsets require ELF64 LE"
    phoff = struct.unpack_from("<Q", original, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", original, 54)
    ph = [phoff + i * phsize for i in range(phnum)]
    loads = [p for p in ph if struct.unpack_from("<I", original, p)[0] == 1]
    dynamic = next(p for p in ph if struct.unpack_from("<I", original, p)[0] == 2)
    stack = next(p for p in ph if struct.unpack_from("<I", original, p)[0] == 0x6474e551)
    dynoff, dynsize = (struct.unpack_from("<Q", original, dynamic + n)[0] for n in (8, 32))
    tags = {}
    for p in range(dynoff, dynoff + dynsize, 16):
        tag, value = struct.unpack_from("<QQ", original, p)
        if tag == 0:
            break
        tags[tag] = (p, value)
    def file_offset(address):
        for p in loads:
            offset, vaddr, _, filesz = struct.unpack_from("<QQQQ", original, p + 8)
            if vaddr <= address < vaddr + filesz:
                return offset + address - vaddr
        raise AssertionError("fixture address is not file-backed")

    source = (Path(REPO_ROOT) / "scripts/build_module.sh").read_text()
    function = source.split("verify_zip() {", 1)[1].split("\n}\n", 1)[0]
    runner = ('set -euo pipefail\nABI_LIST=(x86_64)\nverify_zip() {' + function
              + '\n}\nverify_zip "$1" || exit 1\n')
    archive = root / "release.zip"
    prop = b"id=zygisk_study\nname=Study\nversion=1\nversionCode=1\nauthor=Test\ndescription=Fixture\n"
    shell_names = ("customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh "
                   "webroot/index.html webroot/app.js webroot/styles.css webroot/diagnostics.sh post-mount-hook.sh verify.sh META-INF/com/google/android/update-binary").split()
    base = {name: b"#!/system/bin/sh\n:\n" for name in shell_names}
    base.update({"module.prop": prop, "LICENSE": b"fixture license\n",
                 "META-INF/com/google/android/updater-script": b"#MAGISK\n"})
    for name in ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd"):
        base["libs/x86_64/" + name] = original
    def run(elf=None, entries=None, extra=None, compression=zipfile.ZIP_STORED):
        contents = dict(base)
        if elf is not None:
            contents["libs/x86_64/libzn_loader.so"] = elf
        contents.update(entries or {})
        with zipfile.ZipFile(archive, "w", compression=compression) as z:
            for name, data in contents.items():
                z.writestr(name, data)
            if extra is not None:
                z.writestr(*extra)
        return subprocess.run(["bash", "-c", runner, "release44", str(archive)],
                              env=mk.env({"REPO_ROOT": REPO_ROOT, "TOOLCHAIN": str(root),
                                          "MODULE_DIR": str(root)}),
                              capture_output=True, text=True, timeout=20)
    control = run()
    check("PR13 +44 control: real stripped host ELF verifies", control.returncode == 0,
          control.stdout + control.stderr)
    def reject(number, label, **kwargs):
        proc = run(**kwargs)
        check(f"PR13 +44 {number:02d}: {label}", proc.returncode != 0,
              proc.stdout + proc.stderr)
    def patch(*changes):
        data = bytearray(original)
        for offset, fmt, value in changes:
            struct.pack_into("<" + fmt, data, offset, value)
        return data
    def tag_value(tag, value):
        return patch((tags[tag][0] + 8, "Q", value))

    reject(1, "LOAD file range cannot extend past EOF", elf=patch((loads[-1] + 32, "Q", len(original))))
    reject(2, "LOAD file size cannot exceed memory size", elf=patch((loads[-1] + 40, "Q", 1)))
    reject(3, "LOAD virtual address range cannot overflow", elf=patch((loads[-1] + 16, "Q", 2**64 - 1)))
    reject(4, "LOAD file and virtual page offsets must agree", elf=patch((loads[-1] + 16, "Q", 0x8001)))
    reject(5, "LOAD virtual memory ranges cannot overlap", elf=patch((loads[-1] + 16, "Q", 0)))
    data = bytearray(original)
    a, b = loads[:2]
    data[a:a + phsize], data[b:b + phsize] = data[b:b + phsize], data[a:a + phsize]
    reject(6, "LOAD records must be in ascending virtual order", elf=data)
    reject(7, "release ELF must not request an executable stack", elf=patch((stack + 4, "I", 7)))
    reject(8, "release LOAD cannot be simultaneously writable and executable", elf=patch((loads[1] + 4, "I", 7)))
    reject(9, "a shared library must contain a dynamic segment", elf=patch((dynamic, "I", 0)))
    reject(10, "dynamic file range must be within the artifact", elf=patch((dynamic + 32, "Q", len(original))))
    reject(11, "dynamic segment virtual range must be mapped", elf=patch((dynamic + 16, "Q", 0x10000000)))
    reject(12, "dynamic segment size must contain whole entries", elf=patch((dynamic + 32, "Q", dynsize - 1)))
    data = bytearray(original)
    for p in range(dynoff, dynoff + dynsize, 16):
        if struct.unpack_from("<Q", data, p)[0] == 0:
            struct.pack_into("<QQ", data, p, 21, 0)
    reject(13, "dynamic table must terminate with DT_NULL", elf=data)
    reject(14, "singleton dynamic tags cannot conflict", elf=patch((tags[12][0], "Q", 5)))
    reject(15, "DT_STRTAB is required", elf=patch((tags[5][0], "Q", 21)))
    reject(16, "DT_STRSZ is required", elf=patch((tags[10][0], "Q", 21)))
    reject(17, "dynamic string table must be mapped", elf=tag_value(5, 0x10000000))
    reject(18, "dynamic string table must be completely file-backed", elf=tag_value(10, len(original)))
    reject(19, "DT_NEEDED offsets must be inside the string table", elf=tag_value(1, tags[10][1]))
    data = bytearray(original)
    strings_offset = file_offset(tags[5][1])
    start, end = strings_offset + tags[1][1], strings_offset + tags[10][1]
    data[start:end] = b"x" * (end - start)
    reject(20, "DT_NEEDED names must have a NUL terminator", elf=data)
    reject(21, "DT_NEEDED cannot name an empty library", elf=tag_value(1, 0))
    data = bytearray(original)
    data[start] = ord("/")
    reject(22, "DT_NEEDED cannot bake in a filesystem path", elf=data)
    reject(23, "DT_SYMENT must match the ELF symbol width", elf=tag_value(11, 1))
    reject(24, "DT_SYMTAB must point at file-backed memory", elf=tag_value(6, 0x10000000))
    reject(25, "DT_RELAENT must match the ELF relocation width", elf=tag_value(9, 1))
    reject(26, "DT_RELASZ must contain whole relocations", elf=tag_value(8, tags[8][1] - 1))
    reject(27, "dynamic relocations must be fully file-backed", elf=tag_value(7, 0x10000000))
    reject(28, "DT_INIT must point into an executable segment", elf=tag_value(12, 0x10000000))
    reject(29, "initializer array size must contain whole pointers", elf=tag_value(27, 1))
    reject(30, "initializer array must be completely file-backed", elf=tag_value(25, 0x10000000))
    reject(31, "DT_TEXTREL is rejected for Android API 23+", elf=patch((tags[12][0], "Q", 22)))
    reject(32, "DF_TEXTREL cannot bypass text-relocation rejection", elf=patch((tags[12][0], "Q", 30), (tags[12][0] + 8, "Q", 4)))
    marker = "META-INF/com/google/android/updater-script"
    reject(33, "NUL cannot disappear from the Magisk marker", entries={marker: b"#MAG\x00ISK\n"})
    reject(34, "blank lines cannot disappear from the Magisk marker", entries={marker: b"#MAGISK\n\n"})
    reject(35, "shell files cannot contain binary NUL bytes", entries={"service.sh": b"#!/system/bin/sh\n:\x00\n"})
    reject(36, "CRLF scripts cannot ship broken Android shebangs", entries={"service.sh": b"#!/system/bin/sh\r\n:\r\n"})
    reject(37, "installer shell syntax errors fail before publication", entries={"customize.sh": b"if then\n"})
    reject(38, "control bytes cannot corrupt module metadata", entries={"module.prop": prop.replace(b"name=Study", b"name=Study\r")})
    info = zipfile.ZipInfo("extras/")
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    reject(39, "ZIP directory names cannot claim regular-file attributes", extra=(info, b""))
    reject(40, "recovery-incompatible bzip2 ZIP compression is refused", compression=zipfile.ZIP_BZIP2)
    reject(41, "release cannot accidentally ship the disable marker", extra=("disable", b""))
    reject(42, "release cannot accidentally ship the remove marker", extra=("remove", b""))
    reject(43, "release cannot disable its required system mount", extra=("skip_mount", b""))
    reject(44, "per-install loader state cannot be reused in a release", extra=(".loader_names", b"bridge=libold.so\n"))
    control = run(compression=zipfile.ZIP_DEFLATED)
    check("PR13 +44 control: recovery-compatible deflate remains supported",
          control.returncode == 0, control.stdout + control.stderr)
    control = run(entries={marker: b"#MAGISK\r\n", "service.sh": b":"})
    check("PR13 +44 control: CRLF marker and shell without final newline are valid",
          control.returncode == 0, control.stdout + control.stderr)
    # Exercise both parser widths and all CPU metadata, without requiring a
    # cross compiler locally. CI additionally verifies all four real NDK builds.
    parser = source.split("<<'PY_VERIFY_RELEASE'\n", 1)[1].split("\nPY_VERIFY_RELEASE", 1)[0]
    namespace = {}
    exec(parser.split("\ntry:\n    verify_archive", 1)[0], namespace)
    for cls, machine, abi in ((1, 3, "x86"), (1, 40, "armeabi-v7a"),
                              (2, 62, "x86_64"), (2, 183, "arm64-v8a")):
        namespace["verify_elf"](release_elf_fixture(cls, machine))
        check("PR13 +44 control: structural " + abi + " ELF accepted", True)


def test_pr13_symbol_and_segment_regressions(mk):
    """41 new validation defects, each reproduced for four ABIs (164 cases).

    Count validation defects, NOT their ABI repetitions. Fixtures are structural
    data, never executed. Every mutation is checked through the complete ZIP
    gate and must fail for its specific diagnostic, not some unrelated check.
    """
    import struct
    import zipfile
    from pathlib import Path

    root = Path(mk.root)
    source = (Path(REPO_ROOT) / "scripts/build_module.sh").read_text()
    function = source.split("verify_zip() {", 1)[1].split("\n}\n", 1)[0]
    runner = ('set -euo pipefail\nABI_LIST=("$2")\nverify_zip() {' + function
              + '\n}\nverify_zip "$1" || exit 1\n')
    archive = root / "symbols.zip"
    env = mk.env({"REPO_ROOT": REPO_ROOT, "TOOLCHAIN": str(root), "MODULE_DIR": str(root)})
    base = {name: b"#!/system/bin/sh\n:\n" for name in (
        "customize.sh post-fs-data.sh service.sh uninstall.sh zs_compat.sh "
        "webroot/index.html webroot/app.js webroot/styles.css webroot/diagnostics.sh post-mount-hook.sh verify.sh META-INF/com/google/android/update-binary").split()}
    base.update({"LICENSE": b"fixture\n", "module.prop":
                 b"id=zygisk_study\nname=Study\nversion=1\nversionCode=1\nauthor=Test\ndescription=Fixture\n",
                 "META-INF/com/google/android/updater-script": b"#MAGISK\n"})

    def verify(data, abi, control):
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, contents in base.items():
                z.writestr(name, contents)
            for name in ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd"):
                z.writestr("libs/" + abi + "/" + name,
                           data if name == "libzn_loader.so" else control)
        return subprocess.run(["bash", "-c", runner, "symbol-regressions", str(archive), abi],
                              env=env, capture_output=True, text=True, timeout=20)

    for cls, machine, abi in ((1, 3, "x86"), (1, 40, "armeabi-v7a"),
                              (2, 62, "x86_64"), (2, 183, "arm64-v8a")):
        wide = cls == 2
        word, ehsize, phsize, symsize = (8, 64, 56, 24) if wide else (4, 52, 32, 16)
        uint = "Q" if wide else "I"
        original = bytearray(2048)
        original[:7] = b"\x7fELF" + bytes((cls, 1, 1))
        struct.pack_into("<HHI", original, 16, 3, machine, 1)
        struct.pack_into("<" + uint, original, 32 if wide else 28, ehsize)
        struct.pack_into("<HHH", original, 52 if wide else 40, ehsize, phsize, 6)
        interpreter = b"/system/bin/linker" + (b"64" if wide else b"") + b"\0"
        segments = (
            (1, 5, 0, 0, len(original), 4096, 0x4000),
            (2, 4, 512, 512, 8 * word * 2, 8 * word * 2, word),
            (7, 4, 1728, 1728, 4, 8, 4),
            (3, 4, 1664, 1664, len(interpreter), len(interpreter), 1),
            (6, 4, ehsize, ehsize, 6 * phsize, 6 * phsize, word),
            (0x6474e552, 4, 1728, 1728, 16, 16, 1),
        )
        for i, (kind, flags, off, addr, filesz, memsz, align) in enumerate(segments):
            values = ((kind, flags, off, addr, addr, filesz, memsz, align) if wide else
                      (kind, off, addr, addr, filesz, memsz, flags, align))
            struct.pack_into("<IIQQQQQQ" if wide else "<IIIIIIII", original,
                             ehsize + i * phsize, *values)
        tags = {tag: 512 + i * word * 2 for i, tag in enumerate((5, 10, 6, 11, 4, 0x6ffffef5, 21, 0))}
        for tag, value in ((5, 1600), (10, 9), (6, 1280), (11, symsize),
                           (4, 1024), (0x6ffffef5, 1104), (21, 0), (0, 0)):
            struct.pack_into("<" + uint * 2, original, tags[tag], tag, value)
        struct.pack_into("<IIIIII", original, 1024, 1, 3, 1, 0, 2, 0)
        struct.pack_into("<IIII", original, 1104, 1, 1, 1, 5)
        struct.pack_into("<" + uint, original, 1120, (1 << (word * 8)) - 1)
        bucket = 1120 + word
        chain = bucket + 4
        struct.pack_into("<III", original, bucket, 1, 0x1234, 0x5679)
        struct.pack_into("<I", original, 1280 + symsize, 1)
        struct.pack_into("<I", original, 1280 + 2 * symsize, 5)
        original[1600:1609] = b"\0foo\0bar\0"
        original[1664:1664 + len(interpreter)] = interpreter
        # Fields within a program header differ between ELF32 and ELF64.
        fields = ({"offset": 8, "address": 16, "filesz": 32, "memsz": 40, "align": 48} if wide else
                  {"offset": 4, "address": 8, "filesz": 16, "memsz": 20, "align": 28})

        def patch(*changes):
            data = bytearray(original)
            for off, fmt, value in changes:
                struct.pack_into("<" + fmt, data, off, value)
            return data

        def tag_value(tag, value):
            return (tags[tag] + word, uint, value)

        def field(segment, name, value):
            return (ehsize + segment * phsize + fields[name], uint, value)

        def kind(segment, value):
            return (ehsize + segment * phsize, "I", value)

        cases = [
            ("missing symbol hash", "missing symbol hash", patch((tags[4], uint, 21), (tags[0x6ffffef5], uint, 21))),
            ("unmapped SysV hash header", "SysV hash header", patch(tag_value(4, 4096))),
            ("zero SysV buckets", "SysV bucket count", patch((1024, "I", 0))),
            ("zero SysV symbol count", "SysV symbol count", patch((1028, "I", 0))),
            ("truncated SysV hash arrays", "SysV hash arrays", patch((1024, "I", 512))),
            ("SysV bucket index out of bounds", "SysV bucket index", patch((1032, "I", 3))),
            ("SysV chain index out of bounds", "SysV chain index", patch((1040, "I", 3))),
            ("cyclic SysV lookup chain", "SysV hash cycle", patch((1040, "I", 1))),
            ("unmapped GNU hash header", "GNU hash header", patch(tag_value(0x6ffffef5, 4096))),
            ("zero GNU buckets", "GNU bucket count", patch((1104, "I", 0))),
            ("zero GNU bloom words", "GNU bloom size", patch((1112, "I", 0))),
            ("non-power-of-two GNU bloom", "GNU bloom size", patch((1112, "I", 3))),
            ("undefined GNU bloom shift", "GNU bloom shift", patch((1116, "I", 32))),
            ("truncated GNU bloom and buckets", "GNU hash prefix", patch((1112, "I", 1024))),
            ("GNU bucket before symbol offset", "GNU bucket index", patch((1108, "I", 2))),
            ("unmapped GNU lookup chain", "GNU hash chain", patch((bucket, "I", 10000))),
            ("disagreeing SysV and GNU symbol counts", "symbol counts disagree", patch((1028, "I", 4))),
            ("truncated full dynamic symbol table", "dynamic symbol table extent", patch(tag_value(6, len(original) - symsize))),
            ("nonzero reserved null symbol", "reserved null symbol", patch((1280, "I", 1))),
            ("symbol name offset outside string table", "symbol name offset", patch((1280 + symsize, "I", 9))),
            ("missing initial string-table NUL", "string table must start", patch((1600, "B", 120))),
            ("missing final string-table NUL", "string table must end", patch((1608, "B", 120))),
            ("duplicate DT_HASH", "duplicate singleton", patch((tags[21], uint, 4), tag_value(21, 1024))),
            ("duplicate DT_GNU_HASH", "duplicate singleton", patch((tags[21], uint, 0x6ffffef5), tag_value(21, 1104))),
            ("dynamic file size exceeds memory size", "dynamic filesz exceeds memsz", patch(field(1, "memsz", 1))),
            ("TLS file size exceeds memory size", "TLS filesz exceeds memsz", patch(field(2, "memsz", 1))),
            ("TLS initialization extends past EOF", "TLS file range", patch(field(2, "offset", len(original)))),
            ("TLS file and virtual addresses disagree", "TLS file/virtual", patch(field(2, "address", 1732))),
            ("invalid TLS alignment", "TLS alignment", patch(field(2, "align", 3))),
            ("TLS virtual range overflow", "TLS address overflow", patch(field(2, "address", (1 << (word * 8)) - 4))),
            ("duplicate TLS segment", "duplicate TLS", patch(kind(5, 7))),
            ("interpreter bytes extend past EOF", "interpreter file range", patch(field(3, "offset", len(original)))),
            ("unterminated interpreter", "interpreter terminator", patch((1664 + len(interpreter) - 1, "B", 120))),
            ("embedded interpreter NUL", "interpreter embedded NUL", patch((1665, "B", 0))),
            ("relative interpreter path", "interpreter must be absolute", patch((1664, "B", 120))),
            ("duplicate interpreter segment", "duplicate interpreter", patch(kind(5, 3))),
            ("duplicate PHDR segment", "duplicate PHDR", patch(kind(5, 6))),
            ("PHDR does not describe the program table", "PHDR table range", patch(field(4, "filesz", phsize))),
            ("PHDR file and virtual addresses disagree", "PHDR file/virtual", patch(field(4, "address", ehsize + 4))),
            ("RELRO covers unmapped memory", "RELRO memory range", patch(field(5, "address", 8192))),
            ("entry point is not executable file-backed code", "entry point", patch((24, uint, 8192))),
        ]
        assert len(cases) == 41
        control = verify(original, abi, original)
        check("PR13 +41 control: complete " + abi + " archive", control.returncode == 0,
              control.stdout + control.stderr)
        for number, (label, diagnostic, data) in enumerate(cases, 1):
            proc = verify(data, abi, original)
            check(f"PR13 +41 {number:02d} [{abi}]: {label}",
                  proc.returncode != 0 and diagnostic in proc.stderr, proc.stdout + proc.stderr)
        # Single-hash binaries and the GNU table's legitimate empty-bucket form
        # are supported too. No section headers are present in any fixture.
        for label, data in (
                ("SysV only", patch((tags[0x6ffffef5], uint, 21))),
                ("GNU only", patch((tags[4], uint, 21))),
                ("empty GNU bucket", patch((bucket, "I", 0), (1108, "I", 3))),
                ("zero-filled TLS", patch(field(2, "filesz", 0))),
                ("Thumb entry" if machine == 40 else "valid entry", patch((24, uint, 1025 if machine == 40 else 1024)))):
            proc = verify(data, abi, original)
            check("PR13 +41 control: " + abi + " " + label, proc.returncode == 0,
                  proc.stdout + proc.stderr)


def test_android_syscall_abi_matrix(mk):
    """Compile production helpers under synthetic NDK macro sets, never
    executing foreign syscalls. This checks dispatch/arguments, not a device
    struct layout; the Android cross-build supplies the real Bionic headers.
    """
    from pathlib import Path
    root = Path(REPO_ROOT)
    source = (root / "native/libpayload/src/hide_advanced.cpp").read_text()
    helpers = source[source.index("static inline int zs_raw_fstatat("):
                     source.index("static inline int zs_raw_access(")]
    entry = (root / "native/libpayload/src/entry.cpp").read_text()
    uid_macros = entry[entry.index("#ifdef SYS_setresgid32"):
                       entry.index("namespace zygisk_study {")]
    compiler = shutil.which("g++")
    check("Android syscall regression compiler available", compiler is not None)
    if not compiler:
        return
    preamble = r'''
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cassert>
#undef __ANDROID__
#undef __LP64__
#undef SYS_fstatat64
#undef SYS_fstatat
#undef SYS_newfstatat
#undef SYS_stat
#undef SYS_lstat
// Legacy numbers deliberately coexist: selecting either must fail the test.
#define SYS_stat 901
#define SYS_lstat 902
struct Call { long number; int fd; const char* path; struct stat* st; int flags; };
static Call last;
static bool fail_call;
static long capture(long number, int fd, const char* path, struct stat* st, int flags) {
    last = {number, fd, path, st, flags};
    if (fail_call) { errno = EACCES; return -1; }
    return 0;
}
#define syscall capture
'''
    for name, defines, expected in (
        ("android-arm32", "#define __ANDROID__ 1\n#define SYS_fstatat64 327\n", 327),
        ("android-x86", "#define __ANDROID__ 1\n#define SYS_fstatat64 300\n", 300),
        ("android-arm64", "#define __ANDROID__ 1\n#define __LP64__ 1\n#define SYS_newfstatat 79\n", 79),
        ("android-x86_64", "#define __ANDROID__ 1\n#define __LP64__ 1\n#define SYS_newfstatat 262\n", 262),
    ):
        lp32 = name in ("android-arm32", "android-x86")
        ids = ""
        for index, call in enumerate(("setresgid", "setresuid", "setgid", "setuid"), 1):
            ids += f"#undef SYS_{call}\n#undef SYS_{call}32\n#define SYS_{call} {index}\n"
            if lp32:
                ids += f"#define SYS_{call}32 {index + 100}\n"
        assertions = "\n".join(
            f"static_assert(ZS_SYS_{call} == {index + (100 if lp32 else 0)}, \"UID syscall ABI\");"
            for index, call in enumerate(("setresgid", "setresuid", "setgid", "setuid"), 1))
        program = preamble + defines + ids + uid_macros + assertions + helpers + r'''
int main() {
    struct stat st{};
    const char* path = "relative-link";
    assert(zs_raw_stat(path, &st) == 0);
    assert(last.number == EXPECTED && last.fd == AT_FDCWD && last.flags == 0);
    assert(last.path == path && last.st == &st);
    assert(zs_raw_lstat(path, &st) == 0);
    assert(last.number == EXPECTED && last.flags == AT_SYMLINK_NOFOLLOW);
    assert(last.fd == AT_FDCWD && last.path == path && last.st == &st);
    assert(zs_raw_fstatat(17, path, &st, AT_EMPTY_PATH) == 0);
    assert(last.number == EXPECTED && last.fd == 17 && last.flags == AT_EMPTY_PATH);
    fail_call = true;
    errno = 0;
    assert(zs_raw_stat(path, &st) == -1 && errno == EACCES);
}
'''.replace("EXPECTED", str(expected))
        binary = str(Path(mk.root) / name)
        compiled = subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                                   "-x", "c++", "-", "-o", binary], input=program,
                                  capture_output=True, text=True, timeout=60)
        check(f"{name}: production syscall helpers compile", compiled.returncode == 0,
              compiled.stderr)
        if compiled.returncode == 0:
            ran = subprocess.run([binary], capture_output=True, text=True, timeout=10)
            check(f"{name}: stat and UID ABI dispatch + errno", ran.returncode == 0,
                  ran.stderr)
    # The public hook must actually delegate to the tested helper.
    # Skip the forward declarations near the top of the translation unit.
    # The end marker must also be searched AFTER the definition's start.
    start = source.index('extern "C" int zygisk_study_hook_fstatat(',
                         source.index('static inline int zs_raw_fstatat('))
    hook = source[start:source.index('extern "C" int zygisk_study_hook_statx(', start)]
    check("fstatat hook uses ABI-aware fallback", "zs_raw_fstatat(dirfd, path, st, flags)" in hook)
    check("legacy 32-bit raw fstat never receives a public struct stat",
          "#if defined(SYS_fstat) && defined(__LP64__)" in source)


def test_android_access_contracts(mk):
    """Run the actual hook bodies with captured syscalls, including old headers.
    This is deterministic on hosts without faccessat2 or Android's libc.
    """
    from pathlib import Path
    source = (Path(REPO_ROOT) / "native/libpayload/src/hide_advanced.cpp").read_text()
    start = source.index('extern "C" int zygisk_study_hook_faccessat(',
                         source.index('static inline int zs_raw_access('))
    bodies = source[start:source.index('extern "C" int zygisk_study_hook_fstatat(', start)]
    preamble = r'''
#include <cerrno>
#include <cassert>
#include <fcntl.h>
#include <unistd.h>
#define ZS_LIKELY(x) (x)
#define SYS_faccessat 1001
static bool active;
static int hide_advanced_is_active() { return active; }
static int path_is_hidden(const char*) { return 0; }
using Access = int (*)(int, const char*, int, int);
static Access g_real_faccessat, g_real_faccessat2;
static int calls, argc, seen_fd, seen_mode, seen_flags, fail_errno;
static long seen_number;
static const char* seen_path;
static long capture(long n, int fd, const char* p, int mode) {
    ++calls; argc = 3; seen_number = n; seen_fd = fd; seen_path = p; seen_mode = mode;
    if (fail_errno) { errno = fail_errno; return -1; }
    return 0;
}
static long capture(long n, int fd, const char* p, int mode, int flags) {
    long rc = capture(n, fd, p, mode); argc = 4; seen_flags = flags; return rc;
}
static int libc_access(int, const char*, int, int) { return 42; }
#define syscall capture
'''
    program = r'''
int main() {
    const char* path = "relative-link";
    for (bool enabled : {false, true}) {
        active = enabled;
        g_real_faccessat = nullptr; g_real_faccessat2 = nullptr;
        calls = 0; fail_errno = 0;
        assert(zygisk_study_hook_faccessat(17, path, R_OK, 0) == 0);
        assert(calls == 1 && argc == 3 && seen_number == SYS_faccessat);
        assert(seen_fd == 17 && seen_path == path && seen_mode == R_OK);
        for (int flag : {AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH, 0x40000000}) {
            calls = 0; errno = 0;
            assert(zygisk_study_hook_faccessat(17, path, F_OK, flag) == -1);
            assert(errno == EINVAL && calls == 0);
        }
        // A resolved libc wrapper remains authoritative (including on hosts).
        g_real_faccessat = libc_access;
        assert(zygisk_study_hook_faccessat(17, path, R_OK, 0) == 42);
        // But it must NEVER service faccessat2, even for zero flags.
        for (int flag : {0, AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH}) {
            calls = 0; errno = 0;
#ifdef SYS_faccessat2
            assert(zygisk_study_hook_faccessat2(17, path, R_OK, flag) == 0);
            assert(calls == 1 && argc == 4 && seen_number == SYS_faccessat2);
            assert(seen_fd == 17 && seen_path == path && seen_mode == R_OK && seen_flags == flag);
            for (int error : {ENOSYS, EACCES, EINVAL}) {
                fail_errno = error; errno = 0;
                assert(zygisk_study_hook_faccessat2(17, path, R_OK, flag) == -1);
                assert(errno == error);
            }
            fail_errno = 0;
#else
            assert(zygisk_study_hook_faccessat2(17, path, R_OK, flag) == -1);
            assert(errno == ENOSYS && calls == 0);
#endif
        }
        g_real_faccessat2 = libc_access;
        assert(zygisk_study_hook_faccessat2(17, path, R_OK, 0) == 42);
    }
}
'''
    for modern in (False, True):
        binary = str(Path(mk.root) / ("access-modern" if modern else "access-legacy"))
        code = '#include <initializer_list>\n' + preamble
        if modern:
            code += '#define SYS_faccessat2 1002\n'
        proc = subprocess.run(["g++", "-std=c++17", "-x", "c++", "-", "-o", binary],
                              input=code + bodies + program, capture_output=True, text=True, timeout=60)
        check(f"access contract compiles (modern headers={modern})", proc.returncode == 0, proc.stderr)
        if proc.returncode == 0:
            proc = subprocess.run([binary], capture_output=True, text=True, timeout=10)
            check(f"access flags, dispatch and errno (modern headers={modern})",
                  proc.returncode == 0, proc.stderr)


def test_bridge_pin_without_nodelete(mk):
    """Exercise bridge refcounts without glibc's NODELETE masking the defect.
    An unpinned negative control must unload. Neither case loads a payload.
    """
    from pathlib import Path
    root = Path(REPO_ROOT)
    source = (root / "native/libzygisk/src/entry.cpp").read_text()
    consumer = r'''
#include <dlfcn.h>
#include <cassert>
#include <cstdlib>
int main(int argc, char** argv) {
    assert(argc == 3);
    void* h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    assert(h && dlsym(h, "NativeBridgeItf"));
    assert(dlclose(h) == 0);
    void* retained = dlopen(argv[1], RTLD_NOLOAD | RTLD_NOW);
    assert((retained != nullptr) == (atoi(argv[2]) != 0));
    if (retained) assert(dlclose(retained) == 0);
}
'''
    binary = str(Path(mk.root) / "bridge-consumer")
    proc = subprocess.run(["g++", "-x", "c++", "-", "-o", binary, "-ldl"],
                          input=consumer, capture_output=True, text=True, timeout=60)
    check("no-NODELETE bridge consumer compiles", proc.returncode == 0, proc.stderr)
    if proc.returncode != 0:
        return
    for pinned in (True, False):
        library = str(Path(mk.root) / ("bridge-pinned.so" if pinned else "bridge-unpinned.so"))
        code = source if pinned else source.replace('if (!pin_bridge()) {', 'if (false) {', 1)
        proc = subprocess.run(["g++", "-std=c++17", "-fPIC", "-shared", "-fno-gnu-unique",
                               "-I" + str(root / "native/common"), "-x", "c++", "-",
                               "-o", library, "-ldl"], input=code,
                              capture_output=True, text=True, timeout=60)
        check(f"bridge compiles without NODELETE (pin={pinned})", proc.returncode == 0, proc.stderr)
        if proc.returncode == 0:
            env = dict(os.environ)
            env.pop("LD_LIBRARY_PATH", None)
            proc = subprocess.run([binary, library, str(int(pinned))], cwd=mk.root,
                                  env=env, capture_output=True, text=True, timeout=10)
            check(f"bridge lifetime after ART-style dlclose (pin={pinned})",
                  proc.returncode == 0, proc.stderr)


def test_property_read_and_swap_failures(_mk):
    """Exercise real boot scripts with failing tools, never Android properties."""
    for scenario in ("all-readers-fail", "daemon-fallback", "getprop-fallback",
                     "write-fails", "readback-fails", "readback-mismatch",
                     "backup-fails", "marker-fails", "pending-marker-fails"):
        mk = FakeMagisk()
        try:
            os.makedirs(mk.workdir, exist_ok=True)
            # Failed readers may print plausible output before reporting error.
            # No such output can authorize a swap or contaminate the next reader.
            resetprop = FAKE_RESETPROP.replace(
                'if [ "$#" -eq 1 ]; then',
                '''if [ "$#" -eq 1 ]; then
  case "$ZS_READ_SCENARIO" in
    all-readers-fail|daemon-fallback|getprop-fallback)
      printf 'partial-output'; exit 1 ;;
    readback-fails)
      if [ -f "$STATE" ]; then printf 'libzygisk.so'; exit 1; fi ;;
    readback-mismatch)
      if [ -f "$STATE" ]; then printf '0'; exit 0; fi ;;
  esac''', 1).replace(
                'elif [ "$#" -ge 2 ]; then',
                '''elif [ "$#" -ge 2 ]; then
  [ "$ZS_READ_SCENARIO" = write-fails ] && exit 1''', 1)
            write_exec(os.path.join(mk.bindir, "resetprop"), resetprop)
            write_exec(os.path.join(mk.bindir, "getprop"), '''#!/bin/sh
if [ "$ZS_READ_SCENARIO" = getprop-fallback ]; then
  printf 'libhoudini.so'; exit 0
fi
printf 'partial-output'; exit 1
''')
            write_exec(os.path.join(mk.moddir, "zygiskd"), '''#!/bin/sh
if [ "$1 $2" = 'prop get' ] && [ "$ZS_READ_SCENARIO" = daemon-fallback ]; then
  printf 'libndk_translation.so'; exit 0
fi
printf 'partial-output'; exit 1
''')
            if scenario in ("backup-fails", "marker-fails", "pending-marker-fails"):
                # A directory produces deterministic redirection failure even
                # when this suite is run as root (chmod alone would not).
                name = {"backup-fails": ".native_bridge_backup",
                        "marker-fails": ".native_bridge_applied",
                        "pending-marker-fails": ".mount_pending"}[scenario]
                os.mkdir(os.path.join(mk.workdir, name))
            proc = mk.run_script("post-fs-data.sh", {"ZS_READ_SCENARIO": scenario})
            calls = mk.resetprop_calls()
            applied = os.path.join(mk.workdir, ".native_bridge_applied")
            check(f"{scenario}: boot script exits cleanly", proc.returncode == 0,
                  proc.stderr[-300:])
            check(f"{scenario}: guard never armed", not os.path.isfile(applied))
            pending = os.path.join(mk.workdir, ".mount_pending")
            check(f"{scenario}: no successful mount-pending state",
                  os.path.isdir(pending) if scenario == "pending-marker-fails"
                  else not os.path.exists(pending))
            if scenario in ("all-readers-fail", "daemon-fallback", "getprop-fallback",
                            "backup-fails"):
                check(f"{scenario}: no property mutation", calls == [], repr(calls))
            if scenario in ("all-readers-fail", "daemon-fallback", "getprop-fallback"):
                check(f"{scenario}: no bogus stock backup", mk.backup_value() is None)
                # Test the helper result as well as the fail-closed caller.
                result = subprocess.run(
                    ["sh", "-c", '. "$1/zs_compat.sh"; ZS_DAEMON="$1/zygiskd"; '
                     'zs_prop_get ro.dalvik.vm.native.bridge', "sh", mk.moddir],
                    env=mk.env({"ZS_READ_SCENARIO": scenario}),
                    capture_output=True, text=True, timeout=10)
                expected = {"daemon-fallback": "libndk_translation.so\n",
                            "getprop-fallback": "libhoudini.so\n"}.get(scenario, "")
                check(f"{scenario}: reader status and output preserved",
                      result.stdout == expected and
                      ((result.returncode != 0) == (scenario == "all-readers-fail")),
                      repr((result.returncode, result.stdout)))
            if scenario in ("readback-fails", "readback-mismatch", "marker-fails",
                            "pending-marker-fails"):
                check(f"{scenario}: rollback attempted after swap",
                      calls == ["ro.dalvik.vm.native.bridge libzygisk.so",
                                "ro.dalvik.vm.native.bridge 0"], repr(calls))
                with open(mk.prop_state) as fp:
                    check(f"{scenario}: stock value restored", fp.read().strip() == "0")
        finally:
            mk.cleanup()


def test_loader_mount_failures(mk):
    """Real shell functions with redirected paths and fake mount/copy failures.

    No host mounts are performed. Both dash and BusyBox ash execute the same
    production bodies; only the system/mount-table paths are redirected.
    """
    from pathlib import Path
    import shlex

    root = Path(mk.root)
    system = root / "system"
    mounts = root / "mounts"
    compat = (Path(REPO_ROOT) / "zs_compat.sh").read_text()
    compat = compat.replace("/system/lib", str(system / "lib"))
    compat = compat.replace("#/system}", "#" + str(system) + "}")
    compat = compat.replace("/proc/mounts", str(mounts))
    source = root / "compat-remapped.sh"
    source.write_text(compat)
    shells = [["sh"]]
    if shutil.which("busybox"):
        shells.append(["busybox", "ash"])
    else:
        skip("BusyBox loader regression", "busybox not installed")
    body = r'''
set -e
. "$COMPAT"
ZS_BRIDGE_NAME=libtest.so
ZS_PAYLOAD_NAME=libtest-p.so
ZS_IS64=1
ZS_IS32=0
ZS_OVL_ROOT="$WORKDIR/overlay"
mkdir -p "$WORKDIR" "$MODDIR/system/lib64" "$MODDIR/system/lib" \
         "$SYSTEM/lib64" "$SYSTEM/lib"
for dir in lib lib64; do
  printf 'complete bridge bytes' > "$MODDIR/system/$dir/$ZS_BRIDGE_NAME"
  printf 'complete payload bytes' > "$MODDIR/system/$dir/$ZS_PAYLOAD_NAME"
done
: > "$MOUNTS"
: > "$WORKDIR/.mount_pending"
zs_have_overlayfs() { [ "$OVERLAY" = 1 ]; }
mount() {
  printf 'mount\n' >> "$WORKDIR/mount_calls"
  printf 'overlay %s overlay rw,%s 0 0\n' "$6" "$5" >> "$MOUNTS"
}
cp() {
  if [ "$FAIL_COPY" = "${1##*/}" ]; then
    printf truncated > "$2"
    return 1
  fi
  command cp "$@"
}
mv() {
  [ "$FAIL_RENAME" != 1 ] || return 1
  command mv "$@"
}
case "$CASE" in
  visible*)
    command cp "$MODDIR/system/lib64/"* "$SYSTEM/lib64/"
    command cp "$MODDIR/system/lib/"* "$SYSTEM/lib/"
    case "$CASE" in
      visible32) ZS_IS64=0; ZS_IS32=1; rm -f "$SYSTEM/lib64/"* ;;
      visible64) rm -f "$SYSTEM/lib/"* ;;
      visible_dual) ZS_IS32=1 ;;
      visible_missing_bridge) rm "$SYSTEM/lib64/$ZS_BRIDGE_NAME" ;;
      visible_missing_payload) rm "$SYSTEM/lib64/$ZS_PAYLOAD_NAME" ;;
      visible_missing_secondary) ZS_IS32=1; rm "$SYSTEM/lib/$ZS_PAYLOAD_NAME" ;;
    esac
    case "$CASE" in
      visible_missing*) ! zs_loader_visible ;;
      *) zs_loader_visible ;;
    esac ;;
  copy_failure|rename_failure)
    OVERLAY=0
    if [ "$CASE" = copy_failure ]; then FAIL_COPY="$ZS_PAYLOAD_NAME";
    else FAIL_RENAME=1; fi
    ! zs_ensure_loader_mounted
    test -f "$WORKDIR/.mount_pending"
    test ! -e "$SYSTEM/lib64/$ZS_PAYLOAD_NAME"
    test -z "$(find "$SYSTEM" -name '*.so.*' -print)"
    FAIL_COPY=; FAIL_RENAME=0
    zs_ensure_loader_mounted
    test ! -e "$WORKDIR/.mount_pending"
    cmp "$MODDIR/system/lib64/$ZS_PAYLOAD_NAME" "$SYSTEM/lib64/$ZS_PAYLOAD_NAME" ;;
  direct_bridge_missing|direct_payload_missing)
    OVERLAY=0
    if [ "$CASE" = direct_bridge_missing ]; then name="$ZS_PAYLOAD_NAME";
    else name="$ZS_BRIDGE_NAME"; fi
    command cp "$MODDIR/system/lib64/$name" "$SYSTEM/lib64/$name"
    zs_ensure_loader_mounted
    test ! -e "$WORKDIR/.mount_pending"
    cmp "$MODDIR/system/lib64/$ZS_BRIDGE_NAME" "$SYSTEM/lib64/$ZS_BRIDGE_NAME"
    cmp "$MODDIR/system/lib64/$ZS_PAYLOAD_NAME" "$SYSTEM/lib64/$ZS_PAYLOAD_NAME" ;;
  overlay*)
    OVERLAY=1
    if [ "$CASE" = overlay_foreign ]; then
      tag="$ZS_OVL_ROOT$(echo "$SYSTEM/lib64" | tr '/' '_')"
      printf 'overlay %s overlay rw,upperdir=/foreign 0 0\n' "$SYSTEM/lib64" > "$MOUNTS"
      printf 'overlay /unrelated overlay rw,upperdir=%s/upper 0 0\n' "$tag" >> "$MOUNTS"
      ! zs_self_mount_dir "$SYSTEM/lib64"
      test ! -e "$SYSTEM/lib64/$ZS_BRIDGE_NAME"
      test ! -e "$WORKDIR/mount_calls"
    elif [ "$CASE" = overlay_missing_source ]; then
      rm "$MODDIR/system/lib64/$ZS_PAYLOAD_NAME"
      ! zs_self_mount_dir "$SYSTEM/lib64"
      test ! -e "$WORKDIR/mount_calls"
    else
      FAIL_COPY="$ZS_PAYLOAD_NAME"
      ! zs_self_mount_dir "$SYSTEM/lib64"
      test -f "$SYSTEM/lib64/$ZS_BRIDGE_NAME"
      test ! -e "$SYSTEM/lib64/$ZS_PAYLOAD_NAME"
      test -z "$(find "$SYSTEM" -name '*.so.*' -print)"
      FAIL_COPY=
      zs_self_mount_dir "$SYSTEM/lib64"
      test "$(wc -l < "$WORKDIR/mount_calls")" -eq 1
      cmp "$MODDIR/system/lib64/$ZS_PAYLOAD_NAME" "$SYSTEM/lib64/$ZS_PAYLOAD_NAME"
      zs_self_mount_dir "$SYSTEM/lib64"
      test "$(wc -l < "$WORKDIR/mount_calls")" -eq 1
    fi ;;
esac
'''
    cases = ("visible32", "visible64", "visible_dual", "visible_missing_bridge",
             "visible_missing_payload", "visible_missing_secondary", "copy_failure",
             "rename_failure", "direct_bridge_missing", "direct_payload_missing",
             "overlay_retry", "overlay_foreign", "overlay_missing_source")
    for shell in shells:
        for case in cases:
            for directory in (system, Path(mk.workdir), Path(mk.moddir) / "system"):
                shutil.rmtree(directory, ignore_errors=True)
            env = mk.env({"COMPAT": str(source), "SYSTEM": str(system),
                          "MOUNTS": str(mounts), "MODDIR": mk.moddir,
                          "WORKDIR": mk.workdir, "CASE": case,
                          "OVERLAY": "0", "FAIL_COPY": "", "FAIL_RENAME": "0"})
            proc = subprocess.run(shell + ["-c", body], env=env,
                                  capture_output=True, text=True, timeout=20)
            check(f"loader {shlex.join(shell)}: {case}", proc.returncode == 0,
                  proc.stdout + proc.stderr)


def test_customize_install_failures(mk):
    """Installer success requires complete, labeled files and metadata.

    These are shell contract tests, NOT an Android SELinux policy test.
    Deliberately leave errexit off, matching the root-manager installer.
    """
    import shlex
    from pathlib import Path

    for api in range(21, 37):
        proc, mod = run_customize(mk, api=str(api))
        check(f"installer API {api}: complete installation succeeds",
              proc.returncode == 0, proc.stdout + proc.stderr)
        if proc.returncode == 0:
            mod = Path(mod)
            names = dict(line.split("=", 1) for line in
                         (mod / ".loader_names").read_text().splitlines())
            calls = (mod / "permissions.log").read_text().splitlines()
            for target, mode in ((mod / "system", "0755"),
                                 (mod / "system/lib64", "0755"),
                                 (mod / "system/lib64" / names["bridge"], "0644"),
                                 (mod / "system/lib64" / names["payload"], "0644")):
                check(f"installer API {api}: explicit label for {target.name}",
                      f"{target} 0 0 {mode} u:object_r:system_file:s0" in calls)

    failures_to_inject = (
        ("cp", "/arm64-v8a/libzygisk.so", "primary bridge copy"),
        ("cp", "/arm64-v8a/libpayload.so", "primary payload copy"),
        ("cp", "/armeabi-v7a/libzygisk.so", "secondary bridge copy"),
        ("cp", "/armeabi-v7a/libpayload.so", "secondary payload copy"),
        ("chmod", "/arm64-v8a/zygiskd", "daemon executable permission"),
        ("ln", "zygiskd", "daemon launcher"),
        ("perm", "/system/lib64", "primary directory label"),
        ("perm", "-p.so", "payload label"),
        ("perm", "/system/lib/", "secondary library label"),
        ("metadata", ".loader_names", "library name metadata"),
        ("metadata", ".zygisk_study_info", "installation metadata"),
    )
    for tool, match, label in failures_to_inject:
        fixture = FakeMagisk()
        try:
            mod = Path(fixture.root) / "install"
            _populate_modpath(mod, ("arm64-v8a", "armeabi-v7a"))
            env = {}
            if tool == "perm":
                env["ZS_FAIL_PERM"] = match
            elif tool == "metadata":
                (mod / match).mkdir()  # redirection must fail, not report success
            else:
                real = shlex.quote(shutil.which(tool))
                write_exec(Path(fixture.bindir) / tool,
                           '#!/bin/sh\ncase "$*" in\n'
                           + f'  *"{match}"*) exit 1 ;;\nesac\n'
                           + f'exec {real} "$@"\n')
            proc = _run_customize(fixture, mod, env,
                                  abilist="arm64-v8a,armeabi-v7a")
            check(f"installer refuses {label} failure",
                  proc.returncode != 0 and "ABORT:" in proc.stdout
                  and "Zygisk Study installed" not in proc.stdout,
                  proc.stdout + proc.stderr)
        finally:
            fixture.cleanup()


def main():
    cases = [
        ("PR #14: installer labels and fatal write failures", test_customize_install_failures),
        ("PR #14: complete loader pairs and atomic copy failures", test_loader_mount_failures),
        ("PR #14: property read and swap failures", test_property_read_and_swap_failures),
        ("PR #14: Android access contracts", test_android_access_contracts),
        ("PR #14: Lollipop bridge pin without NODELETE", test_bridge_pin_without_nodelete),
        ("PR #14: Android syscall ABI matrix", test_android_syscall_abi_matrix),
        ("PR #13: 41 symbol/segment defects across four ABIs", test_pr13_symbol_and_segment_regressions),
        ("PR #13: 44 additional release regressions", test_pr13_additional_forty_four),
        ("Nineteen release, recovery and publishing regressions", test_release_and_recovery_nineteen),
        ("PR #12 assertion and build regressions", test_assertion_and_build_regressions),
        ("PR #11 final audit: nine further regressions", test_final_nine_regressions),
        ("PR #11 completion: nine NEW regressions", test_pr11_completion_regressions),
        ("PR #11: nine additional tooling regressions", test_nine_followup_regressions),
        ("Build lifecycle: nine configuration and release regressions", test_build_lifecycle_regressions),
        ("Publish preflight: three non-mutating failure regressions", test_publish_preflight_regressions),
        ("Daemon harness: seven resource and protocol regressions", test_daemon_harness_regressions),
        ("Nineteen: verification and publishing regressions", test_nineteen_validation_regressions),
        ("Verify: preserved PR #8 regressions", test_verify_pr8_regressions),
        ("Artifact verifier: seven format and invocation regressions", test_verify_artifact_regressions),
        ("Publish: five CLI and destination regressions", test_publish_regressions),
        ("Build: three NDK and API input regressions", test_build_input_regressions),
        ("Recovery: two installer failure regressions", test_recovery_installer_regressions),
        ("Makefile: two probe and cleanup regressions", test_make_cleanup_regressions),
        ("post-fs-data: current=0 swaps (Round 29 core fix)",
         test_swap_value_zero),
        ("post-fs-data: absent prop swaps", test_swap_value_absent),
        ("post-fs-data: real bridges are never touched",
         test_swap_refuses_real_bridge),
        ("post-fs-data: backup preserved across re-runs",
         test_backup_not_overwritten),
        ("post-fs-data: randomized names + applied record (Round 30)",
         test_round30_random_name_swap_and_applied_record),
        ("post-fs-data: survives a missing resetprop",
         test_no_resetprop_is_survivable),
        ("post-fs-data: workdir/marker/denylist setup",
         test_installed_marker_and_denylist),
        ("customize: launcher symlink (Round 29 core fix)",
         test_customize_creates_launcher),
        ("customize: 32-bit layout", test_customize_32bit_layout),
        ("customize: real installer ARCH values (Round 32 core fix)",
         test_customize_real_installer_arch_values),
        ("customize: no getprop on PATH (recovery, Round 32)",
         test_customize_no_getprop_on_path),
        ("customize: build.prop fallback for properties",
         test_customize_buildprop_fallback),
        ("customize: API gate (< 21 refused)",
         test_customize_refuses_old_android),
        ("customize: ABI gate", test_customize_refuses_bad_abi),
        ("customize: missing artifacts refused",
         test_customize_refuses_missing_artifacts),
        ("service: starts the daemon via the symlink",
         test_service_starts_symlink_daemon),
        ("service: legacy libs/<abi> fallback",
         test_service_finds_legacy_layout),
        ("service: no daemon, no crash", test_service_survives_missing_daemon),
        ("uninstall: restores 0", test_uninstall_restores_zero),
        ("uninstall: --delete for absent original",
         test_uninstall_deletes_when_backup_empty),
        ("uninstall: set-empty fallback for old resetprop",
         test_uninstall_empty_fallback_on_old_resetprop),
        ("uninstall: random session dir cleanup",
         test_uninstall_cleans_random_session_dir),
        ("uninstall: workdir-record fallback (Round 29)",
         test_uninstall_workdir_record_fallback),
        ("uninstall: foreign session path ignored",
         test_uninstall_leaves_foreign_paths_alone),
        ("Round 38: live daemon killed BEFORE the property restore",
         test_uninstall_kills_daemon_and_restores_after),
        ("Round 38: comm-scan fallback kills an orphan daemon",
         test_uninstall_comm_scan_kills_orphan_daemon),
        ("Round 38: wrong-comm pid never killed (pid-reuse safety)",
         test_uninstall_pid_reuse_safety),
        ("Round 38: backup-less restore falls back to stock 0",
         test_uninstall_backup_missing_restores_zero),
        ("Round 38: backup-less restore never touches a foreign bridge",
         test_uninstall_backup_missing_leaves_foreign_bridge),
        ("Round 38: EBUSY overlay falls back to umount -l",
         test_uninstall_lazy_umount_fallback),
        ("Round 31: engine swap without resetprop (real zygiskd)",
         test_real_engine_swap_without_resetprop),
        ("Round 31: mount pending + post-mount rollback",
         test_mount_pending_and_post_mount_hook),
        ("Round 31: post-mount no-op without pending",
         test_post_mount_noop_without_pending),
        ("Round 31: service.sh late rollback",
         test_service_late_resolution),
        ("Round 31: customize installs post-mount.d hook",
         test_customize_installs_post_mount_hook),
        ("Round 31: customize conflict detection",
         test_customize_conflict_detection),
        ("Round 31: customize dual-arch install",
         test_customize_dual_arch),
        ("Round 31: customize under KSU/APatch env",
         test_customize_root_manager_envs),
        ("Round 31: uninstall removes the post-mount hook",
         test_uninstall_removes_hook),
        ("Round 33: CI script hygiene (exec bits, bash invocation)",
         test_ci_script_hygiene),
        ("Build: NDK version discovery and alternate host toolchains",
         test_build_ndk_discovery),
        ("Build: nine driver and packaging regressions",
         test_build_regressions),
        ("Makefile: sanitizer builds cannot pass with stale binaries",
         test_sanitize_gate),
        ("Makefile: TSan failures are never reported as clean",
         test_tsan_gate),
    ]
    for title, fn in cases:
        print(f"\n== {title}")
        mk = FakeMagisk()
        try:
            fn(mk)
        except Exception as e:  # noqa: BLE001 — report, don't die
            check(f"{title} (no exception)", False, repr(e))
        finally:
            mk.cleanup()

    print()
    if failures:
        print(f"SCRIPT E2E: {len(failures)} FAILURES")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    if skips:
        print(f"SCRIPT E2E: ALL CHECKS GREEN ({len(skips)} skipped, "
              "see [SKIP] lines above)")
    else:
        print("SCRIPT E2E: ALL CHECKS GREEN")
    sys.exit(0)


if __name__ == "__main__":
    main()
