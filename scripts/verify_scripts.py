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
  if [ -s "$STATE" ]; then
    cat "$STATE"
  else
    printf '%s\\n' "$ZS_FAKE_PROP_VALUE"
  fi
  exit 0
fi
printf '%s\\n' "$*" >> "$LOG"
# SET updates the state a subsequent GET returns.
if [ "$1" = "--delete" ]; then
  : > "$STATE"
  [ -n "$ZS_FAKE_DELETE_FAIL" ] && exit 1
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
    if [ -n "${ZS_FAKE_PROP_STATE:-}" ] && [ -s "$ZS_FAKE_PROP_STATE" ]; then
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
        self.resetprop_log = os.path.join(self.root, "resetprop.log")
        self.stub_daemon_log = os.path.join(self.root, "stub_daemon.log")
        self.prop_value = "0"
        self.delete_fail = ""
        self.prop_state = os.path.join(self.root, "prop_state")

    def env(self, extra=None):
        env = dict(os.environ)
        env["PATH"] = self.bindir + os.pathsep + env.get("PATH", "")
        env["ZS_TEST_ROOT"] = self.sysroot
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
    proc = mk.run_script("post-fs-data.sh")
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
    import shutil as _sh
    # BUG (found R34): os.path.expanduser() returns a non-empty path
    # even when the file does not exist, so `which() or expanduser()`
    # could NEVER evaluate falsy — a host without Rust fell into the
    # subprocess below, died with FileNotFoundError, and was reported
    # as "cargo build failed" (a FAIL). Existence must be tested.
    cargo = _sh.which("cargo")
    if not cargo:
        cand = os.path.expanduser("~/.cargo/bin/cargo")
        if os.path.exists(cand):
            cargo = cand
    if not cargo:
        REAL_DAEMON = ""
        REAL_DAEMON_ABSENT_TOOLCHAIN = True
        return ""
    REAL_DAEMON_ABSENT_TOOLCHAIN = False
    zygd = os.path.join(REPO_ROOT, "native", "zygiskd")
    try:
        subprocess.run([cargo, "build", "--release"], cwd=zygd,
                       capture_output=True, timeout=600, check=True)
    except Exception:
        REAL_DAEMON = ""
        return ""
    binp = os.path.join(zygd, "target", "release", "zygiskd")
    REAL_DAEMON = binp if os.path.exists(binp) else ""
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


def _run_customize(mk, modpath, extra_env=None, abilist=None, bridge="0"):
    """Shared customize.sh runner with a remapped /data/adb."""
    env = mk.env(extra_env or {})
    env["MODPATH"] = str(modpath)
    # ROUND 32: the REAL installer value (Magisk/KSU/APatch
    # api_level_arch_detect), not the NDK-style ABI name.
    env["ARCH"] = "arm64"
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
    alternate = fake_ndk(os.path.join(mk.root, "alternate NDK"), "darwin-x86_64")
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
        ("alternate host toolchain", {"NDK": alternate}, alternate),
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

    # Current nineteen-bug pass: build driver regressions 09--14.
    for option in ("--ndk", "--api", "--abis", "--out", "--type"):
        proc, out = run((option, ""))
        check("study 09: rejects empty " + option, proc.returncode == 2
              and "requires a value" in proc.stderr and not os.path.exists(out),
              proc.stdout + proc.stderr)
    for kind in ("Relese", "", "Release;Debug"):
        proc, out = run(("--type", kind))
        check("study 10: rejects invalid build configuration " + repr(kind),
              proc.returncode == 2 and not os.path.exists(out), proc.stdout + proc.stderr)
    # Hide just one executable from command -v without depending on host PATH.
    for number, tool, args in ((11, "cmake", ("--skip-cpp",)),
                               (12, "cargo", ())):
        override = '() { if [[ "$*" == "-v ' + tool + '" ]]; then return 1; fi; builtin command "$@"; }'
        proc, _ = run(args, {"BASH_FUNC_command%%": override})
        with open(env["BUILD_CALLS"]) as fp:
            calls = fp.read()
        check(f"study {number:02d}: {tool} availability checked for the requested build",
              proc.returncode == 0 if number == 11 else
              proc.returncode != 0 and not calls and "cargo not on PATH" in proc.stderr,
              proc.stdout + proc.stderr + calls)

    stable_out = os.path.join(root, "transactional output")
    proc, _ = run(("--out", stable_out))
    passed("study 13 control: initial archive", proc)
    archive_dir = os.path.join(stable_out, "out")
    saved = {name: open(os.path.join(archive_dir, name), "rb").read()
             for name in os.listdir(archive_dir)}
    # Force verification failure, then verify the previous release survives.
    with open(seed, "wb") as fp:
        fp.write(elf)
    proc, _ = run(("--out", stable_out))
    current = {name: open(os.path.join(archive_dir, name), "rb").read()
               for name in os.listdir(archive_dir)}
    check("study 13: failed replacement preserves the last verified archive",
          proc.returncode != 0 and current == saved, proc.stdout + proc.stderr)
    proc, failed_out = run()
    check("study 13: failed first build leaves no release archive", proc.returncode != 0
          and not os.listdir(os.path.join(failed_out, "out")), proc.stdout + proc.stderr)
    with open(seed, "wb") as fp:
        fp.write(valid_elf)

    overlap_out = os.path.join(root, "overlapping output")
    cargo_dir = os.path.join(overlap_out, "module", "cargo")
    os.makedirs(cargo_dir)
    sentinel = os.path.join(cargo_dir, "keep")
    with open(sentinel, "w") as fp:
        fp.write("previous cargo cache")
    proc, _ = run(("--out", overlap_out, "--skip-cpp"), {"CARGO_TARGET_DIR": cargo_dir})
    with open(env["BUILD_CALLS"]) as fp:
        calls = fp.read()
    check("study 14: staging cannot delete Cargo's target directory",
          proc.returncode != 0 and os.path.isfile(sentinel) and not calls,
          proc.stdout + proc.stderr)


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
elif args[:2] == ['rev-parse', 'HEAD']:
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
elif args[:2] in (['remote', 'set-url'], ['remote', 'add']):
    with open(state, 'w') as fp:
        fp.write(args[-1])
elif args[:1] == ['check-ref-format']:
    pass
elif args[:2] in (['config', 'user.email'], ['config', '--get-all']):
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
          and ["push", "-u", "origin", "refs/heads/study-fixes:refs/heads/study-fixes"] in calls, repr(calls))
    proc, calls, _ = run(extra={"PUBLISH_DETACHED": "1"})
    check("bug 09: detached HEAD requires an explicit branch", proc.returncode != 0
          and not any(c[0] == "push" for c in calls), proc.stdout + proc.stderr)
    proc, calls, _ = run(("--branch", "release"), extra={"PUBLISH_DETACHED": "1"})
    check("publish: explicit branch works detached", proc.returncode == 0
          and ["push", "-u", "origin", "refs/heads/release:refs/heads/release"] in calls, repr(calls))

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
        return subprocess.run(["sh", script, "3", "", "module.zip"], env=mk.env(),
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
        "META-INF/com/google/android/update-binary")}
    base.update({"module.prop": prop.encode(),
                 "META-INF/com/google/android/updater-script": b"#MAGISK\n"})
    base.update({"libs/x86_64/" + name: bytes(header()) for name in names})

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


def test_study_recovery_regressions(mk):
    """Regression IDs 01--05: validate the recovery handoff before side effects."""
    import shlex
    with open(os.path.join(REPO_ROOT, "scripts/installer/update-binary")) as fp:
        source = fp.read()
    util = os.path.join(mk.root, "util_functions.sh")
    script = os.path.join(mk.root, "update-binary")
    with open(script, "w") as fp:
        fp.write(source.replace("/data/adb/magisk/util_functions.sh", shlex.quote(util)))
    mounted = os.path.join(mk.root, "mounted")
    installed = os.path.join(mk.root, "installed")
    exported = os.path.join(mk.root, "exported")
    archive = os.path.join(mk.root, "module with spaces.zip")
    with open(archive, "w") as fp:
        fp.write("fixture")
    write_exec(os.path.join(mk.bindir, "mount"),
               "#!/bin/sh\ntouch " + shlex.quote(mounted) + "\n")
    def run(args=None, source_status=0):
        for path in (mounted, installed, exported):
            if os.path.exists(path):
                os.unlink(path)
        with open(util, "w") as fp:
            fp.write("MAGISK_VER_CODE=20400\ninstall_module() {\n"
                     "touch " + shlex.quote(installed) + "\n"
                     "sh -c 'printf \"%s\\n%s\\n\" \"$OUTFD\" \"$ZIPFILE\"' > "
                     + shlex.quote(exported) + "\n}\nreturn " + str(source_status) + "\n")
        env = mk.env()
        env.pop("OUTFD", None)
        env.pop("ZIPFILE", None)
        return subprocess.run(["sh", script, *(args if args is not None else
                                              ("3", "1", archive))], env=env,
                              capture_output=True, text=True, timeout=10)
    for args in ((), ("3",), ("3", "1"), ("3", "1", archive, "extra")):
        proc = run(args)
        check("study 01: recovery rejects wrong argument count " + repr(args),
              proc.returncode != 0 and not os.path.exists(mounted)
              and not os.path.exists(installed), proc.stdout + proc.stderr)
    for fd in ("", "../status", "-1", "one"):
        proc = run(("3", fd, archive))
        check("study 02: recovery rejects invalid output descriptor " + repr(fd),
              proc.returncode != 0 and not os.path.exists(mounted)
              and not os.path.exists(installed), proc.stdout + proc.stderr)
    for path in ("", archive + ".missing", mk.root):
        proc = run(("3", "1", path))
        check("study 03: recovery rejects missing/non-file archive " + repr(path),
              proc.returncode != 0 and not os.path.exists(mounted)
              and not os.path.exists(installed), proc.stdout + proc.stderr)
    proc = run()
    content = open(exported).read() if os.path.exists(exported) else ""
    check("study 04: handoff variables reach installer subprocesses",
          proc.returncode == 0 and content == "1\n" + archive + "\n",
          proc.stdout + proc.stderr + repr(content))
    proc = run(source_status=42)
    check("study 05: failed utility initialization cannot install",
          proc.returncode != 0 and not os.path.exists(installed), proc.stdout + proc.stderr)


def test_study_publish_regressions(mk):
    """Regression IDs 06--08 use real Git configuration, never network pushes."""
    import shlex
    repo = os.path.join(mk.root, "repository")
    os.makedirs(repo)
    real_git = shutil.which("git")
    def git(*args):
        return subprocess.run([real_git, *args], cwd=repo, capture_output=True,
                              text=True, check=True, timeout=10)
    git("init", "-q")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "--allow-empty", "-qm", "fixture")
    git("checkout", "-qb", "topic")
    git("remote", "add", "origin", "https://github.com/study/original.git")
    publisher = os.path.join(repo, "publish.sh")
    shutil.copy(os.path.join(REPO_ROOT, "publish.sh"), publisher)
    log = os.path.join(mk.root, "push.log")
    write_exec(os.path.join(mk.bindir, "git"), '#!/bin/sh\nif [ "$1" = push ]; then\n'
               + shlex.quote(real_git) + ' remote get-url --push --all origin > '
               + shlex.quote(log) + '\nexit 0\nfi\nexec ' + shlex.quote(real_git) + ' "$@"\n')
    def run(*args):
        if os.path.exists(log):
            os.unlink(log)
        return subprocess.run(["bash", publisher, *args], cwd=repo, env=mk.env(),
                              capture_output=True, text=True, timeout=10)
    before = git("config", "--local", "--list").stdout
    proc = run("--branch", "missing", "--repo", "study/other")
    after = git("config", "--local", "--list").stdout
    check("study 06: nonexistent branch fails without remote mutation or push",
          proc.returncode != 0 and before == after and not os.path.exists(log),
          proc.stdout + proc.stderr)
    git("config", "--add", "remote.origin.url", "https://github.com/study/unwanted.git")
    proc = run("--repo", "study/intended")
    urls = open(log).read().splitlines() if os.path.exists(log) else []
    check("study 07: explicit repository overrides every inherited push destination",
          proc.returncode == 0 and urls == ["https://github.com/study/intended.git"],
          proc.stdout + proc.stderr + repr(urls))
    git("config", "--replace-all", "remote.origin.url",
        "https://fixture-secret@github.com/study/private.git?access_token=fixture-query")
    proc = run()
    check("study 08: publishing diagnostics do not disclose URL credentials",
          proc.returncode == 0 and "fixture-secret" not in proc.stdout + proc.stderr
          and "fixture-query" not in proc.stdout + proc.stderr, proc.stdout + proc.stderr)


def test_study_archive_regressions(mk):
    """Regression IDs 15--17: verify the actual archive, including its namespace."""
    import struct
    import warnings
    import zipfile
    names = ("libzygisk.so", "libpayload.so", "libzn_loader.so", "zygiskd")
    seed = os.path.join(mk.root, "seed.so")
    subprocess.run(["cc", "-shared", "-fPIC", "-s", "-Wl,-z,max-page-size=16384",
                    "-x", "c", "-", "-o", seed], input="int fixture(void){return 0;}\n",
                   capture_output=True, text=True, check=True, timeout=30)
    valid = open(seed, "rb").read()
    tools = os.path.join(mk.root, "toolchain", "bin")
    os.makedirs(tools)
    os.symlink(shutil.which("readelf"), os.path.join(tools, "llvm-readelf"))
    os.symlink(shutil.which("strings"), os.path.join(tools, "llvm-strings"))
    libs = os.path.join(mk.moddir, "libs", "x86_64")
    os.makedirs(libs)
    for name in names:
        with open(os.path.join(libs, name), "wb") as fp:
            fp.write(valid)
    entries = {name: b"fixture" for name in (
        "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh", "zs_compat.sh",
        "post-mount-hook.sh", "verify.sh", "LICENSE", "META-INF/com/google/android/update-binary")}
    entries["module.prop"] = (b"id=zygisk_study\nname=Study\nversion=1\nversionCode=1\n"
                              b"author=Study\ndescription=Educational\n")
    entries["META-INF/com/google/android/updater-script"] = b"#MAGISK\n"
    entries.update({"libs/x86_64/" + name: valid for name in names})
    with open(os.path.join(REPO_ROOT, "scripts/build_module.sh")) as fp:
        source = fp.read()
    function = source[source.index("verify_zip() {"):source.index("# Drive the build")]
    def run(extra=(), replace=None):
        archive = os.path.join(mk.root, "module.zip")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "w") as zf:
                for name, data in {**entries, **(replace or {})}.items():
                    zf.writestr(name, data)
                for name, data in extra:
                    zf.writestr(name, data)
        return subprocess.run(["bash", "-c", "set -euo pipefail; ABI_LIST=(x86_64); "
                               + function + '\nverify_zip "$1"', "verify", archive],
                              env=mk.env({"REPO_ROOT": REPO_ROOT, "MODULE_DIR": mk.moddir,
                                          "TOOLCHAIN": os.path.dirname(tools)}),
                              capture_output=True, text=True, timeout=20)
    proc = run()
    check("study archive control: valid archive", proc.returncode == 0, proc.stdout + proc.stderr)
    bad = bytearray(valid)
    cls64 = bad[4] == 2
    phoff = struct.unpack_from("<Q" if cls64 else "<I", bad, 32 if cls64 else 28)[0]
    phsize, phnum = struct.unpack_from("<HH", bad, 54 if cls64 else 42)
    for i in range(phnum):
        offset = phoff + i * phsize
        if struct.unpack_from("<I", bad, offset)[0] == 1:
            struct.pack_into("<Q" if cls64 else "<I", bad, offset + (48 if cls64 else 28), 0x1000)
    proc = run(replace={"libs/x86_64/libpayload.so": bytes(bad)})
    check("study 15: alignment is checked from archived bytes, not staging",
          proc.returncode != 0 and "alignment" in proc.stderr, proc.stdout + proc.stderr)
    for entry in ("libs/mips/", "libs/.hidden/", "libs/x86/zygiskd"):
        proc = run(extra=((entry, b"unexpected"),))
        check("study 16: unexpected archived ABI rejected: " + entry,
              proc.returncode != 0, proc.stdout + proc.stderr)
    for entry in ("libs/x86_64/libpayload.so", "customize.sh"):
        proc = run(extra=((entry, b"untrusted duplicate"),))
        check("study 17: duplicate archive member rejected: " + entry,
              proc.returncode != 0, proc.stdout + proc.stderr)


def test_study_daemon_harness_regressions(mk):
    """Regression IDs 18--19: Cargo output discovery and stream framing."""
    import importlib.util
    import json
    from unittest import mock
    spec = importlib.util.spec_from_file_location("daemon_checks", os.path.join(REPO_ROOT, "scripts/verify_daemon.py"))
    daemon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(daemon)
    binary = os.path.join(mk.root, "custom-target", "debug", "zygiskd")
    os.makedirs(os.path.dirname(binary))
    write_exec(binary, "#!/bin/sh\nexit 0\n")
    artifact = {"reason": "compiler-artifact", "target": {"name": "zygiskd", "kind": ["bin"]},
                "executable": binary}
    built = subprocess.CompletedProcess(["cargo", "build"], 0, json.dumps(artifact) + "\n", "")
    with mock.patch.object(daemon.shutil, "which", return_value="/fixture/cargo"), \
         mock.patch.object(daemon.subprocess, "run", return_value=built) as invoked:
        try:
            result, _ = daemon.cargo_build()
        except SystemExit:
            result = None
        check("study 18: daemon harness uses Cargo's reported executable", result == binary)
        args = invoked.call_args.args[0]
        check("study 18: Cargo emits machine-readable artifact messages",
              "--message-format=json" in args, repr(args))
    # A stale default target binary must never mask a missing Cargo artifact.
    with mock.patch.object(daemon.shutil, "which", return_value="/fixture/cargo"), \
         mock.patch.object(daemon.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
         mock.patch.object(daemon.os.path, "exists", return_value=True):
        try:
            daemon.cargo_build()
            refused = False
        except SystemExit as error:
            refused = error.code == 1
        check("study 18: absent build artifact cannot run a stale default binary", refused)
    stream = mock.Mock()
    stream.recv.side_effect = [b"test", b"mod/zygisk/", b"x86_64/library.so\n", b""]
    with mock.patch.object(daemon, "connect", return_value=stream):
        reply = daemon.ask("fixture", b"L")
    check("study 19: socket reply survives arbitrary stream fragmentation",
          reply == b"testmod/zygisk/x86_64/library.so\n", repr(reply))
    check("study 19 control: socket closed after complete reply", stream.close.call_count == 1)


def main():
    cases = [
        ("Study: recovery regressions 01--05", test_study_recovery_regressions),
        ("Study: publishing regressions 06--08", test_study_publish_regressions),
        ("Study: archive regressions 15--17", test_study_archive_regressions),
        ("Study: daemon harness regressions 18--19", test_study_daemon_harness_regressions),
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
