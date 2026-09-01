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
            field = 8 if frag < name else 12
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
            scan = left2 if frag < nm2 else right2
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


def find_real_daemon():
    """Build (once) the real zygiskd for the property-engine E2E."""
    global REAL_DAEMON
    if REAL_DAEMON is not None:
        return REAL_DAEMON
    import shutil as _sh
    cargo = _sh.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")
    if not cargo:
        REAL_DAEMON = ""
        return ""
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
        check("real daemon built (cargo available)", False, "cargo build failed")
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


def main():
    cases = [
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
    print("SCRIPT E2E: ALL CHECKS GREEN")
    sys.exit(0)


if __name__ == "__main__":
    main()
