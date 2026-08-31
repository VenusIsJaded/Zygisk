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
# Fake resetprop for script E2E. Read mode prints the configured
# value; every invocation is recorded to $ZS_FAKE_RESETPROP_LOG.
LOG="${ZS_FAKE_RESETPROP_LOG:?}"
if [ "$#" -eq 1 ]; then
  printf '%s\\n' "$ZS_FAKE_PROP_VALUE"
  exit 0
fi
printf '%s\\n' "$*" >> "$LOG"
if [ "$1" = "--delete" ] && [ -n "$ZS_FAKE_DELETE_FAIL" ]; then
  exit 1
fi
exit 0
"""

FAKE_LOG = """#!/bin/sh
# Fake Android `log` — silently succeed.
exit 0
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
                       "customize.sh"):
            shutil.copy(os.path.join(REPO_ROOT, script),
                        os.path.join(self.moddir, script))
        write_exec(os.path.join(self.bindir, "resetprop"), FAKE_RESETPROP)
        write_exec(os.path.join(self.bindir, "log"), FAKE_LOG)
        self.resetprop_log = os.path.join(self.root, "resetprop.log")
        self.stub_daemon_log = os.path.join(self.root, "stub_daemon.log")
        self.prop_value = "0"
        self.delete_fail = ""

    def env(self, extra=None):
        env = dict(os.environ)
        env["PATH"] = self.bindir + os.pathsep + env.get("PATH", "")
        env["ZS_TEST_ROOT"] = self.sysroot
        env["ZS_FAKE_RESETPROP_LOG"] = self.resetprop_log
        env["ZS_FAKE_PROP_VALUE"] = self.prop_value
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

def run_customize(mk, abi="arm64-v8a", api="30", is64="true",
                  make_libs=True, missing_artifact=False):
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
    proc = subprocess.run(
        ["sh", "-c", wrapper],
        env=mk.env({"MODPATH": modpath, "ARCH": abi, "API": api,
                    "IS64BIT": is64}),
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
    check("systemless /system/lib64 layout created",
          os.path.exists(os.path.join(sysdir, "libzygisk.so"))
          and os.path.exists(os.path.join(sysdir, "libpayload.so")))


def test_customize_32bit_layout(mk):
    proc, modpath = run_customize(mk, abi="armeabi-v7a", is64="false")
    check("customize.sh (armeabi-v7a) exits 0", proc.returncode == 0,
          proc.stdout[-200:])
    check("32-bit systemless layout at /system/lib",
          os.path.exists(os.path.join(modpath, "system", "lib",
                                      "libzygisk.so")))


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
    check("pid file written", os.path.exists(
        os.path.join(mk.workdir, "zygiskd.pid")))


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
    os.makedirs(mk.workdir, exist_ok=True)
    with open(os.path.join(mk.workdir, ".native_bridge_backup"), "w") as fp:
        fp.write("")
    proc = mk.run_script("uninstall.sh")
    calls = mk.resetprop_calls()
    check("uninstall falls back to set-empty on --delete failure",
          proc.returncode == 0
          and calls == ["--delete ro.dalvik.vm.native.bridge",
                        "ro.dalvik.vm.native.bridge "], str(calls))


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

def main():
    cases = [
        ("post-fs-data: current=0 swaps (Round 29 core fix)",
         test_swap_value_zero),
        ("post-fs-data: absent prop swaps", test_swap_value_absent),
        ("post-fs-data: real bridges are never touched",
         test_swap_refuses_real_bridge),
        ("post-fs-data: backup preserved across re-runs",
         test_backup_not_overwritten),
        ("post-fs-data: survives a missing resetprop",
         test_no_resetprop_is_survivable),
        ("post-fs-data: workdir/marker/denylist setup",
         test_installed_marker_and_denylist),
        ("customize: launcher symlink (Round 29 core fix)",
         test_customize_creates_launcher),
        ("customize: 32-bit layout", test_customize_32bit_layout),
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
