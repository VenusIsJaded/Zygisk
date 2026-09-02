#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Round 28 — LIVE end-to-end verification of the zygiskd daemon.

Until this round the daemon was never compiled or run in this
environment (the standing "inspection-only" residual in
ANDROID-REALISM.md). With a Rust toolchain now available, this
script builds the daemon, runs it against a remapped /data tree
(ZS_TEST_ROOT; see remap_path in main.rs), and probes the REAL
binary over its REAL socket:

  1. randomized session-file socket handshake (R13) — BOTH session
     records since Round 29 (module dir + the /data/system workdir
     copy, including content parity)
  2. process cloak: comm AND cmdline (the R28 rewrite_argv fix)
  3. 'L' module listing from a fake module tree
  4. 'I' should-inject: allow, then deny after a denylist flip
     delivered via the (R28-fixed) inotify rescan path
  5. 'C' companion echo
  6. 'P' properties staging: valid image accepted + staged file
     (mode 0444, content parity), bad magic rejected
  7. zombie reaping: connection children must NOT accumulate
     (the R28 SIGCHLD fix)
  8. previous-boot random-dir cleanup across a restart
  9. (Round 29) the same cleanup when ONLY the workdir session
     record survives (module tree unreadable/removed)
 10. (Round 30) the property guard, LIVE against a fake zygote:
     the stock value is restored once the (fake) bridge library
     appears in the fake zygote's maps, re-applied after each
     zygote death, and rolled back permanently after more than 3
     restarts (Magisk's bootloop policy); an empty stock backup
     restores via --delete (absent, not empty string)

Exits 0 when every check passes, 1 on any failure, 77 when no Rust
toolchain is available (same skip convention as verify_trampolines).
"""

import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON_DIR = os.path.join(REPO_ROOT, "native", "zygiskd")

PROP_MAGIC = b"PROP"          # bytes 8..12  of the area image
PROP_VERSION = bytes.fromhex("abd06efc")  # bytes 12..16 (0xfc6ed0ab LE)
CLOAK_NAME = b"subsysd"

failures = []


def check(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(f"{name}: {detail}")


def cargo_build():
    if shutil.which("cargo") is None and not os.path.exists(
            os.path.expanduser("~/.cargo/bin/cargo")):
        print("NOTE: no Rust toolchain (cargo) — daemon E2E skipped.")
        sys.exit(77)
    env = dict(os.environ)
    env["PATH"] = os.path.expanduser("~/.cargo/bin:") + env.get("PATH", "")
    r = subprocess.run(["cargo", "build"], cwd=DAEMON_DIR, env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr)
        print("cargo build failed")
        sys.exit(1)
    binp = os.path.join(DAEMON_DIR, "target", "debug", "zygiskd")
    if not os.path.exists(binp):
        print("built binary not found:", binp)
        sys.exit(1)
    return binp, env


class Tree:
    """The remapped /data tree the daemon runs against."""

    def __init__(self, root):
        self.root = root
        self.workdir = os.path.join(root, "data/system/zygisk_study")
        self.sockdir = os.path.join(self.workdir, "sock")
        self.session_file = os.path.join(
            root, "data/adb/modules/zygisk_study/session.sock")
        # Round 29 — the daemon's SECOND session record (workdir).
        self.session_file_alt = os.path.join(self.workdir, "session.sock")
        self.modules_root = os.path.join(root, "data/adb/modules")
        os.makedirs(self.workdir, exist_ok=True)
        os.makedirs(self.sockdir, exist_ok=True)
        os.makedirs(os.path.dirname(self.session_file), exist_ok=True)
        os.makedirs(self.modules_root, exist_ok=True)
        open(os.path.join(self.workdir, "denylist"), "w").close()
        open(os.path.join(self.workdir, "modules"), "w").close()
        # A fake module the 'L' verb should report.
        mod = os.path.join(self.modules_root, "testmod",
                           "zygisk", "arm64-v8a")
        os.makedirs(mod, exist_ok=True)
        open(os.path.join(mod, "libzygisk-module.so"), "wb").close()

    def denylist_path(self):
        return os.path.join(self.workdir, "denylist")


def start_daemon(binary, tree, env):
    e = dict(env)
    e["ZS_TEST_ROOT"] = tree.root
    proc = subprocess.Popen(
        [binary, "--workdir", tree.workdir],
        env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for the session file (written before bind).
    deadline = time.time() + 5
    while time.time() < deadline:
        if os.path.exists(tree.session_file):
            break
        if proc.poll() is not None:
            print("daemon exited early with", proc.returncode)
            sys.exit(1)
        time.sleep(0.05)
    else:
        print("session file never appeared")
        proc.kill()
        sys.exit(1)
    time.sleep(0.1)
    return proc


def read_session_path(tree):
    with open(tree.session_file, "r") as f:
        return f.read().strip()


def connect(sock_path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    return s


def ask(sock_path, verb):
    s = connect(sock_path)
    try:
        s.sendall(verb)
        return s.recv(4096)
    finally:
        s.close()


def count_zombies(pid):
    n = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "r") as f:
                stat = f.read()
            # state is field 3; ppid field 4 — after "pid (comm) S".
            close = stat.rfind(")")
            fields = stat[close + 2:].split()
            state, ppid = fields[0], int(fields[1])
            if ppid == pid and state == "Z":
                n += 1
        except (OSError, IndexError, ValueError):
            continue
    return n


def main():
    print("== building the daemon (first live build) ==")
    binary, env = cargo_build()
    # Round 34b: speed up the stand-down zombie sweep for the E2E
    # (device default is 1 Hz — the zombie check's 0.6 s settle
    # window needs the sub-second cadence the env var provides).
    env["ZS_TEST_SWEEP_MS"] = "150"

    tmp = tempfile.mkdtemp(prefix="zygiskd_e2e_")
    tree = Tree(tmp)
    print(f"== tree at {tmp} ==")

    print("== starting daemon ==")
    proc = start_daemon(binary, tree, env)
    try:
        run_checks(binary, tree, env, proc)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print(f"\nDAEMON E2E: {len(failures)} FAILURES")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print("\nDAEMON E2E: ALL CHECKS GREEN")
    sys.exit(0)


def run_checks(binary, tree, env, proc):
    pid = proc.pid

    # 1. session handshake.
    sock_path = read_session_path(tree)
    check("session file points inside the remapped tree",
          sock_path.startswith(os.path.join(tree.root, "data/system/.")),
          sock_path)
    # Round 29: the daemon writes the SAME record into its workdir —
    # the fallback for the Samsung /data/adb/modules-block class.
    alt_exists = os.path.exists(tree.session_file_alt)
    check("workdir session record written", alt_exists,
          tree.session_file_alt)
    if alt_exists:
        with open(tree.session_file_alt) as f:
            alt_path = f.read().strip()
        check("workdir session record matches the module-dir one",
              alt_path == sock_path, alt_path)
    check("randomized socket dir has 0700 perms",
          oct(os.stat(os.path.dirname(sock_path)).st_mode & 0o777) == "0o700",
          oct(os.stat(os.path.dirname(sock_path)).st_mode & 0o777))
    check("socket is bound", os.path.exists(sock_path), sock_path)

    # 2. cloak.
    try:
        with open(f"/proc/{pid}/comm", "rb") as f:
            comm = f.read().strip()
    except OSError:
        comm = b""
    check(f"comm is the cloak name ({CLOAK_NAME.decode()})",
          comm == CLOAK_NAME, comm)
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read()
    except OSError:
        cmdline = b""
    leaked = [t for t in (b"zygiskd", b"--workdir", b"zygisk_study")
              if t in cmdline]
    check("cmdline leaks no daemon identity", not leaked,
          repr(cmdline) + " leaked " + repr(leaked))

    # 3. 'L' module list.
    reply = ask(sock_path, b"L")
    check("'L' reports the fake module",
          b"testmod" in reply and b"libzygisk-module.so" in reply,
          repr(reply))

    # 3b. Round 34 — getprop ABI regression. Before the ChildGrim
    # fix, SIGCHLD=SIG_IGN made Command::output() fail with ECHILD,
    # read_prop() lost getprop's stdout, and pick_abi() was pinned
    # to the arm64-v8a default: on a device whose ro.product.cpu.abi
    # differs, modules under zygisk/<abi>/ were never listed. A fake
    # getprop returning a custom ABI + a module under that ABI
    # exercises the FULL exec path (fork + exec + pipe read + parse)
    # — this check fails under the old SIG_IGN design.
    # (Module name "abifake" deliberately shares no substring with
    # the first tree's "testmod": the not-listed assertion compares
    # raw bytes, and a name like "abitestmod" CONTAINS "testmod" —
    # the exact substring-collision bug this check itself had.)
    # Isolated tree + daemon: a second daemon on the FIRST tree
    # would delete the first daemon's socket dir (random-socket
    # cleanup reads the same session file) and break every later
    # check.
    tmp_abi = tempfile.mkdtemp(prefix="zygiskd_e2e_abi_")
    tree_abi = Tree(tmp_abi)
    fake_abi_mod = os.path.join(tree_abi.modules_root, "abifake",
                                "zygisk", "x86_64")
    os.makedirs(fake_abi_mod, exist_ok=True)
    open(os.path.join(fake_abi_mod, "libzygisk-module.so"), "wb").close()
    bindir = os.path.join(tree_abi.root, "bin")
    os.makedirs(bindir, exist_ok=True)
    getprop = os.path.join(bindir, "getprop")
    with open(getprop, "w") as f:
        f.write("#!/bin/sh\n[ \"$1\" = ro.product.cpu.abi ] && printf 'x86_64\\n' && exit 0\nexit 1\n")
    os.chmod(getprop, 0o755)
    env_abi = dict(env)
    env_abi["ZS_TEST_ROOT"] = tree_abi.root
    env_abi["PATH"] = bindir + ":" + env_abi.get("PATH", "")
    proc_abi = start_daemon(binary, tree_abi, env_abi)
    try:
        sock_abi = read_session_path(tree_abi)
        reply = ask(sock_abi, b"L")
        check("'L' honors getprop's ABI (x86_64 module listed)",
              b"abifake/zygisk/x86_64" in reply, repr(reply))
        check("'L' default-ABI module NOT listed under fake ABI",
              b"testmod" not in reply, repr(reply))
    finally:
        proc_abi.send_signal(signal.SIGTERM)
        try:
            proc_abi.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc_abi.kill()
        shutil.rmtree(tmp_abi, ignore_errors=True)

    # 4. 'I' before / after the denylist flip.
    reply = ask(sock_path, b"Icom.example.app\n")
    check("'I' answers '1' for a non-denied process", reply == b"1",
          repr(reply))
    with open(tree.denylist_path(), "w") as f:
        f.write("com.example.app\n")
    # Trigger the inotify path (module-root event wakes the rescan
    # loop, which also re-checks the denylist mtime).
    poke = os.path.join(tree.modules_root, ".poke")
    open(poke, "w").close()
    os.unlink(poke)
    ok = False
    deadline = time.time() + 3
    while time.time() < deadline:
        reply = ask(sock_path, b"Icom.example.app\n")
        if reply == b"0":
            ok = True
            break
        time.sleep(0.1)
    check("'I' answers '0' after denylist flip via inotify rescan",
          ok, "deny answer never arrived within 3s")

    # 5. 'C' companion echo.
    s = connect(sock_path)
    s.sendall(b"C")
    s.sendall(b"X")
    echo = s.recv(16)
    s.close()
    check("'C' companion echoes bytes", echo == b"X", repr(echo))

    # 6. 'P' staging.
    image = bytearray(64)
    struct.pack_into("<I", image, 0, 64)        # bytes_used_
    struct.pack_into("<I", image, 4, 1)         # serial
    image[8:12] = PROP_MAGIC
    image[12:16] = PROP_VERSION
    req = b"P" + struct.pack("<I", len(image)) + bytes(image)
    reply = ask(sock_path, req)
    staged = reply[1:].decode().strip() if reply.startswith(b"1") else ""
    check("'P' accepts a valid image and names the staged file",
          reply.startswith(b"1") and staged.startswith(
              os.path.dirname(sock_path)),
          repr(reply))
    if staged and os.path.exists(staged):
        with open(staged, "rb") as f:
            content = f.read()
        check("staged file content matches the image", content == bytes(image))
        mode = oct(os.stat(staged).st_mode & 0o777)
        check("staged file mode is 0444 (parity with properties_serial)",
              mode == "0o444", mode)
    else:
        check("staged file exists", False, staged)

    bad = bytearray(64)
    struct.pack_into("<I", bad, 0, 64)
    bad[8:12] = b"GARB"
    bad[12:16] = PROP_VERSION
    reply = ask(sock_path, b"P" + struct.pack("<I", len(bad)) + bytes(bad))
    check("'P' rejects a bad-magic image", reply == b"0\n", repr(reply))

    # 7. zombies (Round 28 first guarded this; Round 34's ChildGrim
    # keeps the property while SIGCHLD stays at its default so
    # std::process children keep working — see the getprop check
    # above). 50 connections, not 10: a leak that strands even 1 in
    # 10 shows up as 5 zombies here, and the reverse (a reaper that
    # waits/block) would blow the 2s settle window.
    for _ in range(50):
        ask(sock_path, b"L")
    time.sleep(0.6)
    n = count_zombies(pid)
    check("no zombie children after 50 connections", n == 0,
          f"{n} zombies")

    # 7b. Round 33: the daemon writes its OWN pid file after the bind
    # (the old service.sh `echo $!` recorded the setsid wrapper's pid,
    # which forks+exits under shell job control — a dead pid from the
    # first millisecond).
    pid_file = os.path.join(tree.workdir, "zygiskd.pid")
    try:
        with open(pid_file) as f:
            file_pid = int(f.read().strip())
        check("zygiskd.pid names the LIVE daemon pid",
              file_pid == pid, f"file={file_pid} live={pid}")
        check("zygiskd.pid is 0600-root-ish (not world-writable)",
              (os.stat(pid_file).st_mode & 0o022) == 0,
              oct(os.stat(pid_file).st_mode))
    except (OSError, ValueError) as e:
        check("zygiskd.pid names the LIVE daemon pid", False, repr(e))

    # 8. previous-boot random-dir cleanup across a restart.
    prev_dir = os.path.dirname(sock_path)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=3)
    check("previous random dir still present before restart",
          os.path.isdir(prev_dir))
    proc2 = start_daemon(binary, tree, env)
    try:
        time.sleep(0.3)
        check("restart cleaned the previous boot's random dir",
              not os.path.isdir(prev_dir))
    finally:
        proc2.send_signal(signal.SIGTERM)
        try:
            proc2.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc2.kill()

    # 9. Round 29 — the cleanup also works when ONLY the workdir
    # record survives (module tree removed/unreadable — the Samsung
    # /data/adb/modules-block class, or a half-uninstalled module).
    # Simulate: a random dir from a "previous boot", named ONLY in
    # the workdir session record; the module-dir record is absent.
    orphan = os.path.join(tree.root, "data/system/.feedface")
    os.makedirs(orphan, exist_ok=True)
    with open(tree.session_file_alt, "w") as f:
        f.write(os.path.join(orphan, "s") + "\n")
    try:
        os.unlink(tree.session_file)
    except FileNotFoundError:
        pass
    proc3 = start_daemon(binary, tree, env)
    try:
        time.sleep(0.3)
        check("workdir-only record still cleans the old random dir",
              not os.path.isdir(orphan))
    finally:
        proc3.send_signal(signal.SIGTERM)
        try:
            proc3.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc3.kill()

    # 10. Round 30 — the property guard, live. A fresh daemon with
    # the Round 30 workdir records; a fake `resetprop` on PATH that
    # logs every invocation; a fake zygote (a python process with an
    # `--zygote` argv token that mmaps the fake bridge library, so
    # the daemon's REAL /proc/<pid>/maps check sees it mapped).
    run_prop_guard_checks(binary, tree, env)
    run_prop_guard_engine_checks(binary, tree, env)
    # ROUND 38: self-exit / inert backoff / orphan sweep /
    # live-uninstall integration.
    run_module_gone_checks(binary, env)
    run_inert_backoff_checks(binary, env)
    run_orphan_sweep_checks(binary, env)
    run_live_uninstall_checks(binary, env)


def start_fake_zygote(bridge_file):
    """A process whose cmdline carries the --zygote token and whose
    maps contain the bridge library (mmap'd read-only)."""
    script = ("import mmap, sys, time\n"
              "f = open(sys.argv[1], 'rb')\n"
              "m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)\n"
              "time.sleep(600)\n")
    return subprocess.Popen(
        [sys.executable, "-c", script, bridge_file, "--zygote"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_prop_guard_checks(binary, tree, env):
    print("== Round 30: property guard ==")
    # The workdir records post-fs-data.sh writes after a swap.
    backup = os.path.join(tree.workdir, ".native_bridge_backup")
    applied = os.path.join(tree.workdir, ".native_bridge_applied")
    with open(backup, "w") as f:
        f.write("0")            # the stock value on 169/173 devices
    BRIDGE = "libtest1234.so"
    with open(applied, "w") as f:
        f.write(BRIDGE)
    # The fake bridge library (only needs to exist + be mappable).
    bridge_file = os.path.join(tree.workdir, BRIDGE)
    with open(bridge_file, "wb") as f:
        f.write(b"\x7fELF-fake-bridge\n" * 8)
    # The fake resetprop: logs "resetprop <args...>" and succeeds.
    bindir = os.path.join(tree.root, "bin")
    os.makedirs(bindir, exist_ok=True)
    proplog = os.path.join(tree.root, "proplog.txt")
    resetprop = os.path.join(bindir, "resetprop")
    with open(resetprop, "w") as f:
        f.write(f"#!/bin/sh\necho \"$@\" >> {proplog}\nexit 0\n")
    os.chmod(resetprop, 0o755)

    e = dict(env)
    e["ZS_TEST_ROOT"] = tree.root
    e["ZS_TEST_POLL_MS"] = "100"
    # ROUND 34: exercise the post-restore SLOW cadence (death
    # detection + periodic census) at test speed — the device default
    # is 2 s and would make the replacement cycle crawl.
    e["ZS_TEST_SLOW_MS"] = "100"
    e["ZS_TEST_ZYGOTE_GRACE_MS"] = "600"
    e["PATH"] = bindir + ":" + e.get("PATH", "")
    e["ZS_PROP_LOG"] = proplog

    def log_lines():
        try:
            with open(proplog) as f:
                return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            return []

    zygotes = []

    def zygote_up():
        z = start_fake_zygote(bridge_file)
        zygotes.append(z)
        return z

    def zygote_down(z):
        z.kill()
        z.wait()
        zygotes.remove(z)

    def wait_for(pred, timeout=6.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.1)
        return False

    proc = subprocess.Popen(
        [binary, "--workdir", tree.workdir],
        env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # Wait for the daemon to be up (session file).
        deadline = time.time() + 5
        while time.time() < deadline and not os.path.exists(tree.session_file):
            time.sleep(0.05)

        # (a) zygote #1 up with the bridge mapped -> restore stock.
        z1 = zygote_up()
        ok = wait_for(lambda: any(
            l == f"ro.dalvik.vm.native.bridge 0" for l in log_lines()))
        check("guard restores stock value once the bridge is mapped",
              ok, str(log_lines()))

        # (b) zygote death -> re-apply the loader value.
        zygote_down(z1)
        ok = wait_for(lambda: any(
            l == f"ro.dalvik.vm.native.bridge {BRIDGE}" for l in log_lines()))
        check("guard re-applies the loader value after zygote death",
              ok, str(log_lines()))

        # (c) replacement zygote -> restore again (crash-restart cycle
        # works more than once).
        n_restore_before = sum(1 for l in log_lines()
                               if l.endswith(" 0"))
        z2 = zygote_up()
        ok = wait_for(lambda: sum(1 for l in log_lines()
                                  if l.endswith(" 0")) > n_restore_before)
        check("guard restores again for the replacement zygote",
              ok, str(log_lines()))

        # (d) bootloop policy: drive restarts past the limit. Each
        # death (re-apply) + replacement (restore) is one restart;
        # the 4th death must trigger the final rollback and stand
        # down: NO further re-applies afterwards.
        zygote_down(z2)                 # restart 2
        wait_for(lambda: sum(1 for l in log_lines()
                             if l.endswith(BRIDGE)) >= 2)
        z3 = zygote_up()                # restored for gen 3
        wait_for(lambda: sum(1 for l in log_lines()
                             if l.endswith(" 0")) >= 3)
        zygote_down(z3)                 # restart 3
        wait_for(lambda: sum(1 for l in log_lines()
                             if l.endswith(BRIDGE)) >= 3)
        z4 = zygote_up()                # restored for gen 4
        wait_for(lambda: sum(1 for l in log_lines()
                             if l.endswith(" 0")) >= 4)
        n_reapply = sum(1 for l in log_lines() if l.endswith(BRIDGE))
        zygote_down(z4)                 # restart 4 -> ROLLBACK + stop
        ok = wait_for(lambda: sum(1 for l in log_lines()
                                  if l.endswith(" 0")) >= 5)
        check("guard rolls back permanently after too many restarts",
              ok, str(log_lines()))
        time.sleep(1.0)
        n_reapply_after = sum(1 for l in log_lines() if l.endswith(BRIDGE))
        check("stood-down guard re-applies nothing further",
              n_reapply_after == n_reapply,
              f"{n_reapply} -> {n_reapply_after}")
        z5 = zygote_up()                # a healthy 5th generation
        time.sleep(1.0)
        n_restore_final = sum(1 for l in log_lines() if l.endswith(" 0"))
        check("stood-down guard stays inert for new zygotes",
              n_restore_final == 5, f"{n_restore_final} restores")
        zygote_down(z5)

        # (e) the daemon itself is still healthy after all this.
        reply = ask(read_session_path(tree), b"L")
        check("daemon still serves 'L' after the guard exercised",
              b"testmod" in reply, repr(reply))

        # (f) ROUND 34 (C8): the guard thread must still be ALIVE as
        # the zombie sweeper after RollbackAndStop — the old code
        # `return`ed from the thread, regressing child reaping to the
        # 30 s rescan tick exactly in the rolled-back state. 30
        # connections + the sweep interval (150 ms here) must leave
        # zero zombies.
        for _ in range(30):
            ask(read_session_path(tree), b"L")
        time.sleep(0.8)
        n_z = count_zombies(proc.pid)
        check("sweeper thread survives rollback (no zombies)",
              n_z == 0, f"{n_z} zombies after rollback")
    finally:
        for z in list(zygotes):
            try:
                z.kill()
                z.wait()
            except OSError:
                pass
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.unlink(proplog)
        except FileNotFoundError:
            pass

    # (f) empty backup -> --delete (absent, never an empty value:
    # the R28-verified ART semantics — "" is a warning-worthy
    # anomaly, absent is genuine stock).
    with open(backup, "w") as f:
        f.write("")
    proplog2 = os.path.join(tree.root, "proplog2.txt")
    with open(resetprop, "w") as f:
        f.write(f"#!/bin/sh\necho \"$@\" >> {proplog2}\nexit 0\n")
    e["ZS_PROP_LOG"] = proplog2
    proc = subprocess.Popen(
        [binary, "--workdir", tree.workdir],
        env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        while time.time() < deadline and not os.path.exists(tree.session_file):
            time.sleep(0.05)
        z = zygote_up()
        ok = wait_for(lambda: os.path.exists(proplog2) and any(
            l == "--delete ro.dalvik.vm.native.bridge"
            for l in open(proplog2).read().splitlines()))
        check("empty stock backup restores via --delete",
              ok, open(proplog2).read() if os.path.exists(proplog2) else "")
        zygote_down(z)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()




# ---------------------------------------------------------------------------
# ROUND 38 — the manual-removal self-exit (U2), the inert-mode guard
# backoff (P1, the GhostLock late-root shape), the crash-window orphan
# sweep (U2b), and the LIVE uninstall.sh integration (U1).
# ---------------------------------------------------------------------------

def start_plain_zygote():
    """A zygote-shaped process that does NOT map the bridge: the
    late-root / GhostLock shape (the daemon armed after the zygote
    booted; injection waits for the next zygote restart)."""
    script = "import time\ntime.sleep(600)\n"
    return subprocess.Popen(
        [sys.executable, "-c", script, "--zygote"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_guard_records(tree, backup="0", applied="libtest1234.so"):
    os.makedirs(tree.workdir, exist_ok=True)
    with open(os.path.join(tree.workdir, ".native_bridge_backup"), "w") as f:
        f.write(backup)
    with open(os.path.join(tree.workdir, ".native_bridge_applied"), "w") as f:
        f.write(applied)
    bridge_file = os.path.join(tree.workdir, applied)
    with open(bridge_file, "wb") as f:
        f.write(b"\x7fELF-fake-bridge\n" * 8)
    return bridge_file


def fake_resetprop_on(tree):
    bindir = os.path.join(tree.root, "bin")
    os.makedirs(bindir, exist_ok=True)
    proplog = os.path.join(tree.root, "proplog.txt")
    resetprop = os.path.join(bindir, "resetprop")
    with open(resetprop, "w") as f:
        f.write(f"#!/bin/sh\necho \"$@\" >> {proplog}\nexit 0\n")
    os.chmod(resetprop, 0o755)
    return bindir, proplog


def run_module_gone_checks(binary, env):
    """U2: `rm -rf /data/adb/modules/zygisk_study` (no manager script
    ever covers it) — the daemon notices the sustained absence,
    restores stock, removes every runtime artifact, exits."""
    print("== Round 38: module-gone self-exit ==")
    tmp = tempfile.mkdtemp(prefix="zs_gone_")
    tree = Tree(tmp)
    bridge_file = write_guard_records(tree)
    bindir, proplog = fake_resetprop_on(tree)
    try:
        e = dict(env)
        e["ZS_TEST_ROOT"] = tree.root
        e["ZS_TEST_MODULE_GRACE_MS"] = "400"
        e["PATH"] = bindir + ":" + e.get("PATH", "")
        proc = start_daemon(binary, tree, e)
        try:
            sock_dir = os.path.dirname(read_session_path(tree))
            check("daemon alive before the module dir is removed",
                  proc.poll() is None)
            shutil.rmtree(os.path.join(tree.modules_root, "zygisk_study"))
            deadline = time.time() + 10
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.1)
            check("daemon exited after sustained module absence",
                  proc.poll() is not None and proc.returncode == 0,
                  f"rc={proc.returncode}")
            check("stock property restored on self-exit",
                  "ro.dalvik.vm.native.bridge 0" in
                  [l.strip() for l in open(proplog) if l.strip()],
                  proplog)
            check("workdir removed on self-exit",
                  not os.path.exists(tree.workdir))
            check("random socket dir removed on self-exit",
                  not os.path.exists(sock_dir))
            check("module-dir session record removed on self-exit",
                  not os.path.exists(tree.session_file))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_inert_backoff_checks(binary, env):
    """P1: the GhostLock late-root shape. A stable zygote that never
    consumed the bridge flips the guard into INERT slow cadence
    (fast forever was the perf bug); death detection still works, a
    NEW bridge-mapping generation re-arms, consumes, restores."""
    print("== Round 38: inert-mode guard backoff ==")
    tmp = tempfile.mkdtemp(prefix="zs_inert_")
    tree = Tree(tmp)
    bridge_file = write_guard_records(tree)
    bindir, proplog = fake_resetprop_on(tree)
    trace = os.path.join(tree.root, "guard_trace.txt")
    try:
        e = dict(env)
        e["ZS_TEST_ROOT"] = tree.root
        e["ZS_TEST_POLL_MS"] = "100"
        e["ZS_TEST_SLOW_MS"] = "150"
        e["ZS_TEST_ZYGOTE_GRACE_MS"] = "500"
        e["ZS_TEST_INERT_AFTER_MS"] = "800"
        e["ZS_TEST_GUARD_TRACE"] = trace
        e["PATH"] = bindir + ":" + e.get("PATH", "")
        z1 = start_plain_zygote()
        proc = None
        try:
            proc = start_daemon(binary, tree, e)
            # Fast real observations, then the inert transition.
            deadline = time.time() + 8
            lines = []
            while time.time() < deadline:
                if os.path.exists(trace):
                    lines = [l.strip() for l in open(trace) if l.strip()]
                    if any(l == "SsI" for l in lines):
                        break
                time.sleep(0.1)
            check("guard drops to the inert slow cadence "
                  "(trace shows SsI)", any(l == "SsI" for l in lines),
                  repr(lines[-10:]))
            check("fast real observations ran before inert",
                  any(l == "Fr-" for l in lines), repr(lines[:10]))
            # Death detection in inert mode: kill the plain zygote
            # and WAIT for the guard to observe the Absent window and
            # re-arm (a fast replace would legitimately skip the
            # re-apply — the prop is still ours, unconsumed).
            z1.kill()
            z1.wait(timeout=5)
            deadline = time.time() + 8
            calls = []
            reapply = "ro.dalvik.vm.native.bridge libtest1234.so"
            while time.time() < deadline:
                if os.path.exists(proplog):
                    calls = [l.strip() for l in open(proplog) if l.strip()]
                    if reapply in calls:
                        break
                time.sleep(0.1)
            check("inert guard still detects death and re-arms",
                  reapply in calls, repr(calls))
            # NOW a BRIDGE-MAPPING generation: it consumes the
            # re-applied value and the guard restores stock — the
            # full late-root lifecycle (the GhostLock soft-reboot
            # shape).
            z2 = start_fake_zygote(bridge_file)
            try:
                deadline = time.time() + 10
                while time.time() < deadline:
                    if os.path.exists(proplog):
                        calls = [l.strip() for l in open(proplog)
                                 if l.strip()]
                        if "ro.dalvik.vm.native.bridge 0" in calls:
                            break
                    time.sleep(0.1)
                check("new generation consumes and restores stock",
                      "ro.dalvik.vm.native.bridge 0" in calls, repr(calls))
                if reapply in calls and "ro.dalvik.vm.native.bridge 0" in calls:
                    check("re-apply lands BEFORE the stock restore",
                          calls.index(reapply) <
                          calls.index("ro.dalvik.vm.native.bridge 0"))
                check("daemon still alive after the full cycle",
                      proc.poll() is None)
            finally:
                z2.kill()
                z2.wait(timeout=5)
        finally:
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if z1.poll() is None:
                z1.kill()
                z1.wait(timeout=5)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_orphan_sweep_checks(binary, env):
    """U2b: crash-window orphans — 8-hex dirs holding only our socket
    file are swept at daemon start; lookalikes are left alone."""
    print("== Round 38: crash-window orphan sweep ==")
    tmp = tempfile.mkdtemp(prefix="zs_orphan_")
    tree = Tree(tmp)
    try:
        base = os.path.join(tree.root, "data/system")
        # (a) a genuine orphan: 8-hex dir, only entry 's'.
        orphan = os.path.join(base, ".feedface")
        os.makedirs(orphan)
        open(os.path.join(orphan, "s"), "w").close()
        # (b) an EMPTY 8-hex dir (crash before the bind).
        empty = os.path.join(base, ".0badcafe")
        os.makedirs(empty)
        # (c) a foreign dir with the same naming class but other
        # content — must NOT be touched.
        foreign = os.path.join(base, ".1337c0de")
        os.makedirs(foreign)
        with open(os.path.join(foreign, "keepme"), "w") as f:
            f.write("x")
        # (d) 8 chars but not hex.
        nonhex = os.path.join(base, ".abcdefgh")
        os.makedirs(nonhex)
        proc = start_daemon(binary, tree, dict(env))
        try:
            time.sleep(0.4)
            check("orphan socket dir swept", not os.path.exists(orphan))
            check("empty crash-window dir swept", not os.path.exists(empty))
            check("foreign same-class dir untouched",
                  os.path.exists(os.path.join(foreign, "keepme")))
            check("non-hex lookalike untouched", os.path.exists(nonhex))
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_live_uninstall_checks(binary, env):
    """U1 integration: the REAL uninstall.sh against the REAL live
    daemon — pid-file kill by comm, property restore AFTER the death,
    every artifact cleaned."""
    print("== Round 38: live uninstall.sh vs the real daemon ==")
    tmp = tempfile.mkdtemp(prefix="zs_unins_")
    tree = Tree(tmp)
    bridge_file = write_guard_records(tree)
    bindir, proplog = fake_resetprop_on(tree)
    # The module dir needs the scripts uninstall.sh sources.
    moddir = os.path.join(tree.modules_root, "zygisk_study")
    for s in ("uninstall.sh", "zs_compat.sh", "post-mount-hook.sh"):
        shutil.copy(os.path.join(REPO_ROOT, s), os.path.join(moddir, s))
    try:
        e = dict(env)
        e["ZS_TEST_ROOT"] = tree.root
        e["PATH"] = bindir + ":" + e.get("PATH", "")
        proc = start_daemon(binary, tree, e)
        sock_dir = os.path.dirname(read_session_path(tree))
        try:
            check("daemon alive before uninstall",
                  proc.poll() is None)
            # IMPORTANT (found the hard way): the script's ZS_TEST_ROOT
            # IS the /data/system sysroot (the verify_scripts.py
            # convention), while the daemon's is a PATH PREFIX — pass
            # each consumer the convention it expects.
            script_env = {**os.environ,
                          "ZS_TEST_ROOT": os.path.join(tree.root,
                                                       "data", "system"),
                          "ZS_TEST_ADB_ROOT": os.path.join(tree.root,
                                                           "data", "adb"),
                          "PATH": bindir + ":" + os.environ.get("PATH", "")}
            u = subprocess.run(
                ["sh", os.path.join(moddir, "uninstall.sh")],
                env=script_env,
                capture_output=True, text=True, timeout=60)
            check("uninstall.sh exits 0 against the live daemon",
                  u.returncode == 0, u.stderr[-300:])
            deadline = time.time() + 5
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.1)
            check("uninstall.sh killed the real daemon (comm match)",
                  proc.poll() is not None)
            calls = []
            if os.path.exists(proplog):
                calls = [l.strip() for l in open(proplog) if l.strip()]
            check("uninstall restored the stock property",
                  "ro.dalvik.vm.native.bridge 0" in calls, repr(calls))
            check("uninstall removed the workdir",
                  not os.path.exists(tree.workdir))
            check("uninstall removed the random socket dir",
                  not os.path.exists(sock_dir))
            check("uninstall removed both session records",
                  not os.path.exists(tree.session_file) and
                  not os.path.exists(tree.session_file_alt))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_prop_guard_engine_checks(binary, tree, env):
    """Round 31: the guard's property writes with NO resetprop binary at
    all — the built-in engine (props.rs) mutates a bionic-shaped
    fixture property area directly, verified by a third (Python)
    implementation of the trie reader."""
    import struct
    print("== Round 31: property guard via the built-in engine ==")

    def build_area(path, props, total=8192):
        buf = bytearray(total)
        struct.pack_into("<IIII", buf, 0, 0, 0, 0x504f5250, 0xfc6ed0ab)
        used = 20 + 92

        def alloc_node(frag):
            nonlocal used
            off = used
            span = 20 + len(frag) + 1
            buf[128 + off:128 + off + span] = b"\0" * span
            struct.pack_into("<I", buf, 128 + off, len(frag))
            buf[128 + off + 20:128 + off + 20 + len(frag)] = frag.encode()
            used += (span + 3) & ~3
            return off

        def bst(root, frag):
            cur = root
            while True:
                nl = struct.unpack_from("<I", buf, 128 + cur)[0]
                nm = bytes(buf[128 + cur + 20:128 + cur + 20 + nl]).decode()
                if nm == frag:
                    return cur
                f = 8 if (len(frag), frag) < (len(nm), nm) else 12  # ROUND 34: bionic cmp_prop_name is (len, bytes)
                ch = struct.unpack_from("<I", buf, 128 + cur + f)[0]
                if ch:
                    cur = ch
                    continue
                off = alloc_node(frag)
                struct.pack_into("<I", buf, 128 + cur + f, off)
                return off

        for name, value in props:
            cur = 0
            frs = name.split(".")
            for i, fr in enumerate(frs):
                ch = struct.unpack_from("<I", buf, 128 + cur + 16)[0]
                if ch == 0:
                    off = alloc_node(fr)
                    struct.pack_into("<I", buf, 128 + cur + 16, off)
                    ch = off
                cur = bst(ch, fr)
                if i == len(frs) - 1:
                    pi = used
                    tot = 96 + len(name) + 1
                    buf[128 + pi:128 + pi + tot] = b"\0" * tot
                    struct.pack_into("<I", buf, 128 + pi, len(value) << 24)
                    buf[128 + pi + 4:128 + pi + 4 + len(value)] = value.encode()
                    buf[128 + pi + 96:128 + pi + 96 + len(name)] = name.encode()
                    used += (tot + 3) & ~3
                    struct.pack_into("<I", buf, 128 + cur + 4, pi)
        struct.pack_into("<I", buf, 0, used)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(bytes(buf))

    def read_prop(path, name):
        buf = open(path, "rb").read()

        def node(off):
            nl = struct.unpack_from("<I", buf, 128 + off)[0]
            nm = bytes(buf[128 + off + 20:128 + off + 20 + nl]).decode()
            prop, left, right, ch = struct.unpack_from("<IIII", buf, 128 + off + 4)
            return nm, prop, left, right, ch

        cur, prop = 0, 0
        rest = name
        while True:
            nm, prop, left, right, ch = node(cur)
            frag, sep, tail = rest.partition(".")
            if ch == 0:
                return None
            scan = ch
            found = None
            while scan:
                nm2, p2, l2, r2, c2 = node(scan)
                if nm2 == frag:
                    found = (scan, p2)
                    break
                scan = l2 if (len(frag), frag) < (len(nm2), nm2) else r2  # ROUND 34: bionic cmp_prop_name is (len, bytes)
            if not found:
                return None
            cur, prop = found
            if not sep:
                break
            rest = tail
        if prop == 0:
            return None
        serial = struct.unpack_from("<I", buf, 128 + prop)[0]
        ln = serial >> 24
        return bytes(buf[128 + prop + 4:128 + prop + 4 + ln]).decode()

    BRIDGE = "libengine98.so"
    backup = os.path.join(tree.workdir, ".native_bridge_backup")
    applied = os.path.join(tree.workdir, ".native_bridge_applied")
    with open(backup, "w") as f:
        f.write("0")
    with open(applied, "w") as f:
        f.write(BRIDGE)
    bridge_file = os.path.join(tree.workdir, BRIDGE)
    with open(bridge_file, "wb") as f:
        f.write(b"\x7fELF-fake-bridge\n" * 8)

    proot = os.path.join(tree.root, "props")
    area = os.path.join(proot, "u:object_r:dalvik_config_prop:s0")
    build_area(area, [("ro.dalvik.vm.native.bridge", BRIDGE),
                      ("ro.build.version.sdk", "36")])
    build_area(os.path.join(proot, "properties_serial"), [])

    e = dict(env)
    e["ZS_TEST_ROOT"] = tree.root
    e["ZS_TEST_POLL_MS"] = "100"
    # ROUND 34: exercise the post-restore SLOW cadence (death
    # detection + periodic census) at test speed — the device default
    # is 2 s and would make the replacement cycle crawl.
    e["ZS_TEST_SLOW_MS"] = "100"
    e["ZS_TEST_ZYGOTE_GRACE_MS"] = "600"
    e["ZS_PROP_ROOT"] = proot
    # NO resetprop anywhere: pure engine path.
    bindir = os.path.join(tree.root, "bin_noprop")
    os.makedirs(bindir, exist_ok=True)
    e["PATH"] = bindir + ":/system/bin:/usr/bin"

    zygotes = []

    def zygote_up():
        z = start_fake_zygote(bridge_file)
        zygotes.append(z)
        return z

    def wait_for(pred, timeout=6.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.1)
        return False

    proc = subprocess.Popen(
        [binary, "--workdir", tree.workdir],
        env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        while time.time() < deadline and not os.path.exists(tree.session_file):
            time.sleep(0.05)
        z1 = zygote_up()
        ok = wait_for(lambda: read_prop(area, "ro.dalvik.vm.native.bridge") == "0")
        check("guard restores stock THROUGH THE ENGINE (no resetprop)",
              ok, str(read_prop(area, "ro.dalvik.vm.native.bridge")))
        check("engine guard leaves other props intact",
              read_prop(area, "ro.build.version.sdk") == "36")
        z1.kill(); z1.wait()
        ok = wait_for(lambda: read_prop(
            area, "ro.dalvik.vm.native.bridge") == BRIDGE)
        check("guard re-applies the loader value through the engine",
              ok, str(read_prop(area, "ro.dalvik.vm.native.bridge")))
    finally:
        for z in list(zygotes):
            try:
                z.kill(); z.wait()
            except OSError:
                pass
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
