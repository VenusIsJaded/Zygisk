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

    # 7. zombies (SIGCHLD fix).
    for _ in range(10):
        ask(sock_path, b"L")
    time.sleep(0.4)
    n = count_zombies(pid)
    check("no zombie children after 10 connections", n == 0, f"{n} zombies")

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
                f = 8 if frag < nm else 12
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
                scan = l2 if frag < nm2 else r2
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
