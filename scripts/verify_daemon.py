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


if __name__ == "__main__":
    main()
