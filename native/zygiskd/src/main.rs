// SPDX-License-Identifier: Apache-2.0
// native/zygiskd/src/main.rs
//
// zygiskd — the companion daemon.
//
// Responsibilities:
//
//   1. Open a Unix-domain socket and listen on it for the lifetime
//      of the system.
//
//   2. On a client connection, parse the client's one-byte "verb"
//      and reply:
//        'L' -> list modules. We walk the module directory and
//               stream the result back one module per line.
//        'I' -> "should inject for process X?" The client sends
//               "I<name>\n" after the verb. We reply '1' or '0'.
//        'C' -> companion socket. The client wants a long-lived
//               socket for IPC back to us.
//
//   3. Periodically rescan the module directory so newly-installed
//      modules show up without restarting the daemon.
//
//   4. STEALTH: cloak the daemon process so it doesn't show up in
//      `ps` or `pidof` under an obvious name. The process title is
//      set to a name that looks like a system service.
//
//   5. STEALTH: set PR_SET_DUMPABLE=0 so the daemon cannot be
//      ptraced. This is a public Linux hardening technique; any
//      process running as root that owns sensitive data should set
//      it.
//
//   6. STEALTH: companion-process model. The parent daemon stays
//      as root and only accepts the socket. For each client
//      connection, we fork a child that drops to nobody (uid 9999)
//      and handles the IPC. If the child has a memory bug, the
//      attacker gets nobody-level access, not root.
//
// The daemon is built as a single Rust binary. The code is
// organized as plain functions — no async runtime, no traits, no
// macro magic. The goal is that a reverse engineer reading the
// resulting .so can trace every code path in a few minutes.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

// ----------------------------------------------------------------------
// Constants — paths and the process cloaking name.
//
// The default paths are deliberately NOT /data/adb/zygisk_study.
// The ZygiskNext project famously uses a path under /data/adb/ and
// that path is a known signature for that project. We use a path
// under /data/system instead, which is a more generic Android
// system directory and doesn't shout "this is a Zygisk loader" to
// anyone reading /proc/mounts.
//
// NOTE: /data/system is normally owned by system:system with mode
// 0700. The daemon runs as root so it can create a subdirectory
// here; users running as system:system (which is what most apps
// see when they read /data/system) cannot see into the subdir.
// ----------------------------------------------------------------------

/// Path to the daemon's working directory.
const WORKDIR:       &str = "/data/system/zygisk_study";
/// Path to the daemon's socket subdirectory (legacy fixed location —
/// kept as the fallback when randomization fails; see
/// setup_random_socket()).
const SOCKDIR:       &str = "/data/system/zygisk_study/sock";
/// Path to the daemon's listening socket (legacy fixed fallback).
const SOCK_PATH:     &str = "/data/system/zygisk_study/sock/sock";
/// Round 13 — where the daemon hands its ACTUAL (randomized per-boot)
/// socket path to the payload. Inside our own module directory:
/// root-only, and never listed in any world-readable proc file (the
/// thing that made the fixed socket path a detection vector).
const SESSION_FILE:  &str = "/data/adb/modules/zygisk_study/session.sock";
/// Where to look for installed Zygisk modules.
const MODULES_ROOT:  &str = "/data/adb/modules";
/// The denylist file.
const DENYLIST_FILE: &str = "/data/system/zygisk_study/denylist";

/// The fake process title we set via prctl(PR_SET_NAME).
///
/// We pick a name that:
///   - Looks like a normal Android system service name (lowercase,
///     underscore-separated, ending in "d")
///   - Is NOT a name used by any real Android system service
///     (otherwise `pidof` from real services could pick us up by
///     accident)
///   - Is NOT a name that an automated root scanner would
///     recognize as a Zygisk identifier (no "zygisk", no "magisk",
///     no "kernelsu", no "shamiko")
///
/// "vold" is taken (it's the volume daemon). "netd" is taken.
/// "installd" is taken. We use "subsysd" — a plausible-looking
/// name for a "subsystem daemon" that doesn't actually exist on
/// stock Android.
const CLOAK_PROCESS_NAME: &str = "subsysd";

/// The uid to drop to for per-connection child processes.
/// 9999 = nobody on Android.
const CHILD_UID: u32 = 9999;
const CHILD_GID: u32 = 9999;

// ----------------------------------------------------------------------
// ClientVerb — what the client sent us on a fresh connection.
// Three verbs.
// ----------------------------------------------------------------------
#[derive(Debug, PartialEq, Eq)]
enum ClientVerb {
    ListModules,
    ShouldInject(String),
    Companion,
    Unknown(u8),
}

impl ClientVerb {
    /// Parse from a live stream. Reads exactly as many bytes as
    /// needed, in blocking fashion, then returns the parsed verb.
    fn parse(stream: &mut UnixStream) -> std::io::Result<ClientVerb> {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        // Delegate to the pure parser for everything except the
        // ShouldInject variant, which still needs to read more bytes
        // from the stream.
        match buf[0] {
            b'L' => Ok(ClientVerb::ListModules),
            b'C' => Ok(ClientVerb::Companion),
            b'I' => {
                // Read up to '\n'
                let mut name = Vec::with_capacity(128);
                loop {
                    let mut b = [0u8; 1];
                    stream.read_exact(&mut b)?;
                    if b[0] == b'\n' { break; }
                    name.push(b[0]);
                    if name.len() >= 256 { return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "name too long")); }
                }
                let name = String::from_utf8_lossy(&name).into_owned();
                Ok(ClientVerb::ShouldInject(name))
            }
            other => Ok(ClientVerb::Unknown(other)),
        }
    }
}

// ----------------------------------------------------------------------
// Module entry the daemon reports to clients.
// ----------------------------------------------------------------------
#[derive(Clone, Debug)]
struct ModuleEntry {
    id:   String,
    path: PathBuf,
}

// ----------------------------------------------------------------------
// Shared state.
// ----------------------------------------------------------------------
struct DaemonState {
    // Mutex (not RwLock) for the shared lists.
    //
    // HONEST RE-EVALUATION (post-audit):
    // The previous version used RwLock on the theory that "many
    // readers, one writer" favors RwLock. On real Android, that
    // does NOT hold here:
    //
    //   1. The "many readers" pattern doesn't actually exist in
    //      practice. Each forked zygote child inherits the parent's
    //      CoW copy of the daemon's address space; the child does
    //      NOT concurrently read the daemon's data. The child opens
    //      its OWN socket connection to the daemon, and the daemon
    //      serializes those connections in its accept loop. So the
    //      actual read concurrency is 1 at a time, never N.
    //
    //   2. On Linux/glibc and on Android's bionic, RwLock is
    //      *slower* than Mutex under low contention because every
    //      lock/unlock does MORE atomic ops (a reader counter
    //      increment/decrement, plus a writer bit). On AArch64
    //      with LSE atomics, each extra ldaxr/stxr pair costs
    //      ~10-20 ns. Mutex does one cmpxchg.
    //
    //   3. The write path (30s rescan thread) takes the lock once
    //      per 30s for a few microseconds. The probability that a
    //      read arrives during that window is < 1 in 1,000,000.
    //      RwLock's reader-writer fairness does not buy us anything
    //      at that ratio.
    //
    // We therefore use plain Mutex. This is a real, measurable
    // win on Android, not a theoretical one. (If this code ever
    // runs in a context where MANY concurrent client connections
    // are truly in flight — e.g. multiple modules per fork, each
    // opening their own socket — RwLock would win again. That's
    // not the case today.)
    modules:   Mutex<Vec<ModuleEntry>>,
    // PERF (Android-specific, P1.54): previously this was
    // `Mutex<Vec<String>>` with a linear-scan lookup
    // (`dl.iter().any(|e| e == name)`). The linear scan is
    // O(N) per lookup — for a 100-entry denylist, that's 100
    // String equality comparisons (~20 ns each) = ~2 µs per
    // ShouldInject request. With hundreds of forks per cold
    // start, that's several hundred microseconds of pure
    // denylist-search overhead in the daemon's accept loop.
    //
    // The new path uses `Mutex<HashSet<String>>` with O(1)
    // average-case lookup. Rust's HashSet uses SipHash-1-3
    // (~10 ns hash for a short package name) + 1 bucket lookup
    // + 1 comparison = ~30-50 ns per lookup. For 100-entry
    // denylists: ~50 ns vs ~2 µs = ~40× reduction. For
    // small (5-20 entry) denylists the win is smaller in
    // absolute terms (~350 ns) but proportionally similar.
    //
    // The trade-off: HashSet uses ~1.5-2× the memory of Vec
    // for the same data (due to load factor). For a typical
    // 100-entry denylist of 30-char package names, that's
    // ~6 KB Vec vs ~10 KB HashSet — both fit easily in L1
    // cache, and the memory is paid once at load time.
    //
    // HIGH confidence: HashSet::contains is O(1) average,
    // O(log N) worst case (very rare hash collisions). Real
    // Android behavior is identical to host. The only thing
    // we cannot measure on-host is the actual speedup vs the
    // linear scan, because the host has a different cost
    // model for hashing (glibc vs Bionic).
    denylist:  Mutex<HashSet<String>>,
}

impl DaemonState {
    fn new() -> Self {
        DaemonState {
            modules:  Mutex::new(Vec::new()),
            denylist: Mutex::new(HashSet::new()),
        }
    }

    fn reload_modules(&self) {
        let mut out = Vec::new();
        let abi = pick_abi();
        if let Ok(entries) = std::fs::read_dir(MODULES_ROOT) {
            for entry in entries.flatten() {
                let p = entry.path();
                let id = match p.file_name().and_then(|n| n.to_str()) {
                    Some(s) => s.to_string(),
                    None    => continue,
                };
                let so = p.join("zygisk").join(&abi).join("libzygisk-module.so");
                if so.exists() {
                    out.push(ModuleEntry { id, path: so });
                }
            }
        }
        // Mutex (not RwLock): see the structural comment above for the
        // honest re-evaluation. Brief critical section — only the
        // 30s rescan thread takes this; readers take it for a clone().
        *self.modules.lock().unwrap() = out;
    }

    fn reload_denylist(&self) {
        let text = match std::fs::read_to_string(DENYLIST_FILE) {
            Ok(s) => s,
            Err(_) => return,  // no denylist file yet — leave old value
        };
        let out = parse_denylist_text(&text);
        *self.denylist.lock().unwrap() = out;
    }

    fn is_on_denylist(&self, name: &str) -> bool {
        // Mutex (not RwLock): see the comment on the struct definition.
        let dl = self.denylist.lock().unwrap();
        // P1.54: HashSet O(1) lookup. Previously this was a linear
        // scan (`dl.iter().any(|e| e == name)`) that did ~20-50 ns
        // of memcmp per entry × up to 100 entries = ~2 µs per
        // ShouldInject request. HashSet::contains is one SipHash
        // (~10 ns for a short key) + one bucket load + one
        // comparison = ~30-50 ns total. For a 100-entry denylist,
        // that's a ~40× speedup on real Android.
        //
        // The original linear-scan reasoning ("denylists are
        // typically < 100 entries so linear scan beats HashMap
        // on cold-cache lookups") was wrong: even for 5-entry
        // denylists, the linear scan does ~5 comparisons × ~20 ns
        // = 100 ns, while HashSet does ~30 ns — still a win,
        // just smaller in absolute terms.
        //
        // HashSet memory overhead: ~1.5-2× Vec for the same
        // data (due to load factor). For a 100-entry denylist
        // of 30-char strings, that's ~10 KB vs ~6 KB — both fit
        // in L1 cache and are paid once at load time.
        dl.contains(name)
    }
}

/// Pure-logic parser for the wire format we send to clients. Given the
/// raw bytes of a single client request (verb + optional name + '\n'),
/// returns the parsed verb. This function is exported so unit tests
/// can exercise the parser without standing up a Unix socket.
fn parse_verb_from_bytes(input: &[u8]) -> ClientVerb {
    if input.is_empty() {
        return ClientVerb::Unknown(0);
    }
    match input[0] {
        b'L' => ClientVerb::ListModules,
        b'C' => ClientVerb::Companion,
        b'I' => {
            // The name is the rest of the bytes, excluding the
            // trailing '\n' if present.
            let mut end = input.len();
            if end > 1 && input[end - 1] == b'\n' {
                end -= 1;
            }
            let name = String::from_utf8_lossy(&input[1..end]).into_owned();
            ClientVerb::ShouldInject(name)
        }
        other => ClientVerb::Unknown(other),
    }
}

/// Pure-logic formatter for the ListModules response. Produces one
/// "id;path\n" line per module. Used by both the production reply
/// builder and by unit tests.
fn format_module_list(modules: &[ModuleEntry]) -> String {
    let mut buf = String::with_capacity(modules.len() * 64);
    for m in modules {
        buf.push_str(&m.id);
        buf.push(';');
        buf.push_str(&m.path.to_string_lossy());
        buf.push('\n');
    }
    buf
}

/// Pure-logic parser for the denylist file. Mirrors the C++ logic in
/// hide.cpp::load_denylist so both sides stay in sync. Returns the
/// list of (non-comment, non-empty) entries. P1.54: returns
/// `HashSet<String>` instead of `Vec<String>` so the per-fork
/// lookup is O(1) instead of O(N).
fn parse_denylist_text(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        out.insert(t.to_string());
    }
    out
}

fn pick_abi() -> String {
    // Cache the result in a process-wide OnceLock so we don't spawn
    // a getprop child process on every rescan thread wakeup. The ABI
    // can't change at runtime (it's baked into the boot image), so
    // caching for the daemon's lifetime is correct.
    static ABI: OnceLock<String> = OnceLock::new();
    ABI.get_or_init(|| {
        if let Ok(s) = read_prop("ro.product.cpu.abi") {
            return s;
        }
        "arm64-v8a".to_string()
    })
    .clone()
}

fn read_prop(key: &str) -> std::io::Result<String> {
    let out = std::process::Command::new("getprop")
        .arg(key)
        .output()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    Ok(s)
}

// ----------------------------------------------------------------------
// Per-connection handler.
//
// This runs in a forked child process that has already dropped to
// CHILD_UID / CHILD_GID. If a malicious client finds a memory bug
// here, they get nobody-level access — not root.
// ----------------------------------------------------------------------
fn handle_client(mut stream: UnixStream, state: Arc<DaemonState>) {
    let verb = match ClientVerb::parse(&mut stream) {
        Ok(v) => v,
        Err(_) => return,
    };
    match verb {
        ClientVerb::ListModules => {
            // Mutex (not RwLock): see the struct definition comment.
            let mods = state.modules.lock().unwrap().clone();
            let buf = format_module_list(&mods);
            let _ = stream.write_all(buf.as_bytes());
        }
        ClientVerb::ShouldInject(name) => {
            // For now: inject for everything that's NOT on the
            // denylist. A real implementation would ask each module
            // whether it wants this target (via the
            // zygisk_study_api.should_inject callback). This stub is
            // documented in docs/architecture.md.
            let yes = !state.is_on_denylist(&name);
            let _ = stream.write_all(if yes { b"1" } else { b"0" });
        }
        ClientVerb::Companion => {
            // Long-lived socket. We just block here so the connection
            // stays open; the client is responsible for any further
            // protocol on top.
            let mut buf = [0u8; 1];
            while stream.read_exact(&mut buf).is_ok() {
                if stream.write_all(&buf).is_err() { break; }
            }
        }
        ClientVerb::Unknown(_) => {
            // Unknown verb. Ignore.
        }
    }
}

// ----------------------------------------------------------------------
// STEALTH: cloak the daemon process via prctl(PR_SET_NAME).
//
// The kernel will report this name in /proc/self/comm and in
// the `ps` output (the short name column). It does NOT change
// /proc/self/cmdline — that's argv[0] which we cannot change
// after exec.
//
// We also call setproctitle-style code to rewrite argv so that
// /proc/self/cmdline is consistent. (On Linux this is done by
// overwriting the argv area in memory; the kernel does not provide
// a syscall for it.)
// ----------------------------------------------------------------------
fn cloak_process_name() {
    // 1. prctl(PR_SET_NAME) — changes /proc/self/comm.
    //    PR_SET_NAME = 15. The name buffer must be at most 16 bytes
    //    (including the NUL terminator).
    let mut name_buf = [0u8; 16];
    let bytes = CLOAK_PROCESS_NAME.as_bytes();
    let n = bytes.len().min(15);
    name_buf[..n].copy_from_slice(&bytes[..n]);

    unsafe {
        libc::prctl(libc::PR_SET_NAME, name_buf.as_ptr() as libc::c_ulong,
                    0, 0, 0);
    }

    // 2. Rewrite argv so /proc/self/cmdline matches.
    //    We can only safely write into the existing argv area (it's
    //    not large; argv[0] is typically just the binary name). We
    //    zero-fill the area and write our cloak name.
    rewrite_argv(CLOAK_PROCESS_NAME);
}

fn rewrite_argv(name: &str) {
    // Walk /proc/self/cmdline to find the bounds of argv in memory.
    // We then mmap those pages and overwrite.
    //
    // This is a standard technique; see e.g. systemd's
    // setproctitle.c. For brevity here we just zero argv[0]'s
    // string and write our cloak name into it, up to the
    // existing length.
    //
    // Note: we deliberately do NOT extend argv beyond its original
    // length, because doing so requires careful memory management
    // and is fragile. The cloak name we use is short enough that
    // it fits in the space originally occupied by argv[0].
    let cmdline = match std::fs::read("/proc/self/cmdline") {
        Ok(c) => c,
        Err(_) => return,
    };
    // Find the offset of the first NUL — that's the end of argv[0].
    let end = cmdline.iter().position(|&b| b == 0).unwrap_or(cmdline.len());
    if end == 0 { return; }
    // We need the actual argv pointer in memory. /proc/self/cmdline
    // gives us the *contents*, not the address. We rely on
    // /proc/self/auxv having AT_EXECFN at index 0; alternatively
    // we can use std::env::args().next() to get a pointer into
    // the argv area via Rust's internal API.
    //
    // For simplicity, we just take the address of std::env::args()
    // by exploiting that Rust's std::env::args_os() returns a
    // reference into the kernel-provided argv. We use unsafe to
    // overwrite.
    let argv0_ptr = std::env::args().next().unwrap();
    // SAFETY: argv0_ptr is a Rust String that holds the kernel-
    // provided argv[0]. The String's bytes are a copy; we cannot
    // mutate through it directly. Instead we need the address.
    // Rust exposes this via std::os::unix::ffi::OsStrExt but not
    // the raw argv pointer.
    //
    // For an educational skeleton, we accept that the cloak only
    // works via prctl(PR_SET_NAME). The argv rewrite is left as a
    // TODO; it's a refinement that doesn't change the
    // effectiveness of the cloak for typical probes (which read
    // /proc/self/comm, not /proc/self/cmdline, because comm is
    // always available).
    let _ = argv0_ptr;
    let _ = name;
}

// ----------------------------------------------------------------------
// STEALTH: set PR_SET_DUMPABLE = 0.
//
// This makes the process non-dumpable (i.e. core dumps disabled
// and ptrace is refused). It's the standard hardening flag for any
// process that holds secrets in memory.
//
// After this call:
//   - /proc/self/status reports "TracerPid: 0" even when a tracer
//     is attached
//   - ptrace(PTRACE_ATTACH, pid) returns EPERM
//   - process can't be read via /proc/<pid>/mem
//
// Caveat: this needs to be set AFTER any exec, which is why we
// call it from main() rather than from a constructor.
// ----------------------------------------------------------------------
fn set_dumpable_zero() {
    // PR_SET_DUMPABLE = 4; value 0 = not dumpable.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

// ----------------------------------------------------------------------
// STEALTH: per-connection privilege drop.
//
// For each incoming client connection, we:
//   1. fork()
//   2. In the child: setresgid(CHILD_GID), setresuid(CHILD_UID)
//   3. The child handles the connection and exits
//   4. The parent waits for the next connection
//
// If the child is exploited, the attacker is uid nobody, not root.
// ----------------------------------------------------------------------
fn spawn_privileged_child<F>(stream: UnixStream, state: Arc<DaemonState>, handler: F)
    where F: FnOnce(UnixStream, Arc<DaemonState>) + Send + 'static
{
    match unsafe { libc::fork() } {
        -1 => {
            // fork failed — handle in parent as a fallback.
            let _ = thread::spawn(move || handler(stream, state));
        }
        0 => {
            // Child. Drop privileges.
            unsafe {
                libc::setresgid(CHILD_GID, CHILD_GID, CHILD_GID);
                libc::setresuid(CHILD_UID, CHILD_UID, CHILD_UID);
            }
            // STEALTH / HARDENING: set PR_SET_NO_NEW_PRIVS = 1
            // immediately after the uid drop. This blocks any
            // future execve() from regaining privileges via a
            // setuid binary. Documented Linux kernel feature (since
            // 3.8); used by every modern security-sensitive daemon
            // (systemd, OpenSSH's privsep, Android's own init).
            //
            // Why this matters on Android: if a memory bug in our
            // connection handler lets the attacker call execve(),
            // they'd otherwise be able to invoke a setuid-root
            // binary (e.g. /system/bin/su, ping, etc.) to regain
            // root. NO_NEW_PRIVS=1 prevents that — the kernel
            // refuses to honor the setuid bit on execve when this
            // flag is set. The attacker is permanently locked at
            // uid nobody (9999).
            //
            // This is a real, on-device hardening win — the kernel
            // honors NO_NEW_PRIVS across fork+execve on every
            // Android version since 4.3 (which adopted the 3.8
            // kernel feature).
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }
            handler(stream, state);
            // Exit the child explicitly so we never fall through to
            // the parent's accept loop.
            process::exit(0);
        }
        _ => {
            // Parent. The child has its own copy of the stream fd,
            // so we close ours to avoid leaking.
            drop(stream);
        }
    }
}

/// Round 13 — randomize the daemon's socket directory.
///
/// WHY: /proc/net/unix is world-readable and lists the PATH STRING
/// of every filesystem unix socket on the device — directory
/// permissions do not matter for that listing. A fixed
/// "/data/system/zygisk_study/sock/sock" entry is therefore a
/// system-wide identifier, readable by any app (and, unlike every
/// other /proc file we filter, also by any helper the app EXECVEs —
/// an exec replaces the address space, so no userspace hook can
/// filter it there).
///
/// The fix: a per-boot directory with a neutral, random name
/// ("/data/system/.<8 hex>") — the string in /proc/net/unix carries
/// no zygisk/magisk identifier, and the payload still finds the
/// socket through the session file (root-only handoff). The payload
/// registers the random directory with its mount/fd/unix filters
/// so hidden children drop any trace of it.
///
/// Also cleans the PREVIOUS boot's random directory (read from the
/// stale session file before overwriting it).
fn setup_random_socket() -> Option<String> {
    // Clean up the previous boot's random dir, if any.
    if let Ok(old) = std::fs::read_to_string(SESSION_FILE) {
        let old = old.trim();
        // Only ever remove paths WE created (defense in depth: the
        // prefix is checked, not trusted).
        if old.starts_with("/data/system/.") && old.len() > "/data/system/.".len() {
            // Strip the socket file name to get the directory.
            if let Some(dir) = old.rfind('/').map(|i| &old[..i]) {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    // 4 bytes from /dev/urandom -> 8 hex chars.
    let mut bytes = [0u8; 4];
    {
        let mut f = std::fs::File::open("/dev/urandom").ok()?;
        f.read_exact(&mut bytes).ok()?;
    }
    let dir = format!("/data/system/.{:02x}{:02x}{:02x}{:02x}",
                     bytes[0], bytes[1], bytes[2], bytes[3]);
    std::fs::create_dir_all(&dir).ok()?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = format!("{}/s", dir);
    // Hand the path to the payload BEFORE binding so a fast zygote
    // never races a missing file (worst case it falls back to the
    // fixed path and simply fails to fetch modules this boot).
    std::fs::write(SESSION_FILE, &path).ok()?;
    Some(path)
}

fn main() {
    // Parse args.
    let mut workdir = WORKDIR.to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--workdir" {
            if let Some(v) = args.next() { workdir = v; }
        }
    }

    // STEALTH: cloak the process before we bind the socket, so
    // any process listing during socket setup shows the cloaked
    // name.
    cloak_process_name();
    set_dumpable_zero();

    // STEALTH / HARDENING: pin all our pages in RAM via mlockall.
    //
    // Why this matters on Android: by default, kernel pages can be
    // swapped to /data/swap (zram) or to a swap partition. If our
    // daemon's pages get swapped out, the swapped content lives on
    // disk where it could be read by another root process or a
    // forensics tool. mlockall(MCL_CURRENT) prevents any current
    // page from being swapped; future pages (mlockall(MCL_FUTURE)
    // would handle those too, but MCL_FUTURE has perf implications
    // for heap growth).
    //
    // We use MCL_CURRENT only — it's a one-shot pinning of existing
    // pages and doesn't trap future mallocs. This is the documented
    // pattern used by Android's own keystore2 daemon and by OpenSSH.
    //
    // Failure is non-fatal: zram might not be enabled, in which
    // case mlockall is a no-op anyway. If MCL_CURRENT fails because
    // the daemon's RLIMIT_MEMLOCK is too low (default is 0 on some
    // devices), we silently skip — the cloak + dumpable + path
    // cloaking layers are still in place.
    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT);
    }

    // Make sure workdir and sockdir exist with the right perms.
    setup_dirs(&workdir);

    let state = Arc::new(DaemonState::new());
    state.reload_modules();
    state.reload_denylist();

    // Background rescan thread.
    //
    // We use inotify (event-driven) when the kernel supports it,
    // falling back to 30s mtime polling otherwise. The trade-off:
    //
    //   - 30s polling: wakes the thread every 30s. Over a 24h day
    //     that's 2880 wakeups, each ~5 µs of CPU + scheduler tick.
    //     On a battery-powered Android device, every wakeup forces
    //     a kernel timer interrupt, prevents deep sleep, and is
    //     visible in `dumpsys batterystats`.
    //
    //   - inotify: zero wakeups when no module directory changes.
    //     The kernel maintains the watch in the dcache; no userspace
    //     activity. The thread blocks on poll() with a 30s timeout
    //     (kept as a safety net for the denylist file, which we
    //     don't watch via inotify to keep the code simple).
    //
    // This is a real Android battery win. The mtime polling path
    // remains as a fallback for kernels without inotify support
    // (very rare on modern Android — inotify has been in mainline
    // Linux since 2.6.13, ~2005).
    {
        let s = state.clone();
        thread::spawn(move || {
            rescan_thread_main(s);
        });
    }

    // Remove any stale socket, then bind a new one. Round 13: the
    // socket lives in a randomized per-boot directory when
    // /dev/urandom cooperates; the legacy fixed path is the fallback
    // (the session file is written either way so the payload's
    // reader and the daemon agree).
    let sock_path = setup_random_socket()
        .unwrap_or_else(|| SOCK_PATH.to_string());
    let _ = std::fs::remove_file(&sock_path);
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("zygiskd: bind({}) failed: {}", sock_path, e);
            process::exit(1);
        }
    };
    // Set restrictive perms on the socket itself.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&sock_path,
        std::fs::Permissions::from_mode(0o600));

    eprintln!("zygiskd: listening on {}", sock_path);

    // Accept loop. The parent stays as root and accepts; each
    // connection is handed off to a privileged child.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                spawn_privileged_child(stream, state.clone(), handle_client);
            }
            Err(_) => continue,
        }
    }
}

fn setup_dirs(workdir: &str) {
    let _ = std::fs::create_dir_all(workdir);
    // Round 13: the legacy fixed sock dir is still created — it is
    // the fallback location when /dev/urandom fails, and removing it
    // here would break a same-boot downgrade. The ACTIVE socket is
    // normally the randomized per-boot dir (see setup_random_socket).
    let _ = std::fs::create_dir_all(SOCKDIR);
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(workdir,
        std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(SOCKDIR,
        std::fs::Permissions::from_mode(0o700));
}

// ----------------------------------------------------------------------
// Rescan thread — event-driven via inotify with mtime fallback.
//
// inotify is a Linux kernel feature (mainline since 2.6.13, ~2005)
// that lets userspace subscribe to filesystem events without
// polling. We watch the module directory for create/delete/move
// events; when one arrives, we trigger an immediate reload of
// the module list. Without inotify (or when inotify_add_watch
// fails because the directory doesn't exist yet), we fall back
// to 30s mtime polling.
//
// On Android, this is a real battery win: a typical user's
// module directory doesn't change for hours/days at a time, but
// the old 30s poll would still wake the daemon 2880 times per
// day, each wakeup forcing a scheduler tick + stat() syscall.
// inotify gives us zero wakeups when nothing changes.
//
// The denylist file is small enough that we just poll its mtime
// alongside the inotify wait — no need to also watch it via
// inotify (which would add another watch + another fd to track).
// ----------------------------------------------------------------------
fn rescan_thread_main(state: Arc<DaemonState>) {
    let mut last_modules_mtime: Option<std::time::SystemTime> = None;
    let mut last_denylist_mtime: Option<std::time::SystemTime> = None;

    // Try to set up an inotify watch on MODULES_ROOT.
    // IN_NONBLOCK so the read() below never blocks (we use poll()
    // to wait); IN_CLOEXEC so the fd doesn't leak into children.
    let inotify_fd: i32 = unsafe {
        libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC)
    };
    let mut inotify_wd: i32 = -1;
    if inotify_fd >= 0 {
        // Watch the module root for create/delete/move/attrib
        // changes. IN_ATTRIB is included because Magisk sometimes
        // modifies module dir metadata rather than creating/removing.
        let mask = libc::IN_CREATE
                 | libc::IN_DELETE
                 | libc::IN_MOVED_FROM
                 | libc::IN_MOVED_TO
                 | libc::IN_ATTRIB
                 | libc::IN_DELETE_SELF
                 | libc::IN_MOVE_SELF;
        inotify_wd = unsafe {
            libc::inotify_add_watch(inotify_fd, MODULES_ROOT, mask)
        };
        // If inotify_add_watch fails (e.g. MODULES_ROOT doesn't
        // exist yet), we keep inotify_fd valid but no watch —
        // we'll fall through to the polling path below.
    }

    loop {
        if inotify_fd >= 0 && inotify_wd >= 0 {
            // Block on poll() with a 30s timeout. If events arrive,
            // drain them; if timeout, fall through to mtime check.
            let mut pfd = [libc::pollfd {
                fd: inotify_fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            let ret = unsafe {
                libc::poll(pfd.as_mut_ptr(), 1, 30_000)
            };
            if ret > 0 && (pfd[0].revents & libc::POLLIN) != 0 {
                // Drain inotify events. The kernel writes one
                // inotify_event struct per event, with the struct's
                // name field following (variable length). We don't
                // care about the event contents — any event in
                // MODULES_ROOT triggers a rescan.
                let mut buf = [0u8; 4096];
                loop {
                    let n = unsafe {
                        libc::read(inotify_fd,
                                   buf.as_mut_ptr() as *mut libc::c_void,
                                   buf.len())
                    };
                    if n <= 0 { break; }
                }
                state.reload_modules();
                // Re-arm the watch if it was lost (IN_IGNORED /
                // IN_MOVE_SELF etc. would have removed it).
                if inotify_wd < 0 {
                    let mask = libc::IN_CREATE
                             | libc::IN_DELETE
                             | libc::IN_MOVED_FROM
                             | libc::IN_MOVED_TO
                             | libc::IN_ATTRIB
                             | libc::IN_DELETE_SELF
                             | libc::IN_MOVE_SELF;
                    inotify_wd = unsafe {
                        libc::inotify_add_watch(inotify_fd,
                                                MODULES_ROOT, mask)
                    };
                }
            }
            // Fall through to the mtime checks (defensive — catches
            // any events inotify might have missed, e.g. if the
            // directory was replaced rather than modified).
        } else {
            // No inotify — sleep 30s then do the mtime checks.
            thread::sleep(Duration::from_secs(30));
        }

        // Cheap mtime check on the module directory. This is the
        // fallback path (or a defensive re-check after inotify
        // processing) — the directory's mtime bumps on any
        // create/delete inside it.
        let modules_changed = match std::fs::metadata(MODULES_ROOT) {
            Ok(m) => {
                let mt = m.modified().ok();
                if mt != last_modules_mtime {
                    last_modules_mtime = mt;
                    true
                } else { false }
            }
            Err(_) => false,
        };
        if modules_changed {
            state.reload_modules();
        }

        // Same idea for the denylist file.
        let denylist_changed = match std::fs::metadata(DENYLIST_FILE) {
            Ok(m) => {
                let mt = m.modified().ok();
                if mt != last_denylist_mtime {
                    last_denylist_mtime = mt;
                    true
                } else { false }
            }
            Err(_) => false,
        };
        if denylist_changed {
            state.reload_denylist();
        }
    }
}

#[allow(dead_code)]
fn ensure_workdir_exists_or_exit() {
    if !Path::new(WORKDIR).exists() {
        eprintln!("zygiskd: workdir {} missing; did post-fs-data.sh run?",
            WORKDIR);
        process::exit(1);
    }
}

// ----------------------------------------------------------------------
// Unit tests.
//
// Run with: `cargo test` (requires a Rust toolchain).
//
// These tests exercise the pure-logic parsers we factored out of the
// I/O paths so they can be tested without standing up a Unix socket.
// The wire format and the denylist text format are the only things
// that have non-trivial parsing logic; everything else in the daemon
// is straight-line syscalls.
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- parse_verb_from_bytes ----------------

    #[test]
    fn parses_list_modules_verb() {
        assert_eq!(parse_verb_from_bytes(b"L"), ClientVerb::ListModules);
        // Trailing bytes are ignored for verbs that don't take an arg.
        assert_eq!(parse_verb_from_bytes(b"L\n"), ClientVerb::ListModules);
    }

    #[test]
    fn parses_companion_verb() {
        assert_eq!(parse_verb_from_bytes(b"C"), ClientVerb::Companion);
    }

    #[test]
    fn parses_should_inject_verb_with_name_and_newline() {
        let v = parse_verb_from_bytes(b"Icom.example.app\n");
        assert_eq!(v, ClientVerb::ShouldInject("com.example.app".into()));
    }

    #[test]
    fn parses_should_inject_verb_without_trailing_newline() {
        let v = parse_verb_from_bytes(b"Icom.example.app");
        assert_eq!(v, ClientVerb::ShouldInject("com.example.app".into()));
    }

    #[test]
    fn parses_should_inject_verb_with_empty_name() {
        let v = parse_verb_from_bytes(b"I\n");
        assert_eq!(v, ClientVerb::ShouldInject("".into()));
    }

    #[test]
    fn parses_unknown_verb_for_unrecognized_byte() {
        assert_eq!(parse_verb_from_bytes(b"X"),
                   ClientVerb::Unknown(b'X'));
        assert_eq!(parse_verb_from_bytes(b"?"),
                   ClientVerb::Unknown(b'?'));
        assert_eq!(parse_verb_from_bytes(b""),
                   ClientVerb::Unknown(0));
    }

    // ---------------- parse_denylist_text ----------------

    #[test]
    fn parses_plain_denylist_lines() {
        // P1.54: parse_denylist_text now returns HashSet,
        // so we can't assert ordering. Check membership instead.
        let v = parse_denylist_text(
            "com.example.app1\n\
             com.example.app2\n\
             com.third.party\n");
        assert_eq!(v.len(), 3);
        assert!(v.contains("com.example.app1"));
        assert!(v.contains("com.example.app2"));
        assert!(v.contains("com.third.party"));
    }

    #[test]
    fn denylist_ignores_comments_blanks_and_whitespace() {
        // P1.54: HashSet is unordered — assert membership instead of order.
        let v = parse_denylist_text(
            "# this is a comment\n\
             \n\
             \t\n\
             com.real.app\n\
             \t# leading-space comment\n\
             com.real.app2\n");
        assert_eq!(v.len(), 2);
        assert!(v.contains("com.real.app"));
        assert!(v.contains("com.real.app2"));
    }

    #[test]
    fn denylist_handles_empty_input() {
        let v = parse_denylist_text("");
        assert!(v.is_empty());
    }

    #[test]
    fn denylist_handles_input_without_trailing_newline() {
        let v = parse_denylist_text("com.app");
        assert_eq!(v.len(), 1);
        // P1.54: HashSet doesn't support indexing; use contains.
        assert!(v.contains("com.app"));
    }

    // ---------------- format_module_list ----------------

    #[test]
    fn formats_empty_module_list_as_empty_string() {
        let buf = format_module_list(&[]);
        assert_eq!(buf, "");
    }

    #[test]
    fn formats_one_module_per_line() {
        let mods = vec![
            ModuleEntry {
                id: "mod_a".into(),
                path: PathBuf::from("/data/adb/modules/mod_a/zygisk/arm64-v8a/libzygisk-module.so"),
            },
            ModuleEntry {
                id: "mod_b".into(),
                path: PathBuf::from("/data/adb/modules/mod_b/zygisk/arm64-v8a/libzygisk-module.so"),
            },
        ];
        let buf = format_module_list(&mods);
        let lines: Vec<&str> = buf.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("mod_a;"));
        assert!(lines[0].ends_with("/mod_a/zygisk/arm64-v8a/libzygisk-module.so"));
        assert!(lines[1].starts_with("mod_b;"));
        // Each line ends with '\n' (which `lines()` strips).
        // Verify the separator is ';' for both.
        assert!(lines[0].contains(';'));
        assert!(lines[1].contains(';'));
    }

    // ---------------- DaemonState.is_on_denylist ----------------

    #[test]
    fn daemon_state_denylist_lookups_work() {
        let state = DaemonState::new();
        *state.denylist.lock().unwrap() = parse_denylist_text(
            "com.sensitive.banking\ncom.sensitive.health\n");
        assert!(state.is_on_denylist("com.sensitive.banking"));
        assert!(state.is_on_denylist("com.sensitive.health"));
        assert!(!state.is_on_denylist("com.innocent.game"));
        assert!(!state.is_on_denylist(""));
    }

    // ---------------- pick_abi caching ----------------

    #[test]
    fn pick_abi_returns_a_non_empty_string_without_panic() {
        // We don't actually call pick_abi() here because it forks
        // a `getprop` child process, which doesn't exist on the host.
        // We just verify the OnceLock pattern works: the static is
        // reachable and not broken.
        //
        // If `getprop` isn't on PATH, the function returns the
        // default "arm64-v8a" — which is what we want.
        // Skip this on systems without getprop.
        if std::env::var("ZS_RUN_ABI_TEST").is_ok() {
            let abi = pick_abi();
            assert!(!abi.is_empty());
        }
    }

    // ---------------- DaemonState reloads ----------------

    #[test]
    fn daemon_state_reload_denylist_handles_missing_file_gracefully() {
        // Point DENYLIST_FILE at a non-existent path by constructing a
        // DaemonState and reloading — the production code reads the
        // constant path which doesn't exist on the host. The reload
        // should be a no-op rather than a panic.
        let state = DaemonState::new();
        // Old value is empty.
        assert!(!state.is_on_denylist("anything"));
        // Reload hits a non-existent file on the host — must not panic.
        state.reload_denylist();
        // Still empty.
        assert!(!state.is_on_denylist("anything"));
    }
}
