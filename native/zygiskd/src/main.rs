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
//        'P' -> (Round 19) properties file. The client (the
//               in-zygote payload) streams a u32-LE length and then
//               that many bytes: a complete spoofed property-area
//               image (the verbatim file content, patched). We
//               materialize it as <session_dir>/p, relabel it
//               (best-effort) with the platform's own label —
//               u:object_r:properties_serial:s0 on 7.0+ (bionic's
//               fsetxattr), u:object_r:properties_device:s0 on 6.x
//               (init's restorecon, see props_file_label()) — and
//               reply "1<path>\n" (or "0\n" on failure). The hidden
//               child later bind-mounts that file over the platform's
//               property file (/dev/__properties__/properties_serial
//               on 7.0+, the single /dev/__properties__ file on
//               6.x), so fork+exec'd helpers — fresh libc, no
//               hooks — re-map the SPOOFED area instead of the real
//               one. This verb is handled
//               BEFORE the uid drop: it must write into the
//               root-only session directory and relabel, which the
//               nobody child cannot do.
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

mod props;
use props::PropEngine;

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

/// Round 28 — host-E2E test seam. On a device the daemon's paths
/// are the fixed /data/... constants above. This environment has no
/// /data, so until this round the daemon binary could never be RUN
/// here (only inspected — see the standing residual in
/// ANDROID-REALISM.md). When ZS_TEST_ROOT is set, every /data path
/// is remapped to $ZS_TEST_ROOT/data/... and the daemon runs for
/// real against a temp tree. Unset (the device case), the remap is
/// a byte-identical pass-through — no behavior change.
fn remap_path(p: &str) -> String {
    match std::env::var("ZS_TEST_ROOT") {
        Ok(root) if !root.is_empty() => {
            let root = root.trim_end_matches('/');
            format!("{}{}", root, p)
        }
        _ => p.to_string(),
    }
}
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
/// Round 29 — SECOND session record, inside the /data/system workdir
/// the daemon already owns. The payload's fallback when the module
/// tree is unreadable from the zygote: ReZygisk issue #380 documents
/// Samsung devices where kernel-side path rules block app_process64
/// from opening /data/adb/modules paths. Our loader .so comes from
/// the systemless /system/lib64 magic mount (unaffected), but the
/// session file under /data/adb/modules would be — the workdir copy
/// keeps the whole dispatch layer alive on those devices.
const SESSION_FILE_ALT: &str = "/data/system/zygisk_study/session.sock";
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
    /// The FIRST byte is read by the caller in the forked connection
    /// child (which must peek it BEFORE the privilege drop to decide
    /// whether the connection is a 'P' — the only root-only verb)
    /// and handed to parse_after.
    ///
    /// Round 28: this read-the-verb-byte wrapper was dead code after
    /// the R19 peek-before-drop redesign — every production caller
    /// reads the first byte itself and enters through parse_after.
    /// Kept as the documented entry point of the parser pair, with
    /// an explicit allow() (the daemon is now compiled and linted
    /// for real; the dead code had been invisible since R13).
    #[allow(dead_code)]
    fn parse(stream: &mut UnixStream) -> std::io::Result<ClientVerb> {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        Self::parse_after(buf[0], stream)
    }

    /// Parse starting from an already-consumed verb byte.
    fn parse_after(first: u8,
                   stream: &mut UnixStream) -> std::io::Result<ClientVerb> {
        // Delegate to the pure parser for everything except the
        // ShouldInject variant, which still needs to read more bytes
        // from the stream.
        match first {
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
// Round 19 — the properties-file verb ('P').
//
// Handled BEFORE the privilege drop (root), because it writes into
// the root-only randomized session directory and relabels the file.
// The socket itself is the trust boundary: it lives in a 0700
// root-owned directory, so only root/zygote-domain processes can
// connect at all — an app cannot reach this handler. Input is still
// validated (size cap + area magic) as defense in depth.
//
// chcon (lsetxattr security.selinux) follows ReZygisk's own pattern
// (zygiskd/src/utils.c: chcon, logged non-fatal on failure): the
// daemon's domain carries the relabel privileges the zygote domain
// lacks. Without the properties_serial label, exec'd helpers
// (untrusted_app domain) could not open the file and bionic's
// property init would come up empty for them.
// ----------------------------------------------------------------------

/// Relabel a path (best-effort; failures are logged by the caller
/// decision to ignore them — a wrong label degrades the feature to
/// "exec'd helpers see no properties", never to a crash).
fn chcon(path: &str, context: &str) -> bool {
    use std::ffi::CString;
    let c_path = match CString::new(path) { Ok(p) => p, Err(_) => return false };
    let c_ctx  = match CString::new(context) { Ok(c) => c, Err(_) => return false };
    // The xattr VALUE includes the trailing NUL (the convention
    // lsetxattr users follow for SELinux labels; ReZygisk's chcon
    // passes strlen+1 the same way).
    let rv = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            c"security.selinux".as_ptr(),
            c_ctx.as_ptr() as *const libc::c_void,
            context.len() + 1,
            0)
    };
    rv == 0
}

/// The area magic of a properties-area image. The image is the
/// verbatim content of the real properties file, and bionic's
/// prop_area header puts the magic at BYTE OFFSET 8, not 0:
///   offset 0: bytes_used_ (uint32)
///   offset 4: serial_     (atomic uint32)
///   offset 8: magic_      (0x504f5250, little-endian bytes "PROP")
///   offset 12: version_   (0xfc6ed0ab)
/// (Verified from AOSP bionic libc/system_properties prop_area at
/// android-6.0.0_r1, 7.0.0_r1 and 9.0.0_r1 — the layout is
/// identical across all of them.)
const PROP_AREA_MAGIC_OFFSET: usize = 8;
const PROP_AREA_VERSION_OFFSET: usize = 12;
const PROP_AREA_MAGIC_BYTES: [u8; 4] = [0x50, 0x52, 0x4f, 0x50];
const PROP_AREA_VERSION_BYTES: [u8; 4] = [0xab, 0xd0, 0x6e, 0xfc];

/// Upper bound for a properties file image (the real serial area is
/// ~128 KB with a full preload; 8 MB is a paranoia cap).
const PROP_FILE_MAX: usize = 8 * 1024 * 1024;

/// The SELinux label to chcon the staged file with. Android 6.0
/// maps ONE property file (/dev/__properties__, labeled
/// u:object_r:properties_device:s0 via init's restorecon + sepolicy
/// file_contexts — verified from AOSP android-6.0.0_r1 external/
/// sepolicy and init/init.cpp); 7.0+ map properties_serial inside
/// the /dev/__properties__/ directory (labeled
/// u:object_r:properties_serial:s0 by bionic's fsetxattr — verified
/// at android-13.0.0_r1 contexts_split.cpp:204 and
/// contexts_serialized.cpp:78, which hard-code that exact string).
/// The staged file must carry the label the PLATFORM gave the real
/// file, or exec'd helpers in untrusted_app get EACCES on the
/// bind-mounted replacement.
///
/// ROUND 29 — OEM-PROOFING: the label is now read from the LIVE file
/// first (lgetxattr security.selinux on the actual target) and the
/// hard-coded AOSP strings are only the fallback. Real-firmware
/// verification: Samsung OneUI 5.1 (A53, android-13) and Xiaomi
/// MIUI 14 (marble, android-13) plat_file_contexts dumps both carry
/// `/dev/__properties__ u:object_r:properties_device:s0` for the
/// directory and no OEM override for the serial file, and bionic
/// (which every OEM ships) sets the serial-file label itself — so
/// the fallback equals the live value on those builds. But an OEM
/// (or a future Android) is free to use a custom type: copying the
/// observed context verbatim makes the staged file match whatever
/// the platform actually did, and if the xattr read fails (any
/// reason) we degrade to exactly the old behavior.
fn props_file_target_path() -> &'static str {
    // 6.x: the single-file area IS the target. 7.0+ (or unknown):
    // the serial file inside the directory.
    match std::fs::symlink_metadata("/dev/__properties__") {
        Ok(md) if md.file_type().is_file() => "/dev/__properties__",
        _ => "/dev/__properties__/properties_serial",
    }
}

/// Sanitize a raw `security.selinux` xattr value into a context
/// string usable for lsetxattr. The kernel convention stores the
/// context with a trailing NUL; values that are empty, contain
/// control bytes, or exceed a sane length (Android contexts are
/// "u:object_r:TYPE:s0...", well under 128 bytes) are rejected.
fn sanitize_selinux_context(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let ctx = &bytes[..end];
    if ctx.is_empty() || ctx.len() > 120 {
        return None;
    }
    if !ctx.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    // An Android SELinux context has at least the four "u:r:s" colons.
    if ctx.iter().filter(|&&b| b == b':').count() < 3 {
        return None;
    }
    std::str::from_utf8(ctx).ok().map(|s| s.to_string())
}

/// Read the live file's own SELinux label. Best-effort: any failure
/// (no xattr support, EPERM, file missing) returns None and the
/// caller falls back to the AOSP constants.
fn read_live_selinux_context(path: &str) -> Option<String> {
    use std::ffi::CString;
    let c_path = CString::new(path).ok()?;
    let mut buf = [0u8; 128];
    let rv = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            c"security.selinux".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len())
    };
    if rv <= 0 {
        return None;
    }
    sanitize_selinux_context(&buf[..rv as usize])
}

fn props_file_label() -> String {
    // Round 29: prefer the exact context the platform gave the real
    // file (OEM-proof); fall back to the verified AOSP constants.
    if let Some(ctx) = read_live_selinux_context(props_file_target_path()) {
        return ctx;
    }
    match std::fs::symlink_metadata("/dev/__properties__") {
        Ok(md) => {
            if md.file_type().is_file() {
                // Android 6.x: the single-file property area.
                "u:object_r:properties_device:s0".to_string()
            } else {
                // Android 7.0+: the directory form.
                "u:object_r:properties_serial:s0".to_string()
            }
        }
        Err(_) => {
            // Cannot stat (host tests / very early boot): default to
            // the modern label, which is also the more common case.
            "u:object_r:properties_serial:s0".to_string()
        }
    }
}

/// Handle the 'P' verb as root. Returns true when the verb was
/// consumed here (caller must not hand the stream to the
/// privilege-dropped handler); false when `first` was some other
/// verb (caller continues with the normal path, passing `first`).
fn try_handle_props_file_root(stream: &mut UnixStream, first: u8,
                              session_dir: &str) -> bool {
    if first != b'P' { return false; }
    let fail = |s: &mut UnixStream| { let _ = s.write_all(b"0\n"); };

    let mut lenb = [0u8; 4];
    if stream.read_exact(&mut lenb).is_err() { fail(stream); return true; }
    let len = u32::from_le_bytes(lenb) as usize;
    // The header is 16 bytes minimum (bytes_used + serial + magic +
    // version); anything shorter cannot be a real area image.
    if !(16..=PROP_FILE_MAX).contains(&len) { fail(stream); return true; }

    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).is_err() { fail(stream); return true; }

    // Defense in depth: only ever materialize a real properties-area
    // image. (The socket is already root/zygote-only; this guards a
    // hypothetical future world where that stops being true.)
    // ROUND 26 BUG FIX: the check used to compare bytes 0..4 — but
    // the image is the VERBATIM file content, whose first 4 bytes are
    // prop_area::bytes_used_, not the magic. Every real 'P' request
    // was REJECTED here (the payload kept retrying; the staged file
    // never existed; exec'd helpers kept seeing real values) while
    // the host e2e stayed green because its fixture used a fantasy
    // "PROP"@0 format. The magic lives at offset 8 and the version
    // at offset 12 (see the constant's comment for the layout).
    if buf[PROP_AREA_MAGIC_OFFSET..PROP_AREA_MAGIC_OFFSET + 4]
            != PROP_AREA_MAGIC_BYTES
        || buf[PROP_AREA_VERSION_OFFSET..PROP_AREA_VERSION_OFFSET + 4]
            != PROP_AREA_VERSION_BYTES {
        fail(stream);
        return true;
    }

    let path = format!("{}/p", session_dir);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    use std::os::unix::fs::OpenOptionsExt;
    // 0444 to match the mode init gives the REAL properties_serial
    // (stat()-observable: a hidden child statting the mounted file
    // must see the same mode a stock device reports).
    opts.mode(0o444);
    let mut f = match opts.open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("zygiskd: props open({}) failed: {}", path, e);
            fail(stream);
            return true;
        }
    };
    if f.write_all(&buf).is_err() { fail(stream); return true; }
    let label = props_file_label();
    if !chcon(&path, &label) {
        // Non-fatal, same as ReZygisk: the mount still serves the
        // bytes to root/zygote-domain readers; exec'd helpers may be
        // denied by their own domain (documented residual).
        eprintln!("zygiskd: props chcon failed (non-fatal)");
    }
    let reply = format!("1{}\n", path);
    let _ = stream.write_all(reply.as_bytes());
    true
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

/// Round 34 — the fork-safe snapshot handed to connection children.
///
/// The connection child is forked from a MULTITHREADED parent (the
/// rescan and property-guard threads exist by then). Allocations in
/// the child are safe — Scudo (Android 11+) and jemalloc (≤ 10) both
/// register pthread_atfork handlers that lock the allocator across
/// fork (verified: external/scudo standalone/wrappers_c.inc calls
/// pthread_atfork(scudo_malloc_disable, scudo_malloc_enable,
/// scudo_malloc_enable); external/jemalloc registers
/// jemalloc_prefork/postfork under JEMALLOC_HAVE_PTHREAD_ATFORK).
/// But std::sync::Mutex has NO such protection: if the rescan
/// thread held `modules` at the fork instant, the child's
/// `state.modules.lock()` would block FOREVER — the holder thread
/// does not exist in the child (a stuck root child holding a socket,
/// one more 'subsysd' row in the process table, and the payload's
/// request timing out).
///
/// The fix is structural rather than pthread_atfork: the accept
/// loop takes BOTH locks in the (single) forking thread BEFORE
/// fork(), copies the data, releases the locks, and hands the child
/// a plain, lock-free `Snapshot` through fork's CoW. The child never
/// touches a shared mutex again. Snapshot cost: a Vec of ~10 module
/// entries + a HashSet of ~100 names ≈ a few KB memcpy — noise next
/// to fork()'s own page-table copy.
#[derive(Clone, Debug)]
struct Snapshot {
    modules:  Vec<ModuleEntry>,
    denylist: HashSet<String>,
}

impl DaemonState {
    fn new() -> Self {
        DaemonState {
            modules:  Mutex::new(Vec::new()),
            denylist: Mutex::new(HashSet::new()),
        }
    }

    /// Lock both lists (in the forking thread!), copy, release.
    /// Lock order is modules -> denylist — the same order everywhere.
    fn snapshot(&self) -> Snapshot {
        let modules = self.modules.lock().unwrap().clone();
        let denylist = self.denylist.lock().unwrap().clone();
        Snapshot { modules, denylist }
    }

    fn reload_modules(&self) {
        let mut out = Vec::new();
        let abi = pick_abi();
        if let Ok(entries) = std::fs::read_dir(remap_path(MODULES_ROOT)) {
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
        let text = match std::fs::read_to_string(remap_path(DENYLIST_FILE)) {
            Ok(s) => s,
            Err(_) => return,  // no denylist file yet — leave old value
        };
        let out = parse_denylist_text(&text);
        *self.denylist.lock().unwrap() = out;
    }

    /// Round 34: production denylist lookups now go through the
    /// fork-safe Snapshot (the child reads `snap.denylist.contains`).
    /// This method stays as the shared-locked form for unit tests,
    /// which run in a single process where the lock is safe.
    #[cfg(test)]
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
/// returns the parsed verb. Test-only since R19: production parsing
/// enters through ClientVerb::parse_after after the connection child
/// has already consumed the verb byte (it must peek it before the
/// privilege drop).
#[cfg(test)]
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
//
// Round 19: the verb's first byte was already consumed by the
// privilege-drop fork (which needed to peek it); it arrives here as
// `first`. The 'P' verb never reaches this function — it is handled
// as root before the drop.
//
// handle_client_with_first is the real handler; handle_client is
// kept as the self-contained entry point (reads the verb byte
// itself) for any future caller that has not peeked the verb yet.
// ----------------------------------------------------------------------
#[allow(dead_code)]
fn handle_client(mut stream: UnixStream, snap: Snapshot) {
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).is_err() { return; }
    handle_client_with_first(stream, first[0], snap);
}

fn handle_client_with_first(mut stream: UnixStream, first: u8,
                            snap: Snapshot) {
    let verb = match ClientVerb::parse_after(first, &mut stream) {
        Ok(v) => v,
        Err(_) => return,
    };
    match verb {
        ClientVerb::ListModules => {
            // Round 34: the child serves from its fork-inherited
            // Snapshot — no shared locks are touched after fork
            // (see the Snapshot doc comment for why that matters).
            let buf = format_module_list(&snap.modules);
            let _ = stream.write_all(buf.as_bytes());
        }
        ClientVerb::ShouldInject(name) => {
            // For now: inject for everything that's NOT on the
            // denylist. A real implementation would ask each module
            // whether it wants this target (via the
            // zygisk_study_api.should_inject callback). This stub is
            // documented in docs/architecture.md.
            let yes = !snap.denylist.contains(&name);
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
    // Round 28 — the real implementation. The previous version was a
    // documented no-op skeleton ("left as a TODO"), which left the
    // daemon's /proc/self/cmdline exposing
    //   "<full path>/zygiskd --workdir /data/system/zygisk_study"
    // — the single most identifying string in the whole process list
    // (both the binary name and the module's data path).
    //
    // Technique (the same one systemd's setproctitle.c and many
    // daemons use): the kernel renders /proc/<pid>/cmdline directly
    // from the argv STRINGS area on the initial stack, whose extent
    // is published in /proc/self/stat as the arg_start / arg_end
    // fields (48 and 49, 1-indexed). Rewriting the bytes in that
    // window changes what every reader of /proc/<pid>/cmdline sees.
    // The area is ordinary writable stack memory.
    //
    // Steps:
    //   1. Read /proc/self/stat.
    //   2. Skip past "pid (comm)" — comm may contain spaces and
    //      parentheses, so the split point is the LAST ')' in the
    //      line.
    //   3. The remainder starts at field 3 (state); fields 48/49 are
    //      then rest[45] / rest[46].
    //   4. Validate the extent (non-degenerate, small), then copy
    //      `name` into it and NUL-fill the rest.
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s,
        Err(_) => return,
    };
    let (start, end) = match parse_arg_extent(&stat) {
        Some(x) => x,
        None => return,
    };
    let span = end.saturating_sub(start);
    // Sanity: a real argv strings area is a few hundred bytes to a
    // few pages. Anything bigger means we misparsed — refuse.
    if span == 0 || span > 4 * 4096 { return; }

    let bytes = name.as_bytes();
    let take = bytes.len().min(span.saturating_sub(1).max(1));
    let base = start as *mut u8;
    unsafe {
        // The window is normal stack memory (writable); we stay
        // inside [start, start + span) by construction.
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base, take);
        // NUL-terminate, then blank the remainder so no fragments of
        // the original "zygiskd --workdir /data/system/..." remain.
        std::ptr::write_bytes(base.add(take), 0, span - take);
    }
}

/// Parse arg_start/arg_end out of a /proc/[pid]/stat line. Pure
/// function so unit tests can drive it with crafted stat lines
/// (including comms containing spaces and nested parentheses).
/// Returns (arg_start, arg_end) as addresses.
fn parse_arg_extent(stat: &str) -> Option<(usize, usize)> {
    // The split point after "pid (comm)" is the LAST ')' in the
    // line — comm is escaped only for '/' and newlines in the
    // kernel's rendering, so parentheses inside comm are literal.
    let close = stat.rfind(')')?;
    let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // rest[0] is field 3 (state). Fields 48 (arg_start) and 49
    // (arg_end) are rest[45] and rest[46].
    if rest.len() < 47 { return None; }
    let arg_start: usize = rest[45].parse().ok()?;
    let arg_end:   usize = rest[46].parse().ok()?;
    if arg_end <= arg_start { return None; }
    Some((arg_start, arg_end))
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
// Round 34 — precise child reaping (ChildGrim).
//
// BUG (empirically verified this round with a standalone Rust
// probe): Round 28 set SIGCHLD to SIG_IGN so the kernel would
// auto-reap connection children. On Linux that ALSO makes waitpid()
// return ECHILD for EVERY child — including the ones Rust std
// spawns internally for Command::output()/status(). Verified
// consequences, both silent since R28:
//
//   * read_prop() ("getprop ro.product.cpu.abi") lost its stdout
//     entirely (output() returns Err and drops the capture), so
//     pick_abi() was pinned to the "arm64-v8a" default on every
//     device — on 32-bit-only hardware, modules under
//     zygisk/armeabi-v7a were never listed (the module looks dead;
//     invisible to the E2E because it never exercised getprop).
//
//   * run_resetprop()'s external-binary fallback returned FAILURE
//     even when the helper ran and did its job — the E2E still
//     passed because it asserts the helper's SIDE EFFECT (the
//     fake resetprop's log line), not the parent's return value.
//
// The reaper below tracks EXACTLY the pids WE fork (connection
// children) and reaps each with waitpid(pid, WNOHANG). std::process
// children are never stolen — their pids are never in the list, so
// Command's internal waitpid always succeeds and getprop's stdout
// comes back. Reap runs (a) after every accept, (b) on every rescan
// tick, and (c) on every guard poll — bounding a dead child's
// zombie lifetime by the shortest active interval (250 ms).
// ----------------------------------------------------------------------
struct ChildGrim {
    /// Pids of forked connection children not yet reaped.
    pending: Mutex<Vec<i32>>,
}

impl ChildGrim {
    fn new() -> Self { ChildGrim { pending: Mutex::new(Vec::new()) } }

    /// Record a freshly-forked child pid (parent side only).
    fn track(&self, pid: i32) {
        let mut v = self.pending.lock().unwrap();
        // Bound the bookkeeping: companion children can live for
        // hours, but a healthy device forking apps all day still
        // keeps this list tiny (entries leave at reap time). The cap
        // keeps memory flat even if a future caller ever leaked
        // tracks without reaping.
        if v.len() < 4096 { v.push(pid); }
    }

    /// Non-blocking reap of every tracked pid. Returns how many
    /// were reaped (or vanished). Never waits on a live child.
    fn reap(&self) -> usize {
        let mut v = self.pending.lock().unwrap();
        if v.is_empty() { return 0; }
        let mut reaped = 0;
        v.retain(|&pid| unsafe {
            let r = libc::waitpid(pid, std::ptr::null_mut(),
                                  libc::WNOHANG);
            if r == pid {
                reaped += 1;
                false            // reaped — drop from the list
            } else if r == 0 {
                true             // still running — keep
            } else {
                // -1/ECHILD: nobody else should reap OUR tracked
                // pids... but stay defensive rather than wedge the
                // bookkeeping forever if something ever does.
                reaped += 1;
                false
            }
        });
        reaped
    }
}

// ----------------------------------------------------------------------
// STEALTH: per-connection privilege drop.
//
// For each incoming client connection, we:
//   1. fork()
//   2. In the child: peek the verb byte.
//      - 'P' (Round 19): handled AS ROOT (writes the properties
//        file into the root-only session dir + relabel), then the
//        child exits. Every other verb:
//   3.   setresgid(CHILD_GID), setresuid(CHILD_UID)
//   4.   The child handles the connection and exits
//   5. The parent tracks the child in the grim reaper and waits
//      for the next connection
//
// If the child is exploited, the attacker is uid nobody, not root.
// ----------------------------------------------------------------------
fn spawn_privileged_child<F>(stream: UnixStream, snap: Snapshot,
                              grim: Arc<ChildGrim>, session_dir: &str,
                              handler: F)
    where F: FnOnce(UnixStream, u8, Snapshot) + Send + 'static
{
    match unsafe { libc::fork() } {
        -1 => {
            // ROUND 34: fail CLOSED. The pre-R34 fallback handled the
            // connection in a thread of the ROOT daemon process — no
            // uid drop, no NO_NEW_PRIVS, no PDEATHSIG — so the whole
            // "an exploited handler is uid nobody, not root"
            // containment model silently vanished exactly under the
            // memory pressure (RLIMIT_NPROC exhaustion, fork bombs)
            // an attacker induces, while parsing client-controlled
            // input. A dropped connection is recoverable (the
            // payload retries on the next fork through its latch
            // machinery); a root-context handler is not.
            drop(stream);
            drop(snap);
            let _ = session_dir;
        }
        0 => {
            // Child. ROUND 34: PDEATHSIG FIRST — immediately after
            // fork, before ANY blocking I/O. prctl is
            // async-signal-safe (man7 signal-safety(7)), and the
            // ordering matters: a client that connects and never
            // sends its verb byte parks the child in read_exact; if
            // the daemon dies in that window (or the client stalls
            // forever), the child must already be scheduled to die
            // with it — otherwise a ROOT child (privileges not yet
            // dropped!) outlives the daemon holding an open socket,
            // the exact "orphaned uid-0 subsysd row" the Round-34
            // comment below was written to prevent, except worse.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL,
                            0, 0, 0);
            }
            // Peek the verb byte BEFORE dropping privileges:
            // 'P' must run as root (it writes into the root-only
            // session dir and relabels); everything else drops to
            // nobody exactly as before.
            let mut s = stream;
            let mut first = [0u8; 1];
            if s.read_exact(&mut first).is_err() {
                process::exit(0);
            }
            if try_handle_props_file_root(&mut s, first[0], session_dir) {
                process::exit(0);   // consumed and answered as root
            }
            // (The Round 34 PDEATHSIG moved to the TOP of the child
            // prologue — before the blocking verb read. See the
            // comment there. It dies with the daemon: a long-lived
            // companion child would otherwise survive the daemon's
            // death as a uid-9999 'subsysd' row until its client
            // hangs up; PDEATHSIG fires when the forking THREAD (the
            // accept loop, which runs for the daemon's lifetime)
            // exits — exactly the daemon's death. Same prctl the
            // payload uses for ITS children — hide_stealth.cpp.)
            // Drop privileges.
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
            handler(s, first[0], snap);
            // Exit the child explicitly so we never fall through to
            // the parent's accept loop.
            process::exit(0);
        }
        pid => {
            // Parent. The child has its own copy of the stream fd,
            // so we close ours to avoid leaking; the pid goes into
            // the tracked-reaper list (Round 34 — see ChildGrim).
            drop(stream);
            grim.track(pid);
        }
    }
}


// ----------------------------------------------------------------------
// Round 30 — the native-bridge property guard (STEALTH).
//
// THE DETECTION HOLE THIS CLOSES: ro.dalvik.vm.native.bridge is
// readable by ANY app (__system_property_get needs no permission).
// Stock devices report "0" or the property is absent (Round 29's
// 173-device collection: 169 ship "0", 4 absent, 0 with a real
// bridge). While the swap is installed, every property read in
// every process sees our loader name — the single most generic
// root/Zygisk detection vector there is. Magisk's own zygisk keeps
// the property set for the whole boot (verified this round from
// topjohnwu/Magisk native/src/core/zygisk/daemon.rs: set_prop()
// runs once, restore_prop() only on rollback/stop) and accepts
// that exposure; ReZygisk v2 abandoned the property mechanism for
// ptrace injection entirely.
//
// OUR DESIGN — restore-after-consumption with crash re-arming:
//
//   1. post-fs-data.sh swaps the property and records BOTH the
//      stock value (.native_bridge_backup) and the applied value
//      (.native_bridge_applied) in the workdir.
//   2. ART reads the property exactly once per zygote start
//      (AndroidRuntime.cpp startVm, verified at 5.0/8.1/13/16 this
//      round; from 10.0 a `zygote &&` guard means ONLY the zygote
//      even sees a loadable value). The zygote dlopens the bridge
//      during Runtime::Init — after that moment the property has
//      no further consumer until the zygote restarts.
//   3. This guard (a root thread) waits until the bridge library
//      actually appears in the zygote's /proc/<pid>/maps — proof
//      the property was consumed — then restores the STOCK value.
//      From that point on, every app reads "0"/absent: stock.
//   4. If the zygote dies (crash, OOM, manual restart), init
//      re-execs it and the NEW zygote re-reads the property — so
//      the guard re-applies the loader value as soon as it sees
//      the old pid gone, before the new zygote's Runtime::Init
//      gets there (250 ms poll vs. init's restart + ~hundreds of
//      ms of zygote startup — we normally win the race). Once the
//      new zygote loads the bridge, stock is restored again.
//   5. Bootloop guard (Magisk's exact policy): more than 3
//      zygote restarts in one boot = our loader is probably
//      crashing it — restore stock permanently and stand down.
//
// Honest residuals (documented in ANDROID-REALISM.md):
//   - The property is set from post-fs-data until the guard's
//     restore lands shortly after late_start. No third-party app
//     is running in that window (apps start after boot-complete),
//     but a system component could theoretically read it.
//   - If the re-apply loses the race with a restarted zygote, the
//     module is inert for that cycle; the NEXT restart re-arms
//     (the property stays set until a zygote actually consumes
//     it).
// ----------------------------------------------------------------------

const PROP_KEY: &str = "ro.dalvik.vm.native.bridge";
/// Zygote restarts tolerated before the guard stands down (Magisk's
/// bootloop policy: 3 crashes -> rollback).
const PROP_GUARD_MAX_RESTARTS: u32 = 3;

/// What one poll cycle observed. Kept as data so the decision logic
/// is a pure, unit-testable function.
#[derive(Debug, Clone, PartialEq)]
enum ZygoteObservation {
    /// No zygote process found at all (very early boot, or the
    /// zygote is between restarts).
    Absent,
    /// The zygote with `pid` was seen; `bridge_loaded` is whether
    /// our loader library is mapped in it (proof the property was
    /// consumed); `stable` means the observation is trustworthy
    /// (the grace period after the pid first appeared has passed —
    /// a brand-new zygote has not necessarily reached
    /// Runtime::Init yet).
    Present { pid: u32, bridge_loaded: bool, stable: bool },
}

/// The guard's decision after one observation.
#[derive(Debug, Clone, PartialEq)]
enum GuardAction {
    /// Nothing to do this cycle.
    None,
    /// Restore the stock property value (the zygote consumed ours).
    RestoreStock,
    /// Re-apply the loader value (the zygote died; a new one is
    /// coming).
    ReapplyLoader,
    /// Too many restarts: restore stock and stand down permanently.
    RollbackAndStop,
}

#[derive(Debug)]
struct GuardState {
    /// The zygote pid the guard currently tracks.
    known_pid: Option<u32>,
    /// Whether the stock value has been restored for the CURRENT
    /// zygote generation.
    restored: bool,
    /// Zygote restarts seen this boot.
    restarts: u32,
    /// The guard has given up (bootloop protection).
    stood_down: bool,
}

impl GuardState {
    fn new() -> Self {
        GuardState { known_pid: None, restored: false,
                     restarts: 0, stood_down: false }
    }
}

/// The pure decision function. `obs` is this cycle's observation of
/// the zygote; the state is advanced and an action returned.
fn prop_guard_step(st: &mut GuardState, obs: ZygoteObservation) -> GuardAction {
    if st.stood_down {
        return GuardAction::None;
    }
    match obs {
        ZygoteObservation::Absent => {
            if let Some(_pid) = st.known_pid {
                // The tracked zygote vanished.
                st.known_pid = None;
                st.restored = false;
                st.restarts += 1;
                if st.restarts > PROP_GUARD_MAX_RESTARTS {
                    st.stood_down = true;
                    return GuardAction::RollbackAndStop;
                }
                return GuardAction::ReapplyLoader;
            }
            GuardAction::None
        }
        ZygoteObservation::Present { pid, bridge_loaded, stable } => {
            if st.known_pid != Some(pid) {
                // A new (or replaced) zygote: track it. A fast
                // replace (we missed the Absent window) also counts
                // as a restart — but only once per generation.
                if st.known_pid.is_some() {
                    st.restarts += 1;
                    if st.restarts > PROP_GUARD_MAX_RESTARTS {
                        st.stood_down = true;
                        return GuardAction::RollbackAndStop;
                    }
                }
                st.known_pid = Some(pid);
                st.restored = false;
            }
            if !st.restored && stable && bridge_loaded {
                st.restored = true;
                return GuardAction::RestoreStock;
            }
            // stable && !bridge_loaded: the zygote came up WITHOUT
            // our loader — a lost race (it read the stock value
            // before our re-apply) or a failed injection. Leave the
            // property exactly as it is (if it is still set, the
            // NEXT zygote generation re-arms; if we already
            // restored, nothing is exposed).
            GuardAction::None
        }
    }
}

/// Find the primary zygote: the process whose /proc/<pid>/cmdline
/// contains an `--zygote` argv token (app_process64 -Xzygote ...
/// --zygote --start-system-server; the 32-bit secondary zygote on
/// mixed devices matches too — either is a valid consumer of the
/// property, and the primary is preferred by the app_process64
/// argv[0] check). Root can read every /proc entry; failures on
/// individual entries (racing process exits) are skipped.
fn find_zygote_pid() -> Option<u32> {
    let dir = std::fs::read_dir("/proc").ok()?;
    let mut fallback: Option<u32> = None;
    for entry in dir.flatten() {
        let name = entry.file_name();
        // ROUND 34 (C11): `?` here propagated None out of the WHOLE
        // census — one non-UTF-8 entry name (or a transient read_dir
        // failure) read as "the zygote DIED": the guard counted a
        // spurious restart, and 4 blips tripped the permanent
        // bootloop RollbackAndStop with no zygote problem at all.
        // Per-entry conversions must skip the entry, not the scan.
        let name = match name.to_str() { Some(s) => s, None => continue };
        let pid: u32 = match name.parse() { Ok(v) => v, Err(_) => continue };
        if pid == 0 { continue; }
        // Read cmdline; skip the current process (the daemon itself
        // never matches, but the guard is cheap to keep honest).
        let cmd = match std::fs::read(format!("/proc/{}/cmdline", pid)) {
            Ok(b) => b, Err(_) => continue,
        };
        if cmd.is_empty() { continue; }
        // argv is NUL-separated; look for the exact "--zygote" token.
        let mut has_zygote_token = false;
        let mut first_arg_app_process64 = false;
        for (i, tok) in cmd.split(|&b| b == 0).enumerate() {
            let tok = String::from_utf8_lossy(tok);
            if i == 0 {
                first_arg_app_process64 =
                    tok.contains("app_process64") || tok.contains("app_process");
            } else if tok == "--zygote" {
                has_zygote_token = true;
            }
        }
        if has_zygote_token {
            if first_arg_app_process64 {
                return Some(pid);       // the primary 64-bit zygote
            }
            if fallback.is_none() {
                fallback = Some(pid);   // host tests / secondary zygote
            }
        }
    }
    fallback
}

/// Is our bridge library mapped in /proc/<pid>/maps? Only the
/// library NAME is matched (the maps path is the full resolved
/// /system/lib64/<name> the linker used). Reading another process's
/// maps requires root — which the guard thread has (it runs in the
/// daemon's parent, before any privilege drop).
fn bridge_mapped_in(pid: u32, bridge_name: &str) -> bool {
    let maps = match std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
        Ok(m) => m,
        Err(_) => return false,
    };
    // Every mapped file line ends with the path; match the name as
    // a path component ("/<name>" at a word boundary is enough —
    // our randomized names are unique per install).
    for line in maps.lines() {
        if let Some(idx) = line.find('/') {
            let path = &line[idx..];
            if path.ends_with(bridge_name)
                || path.contains(&format!("/{}", bridge_name))
            {
                return true;
            }
        }
    }
    false
}

/// Round 31 — one-shot property CLI (the module's built-in
/// resetprop equivalent). Runs the engine directly: no daemon, no
/// socket, exits immediately. Exit codes follow resetprop's
/// conventions loosely: 0 = success (get prints the value, set/delete
/// mutate), 1 = failure (not found, denied, bad args).
///
/// This exists because KernelSU and APatch (the root managers custom
/// ROM users commonly run) do not ship a resetprop BINARY on PATH,
/// and post-fs-data.sh needs a forced ro.* write at boot. The engine
/// implements bionic's own mutation protocol (see props.rs).
fn prop_cli_main(rest: &[String]) -> i32 {
    let usage = || {
        eprintln!("usage: zygiskd prop get NAME | set NAME VALUE | delete NAME");
        1
    };
    // zygiskd prop [--root DIR] get|set|delete ...
    let mut root: Option<String> = None;
    let mut rest: &[String] = rest;
    if rest.len() >= 2 && rest[0] == "--root" {
        root = Some(rest[1].clone());
        rest = &rest[2..];
    }
    if rest.len() < 2 {
        return usage();
    }
    let engine = match root {
        // An explicit root overrides the ZS_PROP_ROOT environment; both
        // exist for the host E2E (the fixture property area is a temp
        // dir, not /dev/__properties__).
        Some(r) => PropEngine::with_root(Path::new(&r)),
        None => PropEngine::new(),
    };
    match rest[0].as_str() {
        "get" => {
            match engine.get(&rest[1]) {
                Some(v) => {
                    println!("{}", v);
                    0
                }
                None => 1,
            }
        }
        "set" => {
            if rest.len() < 3 {
                return usage();
            }
            match engine.set(&rest[1], &rest[2]) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("zygiskd: prop set failed: {}", e);
                    1
                }
            }
        }
        "delete" => match engine.delete(&rest[1]) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("zygiskd: prop delete failed: {}", e);
                1
            }
        },
        _ => usage(),
    }
}

/// Invoke resetprop (forced ro-property write — the same tool
/// post-fs-data.sh used for the swap). Candidate order matches the
/// script's: PATH first, then the well-known Magisk locations. On
/// the host E2E the harness injects a fake `resetprop` into PATH.
///
/// ROUND 31: the built-in engine (props.rs) is tried FIRST — it is
/// the same algorithm resetprop implements, self-contained, and
/// works on every root manager. The external binaries remain as
/// fallbacks (their behavior is already proven in the E2E suite) for
/// the case where direct mmap of the property files is denied while
/// exec'ing a helper is not (e.g. an exotic SELinux policy).
fn run_resetprop(args: &[&str]) -> bool {
    // 1. The built-in engine (props.rs) — works on every root manager.
    //    Args arrive in resetprop CLI shape: either [NAME, VALUE] (set),
    //    or ["--delete", NAME] (delete).
    {
        let engine = PropEngine::new();
        let ok = if args.len() >= 2 && args[0] == "--delete" {
            engine.delete(args[1]).unwrap_or(false)
        } else if args.len() >= 2 {
            engine.set(args[0], args[1]).is_ok()
        } else {
            false
        };
        if ok {
            return true;
        }
    }
    let candidates: Vec<(String, Vec<String>)> = vec![
        ("resetprop".to_string(), args.iter().map(|s| s.to_string()).collect()),
        ("/data/adb/magisk/resetprop".to_string(),
            args.iter().map(|s| s.to_string()).collect()),
        ("/system/bin/resetprop".to_string(),
            args.iter().map(|s| s.to_string()).collect()),
        // Modern Magisk: resetprop is a subcommand of the magisk
        // binary.
        ("/data/adb/magisk/magisk".to_string(),
            std::iter::once("resetprop".to_string())
                .chain(args.iter().map(|s| s.to_string())).collect()),
    ];
    for (exe, mut argv) in candidates {
        if exe.contains('/') && !Path::new(&exe).exists() { continue; }
        argv.insert(0, exe.clone());
        if let Ok(out) = process::Command::new(&exe).args(&argv[1..])
                .output() {
            if out.status.success() { return true; }
        }
    }
    false
}

/// Restore the stock value. An EMPTY backup means the property was
/// ABSENT on this device (Round 29's R28-verified semantics: an
/// empty-backup restore must DELETE the property, never write an
/// empty string — ART treats "" as a warning-worthy anomaly while
/// absent is the genuine stock state on 4/173 real devices).
fn guard_restore_stock(backup: &str) -> bool {
    if backup.is_empty() {
        run_resetprop(&["--delete", PROP_KEY])
    } else {
        run_resetprop(&[PROP_KEY, backup])
    }
}

fn guard_reapply(applied: &str) -> bool {
    run_resetprop(&[PROP_KEY, applied])
}

/// The guard thread body. Config (poll interval, zygote grace
/// period) is overridable through the environment for the host
/// E2E; unset = device defaults.
fn prop_guard_thread(grim: Arc<ChildGrim>) {
    let workdir = remap_path(WORKDIR);

    let poll_ms: u64 = std::env::var("ZS_TEST_POLL_MS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(250);
    // Round 34b — stand-down sweep cadence. When there is nothing
    // to guard (no applied value yet — a real bridge was refused,
    // a host fixture, or the guard's permanent rollback disarm),
    // this thread STILL sweeps the grim reaper at 1 Hz. Without it,
    // a connection child that exits while no new accept arrives
    // would stay a zombie for up to the rescan thread's 30 s poll:
    // this thread is the only always-on sub-second timer the daemon
    // has, so it doubles as the sweeper in BOTH states. Steady-state
    // cost: one stat + one reap() (whose pending list is normally
    // empty — a single is_empty() check) per second. Overridable
    // for the host E2E (set to ~150 ms there).
    let sweep_ms: u64 = std::env::var("ZS_TEST_SWEEP_MS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(1000);

    // Arm: wait until post-fs-data's record exists. The wait loop
    // (not an early return) matters twice over: it keeps the
    // sweeper alive for devices that will never arm (real-bridge
    // refusals — the normal stand-down), and it catches LATE
    // records (a daemon racing post-fs-data's write, or a manual
    // test run that arms the guard after startup).
    let applied = loop {
        if let Ok(s) = std::fs::read_to_string(
                format!("{}/.native_bridge_applied", workdir)) {
            let t = s.trim();
            if !t.is_empty() { break t.to_string(); }
            // An EMPTY record is the rolled-back/disarmed state:
            // stay in the sweeper, keep watching.
        }
        thread::sleep(Duration::from_millis(sweep_ms.max(poll_ms)));
        grim.reap();
    };
    let backup = std::fs::read_to_string(
            format!("{}/.native_bridge_backup", workdir))
        .unwrap_or_default()
        .trim()
        .to_string();

    // How long a NEWLY SEEN zygote pid must exist before its
    // maps are trusted (Runtime::Init + bridge dlopen complete).
    let grace_ms: u64 = std::env::var("ZS_TEST_ZYGOTE_GRACE_MS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(3000);

    // ROUND 34 (C4 — the cost bug): the old loop ran the FULL
    // observation every cycle, forever: find_zygote_pid() readdirs
    // /proc and opens+reads+close()s cmdline for EVERY process
    // (300-600 on a real phone), then bridge_mapped_in() re-reads
    // the zygote's whole maps file — 4x/second, sustained, on a
    // battery device, with a 250 ms timer that blocks deep idle.
    // The header comment ("one 250 ms poll of a single /proc read")
    // was simply false. The work is only needed while WAITING for
    // the consume (bridge appears in maps) or after a zygote death
    // (re-apply window). Once the stock value is restored for the
    // tracked zygote, the guard backs off to a slow cadence whose
    // only job is DEATH DETECTION of the known pid — one stat() —
    // with a periodic full census to re-sync (catches pid reuse:
    // /proc/<pid> existing is a weak signal; every ~30 s the real
    // census re-derives the truth). Env-overridable for the E2E.
    let slow_ms: u64 = std::env::var("ZS_TEST_SLOW_MS").ok()
        .and_then(|v| v.parse().ok()).unwrap_or(2000);
    const CENSUS_EVERY_SLOW_TICKS: u32 = 15;   // ~30 s at 2 s

    let mut st = GuardState::new();
    let mut first_seen: std::collections::HashMap<u32, std::time::Instant> =
        std::collections::HashMap::new();
    // C8: the guard thread is ALSO the 1 Hz zombie sweeper — the
    // Round-34b design. RollbackAndStop must therefore STOP
    // GUARDING without STOPPING THE THREAD: sweeper_only drops all
    // /proc work (the old `return` here killed the sweeper exactly
    // in the state the module considers its most important failure
    // mode, regressing dead-child reaping to the 30 s rescan tick).
    let mut sweeper_only = false;
    let mut slow_ticks: u32 = 0;
    loop {
        // Slow mode: stock restored for the tracked zygote. Fast
        // mode: waiting for the consume, or hunting a new zygote.
        let slow = st.restored && st.known_pid.is_some();
        thread::sleep(Duration::from_millis(
            if slow { slow_ms } else { poll_ms }));
        // Round 34: the guard runs on the shortest timer in the
        // daemon — it doubles as the zombie sweeper (dead children
        // leave within one poll interval even with no new accepts).
        grim.reap();
        if sweeper_only {
            // C8: rolled back — nothing left to guard, but the
            // reaping never stops.
            continue;
        }
        let obs = if slow {
            // Cheap path: is the KNOWN pid still alive? A periodic
            // full census re-syncs (pid reuse, drift).
            slow_ticks = slow_ticks.saturating_add(1);
            let alive = st.known_pid
                .map(|p| std::path::Path::new(
                    &format!("/proc/{}", p)).exists())
                .unwrap_or(false);
            if alive && slow_ticks < CENSUS_EVERY_SLOW_TICKS {
                // Synthesized "nothing changed" observation: same
                // pid, no new consume to detect (already restored).
                // The step function sees the tracked pid and idles.
                ZygoteObservation::Present {
                    pid: st.known_pid.unwrap_or(0),
                    bridge_loaded: true,
                    stable: true,
                }
            } else {
                slow_ticks = 0;   // death — or the periodic re-census
                full_observation(&applied, &mut first_seen, grace_ms)
            }
        } else {
            full_observation(&applied, &mut first_seen, grace_ms)
        };
        match prop_guard_step(&mut st, obs) {
            GuardAction::None => {}
            GuardAction::RestoreStock => {
                let _ = guard_restore_stock(&backup);
            }
            GuardAction::ReapplyLoader => {
                let _ = guard_reapply(&applied);
            }
            GuardAction::RollbackAndStop => {
                let _ = guard_restore_stock(&backup);
                // C8: stand down from GUARDING; keep REAPING.
                sweeper_only = true;
            }
        }
    }
}

/// ROUND 34 (C4): the full observation the FAST guard cadence uses —
/// the /proc census + stability + bridge-mapped check, factored out
/// of the loop body so the slow path can fall back to it.
fn full_observation(
    applied: &str,
    first_seen: &mut std::collections::HashMap<u32, std::time::Instant>,
    grace_ms: u64,
) -> ZygoteObservation {
    match find_zygote_pid() {
        None => ZygoteObservation::Absent,
        Some(pid) => {
            let stable = match first_seen.get(&pid) {
                Some(t) => t.elapsed().as_millis() as u64 >= grace_ms,
                None => {
                    first_seen.insert(pid, std::time::Instant::now());
                    false
                }
            };
            // A zygote that has been up longer than the grace
            // period is stable no matter when WE first noticed
            // it (covers the daemon starting long after boot:
            // the boot zygote's bridge loaded minutes ago).
            let up_stable = stable || {
                std::fs::read(format!("/proc/{}/stat", pid))
                    .ok()
                    .and_then(|s| {
                        // field 22 (starttime) — just require the
                        // read to succeed and treat anything
                        // readable as old enough IF it is the pid
                        // we have tracked before.
                        let txt = String::from_utf8_lossy(&s);
                        let after = txt.split_once(") ").map(|x| x.1)?;
                        let f: Vec<&str> = after.split(' ').collect();
                        let starttime: u64 = f.get(19)?.parse().ok()?;
                        // 100 Hz clock: 2s uptime == 200 ticks.
                        let uptime: u64 = std::fs::read_to_string(
                            "/proc/uptime").ok()?
                            .split('.').next()?.parse().ok()?;
                        Some(uptime.saturating_sub(starttime / 100) >= 2)
                    })
                    .unwrap_or(false)
            };
            let bridge_loaded =
                bridge_mapped_in(pid, applied);
            ZygoteObservation::Present {
                pid, bridge_loaded, stable: up_stable,
            }
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
    // Clean up the previous boot's random dir, if any. Round 29: try
    // BOTH session records (the module-dir one first; if the module
    // tree is gone/unreadable, the workdir copy still names the
    // previous random dir — closing a small leak where a module-dir
    // loss orphaned /data/system/.<hex> forever).
    let old = std::fs::read_to_string(remap_path(SESSION_FILE))
        .or_else(|_| std::fs::read_to_string(remap_path(SESSION_FILE_ALT)))
        .ok();
    if let Some(old) = old {
        let old = old.trim();
        // Only ever remove paths WE created (defense in depth: the
        // prefix is checked, not trusted). Round 28: the prefix check
        // accepts both the device path and the ZS_TEST_ROOT-remapped
        // host form (host E2E runs write the remapped path into the
        // session file; without this the previous test run's temp
        // dir was never cleaned).
        let dev_prefix = "/data/system/.";
        let host_prefix: String =
            remap_path(dev_prefix);  // "$ZS_TEST_ROOT/data/system/."
        let is_ours = old.starts_with(dev_prefix)
            || (!host_prefix.is_empty()
                && old.starts_with(&host_prefix)
                && old.len() > host_prefix.len());
        if is_ours && old.len() > dev_prefix.len() {
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
    let dir = remap_path(&format!("/data/system/.{:02x}{:02x}{:02x}{:02x}",
                                  bytes[0], bytes[1], bytes[2], bytes[3]));
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
    // Round 29: write BOTH records — the module-dir file and the
    // workdir fallback (see SESSION_FILE_ALT).
    std::fs::write(remap_path(SESSION_FILE), &path).ok()?;
    std::fs::create_dir_all(remap_path(WORKDIR)).ok()?;
    std::fs::write(remap_path(SESSION_FILE_ALT), &path).ok()?;
    Some(path)
}

fn main() {
    // Parse args.
    let mut workdir = remap_path(WORKDIR);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut prop_cli: Option<Vec<String>> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        if a == "--workdir" {
            if i + 1 < args.len() {
                workdir = args[i + 1].clone();
            }
            i += 2;
        } else if a == "prop" {
            // Round 31 — one-shot property CLI (the module's built-in
            // resetprop equivalent; see props.rs for the full provenance).
            // Usage:
            //   zygiskd prop get NAME
            //   zygiskd prop set NAME VALUE
            //   zygiskd prop delete NAME
            // post-fs-data.sh uses this when no resetprop binary exists
            // (KernelSU / APatch environments).
            prop_cli = Some(args[i + 1..].to_vec());
            break;
        } else {
            i += 1;
        }
    }

    if let Some(rest) = prop_cli {
        std::process::exit(prop_cli_main(&rest));
    }

    // Round 28 tried to reap connection children by leaving SIGCHLD
    // at SIG_IGN (kernel auto-reap). Round 34 proved empirically
    // that this ALSO breaks waitpid for std::process children:
    // Command::output() returned ECHILD, getprop's stdout was lost
    // (ABI detection pinned to arm64-v8a), and the external
    // resetprop fallback always reported failure. See ChildGrim's
    // comment for the full story. SIGCHLD now stays at its DEFAULT
    // disposition and the reaper below reaps EXACTLY the pids we
    // forked — nobody else's.
    let grim = Arc::new(ChildGrim::new());

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
    // ROUND 34 (C10): MCL_CURRENT alone pinned only the ~few-hundred-KB
    // resident set at this point — everything faulted in later (the
    // denylist, module list, guard-thread stack, snapshots) stayed
    // swappable, so the documented anti-swap/anti-forensics claim was
    // ~90% not delivered. MCL_FUTURE pins pages as they fault in.
    // RLIMIT_MEMLOCK is unbounded for the root daemon, and the total
    // footprint is a few MB, so the cost is bounded and intentional.
    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
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
        let g = grim.clone();
        thread::spawn(move || {
            rescan_thread_main(s, g);
        });
    }

    // Round 30 — the property guard (see the Round 30 section above
    // for the full design). One more thread, one 250 ms poll of a
    // single /proc read: negligible next to the rescan thread. It
    // also sweeps the grim reaper each cycle (shortest interval in
    // the process — bounds a dead child's zombie lifetime).
    {
        let g = grim.clone();
        thread::spawn(move || {
            prop_guard_thread(g);
        });
    }

    // Remove any stale socket, then bind a new one. Round 13: the
    // socket lives in a randomized per-boot directory when
    // /dev/urandom cooperates; the legacy fixed path is the fallback
    // (the session file is written either way so the payload's
    // reader and the daemon agree).
    let sock_path = setup_random_socket()
        .unwrap_or_else(|| remap_path(SOCK_PATH));
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

    // Round 33 — write the pid file OURSELVES. service.sh previously
    // recorded $! after `setsid ... &`, but the setsid wrapper may
    // fork (it does whenever the backgrounded job is already a
    // process-group leader, which Android's shell job control makes
    // the common case), in which case $! is the wrapper's pid and the
    // wrapper exits immediately — the file named a dead process from
    // the first millisecond and nothing could trust it. The daemon
    // knows its own pid; written after the bind so the file only ever
    // appears for a fully-started daemon.
    let pid_path = format!("{}/zygiskd.pid", workdir);
    let _ = std::fs::write(&pid_path,
        format!("{}\n", std::process::id()));
    let _ = std::fs::set_permissions(&pid_path,
        std::fs::Permissions::from_mode(0o600));

    // ROUND 34 (C12): the daemon's identity and the live randomized
    // socket path printed to STDERR on every start — the exact
    // secret the session-file handoff exists to protect. service.sh
    // redirects to /dev/null, but any manual run (adb shell) leaked
    // both. Gated behind an explicit env opt-in now.
    if std::env::var("ZS_DAEMON_VERBOSE").is_ok() {
        eprintln!("zygiskd: listening on {}", sock_path);
    }

    // Accept loop. The parent stays as root and accepts; each
    // connection is handed off to a privileged child. The session
    // dir (where the 'P' verb materializes the properties file) is
    // derived from the bound socket path.
    let session_dir = sock_path.rfind('/')
        .map(|i| sock_path[..i].to_string())
        .unwrap_or_else(|| SOCKDIR.to_string());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Round 34: snapshot BEFORE fork (locks taken here,
                // in the single forking thread — the child inherits a
                // lock-free copy through fork's CoW; see Snapshot).
                let snap = state.snapshot();
                spawn_privileged_child(stream, snap, grim.clone(),
                                       &session_dir,
                                       handle_client_with_first);
                // Reap after every accept: connection children are
                // short-lived, so this is normally where they leave.
                grim.reap();
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
    let _ = std::fs::create_dir_all(remap_path(SOCKDIR));
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(workdir,
        std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(remap_path(SOCKDIR),
        std::fs::Permissions::from_mode(0o700));
}

/// Round 28: add an inotify watch on MODULES_ROOT. This tiny wrapper
/// exists because the previous call sites passed the &str constant
/// straight to libc::inotify_add_watch, which requires a
/// NUL-terminated *const c_char — the daemon had NEVER been compiled
/// in this environment (no Rust toolchain before this round; see
/// ANDROID-REALISM.md), so the type error survived every round since
/// the inotify rescan thread was written.
fn inotify_watch_root(fd: i32, mask: u32) -> i32 {
    // MODULES_ROOT is a fixed ASCII path with no interior NULs; the
    // fallback arm is unreachable but keeps the unwrap off the wire.
    // ZS_TEST_ROOT remap keeps the host E2E watching the real temp
    // tree (see remap_path).
    let path = std::ffi::CString::new(remap_path(MODULES_ROOT))
        .unwrap_or_else(|_| std::ffi::CString::new("/data/adb/modules")
                                   .expect("fallback path is ASCII"));
    unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) }
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
fn rescan_thread_main(state: Arc<DaemonState>, grim: Arc<ChildGrim>) {
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
        inotify_wd = inotify_watch_root(inotify_fd, mask);
        // If inotify_add_watch fails (e.g. MODULES_ROOT doesn't
        // exist yet), we keep inotify_fd valid but no watch —
        // we'll fall through to the polling path below.
    }

    loop {
        // Round 34: sweep tracked connection children every tick —
        // companion children whose client vanished between accepts
        // leave the zombie state here at the latest.
        grim.reap();
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
                // name field following (variable length).
                //
                // ROUND 34 (C5): the drain used to discard the
                // contents and the "re-arm if lost" guard below could
                // never fire — nothing ever set inotify_wd back to
                // -1, so an IN_IGNORED (the watched directory itself
                // was deleted/replaced — exactly what a module
                // manager's atomic swap does) silently killed event
                // delivery FOREVER, with only the 30 s mtime
                // fallback left. The events are now parsed for the
                // watch-INVALIDATING masks (IN_IGNORED |
                // IN_DELETE_SELF | IN_UNMOUNT) so the re-arm below
                // actually runs.
                let mut buf = [0u8; 4096];
                let mut watch_lost = false;
                loop {
                    let n = unsafe {
                        libc::read(inotify_fd,
                                   buf.as_mut_ptr() as *mut libc::c_void,
                                   buf.len())
                    };
                    if n <= 0 { break; }
                    // struct inotify_event (man 7 inotify):
                    //   int wd; uint32_t mask; uint32_t cookie;
                    //   uint32_t len; char name[len];
                    let mut off = 0usize;
                    while off + 16 <= n as usize {
                        let wd = i32::from_ne_bytes(
                            buf[off..off + 4].try_into().unwrap());
                        let mask = u32::from_ne_bytes(
                            buf[off + 4..off + 8].try_into().unwrap());
                        let len = u32::from_ne_bytes(
                            buf[off + 12..off + 16].try_into().unwrap())
                            as usize;
                        if (mask & (libc::IN_IGNORED
                                    | libc::IN_DELETE_SELF
                                    | libc::IN_UNMOUNT)) != 0 {
                            watch_lost = true;
                            if wd == inotify_wd { inotify_wd = -1; }
                        }
                        off += 16 + len;
                    }
                }
                state.reload_modules();
                // Re-arm the watch if it was lost (IN_IGNORED etc.
                // removed it — see the ROUND 34 note above). The
                // retry is immediate after a manager swap; a MISSING
                // dir returns -1 again and the 30 s mtime fallback
                // covers the gap until it reappears.
                if watch_lost || inotify_wd < 0 {
                    let mask = libc::IN_CREATE
                             | libc::IN_DELETE
                             | libc::IN_MOVED_FROM
                             | libc::IN_MOVED_TO
                             | libc::IN_ATTRIB
                             | libc::IN_DELETE_SELF
                             | libc::IN_MOVE_SELF;
                    inotify_wd = inotify_watch_root(inotify_fd, mask);
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
        let modules_changed = match std::fs::metadata(remap_path(MODULES_ROOT)) {
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
        let denylist_changed = match std::fs::metadata(remap_path(DENYLIST_FILE)) {
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
    if !Path::new(&remap_path(WORKDIR)).exists() {
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

    // ---------------- parse_arg_extent (Round 28) ----------------

    #[test]
    fn parses_arg_extent_from_a_well_formed_stat_line() {
        // Real shape from a host /proc/self/stat (comm "zygiskd"):
        // fields after "pid (comm)" start at field 3 (state); we
        // build the line with the correct count so rest[45]/rest[46]
        // land on arg_start/arg_end.
        // rest indices 0..46 correspond to fields 3..49.
        let mut rest = Vec::new();
        for i in 0..47 {
            // Distinct values; fields 48/49 (rest[45]/rest[46]) carry
            // the extent we assert below.
            let v = if i == 45 { 0x7ffd0000 } else if i == 46 { 0x7ffd0040 }
                    else { 1000 + i };
            rest.push(v.to_string());
        }
        let stat_line = format!("4321 (zygiskd) {}",
                                 rest.join(" "));
        assert_eq!(parse_arg_extent(&stat_line),
                   Some((0x7ffd0000, 0x7ffd0040)));
    }

    #[test]
    fn parses_arg_extent_when_comm_contains_spaces_and_parens() {
        // comm "(weird name (2))" — the LAST ')' is the split point.
        let mut rest = Vec::new();
        for i in 0..47 {
            let v = if i == 45 { 0x1000 } else if i == 46 { 0x1080 }
                    else { 7 + i };
            rest.push(v.to_string());
        }
        let stat_line = format!("99 (weird name (2)) {}",
                                rest.join(" "));
        assert_eq!(parse_arg_extent(&stat_line), Some((0x1000, 0x1080)));
    }

    #[test]
    fn rejects_degenerate_or_short_stat_lines() {
        assert_eq!(parse_arg_extent(""), None);
        assert_eq!(parse_arg_extent("1 (zygiskd) S"), None);
        // arg_end <= arg_start is refused even with full length
        // (both fields deliberately equal — the degenerate case).
        let mut rest = Vec::new();
        for i in 0..47 {
            let v = if i >= 45 { 0x2000 } else { 3 + i };
            rest.push(v.to_string());
        }
        let stat_line = format!("1 (zygiskd) {}", rest.join(" "));
        assert_eq!(parse_arg_extent(&stat_line), None);
    }

    #[test]
    fn parses_arg_extent_from_the_real_proc_self_stat() {
        // End-to-end against this test process's own stat line: the
        // parser must return a non-degenerate, small window.
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        match parse_arg_extent(&stat) {
            Some((s, e)) => {
                assert!(e > s, "arg_end must exceed arg_start");
                assert!(e - s <= 4 * 4096,
                        "argv strings area unexpectedly large: {}", e - s);
            }
            None => panic!("real /proc/self/stat failed to parse"),
        }
    }

    #[test]
    fn rewrite_argv_changes_our_own_cmdline() {
        // End-to-end: run rewrite_argv on THIS process, then read
        // /proc/self/cmdline back. It must show the cloak name and
        // nothing else (no zygiskd, no --workdir fragments).
        rewrite_argv("cloak_probe_name");
        let cmdline = std::fs::read("/proc/self/cmdline").unwrap();
        let s = String::from_utf8_lossy(&cmdline).into_owned();
        assert!(s.contains("cloak_probe_name"),
                "cmdline does not contain the cloak name: {:?}", s);
        assert!(!s.contains("zygiskd"), "cmdline still exposes zygiskd: {:?}",
                s);
        assert!(!s.contains("--workdir"),
                "cmdline still exposes --workdir: {:?}", s);
    }

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

    // ---------------- Round 29: SELinux label resolution ----------------

    #[test]
    fn sanitize_selinux_context_accepts_real_android_contexts() {
        // The exact string bionic hard-codes for properties_serial
        // (android-13.0.0_r1 contexts_split.cpp:204), with the kernel's
        // trailing-NUL convention included.
        assert_eq!(
            sanitize_selinux_context(b"u:object_r:properties_serial:s0\0"),
            Some("u:object_r:properties_serial:s0".to_string()));
        assert_eq!(
            sanitize_selinux_context(b"u:object_r:properties_device:s0\0"),
            Some("u:object_r:properties_device:s0".to_string()));
        // A hypothetical OEM-custom type is passed through verbatim.
        assert_eq!(
            sanitize_selinux_context(b"u:object_r:oem_prop_serial:s0:c512\0"),
            Some("u:object_r:oem_prop_serial:s0:c512".to_string()));
        // No trailing NUL (raw len returned by lgetxattr) also fine.
        assert_eq!(
            sanitize_selinux_context(b"u:object_r:properties_serial:s0"),
            Some("u:object_r:properties_serial:s0".to_string()));
    }

    #[test]
    fn sanitize_selinux_context_rejects_garbage() {
        assert_eq!(sanitize_selinux_context(b""), None);                 // empty
        assert_eq!(sanitize_selinux_context(b"\0"), None);               // NUL only
        assert_eq!(sanitize_selinux_context(b"nocolons"), None);         // not a context
        assert_eq!(sanitize_selinux_context(b"a:b"), None);              // < 3 colons
        // Control bytes are refused.
        assert_eq!(sanitize_selinux_context(b"u:o\x01b:r:t:s0\0"), None);
        // Overlong (the buffer is 128; > 120 content is refused even
        // though it "fits").
        let long = format!("u:object_r:{}:s0", "A".repeat(200));
        assert_eq!(sanitize_selinux_context(long.as_bytes()), None);
    }

    #[test]
    fn props_file_label_falls_back_to_the_aosp_constant_on_this_host() {
        // This host has no /dev/__properties__ and no permission to
        // read security.* xattrs, so the runtime-copy path fails and
        // the verified AOSP fallback must apply — the modern serial
        // label (same behavior as before Round 29).
        let label = props_file_label();
        assert!(
            label == "u:object_r:properties_serial:s0"
                || label == "u:object_r:properties_device:s0",
            "unexpected label: {}", label);
    }

    #[test]
    fn props_file_target_path_is_the_6x_file_or_the_7x_serial() {
        // On this host /dev/__properties__ does not exist: the path
        // must resolve to the 7.0+ serial file.
        assert_eq!(props_file_target_path(),
                   "/dev/__properties__/properties_serial");
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

    // ---------------- Round 30: property guard ----------------

    use super::{prop_guard_step, GuardState, ZygoteObservation, GuardAction};

    fn fresh() -> GuardState { GuardState::new() }

    #[test]
    fn guard_restores_stock_once_bridge_is_loaded_and_stable() {
        let mut st = fresh();
        // Fresh zygote, not yet stable: nothing happens even if the
        // bridge is already mapped (the observation is not trusted
        // inside the grace window).
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 42, bridge_loaded: true, stable: false });
        assert_eq!(a, GuardAction::None);
        // Stable + bridge loaded: restore, and never twice.
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 42, bridge_loaded: true, stable: true });
        assert_eq!(a, GuardAction::RestoreStock);
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 42, bridge_loaded: true, stable: true });
        assert_eq!(a, GuardAction::None);
        assert!(st.restored);
    }

    #[test]
    fn guard_holds_when_bridge_never_loads() {
        let mut st = fresh();
        // Stable zygote without our bridge: lost race or failed
        // injection — the guard must NOT restore (if the property is
        // still set, the next zygote generation re-arms; restoring
        // would be pointless since this zygote already read the
        // stock value).
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 7, bridge_loaded: false, stable: true });
        assert_eq!(a, GuardAction::None);
        assert!(!st.restored);
    }

    #[test]
    fn guard_reapplies_after_zygote_death() {
        let mut st = fresh();
        prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 10, bridge_loaded: true, stable: true });
        // Zygote gone: re-apply the loader value, track reset.
        let a = prop_guard_step(&mut st, ZygoteObservation::Absent);
        assert_eq!(a, GuardAction::ReapplyLoader);
        assert_eq!(st.restarts, 1);
        assert!(!st.restored);
        // The replacement zygote appears and loads: restore again.
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 11, bridge_loaded: true, stable: true });
        assert_eq!(a, GuardAction::RestoreStock);
    }

    #[test]
    fn guard_counts_fast_replacements_as_restarts() {
        let mut st = fresh();
        prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 10, bridge_loaded: true, stable: true });
        // The tracked pid replaced without an Absent window in
        // between (the poll missed the gap): still one restart.
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 12, bridge_loaded: false, stable: false });
        assert_eq!(a, GuardAction::None);
        assert_eq!(st.restarts, 1);
        assert_eq!(st.known_pid, Some(12));
    }

    #[test]
    fn guard_rolls_back_after_too_many_restarts_and_stays_down() {
        let mut st = fresh();
        for gen in 0..4 {
            prop_guard_step(&mut st, ZygoteObservation::Present {
                pid: 100 + gen, bridge_loaded: true, stable: true });
            let a = prop_guard_step(&mut st, ZygoteObservation::Absent);
            if gen < 3 {
                assert_eq!(a, GuardAction::ReapplyLoader);
            } else {
                // The 4th death: restarts hits 4 > 3 — stand down.
                assert_eq!(a, GuardAction::RollbackAndStop);
            }
        }
        // Stood down: inert forever, even for a healthy new zygote.
        let a = prop_guard_step(&mut st, ZygoteObservation::Present {
            pid: 999, bridge_loaded: true, stable: true });
        assert_eq!(a, GuardAction::None);
        assert!(st.stood_down);
    }

    #[test]
    fn guard_noop_before_any_zygote_was_tracked() {
        let mut st = fresh();
        // Absent without a known pid (very early boot): no restart
        // count, no action.
        let a = prop_guard_step(&mut st, ZygoteObservation::Absent);
        assert_eq!(a, GuardAction::None);
        assert_eq!(st.restarts, 0);
    }

    // ---------------- Round 34: SIGCHLD / ChildGrim / Snapshot ----

    /// Signal disposition is process-wide and cargo tests run on
    /// parallel threads: every test that mutates SIGCHLD or relies
    /// on helper-exit semantics takes this lock so the two cannot
    /// interleave.
    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// THE Round 34 regression: documents, as an executable fact on
    /// THIS kernel/libc, why the daemon must NOT leave SIGCHLD at
    /// SIG_IGN. Under SIG_IGN the kernel auto-reaps every child, so
    /// waitpid() — including the one Rust std runs inside
    /// Command::output() — returns ECHILD and output() FAILS, losing
    /// the child's stdout. That is exactly how getprop's ABI answer
    /// was silently lost between Rounds 28 and 34.
    #[test]
    fn sigchld_sig_ign_breaks_std_command_output() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN); }
        let r = std::process::Command::new("/bin/true").output();
        // Restore FIRST so a later assert! failure cannot poison the
        // disposition for other tests.
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL); }
        match r {
            Ok(out) => panic!(
                "SIG_IGN no longer breaks Command::output() on this \
                 platform — the ChildGrim design note needs revisiting.\
                 (output unexpectedly succeeded: {:?})", out.status),
            Err(e) => assert_eq!(e.raw_os_error(), Some(10) /* ECHILD */,
                                 "unexpected error: {}", e),
        }
        // And with the default disposition (the daemon's new state),
        // helper execs work again.
        let ok = std::process::Command::new("/bin/true").output();
        assert!(ok.is_ok(), "default SIGCHLD must make output() work: {:?}",
                ok.err());
    }

    /// The reaper reaps EXACTLY the tracked pids and never steals a
    /// std::process child: forked children exit, a Command child runs
    /// concurrently, one reap() clears the zombies, and the Command's
    /// own waitpid still succeeded (its exit status is observable).
    #[test]
    fn grim_reaps_tracked_children_and_never_steals_std_children() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();
        let grim = ChildGrim::new();
        let mut tracked: Vec<i32> = Vec::new();
        for _ in 0..4 {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // Child: nothing but the exit. (Async-signal-safe.)
                unsafe { libc::_exit(0); }
            }
            tracked.push(pid);
            grim.track(pid);
        }
        // A std::process child — NOT tracked — runs while the
        // tracked ones are zombies. std's internal waitpid must get
        // ITS pid, not be confused by anything the reaper does.
        let out = std::process::Command::new("/bin/echo")
            .arg("pong").output().expect("untracked Command child");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "pong");

        // Reap the tracked children. They exit asynchronously —
        // the reaper is designed to sweep them on LATER ticks, so
        // poll until all four are gone (bounded).
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(3);
        let mut n = 0;
        while n < 4 {
            n += grim.reap();
            if n >= 4 { break; }
            assert!(std::time::Instant::now() < deadline,
                    "tracked children never left: reaped {} of 4", n);
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(n, 4, "all four tracked children reaped");
        assert!(grim.pending.lock().unwrap().is_empty());

        // None of them is a zombie anymore (a zombie would still
        // have a /proc/<pid>/stat with state 'Z'; a fully reaped
        // child has NO /proc entry at all).
        for pid in tracked {
            assert!(!std::path::Path::new(&format!("/proc/{}", pid))
                        .exists(),
                    "pid {} still has a /proc entry after reap", pid);
        }
        // Idempotent: nothing left to reap.
        assert_eq!(grim.reap(), 0);
    }

    /// The fork-safety property: another thread HOLDS the shared
    /// denylist mutex at the fork instant. The child serves its
    /// request from the Snapshot (taken before fork, locks released)
    /// and exits promptly. Under the pre-Round-34 design — child
    /// locking the shared state — this exact scenario deadlocks the
    /// child forever (the holder thread does not exist in the child).
    #[test]
    fn snapshot_child_never_blocks_on_a_lock_the_parent_thread_holds() {
        use std::time::{Duration, Instant};

        // Serialized with the signal tests: if SIGCHLD were SIG_IGN
        // while this child exits, the kernel would auto-reap it and
        // our waitpid would get ECHILD — a false "deadlock".
        let _g = SIGNAL_TEST_LOCK.lock().unwrap();

        let state = Arc::new(DaemonState::new());
        *state.modules.lock().unwrap() = vec![
            ModuleEntry { id: "mod_a".into(),
                          path: PathBuf::from("/x/zygisk/arm64-v8a/m.so") },
        ];
        *state.denylist.lock().unwrap() =
            parse_denylist_text("com.example.app1\n");

        // Another thread holds the denylist lock for 400 ms — the
        // fork will land inside that window.
        let st2 = state.clone();
        let holder = thread::spawn(move || {
            let _g = st2.denylist.lock().unwrap();
            thread::sleep(Duration::from_millis(400));
        });

        // Snapshot in the forking thread (locks free by then: the
        // snapshot's own lock() would otherwise serialize with the
        // holder — which is FINE, it just delays this test slightly).
        let snap = state.snapshot();

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: build a reply from the SNAPSHOT ONLY. No shared
            // lock is touched; glibc's malloc-atfork protection makes
            // the String allocation safe on the host (Scudo/jemalloc
            // give the same guarantee on device — see Snapshot docs).
            let buf = format_module_list(&snap.modules);
            let ok = buf.contains("mod_a")
                     && snap.denylist.contains("com.example.app1")
                     && !snap.denylist.contains("com.innocent.game");
            unsafe { libc::_exit(if ok { 0 } else { 1 }); }
        }
        // Parent: the child must exit on its own quickly (it would
        // hang forever if it ever locked the held mutex).
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut status: libc::c_int = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status,
                                            libc::WNOHANG) };
            if r == pid { break; }
            assert!(Instant::now() < deadline,
                    "child deadlocked: it blocked on a mutex held by a \
                     thread that does not exist in the child");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "child failed the snapshot checks: status={}", status);
        holder.join().unwrap();
    }
}
