# Zygisk Study

A from-scratch, **original-source** study project that reimplements — at the
conceptual level only — how a Magisk/KernelSU "Zygisk" loader works.

This repository contains **only source code I wrote myself**, plus build
scripts and documentation. There are **no prebuilt `.so` binaries** checked
in. Anything you build from this repo will be the output of the toolchain on
your machine, not a copy of any upstream artifact.

---

## What this project IS

- An **educational / research** reimplementation of the public, well-documented
  Android "Zygisk" loader pattern (pre-fork injection into `zygote`, a
  companion daemon, an in-process payload, and a small bridge library).
- Written from scratch in C++ (for the in-process pieces) and Rust (for the
  daemon). The source is intentionally clean, well-commented, and easy to
  read. No obfuscation. No tricks. The intent is that anyone reverse
  engineering the resulting `.so` files finds exactly what is in this repo
  and nothing else.
- **Runtime-stealthy**: the loader implements the publicly-documented
  hiding techniques used by Magisk DenyList, Shamiko, and similar
  projects. See `docs/hiding.md` for the complete list (basic + advanced
  layer). The `.so` files themselves remain easy to read in a disassembler —
  the stealth is functional behavior at runtime, not obfuscation of the
  binary.
- Designed to compile with the Android NDK + Rust `aarch64-linux-android`
  target. The CMake / Cargo configuration is provided so you can produce
  your own `.so` files from this source yourself.

## What this project IS NOT

- It is **not** "ZygiskNext". It is **not** a successor, fork, or rebrand
  of any existing Zygisk implementation. The author has no relationship with
  the ZygiskNext project, its binaries, or its source tree.
- It is **not** built from, and does **not** contain, any binary or source
  artifact taken from any other Zygisk project. Every line of source in
  this repository was written by the author based on publicly documented
  Android loader concepts.
- It is **not** tested on a device. It is **not** safe to flash. If you
  build it and install it, you should expect it to crash zygote and possibly
  boot-loop your device. The source is here for study and as a starting
  point for someone who wants to do a serious reimplementation.
- It is **not** a finished product. The `ro.dalvik.vm.native.bridge`
  swap IS implemented (post-fs-data.sh + the systemless layout in
  customize.sh, with uninstall restore), the privilege-drop hook
  chain works end-to-end on host tests, and (since Round 12) the
  Zygisk module lifecycle is actually driven: modules get a real
  JNIEnv at onLoad, real pre/post-specialize callbacks with the
  specialize arguments this hook point can source (uid/gid —
  WRITABLE, forwarded to the real privilege-drop calls — plus
  nice_name / package_name / app_data_dir), a working
  `hookJniEnv` table swap, and `connectCompanion()`. The ptrace
  injection of `libzn_loader.so` remains stubbed, and nothing has
  been booted on real hardware. Treat it as a study skeleton until
  you have personally flashed and recovered it.

## Why this exists

Since version v4-0.9.2, the official ZygiskNext project is no longer GPL and
its license explicitly forbids modification, redistribution, and "picking"
parts of the software into other projects (including "code snippets, functions,
and released binaries"). Anyone who wants a Zygisk-style loader that they
fully control, can read, can audit, and can legally redistribute therefore
has to write their own.

This repository is a starting point for that work. It implements the same
public, well-known architectural concepts — pre-fork zygote injection,
companion daemon, in-process trampoline, hide / denylist — in original,
readable source. Nothing here is taken from any other project.

## Repository layout

```
zygisk_study/
├── README.md                 # this file
├── PERFORMANCE-CLAIMS.md     # honest ledger of perf claims (HIGH/MEDIUM/LOW confidence)
├── LICENSE                   # Apache-2.0
├── .gitignore                # keeps binaries out of the repo
├── .github/workflows/tests.yml  # CI: runs the host tests on every push
├── module.prop               # Magisk module manifest
├── customize.sh              # Magisk install hook
├── post-fs-data.sh           # early boot hook
├── service.sh                # post-boot hook (launches daemon)
├── verify.sh                 # post-install integrity check
├── zygisk.hpp                # public Zygisk module API (companion to Magisk's)
├── zygisk_study_api.h        # optional companion API for init-oriented injection
├── native/
│   ├── CMakeLists.txt
│   ├── common/
│   │   └── log.h             # logging helpers (Android + host fallback)
│   ├── zygiskd/              # Rust daemon (companion process, module registry, IPC)
│   │   ├── Cargo.toml
│   │   └── src/main.rs      # (includes #[cfg(test)] unit tests)
│   ├── libzygisk/            # C++ .so that lands in zygote via ro.dalvik.vm.native.bridge
│   │   ├── CMakeLists.txt
│   │   └── src/entry.cpp      # exports NativeBridgeItf (the symbol ART actually dlsyms)
│   ├── libpayload/           # C++ in-process trampoline (loaded into every app)
│   │   ├── CMakeLists.txt
│   │   └── src/
│   │       ├── entry.cpp     # the privilege-drop GOT hooks + hide pipeline
│   │       ├── resolve_libc.h    # portable libc symbol resolution
│   │       ├── hide.h
│   │       └── hide.cpp          # basic hide layer (unmount, denylist, records)
│   │       ├── hide_advanced.h
│   │       └── hide_advanced.cpp # Tier B hooks, property clone, GOT registry
│   │       ├── hide_stealth.h
│   │       └── hide_stealth.cpp  # readlink hooks + stock-compatible prctls
│   │       ├── unmap_trampoline.h
│   │       ├── unmap_trampoline_aarch64.S  # Tier A self-unmap (arm64)
│   │       └── unmap_trampoline_x86_64.S   # Tier A self-unmap (x86_64)
│   ├── libzn_loader/         # C++ bridge used by daemon to spawn payload
│   │   ├── CMakeLists.txt
│   │   └── src/entry.cpp
│   └── ...
├── tests/                    # host-side unit tests + perf microbenchmarks (no Android needed)
│   ├── Makefile              # `make` builds, `make run` runs them all
│   ├── test_framework.h      # tiny dependency-free test framework
│   ├── test_hide.cpp         # tests for the basic hide layer
│   ├── test_hide_advanced.cpp# tests for the advanced hide layer (memfd filter etc.)
│   ├── test_hide_stealth.cpp # tests for the additional stealth layer
│   ├── test_e2e_hide.cpp    # end-to-end: forks a child, applies hide, verifies
│   └── test_perf.cpp         # microbenchmarks: 3 hot paths measured on the host
└── docs/
    ├── architecture.md       # how the pieces fit together
    ├── hiding.md             # the hide layer explained (public knowledge)
    └── compatibility.md      # Magisk vs KernelSU integration
```

## How to build (when you want your own `.so` files)

The one-command path (Round 32) — builds all four ABIs and assembles
the flashable Magisk-module zip:

```bash
# from the repo root (NDK discovery: ANDROID_NDK_HOME /
# ANDROID_NDK_LATEST_HOME / ANDROID_NDK_ROOT / $ANDROID_HOME/ndk/*)
NDK=/path/to/android-ndk ./scripts/build_module.sh

# output: build/out/zygisk_study-v<sha>-<count>.zip
# (self-verified: layout, module.prop, ELF classes per ABI)
```

The same script is what GitHub Actions runs on every commit
(`.github/workflows/build.yml`) — CI never duplicates build logic.

Requirements:

- Android NDK r26 or newer (clang + the CMake toolchain file; r26+ is
  the first release whose minimum API level, 21, matches this module's
  Android 5.0 floor)
- Rust toolchain with the Android targets installed
  (`rustup target add aarch64-linux-android armv7-linux-androideabi
  i686-linux-android x86_64-linux-android`)
- CMake 3.18+ and `zip`

Manual per-ABI CMake path (equivalent to what the script does):

```bash
# from the repo root
mkdir build && cd build

# arm64 build
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-21 \
  -DCMAKE_BUILD_TYPE=Release \
  ../native
ninja

# the daemon (Rust)
cd ../native/zygiskd
cargo build --release --target aarch64-linux-android
```

The CMake build will produce `libzygisk.so`, `libpayload.so`, and
`libzn_loader.so`. The Cargo build will produce the `zygiskd` daemon.

**16 KB page sizes (Round 27).** The CMake targets now link with
`-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384`, so the
three `.so` files load on 16 KB-kernel devices (Android 15+ optional,
Android 16+ shipping — Pixel 9a onward) exactly as on 4 KB devices
(verified against the official guidance:
developer.android.com/guide/practices/page-sizes). Rust's `cargo`
build of the daemon needs the same alignment on those devices — pass
it through your target linker config, e.g. in
`~/.cargo/config.toml`:

```toml
[target.aarch64-linux-android]
rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=16384",
             "-C", "link-arg=-Wl,-z,common-page-size=16384"]
```

These artifacts are **yours** — they were produced from this source on
your machine, with your toolchain. They are not derived from any other
project.

## How to run the host-side unit tests

The `tests/` directory contains host-side unit tests that exercise the
pure-logic paths of the hide layer (parsers, decision functions, the
memfd filter, the denylist format, etc.) without needing an Android
device or root. They compile the production `.cpp` files directly via
`#include`, so the test binaries have access to the production
`static` helpers and any drift between the two is impossible.

Requirements: g++ with C++17 support and `make`. No NDK, no Rust, no
Android device.

```bash
# from the repo root
cd tests
make            # build all three test binaries
make run        # build + run, exit code is non-zero on any failure
```

The Rust daemon has `#[cfg(test)]` unit tests for the wire-protocol
parsers (verb parsing, denylist parsing, module-list formatting).
Run them with:

```bash
cd native/zygiskd
cargo test
```

What the tests cover (Round 9):

- **`test_hide`** (27 tests) — basic hide layer: maps snapshot,
  denylist parser, decision logic, the property key list, the
  uid/appId denylist math (user 0 / work profile / secondary user
  all collapse to the same appId), the unmap record flag split that
  drives Tier A, and the mount-line parser matching BOTH magic-mount
  sources and mount points. Round 8 adds: the REAL denylist parser
  and its mtime refresh + 2-second throttle (driven through a path
  seam — which caught a production bug where a reload merged into
  the old set instead of replacing it), the app-library-directory
  guard (an app shipping its own `libpayload.so` must not get it
  unmapped), and the Tier A record preprocessing (read-only segments
  anonymized content-preserving, OTHER exec segments munmap'd, SELF
  records prioritized so the trampoline's fixed record array can
  never cut them). Round 9 adds: the mount-namespace seam tests —
  unshare → MS_SLAVE remount → umount ordering, and the fail-closed
  contract that NO umount2 ever runs after a failed unshare or a
  failed slave remount (the old code fell through and would have
  unmounted the init namespace system-wide on a real device), plus
  the prefix-length regression (the /data/system/zygisk_study/
  entry claimed 28 bytes for a 26-byte string, so it never matched).
- **`test_hide_advanced`** (54 tests) — advanced hide layer: the
  hidden-substring set, memfd filtering (drops Magisk/.so entries,
  preserves libc, handles empty input), the open/fopen/FORTIFY
  hook matchers, the **/proc/<pid>/... and /proc/thread-self/...
  path variants** (the pre-Round-7 filter matched only
  `/proc/self/...`), the property **spoof table** (stock values,
  never empty), the **content-preserving property clone**
  (host-simulated end to end), `find_prop_mappings`, the deferred
  Tier B registry, TracerPid rewrite, batched-write correctness,
  smaps filtering, the stat/faccessat2/fstatat/statx hooks behind
  the per-process active gate, and the `wrapped_open` closed-fd fix.
  Round 8 adds: the filter-kind resolver (`/proc/mounts` alias,
  `task/<tid>/` per-thread files, `/proc/net/unix` and its aliases,
  `/proc/self/environ`), per-kind record filtering
  (maps-line drop / TracerPid rewrite / env-entry drop / unix-line
  drop), streaming filtering of arbitrarily large files (a 400 KB
  maps file with hidden lines at the very end — the Round 7 cap
  silently truncated at 256 KB), the six-argument syscall passthrough
  (args 5-6 were garbage before), the hash-indexed hook matcher, the
  fopen open+fdopen fallback, the opendir ENOENT hook, the
  `ro.dalvik.vm.native.bridge` spoof entry, the walked-DSO mark set
  with dlclose garbage collection, and the chunked
  property-mapping scan for >96 KB maps files. Round 9 adds: the
  property ENUMERATION path (`__system_property_read_callback`
  swallows absent keys, legacy `__system_property_read` returns
  empty, `__system_property_foreach` drops absent keys before the
  caller's callback — driven with synthetic prop_info pointers and
  a fake foreach), the scandir/scandirat hooks (root-marker dirent
  entries dropped, hidden directories ENOENT, caller ownership
  preserved), the leaked-fd scan (REAL getdents64 + readlink
  against the host kernel: a fd pointing into the "module" dir is
  closed, a runtime fd survives), and the TLS filter scratch
  (five filter passes, at most one allocation).
- **`test_hide_stealth`** (16 tests) — the readlink rewriters
  (exe targets → stock app_process32/64 by pointer size; fd targets
  → /dev/null), the pid-variant matchers, idempotency, RLIMIT_CORE,
  and the cwd fixup. Round 8 adds: per-thread path variants
  (`/proc/<pid>/task/<tid>/exe|fd`, `thread-self/fd`).
- **`test_e2e_hide`** (5 tests) — forked-child survival, denylist
  inheritance across fork, real /proc/self/maps parsing with a
  spiked Magisk line.
- **`test_unmap_trampoline`** (2 tests) — THE Round 7 test: builds
  the real production sources into an actual `libpayload.so`,
  dlopen()s it, and drives the REAL asm wrapper through the full
  Tier A pipeline in a forked child. Asserts the child survives,
  the wrapper relays the REAL setresgid return value, **and
  `libpayload` is completely gone from the child's maps** — plus
  the pass-through behavior for a non-denylisted uid. This is the
  test that would have caught the original self-unmap crash (and
  that did catch an off-by-one in the first x86_64 register
  restore).
- **`test_perf`** (4 tests) — the microbenchmarks.
- **`test_module_dispatch`** (10 tests) — Round 12, the module
  lifecycle e2e: a fake zygiskd thread serves the REAL 'L'/'C'
  protocol, the REAL payload dlopens a REAL module .so
  (libzs_test_module.so), a fake JavaVM (exported as
  JNI_GetCreatedJavaVMs via -rdynamic) feeds the REAL env
  acquisition, and the REAL setresgid/setresuid hooks dispatch
  onLoad / pre / post into the module. Asserts the full callback
  order, the real argument values (uid, gid, nice_name,
  package_name, app_data_dir, multi-user), that module-rewritten
  uid/gid are forwarded to the real privilege-drop calls (via a
  drop-seam recorder), the server path, the legacy setuid path,
  that denylisted children hide INSTEAD of dispatching, and that
  FORCE_DENYLIST_UNMOUNT runs its unmount phase only after the
  post callbacks.

(Total: 251 host-side tests, the daemon's `cargo test` suite (45
tests), `make verify-daemon` — 32 LIVE checks against the real
zygiskd binary — and `make verify-scripts` (Round 29) — 106 LIVE
checks that run the module's actual shell scripts against a fake
Magisk environment. That last layer is the one that finally
executes post-fs-data.sh/service.sh/customize.sh/uninstall.sh on
the host, closing the "host tests green, device dead" gap for the
install chain. Round 30 adds: the Tier A atexit-purge e2e pair
(the purge-disabled variant is a LIVE regression proof — that
child SIGSEGVs exactly the way every hidden app used to on
exit()), the property-guard lifecycle (restore / re-apply /
rollback / stand-down against a fake zygote and a fake resetprop),
and the randomized-soname install flow.)

The logic suites also run clean under **ASan + UBSan with leak
detection** — `cd tests && make run-sanitize`. That run is where
Round 10 found and fixed a real production bug: the /proc path
matcher used `memcmp(path, "/proc/", 6)`, which reads past any
caller string shorter than 6 bytes — a latent SIGSEGV in the open()
hot path of every hidden app. `test_unmap_trampoline` is excluded
from the sanitized target on purpose: the Tier A anonymize step
legitimately copies entire read-only segments, which under
instrumentation contain ASan redzones (a false positive by
construction — the raw-mapping test runs unsanitized).
- **`test_perf`** (3 tests) — host-side microbenchmarks of the
  three hot paths (`make_filtered_memfd`,
  `hide_setup_for_target` fast path,
  `hide_apply_for_target` fast path). Asserts each completes
  within the documented budget. See `PERFORMANCE-CLAIMS.md`
  for the analysis.
- **`cargo test`** — daemon's pure-logic parsers (no I/O
  required): `parse_verb_from_bytes`, `parse_denylist_text`
  (now returns `HashSet` per P1.54), `format_module_list`,
  `DaemonState.is_on_denylist`, and (Round 28) the
  `/proc/self/stat` arg-extent parser behind the cmdline cloak.
- **`make verify-daemon`** (Round 28) — builds the REAL zygiskd
  with cargo, runs it against a remapped `/data` tree
  (`ZS_TEST_ROOT`; see `remap_path` in main.rs) and probes the
  real socket: the randomized session handshake (both session
  records since Round 29), the comm+cmdline cloak, the
  'L'/'I'/'C'/'P' verbs, zombie reaping, and restart cleanup
  (including the workdir-record-only variant). Skips (exit 77)
  when no Rust toolchain is available.
- **`make verify-scripts`** (Round 29) — runs the module's REAL
  shell scripts against a fake Magisk environment (temp module
  dir, PATH-injected fake `resetprop`/`log`, the `ZS_TEST_ROOT`
  `/data/system` remap): the native-bridge swap decision matrix
  ("" / "0" / real bridges), backup semantics, customize.sh's
  launcher symlink and API/ABI gates, service.sh's three launch
  paths, and the full uninstall restore matrix.
- **`make run`'s public-header check** (Round 28) — compiles
  `zygisk_study_api.h` standalone in both C99 and C++17, the way
  the header's own documentation tells module authors to use it.

What the tests do NOT cover (require Android + root):

- The actual `unshare(CLONE_NEWNS)` + `umount2(MNT_DETACH)` path —
  requires `CAP_SYS_ADMIN`.
- The `__system_property_set` call — only exists in Android's libc.
- The mmap-MAP_PRIVATE property-area clone — depends on
  `/dev/__properties__/` existing and being mmap'd by the runtime.
- The PLT/GOT patching — patches the host's own .so GOT, which is too
  risky to do in a self-test.

The syscall-touching paths are covered by inspection: their logic is
straight-line and the host tests verify the parsers feeding them
produce the right arguments.

## Performance

This is a study project; correctness and readability come before raw
throughput. That said, several optimizations are baked in so that
fork latency stays well below the typical Android zygote budget
(~5 ms per fork).

**See [`PERFORMANCE-CLAIMS.md`](PERFORMANCE-CLAIMS.md) for the
honest ledger of every performance claim, with confidence levels and
host-side measured timings.** That file is the source of truth for
"which optimizations are guaranteed to help on real Android vs.
which are speculation."

### HIGH-confidence optimizations (guaranteed on Android by construction)

- **Module list is fetched once at payload init**, not per fork.
  A `g_modules_loaded` atomic guards against re-fetching. (Without
  this guard, every fork would open a fresh Unix socket to the
  daemon and block on `recv` — a major regression.)
- **`__system_property_set` is resolved at init time** via
  `hide_pre_resolve_symbols()`, not lazily on the first scrub call.
  The post-fork hot path skips a `dlopen` + `dlsym` roundtrip.
- **`ZS_LIKELY` / `ZS_UNLIKELY` branch hints** on the hide fast
  path. The "target not on denylist" branch is taken 99%+ of forks;
  marking it LIKELY saves ~10 cycles per fork on Cortex-A76 and
  later (mispredict cost).
- **`unmount_magisk_paths` uses `getmntent_r` with a caller-supplied
  buffer** instead of `std::vector<std::string>`. Eliminates ~20
  heap allocations on the post-fork hot path (~700 ns saved per
  hide_apply_for_target call, real and measurable on Android's
  scudo allocator).
- **`unmap_self` early-returns if the snapshot is empty.**
- **The daemon's `Mutex` (not `RwLock`)** for the shared module
  list and denylist. RwLock was the original choice based on the
  theory "many readers, one writer" — but that pattern doesn't
  actually exist in this code (forked children open their own
  socket; the daemon serializes them in its accept loop). Under
  1:1 read contention, Mutex is faster than RwLock on AArch64
  (one cmpxchg vs. two atomic ops).
- **The daemon's rescan thread sleeps 30s** (was 15s) and checks
  the directory mtime before walking it. If nothing changed, the
  walk is skipped — a cheap no-op.
- **`pick_abi()` is cached in a process-wide `OnceLock`** so the
  rescan thread doesn't spawn a `getprop` child process on every
  wakeup.

### MEDIUM-confidence optimizations (real but magnitude unmeasured on Android)

- **`make_filtered_memfd` skips stdio FILE\* buffering** and reads
  the whole maps file in one `pread()`. Also: parses each line to
  find the path field and `memmem`s only in that field, not the
  whole line. Host measured: 303 µs for a 500-line / 40 KB
  synthetic maps file. Predicted Android: ~150-200 µs.
- **`g_self_so_records.reserve(16)`** to avoid reallocation during
  the first snapshot.

### Round 7 — crash fixes first, then the wins

The full audit story lives in PERFORMANCE-CLAIMS.md and
docs/ANDROID-REALISM.md; the short version:

- **Seven crash-on-device bugs fixed** that host tests could not see
  (self-unmap executing unmapped code; a property clone that zeroed
  the trie; a direct write to read-only shared property pages;
  close-all-fds destroying the GPU descriptors; a signal reset that
  killed ART's implicit null checks; a fork hook that was never
  implemented; a native-bridge symbol ART never looks up).
- **Tier A "vanish"**: denylisted apps end up with literally nothing
  resident — no hooks, no libraries, no fds, no mounts — via an asm
  self-unmap trampoline (arm64 + x86_64) that restores the original
  register frame and returns the real libc call's result.
- **Hooks moved out of the zygote**: system_server and every
  non-hidden app now execute zero hooked calls.
- Stealth coverage: `/proc/<pid>/...` + `/proc/thread-self/...`
  variants, fopen + FORTIFY + raw syscall() interception, dlopen
  re-patching, magic-mount source matching, stock-value property
  spoofing, module .so unmapping.

### Round 8 — deeper hiding, faster walks, and the bugs underneath

The full ledger lives in PERFORMANCE-CLAIMS.md and
docs/ANDROID-REALISM.md; the short version:

- **Five more real bugs fixed**, all invisible in host tests:
  the `syscall()` hook forwarded only 4 of 6 arguments (any
  5/6-argument syscall through the libc wrapper got garbage
  trailing args in hidden apps); `/proc/mounts` — the classic
  alias — bypassed the filter entirely; `/proc/<pid>/task/<tid>/...`
  per-thread variants bypassed it too; the filtered memfd silently
  truncated files at 256 KB (real `/proc/self/smaps` runs 1-3 MB);
  and a denylist reload merged into the old set instead of
  replacing it (removing a package from the denylist never took
  effect until a zygote restart).
- **Tier A no longer leaves dangling soinfo pointers**: read-only
  segments of every hidden library become content-preserving
  ANONYMOUS pages instead of being unmapped. The dynamic linker's
  `soinfo` nodes point into those segments (program headers,
  `.dynstr` soname) — Round 7's full munmap left every later
  `dlopen()`/`dl_iterate_phdr()` solist walk one `strcmp` away from
  a crash in app code. The bytes stay (linker walks stay safe), the
  file path disappears from maps (the hide stays complete).
- **New stealth coverage**: `/proc/net/unix` (our daemon socket's
  path was readable there system-wide — now filtered),
  `/proc/self/environ` (unsetenv rewrites the environ array, NOT
  the original stack block the proc file serves — our entries are
  filtered out), `opendir` on hidden paths (directory enumeration
  was never gated — Java `File.list()` covered),
  `ro.dalvik.vm.native.bridge` (was literally "libzygisk.so" — now
  spoofed to its pre-swap absent/empty state), and per-thread
  readlink targets.
- **App-library collision guard**: an app shipping its own
  `libpayload.so` in `/data/app/...` no longer gets it unmapped by
  our scanner.
- **Performance**: the GOT-walk hook matcher is hash-indexed (it is
  the inner loop of the most expensive step of a hidden app launch);
  the denylist mtime check is gated by a vDSO clock read (no more
  `stat()` per fork); dlopen re-walks are incremental (only newly
  loaded DSOs re-examined), with a dlclose-hook garbage collection
  that keeps the mark set correct across unload/reload cycles.

### Round 9 — propagation-safe unmount + enumeration-proof properties

Studied ReZygisk (PerformanC) for guidance this round — the ledger
of what we adopted vs. rejected and why lives in
docs/ANDROID-REALISM.md. The short version:

- **CRITICAL mount-propagation fix** (the round's headline): after
  `unshare(CLONE_NEWNS)` the new namespace stays in the same SHARED
  propagation peer group as init's on Android. Two consequences, both
  severe: our `umount2()`s on shared mounts propagate BACK to the
  init namespace (every process on the device loses its module
  mounts — triggered by one denylisted app fork), and any later
  mount event in init propagates INTO the child (root mounts return
  after we unmounted them). The fix is the same one Magisk's
  DenyList and ReZygisk's clean-namespace switch rely on: remount
  `/` as `MS_SLAVE|MS_REC` after the unshare. The pipeline is now
  also FAIL-CLOSED: if the unshare or the slave remount fails, the
  unmount phase is skipped entirely — the old code fell through
  after a failed unshare, and as root in the INIT namespace those
  umount2s would have succeeded (the old comment assumed the
  opposite).
- **Property enumeration closed**: `__system_property_foreach`,
  `read_callback`, and legacy `read` are now hooked. Previously a
  detector could enumerate all properties and see every key we spoof
  as "absent" present with an empty value — an anomaly that only
  hiding creates. `foreach` now drops absent keys before the
  caller's callback runs; `read_callback` swallows reads of absent
  keys entirely (prop_info addresses are collected from our patched
  clone at hide time, so cached/enumumerated pointers are caught
  too).
- **scandir/scandirat hooks**: scandir builds its list through
  libc-internal opendir/readdir, so the opendir GOT hook never saw
  it (documented Round 8 residual — now closed). Hidden directories
  report ENOENT (consistent with opendir); non-hidden directories
  get root-marker ENTRY names dropped in place.
- **Leaked-fd closing by link target**: `readlink("/proc/self/fd/N")`
  is a single-syscall detection vector. The hide pipeline now scans
  /proc/self/fd (raw getdents64, no recursion into our own hooks)
  and closes any descriptor whose target resolves under a
  root-framework path — including fds opened by modules, not just
  the ones we tracked ourselves. Runtime fds (/dev, memfd) are
  untouched.
- **Prefix-length bug**: the `/data/system/zygisk_study/` entries in
  both unmount prefix tables claimed 28 bytes for a 26-byte string.
  memcmp over-read the literal and never matched, so mounts of our
  own working directory were never unmounted from denylisted apps.
  Caught by the new fd-target test, fixed with a behavioral
  regression test on every prefix.
- **Performance**: the 64 KB /proc filter scratch is now a
  thread-local, allocate-once buffer — every filtered open() of
  maps/smaps/mounts/status/environ used to pay an mmap+munmap pair
  PLUS zeroing 16 fresh pages; now the first filtered open on a
  thread pays it once for the process lifetime.

### Round 12 — the module lifecycle actually runs

The feature the README had flagged as "stubbed" since Round 7: the
module dispatch layer. Modules were dlopen'd and constructed in the
zygote, then never called — the JNIEnv was nullptr, `hookJniEnv`
returned 0 without doing anything, `connectCompanion` returned -1,
and none of the five zygisk.hpp lifecycle callbacks ever fired.
Now (`native/libpayload/src/module_dispatch.{h,cpp}`):

- **A real JNIEnv, sourced honestly.** At the zygote's first fork
  (the earliest moment the VM exists and we are still pre-fork),
  the loader resolves `JNI_GetCreatedJavaVMs` (RTLD_DEFAULT, with a
  libart.so soname fallback) and takes the main thread's env via
  GetEnv / AttachCurrentThreadAsDaemon. Children inherit the
  pointer; it stays valid on the same thread through fork +
  specialization. No ART-internal method hooking anywhere.
- **pre/postAppSpecialize with real Zygote arguments.** The
  setresuid/setuid hook ENTRY dispatches the pre callbacks while
  the child is still root; the setresgid hook's argument is
  recorded as the gid. uid and gid are POINTERS into the live
  dispatch state — a module that writes through them changes what
  the real privilege-drop calls receive (the payload re-applies a
  changed gid with setresgid while CAP_SETGID is still held, then
  calls the real setresuid with the rewritten uid). nice_name
  comes from /proc/self/cmdline (falling back to the package name
  when the runtime has not rewritten argv yet — gated on
  PROCESS_UNPRIORITY so nobody-asked forks skip the read);
  package_name from packages.list via the same parse the DenyList
  uid map uses; app_data_dir derived as
  /data/user/<uid/100000>/<package>. post callbacks run right
  after the real privilege drop.
- **pre/postServerSpecialize** for system_server (the only
  uid-1000 zygote child).
- **DenyList contract**: denylisted children take the hide
  pipeline instead of module callbacks — their module .so's get
  unmapped, so running module code there would be a crash, and
  "no modules in hidden processes" is also the upstream semantic.
- **FORCE_DENYLIST_UNMOUNT** (setOption): unmount everywhere
  while still running callbacks. The mount work runs while still
  root (before the pre callbacks, so a module can still add its
  own mounts in the private namespace); the spoof/unmap phase
  runs AFTER the post callbacks — the last module code that ever
  executes in that process.
- **hookJniEnv** is a real function-table swap: the module hands
  in its patched copy of the table, the loader writes it into the
  JNIEnv's table slot (per-thread ART state, writable memory) and
  returns the original for chaining. connectCompanion() returns a
  live fd to the daemon's 'C' channel.
- API version bumped to 2 (zygisk.hpp) with the args structs;
  see the header for the honest deviation from upstream v4 (only
  the arguments this hook point can source are exposed).

### Round 13 — randomized daemon socket, stale-args fix, re-entrancy

- **The /proc/net/unix tell is gone for exec'd helpers.** That file
  is WORLD-READABLE and lists the path string of every filesystem
  unix socket — directory permissions are irrelevant to the listing.
  Our fixed `/data/system/zygisk_study/sock/sock` was therefore a
  system-wide identifier, and (unlike every other /proc file we
  filter) it stayed readable in anything the app EXECVEs — an exec
  replaces the address space, so no userspace hook can follow it
  there. The daemon now creates a per-boot socket directory with a
  neutral random name (`/data/system/.<8 hex>`), hands the actual
  path to the payload through a session file inside our own module
  directory (root-only, never in any world-readable listing), and
  cleans the previous boot's directory at startup. The payload
  registers the random directory with the mount-unmount, fd-close,
  and /proc/net/unix filters at init — hidden children drop every
  trace of it, and the name itself carries no identifier. The legacy
  fixed path remains the fallback when /dev/urandom fails.
- **packages.list staleness fixed** (a Round 12 residual): the
  appId -> package map now reloads when packages.list's OWN mtime
  changes, not only on denylist edits — an app installed after
  zygote start gets real specialize args within the 2 s throttle
  window. The first version of this fix aborted the check when the
  denylist file was missing; the new test caught it (each file is
  now checked independently).
- **The session e2e test caught a real use-after-return**: the
  socket-path setter stored a pointer to the session reader's stack
  buffer. Now copied into durable storage.
- **The R9 bionic re-entrancy residual is closed** with a nested-
  enumeration test: a property callback that itself calls
  __system_property_foreach re-enters the hook, which stays correct
  (each nesting level gets a fresh stack-local context; the hook
  holds no lock of its own).

### Round 14 — hot-path trims + the review pass

- **Derived-args cache (per-fork win):** the common app-launch
  pattern is the same uid forking repeatedly; the dispatch layer now
  caches the derived package_name/app_data_dir per uid (skipping the
  hash lookup + snprintf on every fork after the first of that uid).
  The cache is keyed on the FULL uid (an appId-family key would
  conflate user 0 and user 10 of the same package — different
  /data/user/<id>/ dirs; caught in review before it shipped) and on
  the packages.map generation, so the Round 13 staleness reload
  invalidates the cache in the same breath as the map. The
  invalidation is proven by a test that renames the package behind a
  uid and asserts the next fork sees the new name.
- **Redundant DenyList re-check eliminated:** the standard
  specialization order has the gid-drop hook decide the deny
  question first and the uid-drop hook re-ask it with the same key.
  The uid hook now skips its re-check when the recorded decision key
  matches exactly (one hash lookup less per app fork); a different
  key — the uid != gid corner, or a legacy setuid-only child with no
  prior decision — still re-checks, and a test drives the
  setuid-only denied child to prove the skip never becomes a gap.
- **Review pass over the Round 12-13 code** (the R11 discipline,
  applied to our own additions): thread-safety of the dispatch state
  against app threads and module-spawned threads calling setresuid
  (single-threaded-at-specialization + the done-gates make it safe),
  the FORCE-path ordering, the session reader's bounds, and the
  module-thread/filtered-open interaction (documented: a FORCE
  module's background threads that open /data/adb paths AFTER the
  post callbacks get ENOENT from the Tier B filter — modules must
  read their config in onLoad/pre, which is also when upstream
  modules do it).

### Host-side perf microbenchmarks

`tests/test_perf.cpp` measures the three hot paths above on the
host. Run it with:

```bash
cd tests && make test_perf && ./test_perf
```

Current results on x86_64:

```
[perf] make_filtered_memfd median:           ~190-195 us  (streaming rewrite, Round 8; was 303 us before P1.18)
[perf] hide_setup_for_target fast path median:  0 us  (sub-us; the Round 8 throttle removed the per-fork stat() entirely)
[perf] hide_apply_for_target fast path median:  0 us  (sub-us)
[perf] hook matcher median:                     ~42 ns  (Round 8 hash index; measured through the clock pair itself)
```

Round 6 additionally merged the advanced layer's two
`dl_iterate_phdr` GOT-patching walks into one (P1.60, saves
~60-100 µs at payload init on AArch64) and added prefix fast
gates to the open-hook and stat-hook path matchers (P1.61/P1.62).
These are init-time and hook-hot-path wins not captured by the
three microbenchmarks above — see `PERFORMANCE-CLAIMS.md` for
the honest accounting.

(All three pass their host-side budgets. The actual on-Android
numbers will differ — see `PERFORMANCE-CLAIMS.md` for the honest
analysis. The 44% reduction in `make_filtered_memfd` is the
direct, measurable effect of the P1.18 batched-write + P1.39
constexpr-lengths + P1.40 branch-hint optimizations.)

### Round 30 — the atexit purge, GrapheneOS, the property guard, and randomized names

Research-driven round, same discipline: every claim fetched and
read, nothing guessed. Sources this round: GrapheneOS's actual
exec-spawning implementation (fork+specialize-then-exec, default
on — nothing needed for us; the exec'd app re-reads the bridge
property only pre-10), Magisk's current zygisk daemon (they keep
the property set all boot — the exact hole we now close), bionic's
atexit internals (the __cxa_finalize protocol every proper dlclose
runs; __dso_handle is a self-pointing constant), a public
ZygiskDetector that enumerates libc's atexit array, and the
AndroidRuntime.cpp zygote-guard boundary (5.0-9.0: every
app_process run loads the bridge; 10.0+: zygote only).

Three real fixes/improvements landed:

1. **Tier A atexit purge** (device-fatal since Round 8): hidden
   apps crashed on the first exit() — and any module's
   pthread_atfork handlers crashed every fork() — because Tier A
   unmapped the libraries without purging their libc atexit
   entries (whose fn pointers then dangled into unmapped text).
   The purge mirrors a proper dlclose exactly; the regression is
   proven live (the seam-disabled child SIGSEGVs on the modeled
   bionic exit walk).
2. **The property guard**: ro.dalvik.vm.native.bridge — readable
   by any app — now reads stock again once the zygote has consumed
   it (observed via /proc/<zygote>/maps), with crash re-apply and
   a 3-restart bootloop rollback. The #1 generic root detection
   vector is closed while keeping restart reliability.
3. **Randomized loader names per install** (lib<8-hex>.so /
   lib<8-hex>-p.so, discovered via dladdr with legacy fallbacks):
   fixed-name maps greps no longer match anything.

Measured, not guessed: the per-fork COW audit reports a 0.00
minor-fault delta per child on host — the module's per-fork memory
cost is below the measurement floor, and the standing perf
medians (41 ns hook matcher, 0 us setup/apply) are unchanged.

### Round 31 — custom ROMs, race conditions, profiled performance

The user's brief: "search up every single custom ROM that exists and
make sure it is compatible ... do some race condition testing ... find
out what has the highest cost to run and make it take less resources
without messing anything up." All three, verified the usual way:

1. **The 50-ROM sweep** (compatibility.md has the full org/branch
   table): frameworks/base fetched from every major ROM family —
   LineageOS and its descendants, the privacy ROMs, TrebleDroid GSI,
   the legacy branches. Exactly THREE variants of the native-bridge
   acceptance logic exist across all of them; nobody changed what the
   property accepts, and every modern ROM keeps the spawn paths our
   hooks key on. The real custom-ROM gap was never the ROM — it was
   the ROOT MANAGER: the module now works on KernelSU and APatch
   (no resetprop binary, no magic mount without a metamodule) via
   its own bionic-exact property engine (`zygiskd prop`, 15 cargo
   tests + a live E2E against an independently built property area)
   and a loader-mount fallback chain (root-manager mount → direct
   copy → our own overlayfs → fail-closed rollback), driven by a
   /data/adb/post-mount.d hook on the managers that run it. Plus
   conflict detection (Magisk's Zygisk, ZygiskNext/NeoZygisk
   "zygisksu", ReZygisk) and dual-arch installs for the 32-bit
   zygote (ELF32-verified).
2. **Race-condition testing**: the hidden app is multithreaded, and
   every round before this one tested single-threaded. TSan against
   the pre-fix code reports **8 data races** (concurrent GOT
   re-walks, the mark-set GC, fd-shadow registration, the cwd
   prefix); the fix is a deadlock-free single-walker protocol (a
   plain mutex would AB-BA with bionic's recursive g_dl_mutex —
   constructors run under it, verified from dlfcn.cpp:101 +
   linker.cpp) plus leaf locks with copy-out views. `make race` now
   runs the TSan gate in CI; the proof harness reproduces the old
   code's 8 reports on demand.
3. **Profile-driven performance**: `gprofng collect-app` on a
   production-scale workload put 43% of exclusive CPU in
   zs_filter_record's byte-by-byte token walk. Two
   semantics-preserving changes ('/'-hop scanning with vectorized
   memchr — a hidden token must start with '/' — and compile-time
   length tables; the hidden-path tests caught two bad hand-counted
   lengths before anything shipped) cut the filter path **28%**
   (2.522s → 1.811s on an identical 12 GB workload) and the hot
   function **49%**. A new perf test locks the realistic 2 MB smaps
   contract; the standing medians are unchanged.

### Round 32 — flashable zips for every commit, and the bugs the build exposed

The user's brief: "find more bugs and optimizations and also make the
workflow make a .zip for every commit in actions. A flashable .zip."

1. **Every commit now produces a flashable zip.** `.github/workflows/build.yml`
   runs on every push (any branch), every tag, and manual dispatch: it
   gates on the full host suite (C++ + script E2E + daemon E2E + cargo),
   cross-builds all four ABIs (arm64-v8a, armeabi-v7a, x86_64, x86 —
   exactly the NDK's supported set at the module's minimum API 21) with
   the runner's preinstalled NDK, and uploads
   `zygisk_study-v0.1.0-<shortsha>-<commit-count>.zip` as an artifact.
   Tag pushes additionally publish a GitHub Release. The whole pipeline
   is `scripts/build_module.sh` — the identical script runs locally with
   `NDK=/path/to/ndk ./scripts/build_module.sh` — and the finished zip
   is SELF-VERIFIED (layout, module.prop's strict format, the
   `#MAGISK` updater-script marker, the install.sh legacy-installer
   trap, per-ABI ELF classes) before it can leave a green build. The
   recovery install path uses OUR OWN clean-room `update-binary`
   (Magisk's module_installer.sh is GPL-3.0 and is not vendored into
   this Apache-2.0 tree); Magisk/KSU/APatch app installs need no
   META-INF at all.

2. **Six real bugs the build flushed out** (five of them "the Android
   build had never actually worked" class — every previous round
   verified logic against AOSP sources, but nothing had ever compiled
   this tree with a real NDK):
   - `customize.sh` cased on NDK-style ABI names (`arm64-v8a`, ...) —
     but Magisk, KernelSU AND APatch all pass `ARCH=arm64|arm|x86|x64`
     (verified from all three `api_level_arch_detect` functions). Every
     real install aborted with "does not support arm64". Since Round 1.
   - `customize.sh` runs under `set -e`, and `X=$(getprop ...)` with a
     missing getprop binary (plain-recovery installs) exits 127 through
     the assignment — killing the install mid-way. Fixed with an
     installer-safe `zs_getprop` (getprop first, build.prop grep
     fallback — the same `grep_get_prop` pattern Magisk itself uses).
   - `project(... LANGUAGES C CXX)` — no ASM: CMake silently dropped
     both trampoline `.S` files, so libpayload.so could never link on
     Android (undefined `zs_fork_wrapper` & co.).
   - The raw-syscall fallbacks referenced `SYS_stat`/`SYS_lstat`/
     `SYS_access`/`SYS_readlink` — syscall numbers that DO NOT EXIST on
     aarch64's kernel UAPI (verified in the NDK sysroot headers).
     Now an `#ifdef` ladder: legacy syscall where it exists, the
     equivalent new-style syscall (`newfstatat`/`faccessat`/
     `readlinkat` with `AT_FDCWD`) where it does not.
   - 32-bit ABIs never linked: the GOT-hook wrappers existed only in
     the aarch64/x86_64 assembly. Plain C wrappers (the documented
     Tier-B contract — `hide_process_phase` accepts a null frame
     pointer, which is the Tier B input) now compile for every no-blob
     arch.
   - `dladdr1` is not declared by bionic's public `dlfcn.h` at ANY API
     level (verified in the sysroot) — the direct-call fallback could
     never compile for Android. When the runtime-resolved real
     `dladdr1` is unavailable the hook now degrades to dladdr
     semantics instead.
   Plus one clippy warning (identical test blocks) cleaned up.

3. **Verification additions**: the script E2E suite grew to **101
   checks** — the fake installer environment now feeds the REAL
   `ARCH` values (the old harness fed `arm64-v8a`, which is exactly why
   the ARCH bug survived 31 rounds of green tests), plus regression
   tests for the recovery no-getprop install and the build.prop
   fallback. The full cross-build was executed locally against NDK
   r27b before the workflow was written, and the produced zip was
   flash-simulated end-to-end on the host (arm64 dual-arch and 32-bit
   ARM installs, real ELF artifacts, randomized names, post-mount
   hook).

Final state: **243/243 host tests** (41 hide / 112 advanced / 20
stealth / 5 e2e / 6 perf / 4 trampoline / 23 dispatch / 11
version-compat / 16 zn_loader / 5 race) + `make race` (TSan: zero
data races — the old code's 8 are reproducible via the proof
harness) + `make run-sanitize` green, 45/45 cargo tests, `make
verify-daemon` 30 live checks (incl. the engine-driven guard with
no resetprop on PATH), `make verify-scripts` 101 live checks, 0
warnings, perf medians unchanged, and a locally verified 4-ABI
flashable zip pipeline. The full research trail with every source cited:
`docs/ANDROID-REALISM.md` (Round 32) and `docs/compatibility.md`
(custom ROM section).

### Round 33 — the CI permission bug, and closing the file-content fingerprint

The first live CI run of the flashable-zip workflow died at
`./scripts/build_module.sh: Permission denied` — the script had
been committed with git mode 100644, and a runner checkout
faithfully reproduced the missing exec bit. Fixed three ways: the
git mode is now 100755, the workflow invokes the script through
`bash` (immune to any future bit loss), and `make verify-scripts`
gains a CI-hygiene case that FAILS the build if either the mode or
the invocation regresses.

The stealth half of the round: Round 30 gave the two
`/system/lib[64]`-resident libraries randomized FILE names, but the
FILES themselves are world-readable, and every string constant
shipped verbatim inside — the full `/data/system/zygisk_study` path
map, "libpayload.so"/"libzygisk.so" needles, the root-manager
property keys, a `DT_SONAME` saying `libzygisk.so` inside a file
named `lib<8hex>.so`, ~1 MB of DWARF, a complete `.symtab`, and 528
exported libc++ symbols. A one-line `grep zygisk` over
`/system/lib64/*.so` fingerprinted us regardless of the file name.
Round 33 closes the CONTENT vector:

- Release builds are now the stealth artifact: `-O2`, no debug
  info, `llvm-strip --strip-all` on every packaged ELF,
  `-Wl,--exclude-libs,ALL` (the libc++_static symbols stop
  flooding `.dynsym`), `NO_SONAME` (bionic tolerates the absence —
  verified from its linker source: silent for targetSdk >= 23,
  dedup is by inode), and the `ZS_STEALTH` compile-out of every
  log site. Debug builds keep `-g` and full logs: that is the
  readable-for-study flavor now.
- `native/common/obfstr.h`: compile-time XOR obfuscation
  (constexpr-encrypted `.rodata`, runtime stack decode,
  `volatile` reads so LLVM cannot fold the decode back into a
  plaintext constant) with expression, holder and decode-once
  forms. Every signature literal in the bridge and payload now
  flows through it. The decode-once form initializes at
  `init_array` — NOT a magic static: magic statics reference
  `__cxa_guard_*`, which drags libc++abi's demangling terminate
  handler and its ~180 KB demangler into the library (measured:
  libzn_loader 9 KB -> 357 KB before the fix).
- The payload's internal export names are renamed to neutral
  `zs_entry_*` symbols (export names are the one leak vector
  obfuscation cannot cover — `.dynstr` must stay plaintext for
  dlsym); `-fno-rtti` removes the mangled typeinfo names from
  `.rodata` (verified empirically: virtual dispatch,
  `dynamic_cast<void*>` and module-side RTTI all keep working
  across the DSO boundary).
- `build_module.sh` verifies the result on every CI build: the
  packaged ELFs must be stripped, soname-free, and free of the
  banned-string set ("zygisk", "libpayload", "session.sock",
  ... — the two app-readable libraries only; the root-only daemon
  and the documented-API libzn_loader are out of scope by design).

Measured result: libpayload 1.70 MB -> 343 KB, libzygisk 37 KB ->
12 KB, libzn_loader 28 KB -> 8.3 KB, zip 2.9 MB -> 1.5 MB; the
remaining payload bulk is libc++abi's demangler, reachable only
from the exception-terminate path — generic content every NDK C++
library carries, pages that are never touched in a normal process.
Perf on the same machine, before/after: filter medians 29->31 us
and 1526->1499 us, matcher 63->65 ns — jitter-level; the hot-path
table loops kept their {ptr,len} memcmp shape.

Two more bugs found on the way: the `verify_zip` `set -e` trap
(a no-match `grep` inside a command substitution silently aborted
the whole script — the R32 header warned about exactly this class)
and the `service.sh` pid file, which recorded the PID of the
`setsid` wrapper — a process that forks and exits under shell job
control — so the file named a dead pid from the first millisecond.
The daemon now writes its own pid after the socket bind (verified
live: the E2E asserts the file names the running daemon).

Final state: **251/251 host tests** (8 obfstr / 41 hide / 112
advanced / 20 stealth / 5 e2e / 6 perf / 4 trampoline / 23
dispatch / 11 version-compat / 16 zn_loader / 5 race) + `make
race` TSan zero + `make run-sanitize` green + 45/45 cargo tests +
clippy clean + `make verify-daemon` 32 live checks + `make
verify-scripts` 106 live checks + trampoline binary verification
green (keystone) + the 4-ABI cross-build with all gates green,
built locally with the runner's exact NDK (r27d, 27.3.13750724).
The research trail: `docs/ANDROID-REALISM.md` (Round 33) and
`docs/hiding.md` (Round 33).

## License

Apache-2.0. See `LICENSE`.

The name "Zygisk" is a Magisk concept and is used here only in a descriptive
sense (i.e. "this implements the Zygisk loader pattern"). This project is
not affiliated with, endorsed by, or derived from Magisk, ZygiskNext,
NeoZygisk, ReZygisk, KernelSU, APatch, or any other related project.

## Status

Educational skeleton. Not for production use. Do not flash on a device
you care about without expecting to recover via fastboot.

If you actually want a working Zygisk loader, use the official releases
of the project of your choice from its official source. This repo exists
for people who specifically want to read, study, and reimplement the
loader concept themselves.

### Round 15 — fd-observable parity + linker enumeration closure

Every filtered `/proc` read used to hand the app a memfd whose CONTENT
was right but whose DESCRIPTOR answered questions differently from
procfs: `readlink("/proc/self/fd/N")` said `memfd:scudo`, `fstat`
reported the filtered byte count and mode 0777, and `mmap` succeeded
where procfs answers ENODEV. Each mismatch was a silent hook-detector
with zero false positives. The fd shadow table (dev/ino/size identity,
self-healing stale entries, dup-aware identity scan) now makes those
descriptors answer exactly like stock procfs, and `dl_iterate_phdr`/
`dladdr` no longer leak our library paths through the linker's solist
(with the dlpi_adds counter arithmetic kept exact).

### Round 16 — directory contents + relative /proc opens

`readdir`/`readdir_r` now drop hidden entry names (listing `/` shows no
`debug_ramdisk`, `/data` shows no `adb` — the classic RootBeer checks),
and raw `syscall(SYS_getdents64)` results are compacted in place.
`chdir("/proc/self"); open("maps")` and `openat(proc_dirfd, "maps")` —
including `.`/`..` traversal — are filtered exactly like the absolute
path.

### Round 17 — adversarial pass: a real crash class flushed out

The GOT patcher had been leaving pages `PROT_READ|PROT_EXEC` since
Round 7, which breaks LAZY PLT BINDING: the dynamic linker writes
resolved addresses into lazy `.got.plt` slots at first call, and
writing to an RX page faults. Any hidden app that dlopen'd a
lazy-binding third-party library would have crashed on the first call
of an unresolved import. Found by the new registry pin test (which
crashed the test binary at exit after all tests passed), fixed by
computing each page's original protection from the ELF headers.
Also: oversized streaming records no longer lose just their first
chunk, the getdents64 compactor survives a 2000-iteration adversarial
fuzz under ASan, and the GOT registry capacity moved 48 → 64 before
the live set (47) silently hit the ceiling.

Android version research behind these rounds (bionic sources read
across Android 9/13/main: fortify `__open_2` routing, no `openat2`
wrapper in any release, `memfd_create` API 30+, aarch64 fstat-as-
fstatat, `readdir_r` still exported) is documented in
docs/ANDROID-REALISM.md.

### Round 18 — version-research matrix

Every version-sensitive claim from Rounds 15-17 recorded as a
verifiable fact table (source file + release) in
docs/ANDROID-REALISM.md, with the honest residuals ledger.

### Round 19 — zygote research, the mounts-format leak, execve-proof properties

AOSP's own Zygote.cpp (read at 9/13/15/main) proves the
`setresgid`→`setresuid` pair this project hooks is byte-stable
across every supported version — and that A17's JNI-signature churn
(which ReZygisk just patched around) cannot touch this design. Two
real device bugs found and fixed this round: the /proc line filter
only understood the MAPS column layout, so mounts/mountinfo lines
leaked every root path (the fail-closed unmount backstop was broken
since Round 8); and the module dispatch fetched its list exactly
once at zygote start — before the daemon (late service stage) ever
exists, so zero modules ever loaded on a real device. The round's
headline feature closes the largest standing residual class:
exec'd helpers (`Runtime.exec("getprop ...")`) now re-map a
SPOOFED properties_serial through a private-namespace bind mount —
the same mechanism, in the same SELinux domain and the same boot
window, that AOSP itself uses for appcompat property overrides.

### Round 20 — the opendir dirfd bypass + stat parity

`opendir("/proc/self")` + `openat(dirfd, "maps")` read the REAL
unfiltered maps: opendir's internal open never crosses the GOT, so
no proc-dir record existed for the dirfd it hands back (the last R16
residual). The dirfd is now registered in the opendir hook. And the
mounted properties file now answers the REAL file's full stat()
identity (st_dev/st_ino/mode/size) through every query path —
stat/lstat/statx/fstat — closing the device-id cross-check gap from
Round 19.

**171/171 host tests** (35 hide / 91 advanced / 18 stealth / 5 e2e /
4 perf / 2 trampoline / 16 dispatch), 0 warnings, ASan+UBSan+leaks
green, every test binary exits 0.

### Round 22 — the property trie, read from bionic source this round

The round started by FETCHING and reading bionic's actual property
area sources (prop_area.h, prop_info.h, prop_area.cpp at
refs/heads/main AND android-9.0.0_r1 — byte-identical), and that
immediately paid for itself twice:

- **A REAL crash-class bug, shipped since Round 8**: bionic's
  reader takes the property value's LENGTH from the serial's top
  byte (`SERIAL_VALUE_LEN`, memcpy of len+1 bytes). The value
  patchers never updated that byte, so spoofing a LONGER value over
  a shorter device original (e.g. "enforcing" over "logging") made
  `__system_property_get` return a truncated, non-NUL-terminated
  string — a buffer over-read inside the hidden app. Both patchers
  (in-process clone and file image) now rewrite the length byte
  with the same odd/even serial protocol bionic's own writer uses.
- **The "trie cannot express deletion" claim was wrong** — the docs
  had it since Round 19, and it was the only reason absent-spoofed
  keys (`ro.magisk.version` etc.) stayed present-but-empty in the
  file image and hook-gated-only in the clone. A trie node with
  `prop == 0` is a legal "fragment without a property" (every
  intermediate node is one): zeroing a terminal node's prop offset
  is a deletion every bionic reader already understands. Both the
  exec'd-helper file image AND the in-process clone now delete the
  keys natively — find()/foreach()/get() report absence with NO
  hook involved — and the orphaned entries are scrubbed to zero, so
  a raw-forensics scan of the 128 KB image (or the process's
  memory) no longer finds "ro.magisk.version" as a dead record.

More this round: `__system_property_set` is now hooked to reflect
successful writes back into the clone (a hidden app that sets a
property and reads it back used to see its own write FAIL —
simultaneously a functional bug and a setprop/getprop mismatch
detector); fdopendir() registers bare /proc dirfds (the R15-17
residual — a DIR* built from an fd that never crossed a hooked
entry point); over-383-byte traversal strings now resolve through
a heap fallback instead of falling through UNFILTERED (the
documented R16 bypass — ASan caught a use-after-free in the first
version of exactly that code before it shipped); the clone copies
only the live prefix of the property area (~35-50% less memcpy on
the hide critical path, and the zeroed tail is strictly more
conservative than copying init's dead entries); and the aarch64
self-unmap blob — "verified by inspection only" since Round 7 — is
now ASSEMBLED and contract-checked by a real assembler
(`scripts/verify_trampolines.py`, keystone-engine: 161 aarch64 +
122 x86-64 instructions assemble, every restore slot matches the
wrapper's save slot register-by-register, __NR_munmap verified
from the encoding).

**182/182 host tests** (35 hide / 102 advanced / 18 stealth / 5
e2e / 4 perf / 2 trampoline / 16 dispatch), 0 warnings,
ASan+UBSan+leaks green, trampoline binary verification green,
every test binary exits 0.

### Round 23 — the adversarial pass: three real leaks

Reviewing the newest and the least-audited code with fresh eyes found
three real gaps, all closed with regression tests. First, the
readlink hooks only matched ABSOLUTE paths — `readlinkat(proc_dirfd,
"fd/3")` and `chdir("/proc/self"); readlink("fd/3")` answered with
the raw "/memfd:scudo (deleted)" target that the absolute-path arm
had been rewriting since Round 15 (the same bypass class Round 16
closed for open/openat). Second, every stock Android process carries
exactly two /dev/__properties__ file-backed lines in its maps, and
the property clone had silently replaced them with anonymous lines at
the same addresses since Round 7 — the Tier B filter now restores the
captured stock lines (the implementation tale — in-place compaction
cannot grow a record, and one sscanf per maps line would have
regressed the Round 19 filter win 2-5x — is in
docs/ANDROID-REALISM.md). Third, the heap fallback's path normalizer
used memcpy on formally-overlapping ranges (memmove now).

**186/186 host tests** (35 hide / 104 advanced / 20 stealth / 5 e2e /
4 perf / 2 trampoline / 16 dispatch), 0 warnings, ASan+UBSan+leaks
green, trampoline binary verification green, every test binary
exits 0.

### Round 24 — kernel research catches the merged-VMA trap

Reading mainline Linux's `mm/Kconfig` ANON_VMA_NAME help text ("an
area might prevent merging **due to the difference in their name**")
revealed that the two property-clone mappings — adjacent addresses,
identical protection, identical "linker_alloc" name — MERGE into one
VMA on a real device. The Round 23 maps restoration matched exact
per-mapping ranges: it would have silently done nothing in exactly
the real-device case (my host tests used two separate lines; the
kernel shows one merged line). The matcher is now containment-based:
one merged anon line in, the exact two stock lines out. PR_SET_VMA
constants and CONFIG_ANON_VMA_NAME's kernel gating were verified from
prctl.h/mm/Kconfig in the same pass, and the module dispatch's JavaVM
vtable indices (GetEnv@6, AttachCurrentThreadAsDaemon@7) against the
JNI spec.

**188/188 host tests**, 0 warnings, ASan+UBSan+leaks green, trampoline
binary verification green.

### Round 25 — Android 7.0/7.1/7.1.2/8.0/8.1 support: the bootstrap was never real

The round's version research (AOSP fetched at android-7.0.0_r1,
7.1.2_r33, 8.0.0_r17, 8.1.0_r81, plus 9.0/13.0 for boundaries)
found **two device-fatal defects that affected every Android
version, not just 7/8**:

1. **ART never calls the native bridge's `initialize()` in the
   zygote** — on every version studied (7.0 through 13), `Runtime::Init`
   only dlopen+dlsym+version-checks the bridge; the initialize call
   lives in `ZygoteHooks_nativePostForkChild` and only fires for
   foreign-arch children, while every same-arch child takes `kUnload`
   and **dlcloses** the bridge handle. The pre-Round-25 bootstrap
   (load the payload from `initialize()`) therefore never executed
   on real hardware: no hooks, no modules, nothing. The payload now
   bootstraps from a library **constructor** (runs inside the zygote
   at the dlopen, on every version), and both libraries are linked
   with **`-z nodelete`** plus a runtime self-pin in the payload —
   because bionic's `dlclose` calls `DT_FINI` when a refcount hits
   zero, and a Tier A (self-unmapped) hidden child no longer has that
   code mapped: without NODELETE that destructor call crashes every
   hidden Tier A child at `callPostForkChildHooks`.
2. **7.0–9.x call `isCompatibleWith()` during `LoadNativeBridge`**
   whenever the table's version >= 2 — our slot was NULL: a zygote
   SIGSEGV at boot. The table is now the exact 15-slot AOSP layout
   with every slot implemented (contract-valid no-ops, forwarded to
   the real translation bridge when present, version-gated).

For Android 7.x/8.x specifically, the research also confirmed the
zygote drop order (setgroups → setresgid → setresuid, no seccomp
between) and that 7.0+ already use the `/dev/__properties__/`
directory + trie property format with the same label — the whole
R19/R20/R22 execve-proof property layer works on 7.x unchanged.
Two more real bugs closed in the same pass: the property-clone
**pre-map ordering crash** (bionic maps per-context property files
lazily; a spoof key whose context the zygote never queried was
patched on the REAL read-only page — SIGSEGV at hidden-app launch,
all versions) and the **old-kernel memfd fallback** (Android 7.x
devices on 3.4/3.10 kernels have no memfd_create; the /proc filter
silently fail-opened — serving unfiltered content — it now writes
to an unlinked file in the hidden target's own data dir).

**199/199 host tests** (36 hide / 109 advanced / 20 stealth / 5 e2e /
4 perf / 2 trampoline / 17 dispatch / 6 version-compat), 0 warnings,
ASan+UBSan+leaks green, trampoline binary verification green.

### Round 26 — Android 6.0/6.0.1 support + two more device-fatal bugs found by version research

The 6.x research pass (AOSP fetched and READ at android-6.0.0_r1 and
android-6.0.1_r81: libnativebridge, art/runtime, bionic system_properties
+ linker, Zygote.cpp, init.rc, sepolicy, installd) confirmed the R25
bootstrap/bridge/lifecycle design works on Marshmallow **as-is** — M
loads by bare soname (`NativeBridgeNameAcceptable` rejects `/` on
every version 6.0 through 13.0 — the docs' full-path example was
wrong everywhere and is now fixed), reads only the 8-slot prefix of
our table, asks `isCompatibleWith(2)`, never calls `initialize()` in
the zygote, dlcloses the bridge in same-arch children, and its bionic
linker honors DF_1_NODELETE and RTLD_NOLOAD.

The 6.x property layer differs in exactly three ways (all verified
from M's own sources: same trie, same prop_info, same area header,
same serial protocol — only the PATH, the file-vs-directory form,
and the SELinux label differ): the maps matchers now catch the
single-file line, one cached `stat()` selects the image-builder
path / bind-mount target / daemon chcon label
(`u:object_r:properties_device:s0` on 6.x), and the stock-line
restoration covers the single 6.x maps line.

The same research caught **two device-fatal bugs on ALL versions**:

1. **The Rust daemon's 'P' validation read the area magic at byte
   offset 0** — but the streamed image is the verbatim property
   file, whose first 4 bytes are `bytes_used_` (the magic lives at
   offset 8, the version at 12; verified across 6.0/7.0/9.0). Every
   real 'P' request was rejected → the staged file never existed →
   fork+exec'd helpers kept seeing real property values — the
   entire execve-proof layer (R19/R20/R22) was dead on devices
   while the host suite stayed green: the e2e fixture used a fantasy
   "PROP"@0 format that agreed with the daemon's equally-wrong
   offset-0 check. Fixed at the daemon, the fake test daemon, the
   fixtures (now real-format), and the payload's self-check + magic
   registration (offset 8 everywhere, 16-byte length floor).
2. **The R22 set round-trip never woke waiters**: bionic's update
   path (verified at 6.0 AND 7.0) ends with a +1 release-store on
   the area serial AND a futex wake (plus a per-entry wake) — the
   clone never saw init's bump, so `__system_property_wait_any`
   slept forever after the app's own successful setprop. The set
   hook now reproduces the platform protocol on the clone (entry
   wake + area-serial bump + FUTEX_WAKE, inside the mprotect
   window — kernel semantics verified from Linux 3.10/5.10
   get_futex_key sources). Fully closes the round trip on 6.x
   (single area) and for default-context keys on 7.x.

**206/206 host tests** (37 hide / 112 advanced / 20 stealth / 5 e2e /
4 perf / 2 trampoline / 19 dispatch / 7 version-compat), 0 warnings,
ASan+UBSan+leaks green, trampoline binary verification green.
Android support now spans **6.0 through 15**, all boundary-verified
from AOSP sources.

### Round 27 — Android 5.0/5.1.1 support, Android 16/17 completion, and the 16 KB page-size fix

The research pass (AOSP fetched and READ at android-5.0.0_r1 /
android-5.1.1_r37 / android-6.0.0_r1 / android-7.0.0_r1 /
android-8.1.0_r81 / android-13.0.0_r1 / android-16.0.0_r1 and
refs/heads/main — note libnativebridge moved from system/core into
the **art** repo at Android 11, which is where 13/16/17 sources
live) closed three version gaps:

1. **Android 5.0/5.1.1 (Lollipop).** The 5.x loader is the ONLY
   exact-match generation: `kNativeBridgeCallbackVersion = 1` and
   `VersionCheck` demands `cb->version == 1` with no
   isCompatibleWith negotiation — our version=2 table would have
   been rejected with a boot warning and an immediate zygote-side
   dlclose. The constructor now rewrites the exported table's
   version field to 1 on SDK 21/22 (and 8 elsewhere) before ART's
   dlsym/VersionCheck runs; the table itself moved to writable
   `.data` (a const struct of function pointers lands in RELRO'd
   `.data.rel.ro`, where the rewrite would fault). Everything else
   on 5.x was verified identical from source: the property area is
   the SAME single file `/dev/__properties__` (128K, trie, prop_info,
   area header, serial+futex protocol byte-identical to 6.x — the
   trie landed in L, not M), same SELinux label
   (`u:object_r:properties_device:s0`, verified in 5.0/5.1.1
   file_contexts), same `map_prop_area_rw` creation in init, same
   ForkAndSpecializeCommon drop order (setgroups → setresgid →
   setresuid, no seccomp — app seccomp does not exist on 5.x), same
   child-side kUnload → dlclose lifecycle, `dladdr`/`dl_iterate_phdr`
   exported since 5.0, RTLD_NOLOAD bumps the refcount and
   `soinfo_unload` gates on `ref_count == 1` (the self-pin holds even
   though the 5.x linker does NOT honor DF_1_NODELETE — libzygisk is
   hook-free and disappears by design), installd creates
   `/data/user/0 → /data/data` at boot, and the 19-byte
   `/dev/__properties__` maps prefix already covers the single-file
   line.
2. **Android 16/17.** The bridge interface grew past our table: 13
   added v5 `getExportedNamespace` + v6 `preZygoteFork`, 16/main
   (= 17-dev, byte-identical) add v7 `getTrampolineWithJNICallType`
   + `getTrampolineForFunctionPointer` and v8
   `isNativeBridgeFunctionPointer` — 20 slots total. All v5-v8 entry
   points are isCompatibleWith-guarded, but answering false (the
   pre-R27 behavior) disables the features AND logs
   `ALOGE("not compatible ...")` on every fork in every bridge-
   initialized process (app-zygote children on real devices). The
   table is now the full 20-slot layout, isCompatibleWith answers
   1..8 true (0 and 9+ refused), and every new slot is implemented
   with the loader's own documented fallback (e.g.
   getTrampolineWithJNICallType falls back to the plain
   getTrampoline, exactly what the 16 loader itself does for
   pre-v7 bridges). The 16/17 drop order gained
   `SetUpSeccompFilter` + `SetSchedulerPolicy` BETWEEN the gid/uid
   drops — verified harmless: the whole hide pipeline runs at the
   gid-drop hook, i.e. before the app seccomp filter exists, and a
   Tier A child jumps out before any of it.
3. **16 KB page sizes (device-fatal on Android 16+ hardware).** The
   dynamic linker on a 16 KB-kernel device (Pixel 9a with Android
   16 onward) refuses ELF LOAD segments aligned below the kernel
   page size — a 4 KB-aligned `libzygisk.so` fails to dlopen **in
   the zygote**, killing injection entirely. All three CMake
   targets now link with `-Wl,-z,max-page-size=16384
   -Wl,-z,common-page-size=16384` (official NDK guidance, fetched
   and read); the payload's page math already used
   `sysconf(_SC_PAGESIZE)` everywhere it matters.

`customize.sh` now refuses installs below API 21 (4.x was closed
out by the Round 28 research: there is NO native bridge in Dalvik —
see the compatibility table).
**209/209 host tests** at that commit (37 hide / 112 advanced / 20
stealth / 5 e2e / 4 perf / 2 trampoline / 19 dispatch / 10
version-compat; the earlier "211" claim in this README and the R27
commit message was an arithmetic slip, corrected in Round 28),
0 warnings, ASan+UBSan+leaks green, trampoline binary verification
green. Android support spans **5.0 through 17-dev**, every boundary
verified from AOSP sources.

### Round 28 — the Android 4.3 verdict, and the round that made the daemon real

**Android 4.3/4.x: not possible, and now proven from AOSP rather
than assumed.** system/core at android-4.3_r1, 4.3.1_r1 and even
4.4.2_r1 has **no `libnativebridge` at all** (the library first
ships in L); Dalvik has no bridge-loading path (the VM's only
dlopen is the per-app `System.loadLibrary` loader, and every
"bridge" in dalvik/vm/Native.cpp is the VM-internal
`DalvikBridgeFunc` JNI call bridge, not a translation bridge);
`AndroidRuntime.cpp@4.3` reads the complete `dalvik.vm.*` surface
(17 keys) and no native-bridge property exists anywhere in the 4.3
bootstrap; the pre-L `/dev/__properties__` is the old flat-TOC
format (magic 0x504f5250 at the SAME offset 8 — a trap for
magic-only validators! — but version 0x45434f76 and fixed-size
`prop_info` records, no trie/contexts/wait_any); and the 4.3 zygote
drop sequence (dalvik_system_Zygote.cpp: PR_SET_KEEPCAPS →
PR_CAPBSET_DROP → setgroups → setresgid → setresuid → capset)
exists but is unreachable without a load mechanism. The
4.3-era alternatives were app_process replacement (Xposed classic,
/system writes — a different architecture) and the per-app
`wrap.<package>` root-peer wrapper — neither is zygote injection.
`customize.sh`'s API<21 refusal now cites all of this; the
compatibility table carries the full row. As a bonus, the
`ro.dalvik.vm.native.bridge` swap property was re-verified
byte-identical at 5.0/6.0/7.1.2/8.1/16/17-dev (16 adds a
zygote-only guard our swap already satisfies).

**The meta-fix: the daemon is now compiled, linted, tested AND
run for the first time since R13.** A Rust toolchain was installed
in this environment, which immediately paid off:

- **The daemon did not compile.**
  `libc::inotify_add_watch(inotify_fd, MODULES_ROOT, mask)` passed
  a `&str` where libc demands a `*const c_char` — a hard type error
  at BOTH call sites in the rescan thread. Invisible while no
  toolchain existed; fixed with a CString-building helper.
- **Zombie leak:** the accept loop forks one child per connection
  and never reaped them — 10 short connections leave 17 defunct
  rows in /proc (regression-proven by reverting the fix). Fixed
  with `signal(SIGCHLD, SIG_IGN)` (kernel auto-reap).
- **The cloak was half a cloak:** `rewrite_argv` was a documented
  no-op TODO, so `/proc/<pid>/cmdline` kept exposing
  `zygiskd --workdir /data/system/zygisk_study`. Now implemented
  for real via /proc/self/stat `arg_start`/`arg_end` (fields 48/49,
  split at the last ')'), the same setproctitle technique systemd
  uses; a cargo test runs it on the test process itself and asserts
  the cmdline afterwards.
- **`scripts/verify_daemon.py`** (+ `make verify-daemon`): a LIVE
  E2E — builds the real binary, runs it against a `ZS_TEST_ROOT`
  remapped tree, and checks 16 things over the real socket: the
  randomized session handshake, comm+cmdline cloak, 'L'/'I'/'C'/'P'
  verbs, denylist flip via the inotify path, zombie absence, and
  restart cleanup. All green; the zombie check was proven to fail
  with the fix reverted.

**More bugs found and fixed:** the public API header
`zygisk_study_api.h` did not compile standalone (missing
`<sys/types.h>` for uid_t/gid_t — the documented module-author
usage failed in both C and C++; now checked by `make run` in both
languages); **libzn_loader's init-oriented API was dead on devices
ever since R13's socket randomization** (it hardcoded the legacy
fixed path — `should_inject` always answered "no",
`open_companion_fd` always -1; now uses the session-file handshake,
with its first dedicated 13-test binary including live protocol
e2e); **both session-file parsers silently accepted truncated
overlong paths** and registered the garbage as hide-filter
prefixes (now rejected; +2 payload tests); **uninstall.sh used an
undefined `$MODDIR`** so the stale random-dir cleanup never ran,
and its `--delete`-then-set-`""` sequence re-created an empty
`ro.dalvik.vm.native.bridge` entry no stock device has (both
fixed).

**224/224 host tests** (37 hide / 112 advanced / 20 stealth / 5
e2e / 4 perf / 2 trampoline / 21 dispatch / 13 zn_loader / 10
version-compat) + the standalone public-header check, 20/20
cargo tests, clippy clean, `cargo build --release` green,
`make verify-daemon` 16/16 live checks, 0 warnings,
ASan+UBSan+leaks green, trampoline binary verification green,
perf medians unchanged. Android support remains **5.0 through
17-dev**, now with 4.x closed out as researched-not-possible.

### Round 29 — OEM firmware compatibility, verified the no-guessing way

Commissioned as "guarantee compatibility with all Samsung firmware
from Android 5 and Xiaomi, and others — do not ever guess." The
research pass mined real firmware, not assumptions: **173
physical-device getprop dumps** (Samsung OneUI 1.0-8.0, MIUI 9-14,
HyperOS, ColorOS, EMUI, HarmonyOS, OriginOS, Flyme, ...) showed
`ro.dalvik.vm.native.bridge` ships as `"0"` on 169 devices, absent
on 4, and a real bridge on zero — while ART (verified at
5.0.0_r1 and 16.0.0_r1) treats `""` AND `"0"` as no-bridge. The
two device-fatal bugs that fell out of that mismatch:

- **The module was dead on ~98% of real devices**: the swap guard
  only accepted an EMPTY value. Now both free values swap; real
  bridges are still refused.
- **The daemon never started on any install**: service.sh expected
  `$MODDIR/zygiskd`, which no script ever created. customize.sh
  now creates the launcher symlink; service.sh also falls back to
  scanning `libs/<abi>/`.

More from the same pass: the Samsung DEFEX kernel analysis
(unlocked-bootloader kill switch read from three kernel-source
generations — S7/S21/S24-era), OneUI/MIUI firmware-dump proof that
the property-area SELinux labels are stock (plus the daemon now
COPIES the live label instead of assuming it), the ReZygisk #380
Samsung path-block report answered with a dual session record
(module dir + the /data/system workdir) so the payload survives a
blocked `/data/adb/modules` tree, the frozen-deny-map retry fix
(a denied fopen used to latch empty maps for the whole boot), and
`make verify-scripts` — 45 live checks that finally EXECUTE the
module's shell scripts on the host against a fake Magisk
environment. Full fact table and honest residuals:
`docs/compatibility.md` (OEM section) and `docs/ANDROID-REALISM.md`
(Round 29).

**231/231 host tests** (39 hide / 112 advanced / 20 stealth / 5
e2e / 4 perf / 2 trampoline / 23 dispatch / 16 zn_loader / 10
version-compat) + the public-header check, 24/24 cargo tests,
`make verify-daemon` 19/19 live checks, `make verify-scripts`
45/45 live checks, 0 warnings, ASan+UBSan+leaks green, trampoline
verification green, perf medians unchanged (0 us / 0 us / 41 ns —
already at the measurement floor; no forced optimizations).
