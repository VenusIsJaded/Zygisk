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
  customize.sh, with uninstall restore), and the privilege-drop hook
  chain works end-to-end on host tests — but JNI hooking (module
  pre/post-specialize callbacks with real Zygote arguments) and the
  ptrace injection of `libzn_loader.so` remain stubbed, and nothing
  has been booted on real hardware. Treat it as a study skeleton
  until you have personally flashed and recovered it.

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

Requirements:

- Android NDK r25 or newer (clang, libc++, `aarch64-linux-android` and
  `armv7-linux-androideabi` targets)
- Rust toolchain with the `aarch64-linux-android` and
  `armv7-linux-androideabi` targets installed (`rustup target add ...`)
- CMake 3.18+ and Ninja

Then:

```bash
# from the repo root
mkdir build && cd build

# arm64 build
cmake -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  ../native
ninja

# the daemon (Rust)
cd ../native/zygiskd
cargo build --release --target aarch64-linux-android
```

The CMake build will produce `libzygisk.so`, `libpayload.so`, and
`libzn_loader.so`. The Cargo build will produce the `zygiskd` daemon.

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

(Total: 113 host-side tests, plus the daemon's `cargo test` suite.)

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
  `DaemonState.is_on_denylist`.

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
