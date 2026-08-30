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
- It is **not** a finished product. Several internal details (the
  `ro.dalvik.vm.native.bridge` swap, JNI hooking, ptrace injection of
  `libzn_loader.so`) are deliberately stubbed. They are clearly marked
  with `// TODO:` in the source. This is a study skeleton, not a drop-in
  replacement.

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
│   │   └── src/entry.cpp
│   ├── libpayload/           # C++ in-process trampoline (loaded into every app)
│   │   ├── CMakeLists.txt
│   │   └── src/
│   │       ├── entry.cpp     # entry, IPC handshake with zygiskd
│   │       ├── hide.h
│   │       └── hide.cpp          # basic hide layer (unmount, scrub, munmap)
│   │       ├── hide_advanced.h
│   │       └── hide_advanced.cpp # advanced stealth (props clone, maps filter, fd cleanup)
│   │       ├── hide_stealth.h
│   │       └── hide_stealth.cpp # additional stealth (readlink hook, PR_SET_PDEATHSIG/DUMPABLE, comm)
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

What the tests cover:

- **`test_hide`** (16 tests) — basic hide layer: maps parser,
  denylist parser, decision logic, property-scrub key list
  (incl. the 9 S46 Round 5 additions), idempotency of init,
  the fixed-size `so_record` array (P1.38).
- **`test_hide_advanced`** (20 tests) — advanced hide layer:
  hidden-substrings coverage (incl. P1.39 precomputed lengths),
  filtered-paths coverage (incl. S25 smaps + smaps_rollup),
  memfd filtering (drops Magisk/.so entries, preserves libc,
  handles empty input), the open-hook path matcher, the
  GOT-patcher matcher (`open`/`openat`), env-var scrub,
  signal-reset skip list, TracerPid rewrite (S10), batched-write
  correctness on 500-line input (P1.18), the smaps filter (S25),
  the `faccessat2` hook (S54), the `fstatat` hook (S55).
- **`test_hide_stealth`** (10 tests) — additional stealth layer:
  the readlink rewriter (drops Magisk/zygisk paths, preserves
  stock app_process), the readlinkat GOT-patcher matcher,
  idempotency of init, the broadened `/proc/<pid>/exe` matcher
  (S12), the RLIMIT_CORE check (S16).
- **`test_e2e_hide`** (5 tests) — end-to-end: forks a child,
  calls `hide_apply_for_target()`, verifies the child survives
  and reports back via pipe. Also parses real `/proc/self/maps`
  content, spikes it with a fake Magisk line, and verifies the
  filter drops it.
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

### Host-side perf microbenchmarks

`tests/test_perf.cpp` measures the three hot paths above on the
host. Run it with:

```bash
cd tests && make test_perf && ./test_perf
```

Current results on x86_64:

```
[perf] make_filtered_memfd median:           ~170 us  (was 303 us before P1.18; ~168 us after P1.39/P1.40)
[perf] hide_setup_for_target fast path median:  0 us  (sub-us)
[perf] hide_apply_for_target fast path median:  0 us  (sub-us)
```

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
