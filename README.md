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
│   ├── libzn_loader/         # C++ bridge used by daemon to spawn payload
│   │   ├── CMakeLists.txt
│   │   └── src/entry.cpp
│   └── ...
├── tests/                    # host-side unit tests (no Android needed)
│   ├── Makefile              # `make` builds, `make run` runs them all
│   ├── test_framework.h      # tiny dependency-free test framework
│   ├── test_hide.cpp         # tests for the basic hide layer
│   ├── test_hide_advanced.cpp# tests for the advanced hide layer (memfd filter etc.)
│   └── test_e2e_hide.cpp     # end-to-end: forks a child, applies hide, verifies
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

- **`test_hide`** — basic hide layer: maps parser, denylist parser,
  decision logic, property-scrub key list, idempotency of init.
- **`test_hide_advanced`** — advanced hide layer: hidden-substrings
  coverage, filtered-paths coverage, memfd filtering (drops
  Magisk/.so entries, preserves libc, handles empty input), the
  open-hook path matcher, the GOT-patcher matcher (only `open` /
  `openat`), env-var scrub, signal-reset skip list.
- **`test_e2e_hide`** — end-to-end: forks a child, calls
  `hide_apply_for_target()`, verifies the child survives and reports
  back via pipe. Also parses real `/proc/self/maps` content, spikes it
  with a fake Magisk line, and verifies the filter drops it.
- **`cargo test`** — daemon's pure-logic parsers (no I/O required):
  `parse_verb_from_bytes`, `parse_denylist_text`, `format_module_list`,
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
(~5 ms per fork):

- **Module list is fetched once at payload init**, not per fork.
  A `g_modules_loaded` atomic guards against re-fetching. (Without
  this guard, every fork would open a fresh Unix socket to the
  daemon and block on `recv` — a major regression.)
- **`__system_property_set` is resolved at init time** via
  `hide_pre_resolve_symbols()`, not lazily on the first scrub call.
  The post-fork hot path skips a `dlopen` + `dlsym` roundtrip.
- **The daemon's module list / denylist use `RwLock`**, not `Mutex`.
  Multiple concurrent child connections reading the module list
  don't block each other; only the 30s rescan thread takes a write
  lock.
- **The daemon's rescan thread sleeps 30s** (was 15s) and checks
  the directory mtime before walking it. If nothing changed, the
  walk is skipped — a cheap no-op.
- **`pick_abi()` is cached in a process-wide `OnceLock`** so the
  rescan thread doesn't spawn a `getprop` child process on every
  wakeup.
- **`make_filtered_memfd` parses each maps line to find the path
  field** and only `strstr`s the substrings against that field,
  not the whole line. ~2x speedup on a typical ~500-line maps file.
- **`g_self_so_records` reserves capacity upfront** to avoid
  reallocation during the first snapshot.

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
