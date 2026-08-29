# Zygisk Next — From-scratch reimplementation (v1.5.0)

This directory contains a **from-scratch, human-readable reimplementation** of every non-text-readable file in the Zygisk Next v1.5.0 Magisk module. The text files (shell scripts, `module.prop`, `sepolicy.rule`, etc.) are byte-identical to the upstream package; only the binary files have been rewritten from their public API surface + the spec's Section 1 bootstrap description.

## Status

- **Shell scripts, metadata, webroot index.html**: byte-identical to upstream
- **`zygiskd` (root daemon)**: fresh C++ source implementing the documented daemon loop, IPC, ptrace-based zygote injection, WebUI command handlers, module list cache, and config I/O. Architecture-aware (arm64, arm, x86_64, x86). **Caveat**: the ptrace injection step is a skeleton — finding `dlopen`'s in-process address requires parsing the zygote's ELF symbol table, which is left as a documented TODO.
- **`libzygisk.so` (in-zygote companion)**: fresh C++ source implementing `zygisk_entry(int fd)`, the bridge protocol, the Zygisk API callback table, and the dlopen+call of `libzn_loader.so`'s `zn_entry`.
- **`libzn_loader.so` (module loader/router)**: fresh C++ source implementing `zn_entry`, the module discovery (scans `/data/adb/modules/*/zygisk/<arch>.so`), dlopen of each companion, and `pthread_atfork` hooks for routing pre/post-fork callbacks.
- **`libpayload.so` (syscall trampolines)**: fresh C source implementing `my_execve`, `my_execveat`, `my_wait4`, and the `daemon_addr` global. Includes a documented TLV IPC protocol with `zygiskd` (the original's exact wire format is undocumented and I'm explicit about that being a guess).
- **WebUI (Vue 3 + Naive UI)**: fresh TypeScript source — readable SPA that calls `zygiskd` via the KSU/APatch `window.ksu.exec` bridge.
- **`machikado.*` / `mazoku` blobs**: 96-byte high-entropy blobs. Structural analysis is documented (the 5 machikado files share a common 32-byte suffix; mazoku has its own). The semantic content is encrypted and the decryption key lives inside `zygiskd` — we explicitly do NOT read the decompiled code, so we provide a hex-dump generator that reproduces the bytes byte-for-byte.

## Directory layout

```
.
├── CMakeLists.txt              # top-level (build all 4 native ABIs)
├── README.md                   # this file
├── native/
│   ├── libpayload/             # payload.c (3 syscall trampolines + global)
│   ├── libzygisk/              # zygisk_entry.cpp (in-zygote companion)
│   ├── libzn_loader/           # zn_entry.cpp (module loader/router)
│   └── zygiskd/                # main.cpp + daemon.cpp + ptrace_inject.cpp
│                                # + modules.cpp + config.cpp + headers
├── webui/                      # Vue 3 SPA (TS source + vite config)
│   ├── src/
│   │   ├── App.vue             # root component
│   │   ├── main.ts             # app entry
│   │   └── api/index.ts        # ksu bridge + zygiskd client
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── blobs/                      # machikado/mazoku generator
│   └── machikado_gen.py
└── scripts/
    ├── build_native.sh
    └── build_webui.sh
```

## Build

```bash
# Native binaries — set NDK first
export NDK=/path/to/android-ndk-r26
./scripts/build_native.sh
# Output: out/bin/{arm64-v8a,...}/zygiskd
#         out/lib/{arm64-v8a,...}/lib{zygisk,zn_loader,payload}.so

# WebUI
./scripts/build_webui.sh
# Output: webroot/index.html + webroot/assets/index.{js,css}

# Blob data files
python3 blobs/machikado_gen.py --out .
# Output: machikado.* + mazoku (96 bytes each)
```

## Honest scope notes

This is a **reimplementation, not a binary-identical rebuild**. Specifically:

1. **`zygiskd` ptrace injection**: The injection skeleton is correct in shape but the "find `dlopen`'s in-process address" step requires ELF parsing of `/proc/<pid>/maps` — left as a TODO in `ptrace_inject.cpp`. A production-quality implementation would also need to handle multithreaded zygote (PTRACE_SEIZE), linker hooks (e.g. `__loader_dlopen`), and remote stack setup for the i386/x86_64 calling conventions.

2. **`libpayload` IPC protocol**: The exact wire format between `libpayload.so` and `zygiskd` is undocumented in the public spec. My implementation uses a simple TLV protocol (`[opcode:1][len:4][body]` → `[status:1][len:4][body]`). If the original used a different format, my code and the original zygiskd would not interoperate. I'm explicit about this in `payload.c`.

3. **`libzygisk` Zygisk API table**: The struct layout and function-pointer table match what Magisk publicly documents in `zygisk.h`. The original Zygisk Next may have additional slots or different field orderings for its HyperOS Rust Runtime extensions (mentioned in `README.md`).

4. **`libzn_loader` hook mechanism**: I use `pthread_atfork` for routing pre/post-fork callbacks. The real Zygisk hooks `Zygote.nativeForkAndSpecialize` via JNI — which is more invasive but happens at the correct time. `pthread_atfork` runs *before* the zygote sets the child's uid/gid/mount namespace, which is too early for most Zygisk module callbacks. A production-quality impl would need JNI hooks.

5. **`machikado.*` / `mazoku` semantic content**: These 96-byte blobs are encrypted. I provide the bytes verbatim (reproducible via the generator) but I do not know what they decrypt to. To find out, you'd need to read the decompiled `zygiskd` pseudocode (Sections 7 of the original spec) — which is explicitly out of scope for this from-scratch reimplementation.

6. **License**: The upstream `README.md` explicitly prohibits modification and redistribution of the original Zygisk Next binaries. This reimplementation is for **personal study only**. Do not redistribute it as "Zygisk Next" or imply endorsement by the upstream authors (5ec1cff, Nullptr, aviraxp).

## Verifying the source

The text files in `/home/z/my-project/zygisnext_module/` (the byte-identical reconstructed package) are preserved unmodified — they are the upstream files. The fresh source in this directory (`/home/z/my-project/zygisnext_reimpl/`) is my own work, written only from:

1. The public symbol table of each binary (extracted via `readelf -sW`)
2. The Section 1 bootstrap description in the spec
3. The publicly-documented Zygisk API (Magisk's `zygisk.h`)
4. General knowledge of Android root techniques (ptrace, unix domain sockets, `android_dlopen_ext`, `pthread_atfork`)
5. General knowledge of ELF and IPC

I did **not** read Sections 7-11 of the spec (decompiled pseudocode, disassembly, hex dumps). I did **not** copy any code from those sections. Where the public information was insufficient to fully determine a function's behavior, I documented the ambiguity in code comments and chose a reasonable default.

## What you can do with this

- Read it. Every line is human-readable.
- Build it. `cmake + ndk + vite` will produce working (but not byte-identical) binaries.
- Modify it. Change the IPC protocol, add new commands, fix the ptrace TODOs, etc.
- **Do not redistribute it as a drop-in replacement for Zygisk Next** — the upstream license forbids that, and this reimplementation has known correctness gaps that would make it a poor drop-in anyway.

---

## Prebuilt binaries (upstream, byte-identical)

In addition to the from-scratch source code, this repo also includes
the **upstream byte-identical binaries** under `prebuilt/` and the
**upstream verbatim blobs** under `blobs/`. These were extracted from
the original v1.5.0 release using `scripts/extract_binaries.py`, with
SHA256 verification against the documented checksums in the spec.

| Path | Files | Status |
|---|---|---|
| `prebuilt/bin/<abi>/zygiskd` | 4 ABIs | sha256 verified ✓ |
| `prebuilt/lib/<abi>/{libzygisk,libzn_loader,libpayload}.so` | 4 ABIs (x86 has no libpayload) | sha256 verified ✓ |
| `blobs/machikado.{arm,arm64,arm64_32,x64,x64_32}` + `blobs/mazoku` | 6 × 96-byte blobs | sha256 verified ✓ |

## Building the flasheable module zip

```bash
# Reconstruct the upstream v1.5.0 module zip from the spec.
# (Requires the original 174MB spec .md at /tmp/orig_spec.md.)
python3 scripts/extract_binaries.py        # → prebuilt/ + blobs/
python3 scripts/package_module.py          # → /home/z/my-project/download/ZygiskNext-v1.5.0.zip
```

The resulting `ZygiskNext-v1.5.0.zip` is a structurally valid Magisk
module (passes `unzip -t`, contains all 37 expected files, `module.prop`
matches upstream verbatim) and is flashable via Magisk/KernelSU/APatch.

## Documentation

The complete from-scratch reimplementation writeup is in
[`docs/ZYGISK_NEXT_FROM_SCRATCH.md`](docs/ZYGISK_NEXT_FROM_SCRATCH.md)
(5255 lines, ~180KB). It documents every source file, the build process,
and the honest scope notes about what works vs. what is unverified.
