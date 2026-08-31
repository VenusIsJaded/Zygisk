# Architecture

This document explains, in plain English, how Zygisk Study fits
together. It is intended to be read alongside the source — every
claim here maps to a comment in the source.

## Overview

Zygisk Study is a four-component reimplementation of the public
Android "Zygisk" loader pattern:

```
                  boot
                   │
                   ▼
        ┌──────────────────────┐
        │     zygiskd          │  Rust binary, root context
        │  (long-running       │  Holds module registry + denylist
        │   companion daemon)  │  Listens on Unix socket
        └─────────┬────────────┘
                  │  (socket)
                  │
        ┌─────────▼────────────┐
        │  libpayload.so        │  C++ .so loaded into zygote
        │  - fork() hook        │  Calls zygiskd for module list
        │  - module dispatch    │  Runs per-module pre/post specialize
        │  - hide layer         │  Implements documented hide
        └─────────▲────────────┘
                  │  (loaded by)
                  │
        ┌─────────┴────────────┐
        │  libzygisk.so         │  C++ .so, the native-bridge
        │  - JNI_OnLoad         │  entry. Loaded by ART via
        │  - NativeBridgeItf    │  ro.dalvik.vm.native.bridge
        │    (NativeBridge2Itf  │  (the historical alias is kept
        │     kept as alias)    │  exported alongside it)
        └──────────────────────┘
                  │
                  │
        ┌─────────┴────────────┐
        │  libzn_loader.so      │  C++ .so, optional bridge
        │  - ptrace-injected    │  Used on platforms where the
        │    into non-zygote    │  native-bridge trick doesn't work
        │    targets            │  Exposes init-oriented API
        └──────────────────────┘
```

## Boot sequence

1. `post-fs-data.sh` runs. It makes `/data/system/zygisk_study`
   and `/data/system/zygisk_study/sock` with mode 0700
   (deliberately NOT under `/data/adb/` — that path is a known
   Zygisk signature). It also creates the empty `denylist` and
   `modules` files the daemon will read, saves the previous
   native-bridge property value, and — if `ro.dalvik.vm.native.bridge`
   is currently EMPTY — sets it to the BARE SONAME `libzygisk.so`
   (Round 7; the bare name is mandatory:
   `NativeBridgeNameAcceptable` rejects a path with `/` on every
   studied Android version). Devices that already run a real
   translation bridge are never overridden.

2. `service.sh` runs (post-boot). It launches the `zygiskd` binary
   in its own session (setsid) and waits one second for the socket
   to come up.

3. `zygiskd` opens a Unix socket in a per-boot RANDOMIZED,
   root-only directory (Round 13 — the legacy fixed path
   `/data/system/zygisk_study/sock/sock` remains the fallback),
   registers the real path with its own filters, and starts
   accepting connections. It also spawns a background thread that
   rescans `/data/adb/modules/<id>/zygisk/<abi>/libzygisk-module.so`
   every 15 seconds so newly-installed modules show up without
   restarting.

4. The next time ART starts the zygote, `Runtime::Init` dlopens
   the library named by `ro.dalvik.vm.native.bridge` —
   `/system/lib[64]/libzygisk.so`, the systemless copy customize.sh
   installed. ART looks up `NativeBridgeItf` and version-checks it;
   it NEVER calls `initialize()` in the zygote (verified from AOSP
   5.0 through 16: same-arch children even `dlclose` the bridge).

5. Our library CONSTRUCTOR (Round 25 — the only hook point that
   runs in the zygote on every Android version) runs inside that
   same dlopen: it dlopens the *real* native bridge if one is
   present (so the device's translation bridge still works), then
   dlopens `libpayload.so` and calls its
   `zygisk_study_payload_init` entry point.

6. `libpayload.so` initializes:
     - Snapshots `/proc/self/maps` to remember what was there
       before any of *us* was mapped. (Used by the hide layer.)
     - Resolves the real libc `setresgid`/`setresuid` (plus the
       legacy `setgid`/`setuid`) via `dlsym`.
     - Self-pins with `dlopen(dladdr(self), RTLD_NOLOAD)` so no
       child-side `dlclose` chain can ever unload it.
     - Connects to the daemon, requests the module list, dlopens
       every module's .so, and calls each module's `onLoad`.

7. Every fork inside the zygote reaches our hooks through the
   PRIVILEGE-DROP calls of the specialization sequence
   (`setresgid` → `setresuid`, with the legacy `setgid`/`setuid`
   pair covered — Round 7; a `fork()` hook was the pre-Round-7
   design and never actually existed). The gid hook fires first,
   still root: it resolves the target uid against the DenyList,
   and denylisted children run the hide pipeline (unshare +
   unmounts, property clone, Tier A vanish / Tier B hook install)
   right there. Non-denylisted children dispatch the module
   `preAppSpecialize` / `preServerSpecialize` callbacks before the
   real drop and `postAppSpecialize` / `postServerSpecialize`
   after it.

## Module contract

A module is a `.so` placed under
`/data/adb/modules/<module_id>/zygisk/<abi>/libzygisk-module.so`.

It must export the symbol `zygisk_module` (the standard Zygisk
factory). The factory's signature is:

```cpp
extern "C" __attribute__((visibility("default")))
zygisk::Module* zygisk_module(zygisk::Api* api, JNIEnv* env);
```

The factory returns a heap-allocated instance of a class derived
from `zygisk::Module`. The loader calls the four lifecycle
callbacks on this instance in this order:

```
onLoad
  └─ per fork
       preAppSpecialize  /  preServerSpecialize
       postAppSpecialize /  postServerSpecialize
```

## IPC protocol

The daemon speaks a tiny one-byte-verb protocol on its Unix socket:

| Verb | Direction  | Format                          | Reply                          |
|------|------------|---------------------------------|--------------------------------|
| 'L'  | client→srv | `L`                             | `<id>;<path>\n` lines until EOF |
| 'I'  | client→srv | `I<name>\n`                     | `1` or `0` (one byte)          |
| 'C'  | client→srv | `C`                             | long-lived echo connection    |
| 'P'  | client→srv | `P` + u32le length + area image | `1<staged-path>\n` or `0\n`   |

The 'P' verb (Round 19, verified live in Round 28) uploads a
properties-area image; the daemon validates magic@8 + version@12
(the R26 fix), stages it as a 0444 file inside the root-only
randomized session directory, and relabels it (chcon,
properties_serial/properties_device per version) so exec'd helpers
can read it. It is the only root-handled verb: the connection child
peeks the verb byte BEFORE its privilege drop.

This protocol is intentionally tiny — small enough that a reverse
engineer can recognize it from the binary in a few seconds.

## What is implemented vs. stubbed

| Feature                               | Status     |
|---------------------------------------|------------|
| Daemon IPC                             | implemented (Round 28: verified LIVE by `make verify-daemon` — the real binary, real socket, all four verbs) |
| Module enumeration                     | implemented |
| Hide layer (unmount + scrub + unmap)  | implemented (techniques) |
| ro.dalvik.vm.native.bridge swap       | implemented in `post-fs-data.sh` (Round 7: resetprop with the empty-value guard + backup for uninstall.sh; the bare-soname requirement documented in compatibility.md) |
| Per-module companion socket pair      | stubbed (modules use the daemon socket) |
| JNI hooking                           | stubbed (`hookJniEnv` returns 0) |
| ptrace injection of libzn_loader      | stubbed (daemon doesn't yet do this; the loader-side entry + API table are implemented and tested — Round 28) |
| WebUI                                  | not in this repo |

The stubbed pieces are marked with `// TODO:` in the source. They
are deliberate stubs, not bugs — this is a study skeleton, not a
finished product.
