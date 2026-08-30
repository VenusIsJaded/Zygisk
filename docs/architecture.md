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
        │  libzygisk.so         │  C++ .so, the NativeBridge2 entry
        │  - JNI_OnLoad         │  Loaded by ART via
        │  - NativeBridge2Itf   │  ro.dalvik.vm.native.bridge
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

1. `post-fs-data.sh` runs. It makes `/data/adb/zygisk_study` and
   `/data/adb/zygisk_study/sock` with mode 0700. It also creates
   the empty `denylist` and `modules` files the daemon will read.

2. `service.sh` runs (post-boot). It launches the `zygiskd` binary
   in its own session (setsid) and waits one second for the socket
   to come up.

3. `zygiskd` opens its Unix socket at
   `/data/adb/zygisk_study/sock/zygisk_study.sock` and starts
   accepting connections. It also spawns a background thread that
   rescans `/data/adb/modules/<id>/zygisk/<abi>/libzygisk-module.so`
   every 15 seconds so newly-installed modules show up without
   restarting.

4. The system property `ro.dalvik.vm.native.bridge` is set to
   `/system/lib64/libzygisk.so` by the daemon (this part is NOT
   implemented in the current study build; the property swap is
   documented in `compatibility.md`). The next time ART starts the
   zygote, it dlopens `libzygisk.so` and calls
   `NativeBridge2Itf.initialize`.

5. `libzygisk.so`'s `initialize` hook runs. It dlopens the *real*
   native bridge if one is present (so the device's bridge still
   works) and then dlopens `libpayload.so` and calls its
   `zygisk_study_payload_init` entry point.

6. `libpayload.so` initializes:
     - Snapshots `/proc/self/maps` to remember what was there
       before any of *us* was mapped. (Used by the hide layer.)
     - Resolves the real libc `fork()` via `dlsym(RTLD_NEXT, ...)`.
     - Connects to the daemon, requests the module list, dlopens
       every module's .so, and calls each module's `onLoad`.

7. Subsequent forks inside zygote go through our `fork()` hook.
   Pre-fork: we run each module's `preAppSpecialize` /
   `preServerSpecialize`. Post-fork (in the child): we run the hide
   layer (if the target is on the denylist) and then each module's
   `postAppSpecialize` / `postServerSpecialize`.

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

This protocol is intentionally tiny — small enough that a reverse
engineer can recognize it from the binary in a few seconds.

## What is implemented vs. stubbed

| Feature                               | Status     |
|---------------------------------------|------------|
| Daemon IPC                             | implemented |
| Module enumeration                     | implemented |
| Hide layer (unmount + scrub + unmap)  | implemented (techniques) |
| ro.dalvik.vm.native.bridge swap       | stubbed (documented in compatibility.md) |
| Per-module companion socket pair      | stubbed (modules use the daemon socket) |
| JNI hooking                           | stubbed (`hookJniEnv` returns 0) |
| ptrace injection of libzn_loader      | stubbed (daemon doesn't yet do this) |
| WebUI                                  | not in this repo |

The stubbed pieces are marked with `// TODO:` in the source. They
are deliberate stubs, not bugs — this is a study skeleton, not a
finished product.
