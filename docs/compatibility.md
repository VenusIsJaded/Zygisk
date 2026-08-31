# Compatibility

This document describes how Zygisk Study integrates with the major
Android root managers (Magisk, KernelSU, APatch) and what the user
needs to know before installing it.

## Supported root managers

| Root manager | Support level                 |
|--------------|-------------------------------|
| KernelSU     | Best-supported; the `service.sh` and `post-fs-data.sh` hooks follow the KSU module conventions. |
| Magisk       | Supported, with one caveat (see below). The module directory layout matches what Magisk expects from a Zygisk alternative. |
| APatch       | Supported via the same Magisk-compatible hooks. |

## The Magisk caveat

Magisk has its own built-in Zygisk implementation. If the user has
Magisk's built-in Zygisk **turned on** while Zygisk Study is also
installed, both loaders will try to inject into zygote and the
result is undefined (typically: a boot-loop or a per-process
crash).

The user must turn Magisk's built-in Zygisk **off** before
installing Zygisk Study. This is the same constraint the official
ZygiskNext project imposes and there is no way around it — there
is only one `ro.dalvik.vm.native.bridge` property and only one
loader can own it.

## The `ro.dalvik.vm.native.bridge` swap

The standard way for a Zygisk alternative to land its bootstrap
library into zygote is:

1. Pick a path that ART will accept as a "native bridge" (it must
   look like `/system/lib*/*.so`).
2. Bind-mount the bootstrap library at that path (Magisk does this
   from `post-fs-data.sh`).
3. Set `ro.dalvik.vm.native.bridge` to that path using the
   standard property-set mechanism (only root can set `ro.`
   properties after init has run, so this happens early).

Zygisk Study's `post-fs-data.sh` does **not** currently do steps 2
and 3. The reason is that the bind-mount + property-set dance is
the most fragile part of the whole pipeline — if you get it
wrong, you brick the device. The current build leaves this to the
user (or to a future revision of the project).

To enable the swap by hand:

```sh
# Bind-mount libzygisk.so into /system/lib64
mkdir -p /system/lib64
mount --bind /data/adb/modules/zygisk_study/libs/arm64-v8a/libzygisk.so \
              /system/lib64/libzygisk.so

# Set the property. Use resetprop (Magisk) or ksud (KernelSU) for
# the actual set.
resetprop -n ro.dalvik.vm.native.bridge /system/lib64/libzygisk.so
```

This is the standard Magisk-style setup and is documented in
several public Magisk guides. The technique itself is public
knowledge; the implementation here simply omits the destructive
part.

## Per-ABI considerations

Zygisk Study ships separate libraries for each ABI:

- `arm64-v8a`  (primary, all 64-bit ARM devices)
- `armeabi-v7a` (32-bit ARM, only used by a small number of
  legacy devices and by Android's 32-bit app compatibility shim
  on some 64-bit devices)
- `x86_64`      (emulators and Chromebook Linux app compat)
- `x86`         (rare)

The `customize.sh` script picks the right one based on
`$ARCH`. If you have an unusual ABI (e.g. `riscv64`), the
script will abort with "Unsupported ABI".

## Relationship to other Zygisk implementations

Zygisk Study is **not** a successor, fork, or rebrand of any other
Zygisk implementation. The author has no relationship with the
ZygiskNext, NeoZygisk, ReZygisk, or Magisk-internal-Zygisk
projects.

Per the upstream ZygiskNext project's license (since v4-0.9.2):

> No Modifications: The software may not be modified in any way.
> No Redistribution: The software may not be redistributed in any form.
> No Picking: No parts, pieces, or components of the software may be
>             extracted and submitted to other projects.
> No Claim to Succession: Any fork of the software that was created
>             before the license change may not claim to be an
>             official or unofficial successor to the project.

Zygisk Study is therefore a **from-scratch original reimplementation**
of the public Android Zygisk loader pattern. It does not contain
any code from ZygiskNext, does not redistribute any ZygiskNext
binary, and does not claim to be a successor.

The "Zygisk" name itself is a Magisk concept and is used here only
in the descriptive sense (i.e. "this implements the Zygisk loader
pattern"). It is not a trademark.

## What to do if the device boot-loops

If you install Zygisk Study and the device fails to boot:

1. Boot into fastboot/recovery.
2. Mount `/data` and rename or delete the
   `/data/adb/modules/zygisk_study` directory.
3. Reboot.

This is the standard Magisk-module recovery procedure. The
Zygisk Study module is no more or less dangerous than any other
Zygisk alternative — the recovery procedure is the same.

## Android version support (Round 25)

The loader's Android surface was verified against AOSP sources at
android-7.0.0_r1, android-7.1.2_r33, android-8.0.0_r17,
android-8.1.0_r81 (plus 9.0/13.0 for boundary pinning):

| Android | Status | Verified from source |
|---|---|---|
| 7.0 / 7.1 / 7.1.2 | Supported | nativebridge VersionCheck + isCompatibleWith(2) call; zygote setresgid→setresuid order; the /dev/__properties__/ directory + trie format; kernel floors (memfd fallback for 3.4/3.10) |
| 8.0 / 8.1 | Supported | LoadNativeBridge isCompatibleWith(3) call; the 15-slot table; same property format; 3.18/4.4 kernels have memfd |
| 9 – 15 | Supported (as before) | Rounds 7–24 research (9/13/15/main); Round 25 pinned the 9.x bridge lifecycle to the same constructor contract |

Key version-specific mechanisms and where they are handled:

- **Bootstrap**: a library constructor runs in the zygote during
  Runtime::Init's dlopen of the native bridge — the only hook point
  that exists on every version (ART never calls `initialize()` in
  the zygote; same-arch children even `dlclose` the bridge, which the
  payload's self-pin neutralizes).
- **NativeBridgeCallbacks**: the exact 15-slot AOSP table with
  `isCompatibleWith` implemented — 7.0–9.x call that slot during
  `LoadNativeBridge` and a NULL slot is a boot crash.
- **Properties**: 7.0+ all use the same `/dev/__properties__/`
  directory + trie (magic 0x504f5250, version 0xfc6ed0ab) and the
  same `u:object_r:properties_serial:s0` label — the execve-proof
  file image, the bind-mount, and the in-process clone work
  unchanged.
- **Old kernels (3.4/3.10 on 7.x devices)**: no memfd_create — the
  /proc filter falls back to an unlinked scratch file in the hidden
  app's own data dir; `PR_SET_VMA`/`statx`/`openat2` absence is
  handled by the existing best-effort/fallback chains.
