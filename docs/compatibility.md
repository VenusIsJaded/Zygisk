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

1. Install the bootstrap library where the zygote's dlopen can
   find it (Zygisk Study's `customize.sh` installs systemless
   copies under `$MODPATH/system/lib[64]/` — the magic mount makes
   them appear at `/system/lib[64]/libzygisk.so`).
2. Set `ro.dalvik.vm.native.bridge` to the library's BARE SONAME
   (`libzygisk.so`) using the standard property-set mechanism
   (only root can set `ro.` properties after init has run, so this
   happens early).

**Round 26 correction (important):** the property value must be the
BARE SONAME, never a full path. libnativebridge's
`NativeBridgeNameAcceptable` rejects every filename containing `/`
(on every version studied — 6.0.0_r1, 6.0.1_r81, 7.0.0_r1,
7.1.2_r33, 8.0.0_r17, 8.1.0_r81, 9.0.0_r1 and 13.0.0_r1; the
allowed character set is `[a-zA-Z0-9._-]` with a leading letter).
A full path is silently rejected and the bridge never loads: the
zygote comes up without the loader and the module does nothing.
Because ART dlopen()s the bare soname through the default system
library path (`/vendor/lib[64]:/system/lib[64]` — and on 6.0 there
are no linker namespaces to complicate resolution), the magic-
mounted copy is what the zygote finds.

Zygisk Study's `post-fs-data.sh` performs the swap itself (Round 7):
it writes `libzygisk.so` into `ro.dalvik.vm.native.bridge` with
`resetprop`, but ONLY when the property is currently empty —
devices that already run a real native bridge (x86 ARM translation
hubs, ChromeOS-style bridges) must never be overridden, since
breaking translation breaks the whole device. The previous value
is saved for `uninstall.sh` to restore.

To enable the swap by hand on a device where the module's own
script did not run (e.g. no `resetprop` in the environment):

```sh
# The systemless copy is already at /system/lib64/libzygisk.so
# via the magic mount. Set the property to the BARE SONAME —
# a full path is rejected by libnativebridge on EVERY Android
# version studied (see the Round 26 correction above).
resetprop -n ro.dalvik.vm.native.bridge libzygisk.so
```

This is the standard Magisk-style setup and is documented in
several public Magisk guides. The technique itself is public
knowledge; the implementation here simply omits the destructive
part (overriding a real translation bridge).

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

## Android version support (Round 26)

The loader's Android surface was verified against AOSP sources at
android-6.0.0_r1, android-6.0.1_r81, android-7.0.0_r1,
android-7.1.2_r33, android-8.0.0_r17, android-8.1.0_r81 (plus
9.0/13.0 for boundary pinning):

| Android | Status | Verified from source |
|---|---|---|
| 6.0 / 6.0.1 | Supported (Round 26) | libnativebridge in system/core: same `NativeBridgeItf` symbol, 8-slot v2 table, VersionCheck asks isCompatibleWith(2) (6.0.1's native_bridge.cc is byte-identical to 6.0.0's, md5-verified); Runtime::Init dlopen + zygote-never-initializes + same-arch-child dlclose (identical lifecycle to 7.x); the SINGLE-FILE property area `/dev/__properties__` (same trie, prop_info, area header, serial protocol as 7.0 — only the PATH and the SELinux label `u:object_r:properties_device:s0` differ); bionic M linker honors DF_1_NODELETE + RTLD_NOLOAD; zygote drop order setgroups→setresgid→setresuid with no seccomp between; `/data/user/0 → /data/data` symlink created by installd at boot; 3.4/3.10 kernels → memfd fallback |
| 7.0 / 7.1 / 7.1.2 | Supported | nativebridge VersionCheck + isCompatibleWith(2) call; zygote setresgid→setresuid order; the /dev/__properties__/ directory + trie format; kernel floors (memfd fallback for 3.4/3.10) |
| 8.0 / 8.1 | Supported | LoadNativeBridge isCompatibleWith(3) call; the 15-slot table; same property format; 3.18/4.4 kernels have memfd |
| 9 – 15 | Supported (as before) | Rounds 7–24 research (9/13/15/main); Round 25 pinned the 9.x bridge lifecycle to the same constructor contract |

Key version-specific mechanisms and where they are handled:

- **Bootstrap**: a library constructor runs in the zygote during
  Runtime::Init's dlopen of the native bridge — the only hook point
  that exists on every version (ART never calls `initialize()` in
  the zygote — verified at 6.0 too, from M's own
  `ZygoteHooks_nativePostForkChild` + `Runtime::DidForkFromZygote`;
  same-arch children even `dlclose` the bridge, which the
  payload's self-pin neutralizes).
- **NativeBridgeCallbacks**: the exact 15-slot AOSP table with
  `isCompatibleWith` implemented — 6.0–9.x call that slot during
  `LoadNativeBridge` and a NULL slot is a boot crash. M only reads
  the strict 8-slot prefix and asks `isCompatibleWith(2)`.
- **Bridge property value**: the BARE SONAME `libzygisk.so` on
  every version — `NativeBridgeNameAcceptable` (6.0 through 13.0,
  all fetched and read) rejects any value containing `/`.
- **Properties**: 6.x map ONE regular file (`/dev/__properties__`,
  labeled `u:object_r:properties_device:s0` by init's restorecon);
  7.0+ map the `/dev/__properties__/` directory
  (`properties_serial` labeled `u:object_r:properties_serial:s0`
  by bionic's fsetxattr). The trie, prop_info, area-header layouts
  and the serial protocol are byte-identical across 6.0/7.0/9.0 —
  the payload detects the form with one stat() and points the
  image builder, the bind-mount target, and the daemon's label at
  the platform's own file.
- **Old kernels (3.4/3.10 on 6.x/7.x devices)**: no memfd_create —
  the /proc filter falls back to an unlinked scratch file in the
  hidden app's own data dir; `PR_SET_VMA`/`statx`/`openat2` absence
  is handled by the existing best-effort/fallback chains.
