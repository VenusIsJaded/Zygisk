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
it writes the bridge's soname into `ro.dalvik.vm.native.bridge` with
`resetprop`, but ONLY when the property currently means "no bridge"
— devices that already run a real native bridge (x86 ARM translation
hubs, ChromeOS-style bridges) must never be overridden, since
breaking translation breaks the whole device. The previous value
is saved for `uninstall.sh` to restore.

**Round 30 — restore-after-consumption (the property guard).**
The property value is readable by any app and is the single most
generic root/Zygisk detection vector there is. Verified this round
from the actual sources: Magisk's own zygisk keeps the property set
for the whole boot (topjohnwu/Magisk
native/src/core/zygisk/daemon.rs — `set_prop()` once, `restore_prop()`
only on rollback/stop), and ReZygisk v2 abandoned the property
mechanism entirely for ptrace injection. Zygisk Study instead
restores it: the daemon's property-guard thread waits for the
bridge library to appear in the zygote's `/proc/<pid>/maps` — proof
ART consumed the value (AndroidRuntime.cpp reads it exactly once
per zygote start; from 10.0 a `zygote &&` guard means only the
zygote even attempts the load, verified at 5.0.0_r1 / 8.1.0_r81 /
10.0.0_r1 / 12.0.0_r1 / 13.0.0_r1 / 16.0.0_r1) — then writes the
stock value back with `resetprop`. On a zygote crash-restart the
guard re-applies the loader value before the new zygote's
Runtime::Init reads it (a 250 ms poll against init's restart
sequence), and after more than 3 restarts in one boot it rolls
back to stock permanently (Magisk's bootloop policy). The honest
residual: the property is set from post-fs-data until the guard's
restore lands shortly after `late_start` — no third-party app runs
in that window (apps start after boot-complete), but a system
component could theoretically read it; and a lost re-apply race
leaves the module inert for that zygote generation (the next
restart re-arms).

**Round 30 — randomized loader names.** `customize.sh` installs the
bridge and payload under per-install random names
(`lib<8-hex>.so` / `lib<8-hex>-p.so`), recorded in
`.loader_names`. A fixed `libzygisk.so` / `libpayload.so` in every
process's `/proc/self/maps` is a trivial string signature for
name-based Zygisk detectors; a random name per install defeats that
class of scan. The payload discovers its own path and the bridge's
via `dladdr` at runtime (`derive_payload_path` in libzygisk,
`discover_own_paths` in hide.cpp), with the legacy fixed names kept
as fallbacks for manual installs. On 5.0–9.0 the restore also stops
every non-zygote `app_process` run (`adb shell am` and friends)
from loading the bridge at all — those runs read the property
through the same AndroidRuntime.cpp path with no zygote guard
(verified: the guard first appears at 10.0).

**Round 29 correction (the biggest device-side bug this module ever
had):** "no bridge" is BOTH the empty value AND `"0"`. ART's own
loading decision (frameworks/base `core/jni/AndroidRuntime.cpp`,
verified at `android-5.0.0_r1:862-871` and
`android-16.0.0_r1:1109-1117`) is:

```cpp
property_get("ro.dalvik.vm.native.bridge", propBuf, "");
if (propBuf[0] == '\0') {
    ALOGW("ro.dalvik.vm.native.bridge is not expected to be empty");
} else if (strcmp(propBuf, "0") != 0) {
    // pass "-XX:NativeBridge=<value>" -> the runtime dlopen()s it
}
```

and a 173-device real-firmware collection
([getActivity/AndroidSystemPropertyCollect](https://github.com/getActivity/AndroidSystemPropertyCollect)
— Samsung OneUI 1.0-8.0, Xiaomi MIUI 10-14 + HyperOS 1-2, OPPO/OnePlus
ColorOS, Huawei EMUI + HarmonyOS(+NEXT), vivo OriginOS + FuntouchOS,
Meizu Flyme, realme, ZUI, RedMagic, and more) shows the split
directly: **169 devices ship `ro.dalvik.vm.native.bridge=0`, 4 ship
it absent, and zero ship a real bridge.** The pre-Round-29 guard
only accepted the empty value, so the module never installed its
loader on ~98% of real devices while every host test stayed green.
The guard now swaps on both free values and refuses anything else
(a real bridge soname) exactly as before.

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

## Android version support (Round 28)

The loader's Android surface was verified against AOSP sources at
android-4.3_r1, android-4.3.1_r1, android-4.4.2_r1,
android-5.0.0_r1, android-5.1.1_r37, android-6.0.0_r1,
android-6.0.1_r81, android-7.0.0_r1, android-7.1.2_r33,
android-8.0.0_r17, android-8.1.0_r81, android-13.0.0_r1,
android-16.0.0_r1 and refs/heads/main (= Android 17 development —
the bridge interface is byte-identical to 16's). Note: since Android
11, libnativebridge lives in the **art** repo
(`art/libnativebridge`), not system/core.

| Android | Status | Verified from source |
|---|---|---|
| 4.3 / 4.3.1 (and every 4.x) | **Not possible — the load mechanism does not exist** (Round 28 research) | system/core directory listings at android-4.3_r1, 4.3.1_r1 AND 4.4.2_r1 contain **no `libnativebridge` at all** — the library first ships in L (5.0); Dalvik has no bridge-loading path (dalvik/vm/Native.cpp's only dlopen is `dvmLoadNativeCode` for the per-app `System.loadLibrary`, and every other "bridge" in that file is the VM-internal `DalvikBridgeFunc` JNI call bridge, not a translation bridge); `frameworks/base/core/jni/AndroidRuntime.cpp@4.3` assembles the complete `dalvik.vm.*` property surface (17 keys — check-dex-sum … stack-trace-file) and no `ro.dalvik.vm.native.bridge` key is read anywhere in the 4.3 VM bootstrap; the pre-L property area is the OLD flat-TOC format (`/dev/__properties__` single file, magic 0x504f5250@8 — same value and offset as L+! — but version **0x45434f76**, a `toc[]` of 32-bit entries with the name length in the top 8 bits and a 24-bit offset, fixed-size `prop_info { char name[32]; serial; char value[92] }`, per-entry SERIAL_DIRTY protocol with `__system_property_wait` on the entry's own serial — no trie, no contexts, no area-serial wait_any broadcast). The 4.3 zygote's privilege drop DOES exist in native code (`dalvik/vm/native/dalvik_system_Zygote.cpp`: PR_SET_KEEPCAPS → PR_CAPBSET_DROP loop → setgroups → setresgid → setresuid → capset) — but with no way to load a library into that zygote there is no hook to reach it from. The only 4.3-era code-loading mechanisms are app_process replacement (the classic Xposed route — requires /system writes, outside this project's systemless model) and the per-app `wrap.<package>` invokeWith path (`ZygoteConnection.java@4.3` requires a root peer, and 4.3's init `check_perms` lets uid 0 set any property — but it wraps ONE app's launch as a post-drop wrapper process, which is not zygote injection and not Zygisk). `customize.sh` refuses API < 21 with this reasoning. |
| 5.0 / 5.0.x / 5.1 / 5.1.1 | Supported (Round 27) | system/core/libnativebridge at 5.0.0_r1 + 5.1.1_r37: `NativeBridgeItf` symbol, version field + FIVE v1 slots (initialize/loadLibrary/getTrampoline/isSupported/getAppEnv), `kNativeBridgeCallbackVersion = 1`, VersionCheck demands `cb->version == 1` EXACTLY (no negotiation) — handled by the constructor-time version rewrite; Runtime::Init dlopens the bridge (constructor bootstrap works); `DidForkFromZygote(kUnload)` → `UnloadNativeBridge` → dlclose in same-arch children (from 5.0's `art/runtime/native/dalvik_system_ZygoteHooks.cc`); `ForkAndSpecializeCommon` drop order setgroups→setresgid→setresuid with NO app seccomp (introduced later); the SINGLE-FILE property area `/dev/__properties__` with the SAME 128K trie/prop_info/area-header/magic 0x504f5250@8/version 0xfc6ed0ab@12/serial+futex protocol as 6.x (the trie landed in L, not M — verified from bionic at 5.0.0_r1, 5.1.1 differs only by SOCK_CLOEXEC on the property socket); `__system_property_update` bumps the area serial + futex-wakes (identical protocol — the R26 wake fix covers 5.x); SELinux label `u:object_r:properties_device:s0` (verified in 5.0/5.1.1 external/sepolicy file_contexts, same as 6.x); bionic L linker: RTLD_NOLOAD exists and bumps the refcount, `soinfo_unload` gates on `ref_count == 1`, `add_child` only happens for DT_NEEDED (the self-pin holds even though DF_1_NODELETE is NOT honored — libzygisk is hook-free and vanishes by design); `dladdr`/`dl_iterate_phdr` exported since 5.0; installd.c creates `/data/user/0 → /data/data` at boot; 3.4/3.10 kernels → memfd fallback |
| 6.0 / 6.0.1 | Supported (Round 26) | libnativebridge in system/core: same `NativeBridgeItf` symbol, 8-slot v2 table, VersionCheck asks isCompatibleWith(2) (6.0.1's native_bridge.cc is byte-identical to 6.0.0's, md5-verified); Runtime::Init dlopen + zygote-never-initializes + same-arch-child dlclose (identical lifecycle to 7.x); the SINGLE-FILE property area `/dev/__properties__` (same trie, prop_info, area header, serial protocol as 7.0 — only the PATH and the SELinux label `u:object_r:properties_device:s0` differ); bionic M linker honors DF_1_NODELETE + RTLD_NOLOAD; zygote drop order setgroups→setresgid→setresuid with no seccomp between; `/data/user/0 → /data/data` symlink created by installd at boot; 3.4/3.10 kernels → memfd fallback |
| 7.0 / 7.1 / 7.1.2 | Supported | nativebridge VersionCheck + isCompatibleWith(2) call; zygote setresgid→setresuid order; the /dev/__properties__/ directory + trie format; kernel floors (memfd fallback for 3.4/3.10) |
| 8.0 / 8.1 | Supported | LoadNativeBridge isCompatibleWith(3) call; the 15-slot table; same property format; 3.18/4.4 kernels have memfd |
| 9 – 15 | Supported (as before) | Rounds 7–24 research (9/13/15/main); Round 25 pinned the 9.x bridge lifecycle to the same constructor contract |
| 16 / 17-dev | Supported (Round 27) | art/libnativebridge at android-16.0.0_r1 == refs/heads/main (byte-identical, diff-verified): the 20-slot table (13.0 added v5 getExportedNamespace + v6 preZygoteFork; 16/main add v7 getTrampolineWithJNICallType + getTrampolineForFunctionPointer and v8 isNativeBridgeFunctionPointer; the v3 initAnonymousNamespace slot was renamed unused_initAnonymousNamespace — same position, ABI-stable); LoadNativeBridge asks isCompatibleWith(3) — accepts our table; every v5..v8 entry point is isCompatibleWith-guarded (RUNTIME_NAMESPACE=5, PRE_ZYGOTE_FORK=6, CRITICAL_NATIVE=7, IDENTIFY_NATIVELY_BRIDGED=8) and our table implements every slot so the guards pass; `InitNonZygoteOrPostFork(kUnload)` → dlclose lifecycle unchanged; Zygote.cpp drop order setresgid → **SetUpSeccompFilter + SetSchedulerPolicy BETWEEN the drops** → setresuid (16/main) — verified harmless: the hide pipeline runs at the gid-drop hook, before the app seccomp filter exists; 16 KB-kernel devices (Pixel 9a+) require `-Wl,-z,max-page-size=16384` ELF alignment — now set on all three CMake targets |

Key version-specific mechanisms and where they are handled:

- **Bootstrap**: a library constructor runs in the zygote during
  Runtime::Init's dlopen of the native bridge — the only hook point
  that exists on every version (ART never calls `initialize()` in
  the zygote — verified at 5.0, 6.0, 7.x, 8.x, 9.0, 13.0 and 16.0
  from each version's own `ZygoteHooks_nativePostForkChild` +
  `Runtime::DidForkFromZygote`/`InitNonZygoteOrPostFork`;
  same-arch children even `dlclose` the bridge, which the
  payload's self-pin neutralizes — on 5.x the pin is the ONLY
  protection, since the L linker ignores DF_1_NODELETE).
- **NativeBridgeCallbacks**: the exact 20-slot AOSP table (16 ==
  17-dev) with every slot implemented — 6.0+ call
  `isCompatibleWith` during LoadNativeBridge and a NULL slot is a
  boot crash; 16/17 index the v5..v8 slots once we claim those
  versions. The table's version FIELD is chosen at runtime:
  1 on SDK 21/22 (the 5.x loader demands `version == 1` exactly,
  no negotiation), 8 elsewhere (every 6.0+ loader negotiates). The
  table lives in writable `.data` so the constructor can rewrite
  the field before ART's dlsym/VersionCheck observes it.
- **Bridge property value**: the BARE SONAME `libzygisk.so` on
  every version — `NativeBridgeNameAcceptable` (5.0 through 13.0,
  all fetched and read; the character rules are in 5.1.1's own
  source comments) rejects any value containing `/`.
- **Properties**: 5.x/6.x map ONE regular file
  (`/dev/__properties__`, labeled
  `u:object_r:properties_device:s0` — same label on 5.x and 6.x,
  verified in each version's file_contexts);
  7.0+ map the `/dev/__properties__/` directory
  (`properties_serial` labeled `u:object_r:properties_serial:s0`
  by bionic's fsetxattr). The trie, prop_info, area-header layouts
  and the serial protocol are byte-identical across
  5.0/6.0/7.0/9.0 (the trie landed in Lollipop — bionic at
  5.0.0_r1 has prop_bt, the PORP magic at offset 8, the
  0xfc6ed0ab version at 12, and the same
  area-serial-bump+futex-wake update protocol) — the payload
  detects the form with one stat() and points the image builder,
  the bind-mount target, and the daemon's label at the platform's
  own file.
- **Old kernels (3.4/3.10 on 5.x/6.x/7.x devices)**: no memfd_create —
  the /proc filter falls back to an unlinked scratch file in the
  hidden app's own data dir; `PR_SET_VMA`/`statx`/`openat2` absence
  is handled by the existing best-effort/fallback chains.
- **16 KB page kernels (Android 15+ optional, 16+ shipping)**: all
  three CMake targets link with
  `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384` (the
  official NDK guidance) — a 4 KB-aligned bridge fails to dlopen
  in the zygote on a 16 KB device. The payload's page math already
  used `sysconf(_SC_PAGESIZE)` at every spot that matters, and the
  daemon's cargo build needs the same link flags (see README).
- **Install gate**: `customize.sh` refuses API < 21 — Android 4.x
  has a different property area generation and a different bridge
  symbol surface, and was never studied.

## OEM firmware compatibility (Round 29)

This section answers "does it work on Samsung / Xiaomi / other OEM
firmware?" with the same standard as the rest of the document:
every claim below is backed by a named source — real firmware dumps,
kernel source, or AOSP code — and the places we could NOT verify are
listed as residuals, not smoothed over. Nothing here is a guess.

### What every OEM has in common (verified from 173 real devices)

The load mechanism the module depends on — ART reading
`ro.dalvik.vm.native.bridge` and dlopen()ing the bare soname from
`/system/lib[64]` — is stock AOSP behavior that no phone OEM removes
(some x86 tablets and ChromeOS-style devices ship a REAL bridge;
the install guard refuses those devices rather than breaking them).
The evidence, from
[getActivity/AndroidSystemPropertyCollect](https://github.com/getActivity/AndroidSystemPropertyCollect)
(a collection of real getprop dumps taken from physical devices):

| OEM skin | devices sampled | value shipped |
|---|---|---|
| Samsung OneUI 1.0-8.0 (S8 to Z Fold7, A51-A55, Tabs) | 8 | all `0` |
| Xiaomi MIUI 9.2-14 (MI 5s to Mi 9, Redmi 5A to Note 7) | 26 | all `0` |
| Xiaomi HyperOS 1.0-2.0 (Android 13-15) | 14 | 12x `0`, 2x absent |
| OPPO/OnePlus ColorOS 11.1-15 (Reno, Find X, OnePlus 8/9) | 18 | all `0` |
| Huawei EMUI (P-series, Mate) | 11 | all `0` |
| Huawei HarmonyOS + NEXT | 15 | all `0` |
| vivo OriginOS 3-5 / FuntouchOS 9-12 | 9 | 8x `0`, 1x absent |
| Meizu Flyme 8-10.5 | 10 | 9x `0`, 1x absent |
| realmeUI 2-5, ZUI, RedMagicOS, MYUI, MagicOS, H2OS, 360UI, ... | 30+ | all `0` |
| LineageOS / PixelExperience (custom ROMs) | 4 | all `0` |

**169 of 173 devices ship `0`; the 4 newest builds ship the property
absent; zero ship a real bridge.** TouchWiz-era evidence matches: a
real Samsung Galaxy S7 (SM-G930F, G930FXXU1DQJ8, Android 7.0)
getprop capture (pytorch/cpuinfo's galaxy-s7-global fixture, taken
from a physical device) and an S6-era kernel's default.prop both
carry `ro.dalvik.vm.native.bridge=0`.

### Samsung specifics

**Property-area labels — verified from a real OneUI 5.1 (Galaxy A53,
Android 13) firmware dump** (`SelynCatto/samsung_a53x_dump`,
`system/system/etc/selinux/plat_file_contexts`): Samsung carries the
stock entries — `/dev/__properties__` (the directory) is labeled
`u:object_r:properties_device:s0` and nothing in Samsung's
`vendor_file_contexts` overrides it (checked: the vendor file's
`/dev` entries are Samsung's radio/GPU/modem nodes only). bionic —
which every OEM ships, it is the libc — sets the serial file's
`u:object_r:properties_serial:s0` label itself at creation
(`contexts_split.cpp:204` / `contexts_serialized.cpp:78` at
android-13.0.0_r1). Round 29 additionally made the daemon copy the
live label off the real file (`lgetxattr security.selinux`) and only
fall back to the hard-coded AOSP strings, so a future/custom OEM
type is handled automatically.

**Kernel-side (DEFEX / Knox)** — read from Samsung kernel source
mirrors (sm8650 = Galaxy S24 era, sm7325 = S20FE/S21 era,
universal8890 = S7 era):

- Modern Samsung kernels gate DEFEX on the bootloader state:
  `task_defex_enforce()` opens with `if (is_boot_state_unlocked())
  return DEFEX_ALLOW;` and the init log literally says
  "Device is unlocked and DEFEX will be disabled" — the module
  requires an unlocked bootloader (it is a Magisk module), so DEFEX
  is inert in exactly the configuration we run in.
- In both eras' syscall catch lists, `open`/`openat` carry
  `err_code = 0` — a zero err_code means DEFEX never inspects the
  call at all.
- PED (the credential-escalation killer) only fires when a process
  GAINS credentials; our payload only ever drops privileges (it
  hooks the setresgid/setresuid descent), and it runs inside
  app_process64, which is in the safeplace rules list.
- SafePlace only restricts which binaries a ROOT process may
  execve; the payload never execs, and the daemon is exec'd by
  Magisk's own service runner (which demonstrably runs on Samsung).

**The one real-world report against the pattern:**
[ReZygisk issue #380](https://github.com/PerformanC/ReZygisk/issues/380)
("Samsung DEFEX blocks app_process64 from open()ing /data/adb/modules
paths") — a field report from ReZygisk's ptrace injection flow, which
loads its library from the module directory. Zygisk Study does NOT:
its loader .so is magic-mounted at `/system/lib64/libzygisk.so` and
dlopen'd from there. But the session handoff file DID live only under
`/data/adb/modules/`, so Round 29 hardened exactly this class:

- The daemon now writes its session record TWICE — the module-dir
  file and `$WORKDIR/session.sock` inside its own
  `/data/system/zygisk_study` tree — and the payload (and
  libzn_loader) fall back to the second record when the module tree
  is unreadable. A device in the #380 state loses nothing; a healthy
  device pays zero extra syscalls (the fallback is opened only after
  the primary open fails).
- The denylist/packages.list loader now RETRIES after a failed
  fopen (the old code latched "loaded" and stored the current mtime,
  so one EACCES froze an empty deny map for the whole boot); a
  permanently-failing open costs one fopen attempt per 2 s.

**Dual Messenger / Secure Folder:** cloned and containerized apps
are separate Android users (Secure Folder is userId 150 — Samsung's
own support ecosystem describes it as "basically another Android
user"; Dual Messenger uses the same mechanism). The payload's
denylist matching is BY PACKAGE NAME, and its uid math
(`uid % 100000` to the appId family, `uid / 100000` to the user) is
user-ID-agnostic — verified against AOSP `UserHandle.getUid` — so a
Secure Folder copy of a denylisted app resolves the same package
name and hides the same way. `/data/user/<id>/<pkg>` paths follow
the real user id per fork.

**Knox warranty bit / RKP / TIMA:** the warranty bit trips on
bootloader unlock (prerequisite of any Magisk module on Samsung) —
documented, unavoidable, and orthogonal to this module. RKP/TIMA are
kernel-integrity features aimed at kernel-level root; a userspace
Magisk module is outside their threat model and Magisk has run on
unlocked Samsung devices for years.

**Honest residual:** Samsung does not publish its userspace, so
TouchWiz-era (5.x-8.x) per-model ART/sepolicy deltas can't be
diffed from here; those builds are AOSP 5.x/6.x/7.x-based (the real
S7@7.0 capture above proves the bridge path exists on TouchWiz),
the version-compat layer already handles their bridge tables, and
the kernel-source analysis above covers their DEFEX generation.
Per-model stock kernel configs are also not individually fetchable
(Samsung's OSS portal distributes per-model zip archives); the three
generations read above (S7 / S21 / S24-era) bracket the range.

### Xiaomi (MIUI / HyperOS)

All 40 MIUI + HyperOS dumps in the collection ship `0` (or absent on
the two newest HyperOS 2.0 builds). Xiaomi does not fork bionic, and
the package list the hide pipeline consumes
(`/data/system/packages.list`) is still written by stock
PackageManagerService on current Android — verified at
`android-16.0.0_r1` `services/.../pm/Settings.java:721`
(`mPackageListFilename = new File(mSystemDir, "packages.list")`) with
the parser reading only the first two fields of the 11-field modern
format, so MIUI's extra packages parse identically. Xiaomi Dual Apps
are Android user 999 (community-documented, and consistent with the
uid math above); no MIUI-specific native-bridge problems appear in
the ReZygisk/ZygiskNext issue-tracker sweeps (their OEM-specific
reports center on Samsung's kernel rules, not MIUI's userspace).

### GrapheneOS (Round 30 research)

GrapheneOS's exec-based spawning ("secure app spawning",
`persist.security.exec_spawn`, **default ON** — verified from
GrapheneOS/platform_frameworks_base branch 16,
android/ext/settings/ExtSettings.java) does NOT change anything for
this module. Reading their actual implementation
(core/java/com/android/internal/os/ExecInit.java +
ZygoteConnection.java): apps still fork from the zygote and run the
full specialization — `handleChildProc` then calls
`ExecInit.execApplication` → `Os.execv("/system/bin/app_process64",
...)` from the ALREADY-SPECIALIZED child. The privilege drop our
hooks key on happens before the exec, and both the private mount
namespace and the execve-proof property spoofing survive `execve`
by design. The exec'd app_process re-initializes a runtime and
re-reads `ro.dalvik.vm.native.bridge` (pre-10 only — from 10.0 the
`zygote` guard in AndroidRuntime.cpp keeps non-zygote runs from
loading any bridge), which is exactly the second-load surface the
Round 30 property restore eliminates. hardened_malloc
(`DISABLE_HARDENED_MALLOC` runtime flag) is a malloc interposition
and does not interact with our GOT-hook mechanism. Nothing in
GrapheneOS's fork-then-exec flow requires special handling.

### What this is, and what it is not

This is a **mechanism-level compatibility statement backed by
cited firmware/kernel/AOSP sources plus fail-closed hardening for
the reported OEM failure modes** — not a per-model guarantee (nobody
can honestly give one without testing on the hardware). Every
residual unknown above degrades closed: a blocked path means "no
injection" or "no hide" for that feature, never a crash, and the
module refuses (rather than breaks) the only device class that
would actually malfunction (real-bridge x86 translation devices).

## Round 31 — custom ROM compatibility (the 50-ROM sweep)

### What was actually verified (nothing guessed)

The custom-ROM question is answered the same way the OEM question
was in Round 29: by reading the ROMs' own source trees. This round
fetched `frameworks/base` surfaces (core/jni/AndroidRuntime.cpp —
the native-bridge load logic; core/jni/
com_android_internal_os_Zygote.cpp + core/java/com/android/internal/
os/{Zygote,ZygoteConnection}.java — every spawn path) from **50
custom-ROM repos** and diffed them against AOSP. The ROM set covers
every family users actually flash in 2025-2026:

| Family | ROMs verified (org/branch) |
|---|---|
| LineageOS + descendants | LineageOS/lineage-23.2, crdroidandroid/16.0, RisingOS-Revived/sixteen, RisingTechOSS/fourteen, SuperiorOS/fifteen, OmniROM/android-16, Evolution-X/cnb, DerpFest-AOSP/16.2, AICP/w16.2, VoltageOS/17, ProjectMatrixx/16.2, Octavi-Staging/sixteen, Project-Elixir/UNO, Komodo-OS/15, bananadroid/14, CherishOS/uqpr2, Project-Awaken/ursa, P-404/umai, PixelOS-AOSP/seventeen, PixelBuildsROM/infinity-oss, AospExtended/12.1.x, ArrowOS/arrow-13.1, StatiXOS/bp4a, Havoc-OS/thirteen, DotOS/dot12.1, Corvus-AOSP/13, CipherOS/fourteen-qpr, Project-Kaleidoscope/sunflowerleaf, Zeus-OS/11.1, RevengeOS/r11.0, ShapeShiftOS/android_13, ViperOS/ten, exthmui-legacy/exthm-11, LiquidRemix/ten, Nitrogen-project/14, PotatoProject/frico_mr1, Xtended-Tomato/8.0, MSM-Xtended, PixysOS, Bliss (TeamBliss), BootleggersROM, MoKee/mkq-mr1, ResurrectionRemix/Q, DirtyUnicorns/r11x |
| Privacy ROMs | GrapheneOS/17 (re-verified: exec_spawn present), CalyxOS, DivestOS, /e/OS, iodéOS, LineageOS for microG |
| GSI | TrebleDroid/android-16.0.0_r2-td (phhusson lineage) |
| Legacy | CyanogenMod/cm-14.1, ParanoidAndroid/jb43 (see below) |
| Other AOSP forks | ProtonAOSP/sc-qpr3, commaai (comma three), nDroidProject, ChameleonOS/kitkat, TeamBliss/kk4.4 |

**The result: exactly three variants of the native-bridge
acceptance logic exist across all 50 ROMs.** 46 ROMs ship AOSP's
current form byte-for-byte (`propBuf[0] == '\0'` -> ALOGW; `zygote
&& strcmp(propBuf, "0") != 0` -> addOption); 3 ship the pre-10 form
without the zygote guard (CyanogenMod 14.1, commaai, Xtended 8.0 —
the R30-documented second-load surface, which our post-consume
property restore already handles); 4 legacy branches predate
Android 5.0 and contain **no native-bridge mechanism at all**
(ParanoidAndroid jb43, Bliss kk4.4, ChameleonOS kitkat, nDroid —
the R28 verdict applies: below 5.0 the load mechanism does not
exist, and those branches are for 2013-2014 devices anyway). No ROM
changes what the property accepts, and every modern ROM keeps all
spawn paths through `nativeSpecializeAppProcess`/`SpecializeCommon`
(the setresgid/setresuid points our GOT hooks key on).

### The root-manager compatibility layer (the real custom-ROM gap)

Reading a ROM's framework tells you whether the injection mechanism
works; reading the ROOT MANAGER tells you whether the module's
installer survives contact with the boot chain. Custom-ROM users
run three root managers (Magisk, KernelSU, APatch — plus forks), and
this round read all three from their own sources:

* **Magisk** mounts a module's `system/` over `/system` with magic
  mount before post-fs-data scripts run, and ships a `resetprop`
  binary. Everything the old rounds relied on.
* **KernelSU** (ksud `init_event.rs`, read this round): module
  post-fs-data scripts run BEFORE the metamodule that mounts module
  system/ dirs — and per the official module guide, "KernelSU uses a
  metamodule architecture for mounting the system directory. Only if
  your module needs to modify /system files do you need to install a
  metamodule". No resetprop BINARY exists on PATH. Both gaps are now
  handled (below). KernelSU also steps aside when Magisk is present
  ("Magisk detected, skip post-fs-data").
* **APatch** (apd `event.rs`): same metamodule delegation, same
  post-mount stage, same "skip if Magisk" rule — but it DOES ship an
  internal resetprop (the `prop-rs-android` crate).

Two hard facts close the design (verified from AOSP main this
round, not assumed):

1. **The bridge library name is a bare soname, always.** ART's
   `NativeBridgeNameAcceptable` (libnativebridge/native_bridge.cc)
   accepts only `[a-zA-Z0-9._-]` with a leading letter — a value
   containing `/` is rejected before any dlopen. Absolute paths
   into /data are impossible.
2. **The loader must live in `/system/lib[64]` (or
   /system_ext/lib[64]) of the zygote's mount namespace.** The load
   goes through the exported "system" linker namespace
   (OpenSystemLibrary → `android_get_exported_namespace("system")`),
   whose search paths (system/linkerconfig contents/namespace/
   system.cc) are exactly `/system/${LIB}` and
   `SYSTEM_EXT/${LIB}`; the namespace is non-isolated, but the
   soname resolution only ever searches those directories.

So the module now carries its own compatibility chain:

* **A built-in property engine** (`zygiskd prop`, props.rs): a
  Rust implementation of bionic's own property-area mutation
  protocol — the trie walk, the dirty-backup copy, the release
  fences, the serial publish, the futex wakes, the global
  `properties_serial` bump — all verified line-by-line against
  libc/system_properties (prop_area.cpp, prop_info.cpp,
  system_properties.cpp, contexts_split.cpp) this round. It handles
  the Android 7+ per-context directory layout (including the exact
  `u:object_r:dalvik_config_prop:s0` file the property lives in,
  from system/sepolicy's property_contexts), the pre-7 single-file
  layout, the A10+ dirty-backup region, and long-value records
  (delete + re-add, Magisk's own rule). post-fs-data.sh falls back
  to it when no resetprop binary exists; the daemon's property guard
  prefers it over shelling out. 15 cargo tests + a live E2E where
  post-fs-data.sh, with NO resetprop on PATH, swaps the bridge in a
  bionic-shaped fixture area read back by a THIRD independent trie
  implementation (Python).
* **A loader-mount fallback chain** (zs_compat.sh +
  post-mount-hook.sh): post-fs-data checks whether the bridge is
  visible at /system/lib[64]; on KernelSU it is not yet (scripts run
  before metamodule mounting), so a pending flag is set and the
  /data/adb/post-mount.d hook — installed by customize.sh, run by
  KernelSU/APatch AFTER their metamodule mounting and before zygote
  — resolves it: metamodule mount (already visible), a direct copy
  (RW /system, rare), or OUR OWN overlayfs over the lib dir (the
  same approach KernelSU's official meta-overlayfs metamodule uses,
  with a /proc/filesystems capability check). If nothing works, the
  property swap is rolled back and the guard stands down: the boot
  never references a file ART cannot load. service.sh is the
  last-resort retry point (a late resolution arms the module for the
  next zygote generation).
* **Conflict detection** (customize.sh): Magisk's own Zygisk
  (ZYGISK_ENABLED env, or the live `libzygisk.so` value), ZygiskNext
  / NeoZygisk (module id `zygisksu` — from NeoZygisk's own
  build.gradle.kts — plus `/data/adb/neozygisk`), ReZygisk (module
  id + `/data/adb/rezygisk`). Two zygote-injection frameworks at
  once is undefined behavior; the installer refuses with the
  conflicting component named.
* **Dual-arch installs** (customize.sh): on a 64-bit device that
  also runs a 32-bit zygote (most pre-2018 SoCs — common on
  LineageOS-class ROMs), the 32-bit zygote resolves the SAME soname
  through /system/lib, so the 32-bit pair is installed beside the
  64-bit one when the device's abilist includes the 32-bit ABI —
  gated on the artifacts actually being ELF32 (EI_CLASS byte
  checked; a 64-bit binary in the 32-bit slot is refused with the
  reason logged).

### Round 31 residuals (honest scope)

* The custom-ROM framework sweep covers frameworks/base; ROM-specific
  init.rc changes or kernel configs are not enumerated per-ROM — the
  runtime capability checks (overlayfs presence, mount permissions)
  cover the mechanism, not each of the hundreds of ROM builds.
* The overlayfs self-mount runs in whatever SELinux domain the root
  manager executes module scripts in (magisk/su — the same domains
  KernelSU's own meta-overlayfs runs in). A ROM with a policy that
  denies mounts to those domains degrades to the documented
  fail-closed rollback.
* Legacy ROM branches below Android 5.0 have no native-bridge
  mechanism at all (verified, R28) — the installer's API gate
  already refuses them.

## Round 32 — the installer $ARCH contract, and the flashable zip

Two install-chain corrections and one new delivery mechanism, all
verified from the actual installer sources (Magisk's
scripts/util_functions.sh at master, KernelSU's
userspace/ksud/src/installer.sh, APatch's apd/assets/installer.sh —
the three byte-identical api_level_arch_detect functions):

- **$ARCH is `arm64 | arm | x86 | x64 | riscv64`** (with `$ABI32` and
  `$IS64BIT` alongside). It is NOT the NDK-style ABI name. customize.sh
  now maps the real values to the `libs/<abi>` directories; before
  Round 32 it cased on `arm64-v8a`/`armeabi-v7a`/`x86_64`/`x86` and
  aborted every real install with "does not support arm64" — since the
  first round, invisible to the host harness because the harness fed
  the NDK-style names. The harness now feeds the real values, and
  riscv64 (which Magisk can report on newest devices) is refused
  cleanly because no riscv64 build ships.
- **Plain-recovery installs** have no `getprop` binary. customize.sh
  runs under `set -e`, and a bare `X=$(getprop ...)` with a missing
  binary exits 127 through the assignment — which killed the install
  mid-way (after the libraries were copied, before the conflict
  checks / launcher / marker). The `zs_getprop` helper now tries
  getprop first and falls back to a CRLF-safe grep over
  /system/build.prop, /vendor/build.prop and /odm/etc/build.prop —
  the same `grep_get_prop` pattern Magisk's own util_functions.sh
  uses for the same reason. The dual-arch abilist lookup and the
  live-bridge conflict check both go through it.

The **flashable zip** (Round 32): every commit on every branch builds
`zygisk_study-v<shortsha>-<count>.zip` in GitHub Actions
(.github/workflows/build.yml) — all four NDK ABIs at API 21, gated on
the full host test suite, self-verified (layout, module.prop format,
ELF classes, 16 KB LOAD alignment on every packaged ELF), uploaded as
a workflow artifact, and released on tag pushes. It installs through:

- the **Magisk / KernelSU / APatch app** ("Install from storage") —
  no META-INF is needed on this path; the app runs its own extraction
  and sources customize.sh;
- **custom recoveries** (TWRP-class) — via
  `META-INF/com/google/android/update-binary`, a clean-room
  implementation of the documented recovery protocol (source
  /data/adb/magisk/util_functions.sh, require v20.4+, call
  install_module; updater-script is the conventional "#MAGISK"
  marker). Magisk's own module_installer.sh is GPL-3.0 and is not
  vendored into this Apache-2.0 tree.

Locally the same zip is produced by
`NDK=/path/to/ndk ./scripts/build_module.sh` — the workflow runs the
identical script (all runner assumptions — preinstalled NDK via
ANDROID_NDK_HOME, Rust, CMake, zip — are verified from the
actions/runner-images documentation).

## Round 34 — verified 6.0 negotiation, bounded sockets, and the guard back-off

- **Android 6.0 re-verified from the actual source** (the one
  release the bridge table's version comment previously covered
  only by extrapolation): system/core/libnativebridge/
  native_bridge.cc:144-160 at android-6.0.0_r1 — version==1 is
  accepted unconditionally, version>=2 requires
  `callbacks->isCompatibleWith(2)` to return true. Our version=8
  table with `isCompatibleWith(1..8) == true` is accepted; the
  5.x exact-match pin stays.
- **Zygote-side daemon sockets are bounded** (100 ms connect
  handshake via non-blocking connect + poll; 100/250 ms
  SO_RCVTIMEO/SO_SNDTIMEO on the single-shot request sockets —
  AF_UNIX honors both, kernel af_unix.c). A stalled daemon can no
  longer freeze the zygote's fork hook (i.e. every app launch);
  timeouts behave exactly like "daemon not up" and retry on the
  next fork through the existing latch machinery. Long-lived
  companion fds keep plain blocking semantics — the module owns
  them after the handshake.
- **The property guard's steady-state cost** dropped from a full
  /proc census + zygote maps re-read 4x/second to one stat() every
  2 s after the stock value is restored (death watch on the known
  pid, with a periodic full census re-sync for pid reuse), and the
  guard thread survives its own rollback as the zombie sweeper.
- **The 5.x tool question closed with sources**: Magisk runs every
  module script under busybox ash standalone mode (docs/guides.md —
  full command suite regardless of Android version), so `setsid`
  and `od` exist there; the 5.0.0_r1 toolbox applet list (fetched)
  contains neither, which only matters for non-Magisk managers —
  the scripts guard `command -v setsid` and degrade to a plain
  background launch.

## Round 36 — the setcontext contract across the range, and 32-bit parity

The isolated-process coverage hooks
`selinux_android_setcontext(uid, isSystemServer, seInfo, niceName)`
from libselinux. Verified per release: the symbol exists with the
same C signature at 5.0.0_r1 (external/libselinux/src/android.c)
and on main (libselinux/src/android/android_device.c — bool vs int
is ABI-identical); the call site in SpecializeCommon runs after
setresuid on 5.0.0_r1, 10.0.0_r1, 12.0.0_r1, 16.0.0_r1 and main,
with the same four-argument shape and a nullable nice_name. The
hook degrades cleanly: a vendor build that hides the symbol leaves
the hook unregistered and isolated children keep the pre-R36
uid-drop dispatch (modules keep working; no coverage, no crash).

32-bit parity: armeabi-v7a and x86 get the plain-C wrapper stub
(null frame = the documented Tier B input), so the isolated
coverage, the deferral and the matcher all work there — only the
Tier A self-unmap is absent, exactly like the other five wrappers
on no-blob arches (Round 32's class, caught by the same 4-ABI
cross-build gate). The SDK-sandbox uid remap is Android 13+ only
by construction: pre-13 platforms never allocate appId
20000-29999 (absent in 12.0.0_r1's Process.java), so the branch is
dead there and harmless.

## Round 37 — the R36 coverage extended to app-zygote children (Android 10+)

The R36 isolated-process coverage shipped with a second guard gap
found this round: the dispatch latches are copy-on-write INHERITED,
and an app zygote (Android 10+; FIRST_APP_ZYGOTE_ISOLATED_UID=90000
verified absent at 9.0.0_r1, present 10.0.0_r1..main) sets every
latch when its own specialization dispatches modules. Its isolated
children (appId 90000-98999) then bounced off the inherited state —
no setcontext name check, no pre/post callbacks — on every Android
version with app zygotes (10, 11, 12, 13, 14, 15, 16). The latches
now record the pid they were set in: an inherited latch re-arms the
isolated-range coverage (deny check, deferral, deferred dispatch
with the full nice_name), while a non-isolated child of a dispatched
process (an app's own fork() worker re-calling setresuid with the
app uid — not a specialization) keeps the inherited semantics
exactly as before. Pid-reuse cannot false-positive: a latch holder
is always an ancestor of the reading process, and a live process'
pid differs from every ancestor's.

Also this round: the SDK-sandbox remap (Android 13-16) now applies
in the package-name lookup too (module args carry the owning app's
package/data dir for sandboxed processes; pre-13 the branch is dead
as before), and the daemon-client plumbing (session-file re-read +
bounded 'P' socket + reply-vs-timeout classification) is version-
independent — it runs in the zygote on every supported release.
