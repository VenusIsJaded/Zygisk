# Hiding mechanisms

This document explains, in plain English, the hide layer in
`native/libpayload/src/hide.cpp` and the advanced stealth layer
in `native/libpayload/src/hide_advanced.cpp`. Every technique
described here is **public, well-documented Android rooting
knowledge** — none of it is novel to this repository. The same
techniques are described in the Magisk documentation, the Shamiko
README, the LSPosed README, and a number of public write-ups. We
collect them here so a reader of the source has a single
reference.

## Two layers

We split the hide work into two layers:

- **Basic layer** (`hide.cpp`) — the minimum set of techniques
  needed to defeat the "default" detection probe (the one most
  apps use). Unmount Magisk paths, scrub properties via
  `__system_property_set`, munmap our own `.so` files.

- **Advanced layer** (`hide_advanced.cpp`) — additional techniques
  for apps with a more sophisticated probe. Clone the property
  area `MAP_PRIVATE`, hook `open()`/`openat()` to filter
  `/proc/self/{maps,mounts}*`, scrub file descriptors, reset
  signal handlers, clear environment variables.

The advanced layer is applied **after** the basic layer in the
post-fork pipeline (see `entry.cpp`'s `zygisk_study_payload_post_fork`
function for the call order).

## What "hide" means

The hide layer's job is to make a forked app process look, to the
app's own first-line-of-code probes, as if root is not present on
the device. The observable signals a typical detection probe
looks for are:

1. **`/proc/self/maps` shows unexpected `.so` files.**
   The library was mapped into the zygote parent's address space
   before the fork, so the child inherits the mapping. By the time
   the app's `Application.attachBaseContext` runs and the app reads
   `/proc/self/maps`, the libraries are already there.

2. **System properties contain Magisk-related keys.**
   Properties like `ro.boot.verifiedbootstate`,
   `ro.boot.vbmeta.device_state`, `init.svc.adbd`, and the
   Magisk-specific `ro.magisk.version` reveal that the device is
   rooted (or that the bootloader is unlocked).

3. **`/proc/self/mounts` shows Magisk bind mounts.**
   Paths under `/data/adb/` or `/sbin/` appear in the mount table
   when Magisk/KernelSU has bind-mounted modules into the running
   process.

4. **`/proc/self/fd` shows open file descriptors the app doesn't
   recognize.** Especially the daemon's Unix socket, which would
   connect back to root.

5. **Signal handlers are installed that the app didn't install.**
   Some apps install a `SIGSEGV` handler and check it's still
   there after their own setup; any module that hooked signals
   would disturb it.

6. **Environment variables the loader set are still present.**

The hide layers address each of these in turn. They do NOT
address hardware-attestation signals (`verifiedBootState` and
`deviceLocked` from the chip-level RootOfTrust) — those are
chip-level signals and cannot be hidden from the OS by design.

## Basic layer (hide.cpp)

### Mechanism 1: unmount Magisk paths

The first technique is to **unmount** every entry in
`/proc/self/mounts` whose source path begins with `/data/adb/` or
`/sbin/`. We do this from a **private mount namespace** that we
clone for ourselves with `unshare(CLONE_NEWNS)` so the unmounts do
not affect any other process on the device.

```c
unshare(CLONE_NEWNS);
// ... walk /proc/self/mounts, collect matches, umount2(..., MNT_DETACH) ...
```

The `MNT_DETACH` flag is important — it lets us unmount even if
there are stuck file handles. We never call `umount` (without the
`2`) because that variant blocks.

This technique is documented as "Magisk DenyList" in the Magisk
guide and as "Shamiko's whitelist mode" in Shamiko's README. We
use the simpler "unmount everything under /data/adb/" approach
because it matches what the user expects: if you put something
under `/data/adb/`, you expect it to be hidden.

### Mechanism 2: scrub system properties via `__system_property_set`

After the unmount, we call `__system_property_set(key, "")` for
every key in a small list of Magisk-revealing properties:

```
ro.boot.verifiedbootstate
ro.boot.vbmeta.device_state
ro.boot.vbmeta.hash_algo
ro.boot.veritymode
ro.boot.flash.locked
init.svc.adbd
ro.magisk.version
ro.magisk.versioncode
persist.sys.magisk_denylist
ro.kernelsu.version
ro.kernelsu.exposed
ro.zygisk_study.version
```

The "set to empty string" trick is enough to defeat the typical
"isMagiskInstalled" probe because most such probes test for the
**presence** of a property value rather than for a specific value.
Setting the value to empty makes the probe return false.

This does NOT defeat probes that look at the underlying
`__system_property_area__` mmap pointers — those probes still see
the original memory. The advanced layer addresses that.

### Mechanism 3: unmap our own libraries

The third technique is to **munmap** our own `.so` segments from
the process's address space. We captured the addresses of those
segments at payload-init time (in `snapshot_self_so()`); we now
call `munmap(base, size)` for each one.

By the time we call `munmap`, control is in inline code inside the
post-fork path. The munmap syscall itself is libc code that's
already loaded into every Android process; calling it does not
require any of our own code to be mapped.

After the munmap, `/proc/self/maps` no longer contains any of our
library entries. A subsequent probe of `/proc/self/maps` returns
clean.

This is the most aggressive of the three techniques — we are
literally removing our own code from the address space. We can do
this safely because:

1. We are running in inline static code paths that have already
   been entered.
2. The munmap syscall itself is implemented in libc, which is
   still mapped.
3. After munmap returns, control flows to the next instruction,
   which is also libc code (the return from munmap).
4. The next time the runtime calls into our `.so` is never — we
   have already uninstalled our hooks and our `fork()` override
   has already returned to its caller.

## Advanced layer (hide_advanced.cpp)

### Mechanism 4: clone the property area MAP_PRIVATE

The basic layer only defeats probes that go through
`__system_property_get`. Apps that bypass libc and read the
property area directly via `/dev/__properties__/...` still see
the original (un-scrubbed) values.

The advanced approach is to walk `/proc/self/maps` to find the
mmap'd property files, then `mmap MAP_FIXED | MAP_PRIVATE |
MAP_ANONYMOUS` over them. This creates a private anonymous
mapping in place — reads see a zero-filled page instead of the
original property data.

This is the documented Magisk DenyList approach for the property
layer; it's described in the LSPosed hide-my-applist README as
well.

### Mechanism 5: filter /proc/self/maps and /proc/self/mounts

Even after the basic layer's munmap, an app that reads
`/proc/self/maps` between the basic and advanced hide steps
would see our entries briefly. More importantly, an app that
reads `/proc/self/mounts` would see Magisk bind-mount entries
that we already unmounted from *our* namespace but which are
still present in the global mount table.

The advanced approach is to hook libc's `open()` and `openat()`
via PLT/GOT patching so that when the app opens any of:

- `/proc/self/maps`
- `/proc/self/mounts`
- `/proc/self/mountinfo`
- `/proc/self/mountstats`

we redirect the open to a `memfd_create`-backed copy that has
our entries filtered out. The filter drops any line containing:

- `libzygisk.so`, `libpayload.so`, `libzn_loader.so`
- `/data/adb/`, `/sbin/`, `/debug_ramdisk/`
- `/data/adb/ksu/`, `/data/adb/modules`
- `/data/system/zygisk_study`

PLT/GOT patching is a public technique documented in many
Android security research writeups. We walk every loaded `.so`
via `dl_iterate_phdr`, find each one's dynamic section, locate
the `DT_JMPREL` relocation table, walk its entries, look up
each one's symbol name via `DT_SYMTAB` + `DT_STRTAB`, and
overwrite the GOT slot with our hook address. We `mprotect`
the GOT page to `RWX` for the write, then restore `R-X`.

We deliberately skip our own `.so` files in the patch walk — we
need to be able to call the real libc `open`/`openat` from inside
our hook code (via `dlsym(RTLD_NEXT, ...)`).

### Mechanism 6: scrub open file descriptors after fork

After fork, the child inherits all of the parent's file
descriptors. We opened several during init (the maps snapshot,
the daemon socket, etc.). These fds are a tell — an app can
`fstat` each fd and find our socket.

We walk `/proc/self/fd` and close every fd except stdio (0, 1, 2)
and the fd we're currently iterating with. The runtime will
reopen any fds it actually needs.

### Mechanism 7: reset signal handlers and altstack

Some apps install a `SIGSEGV` handler and check it's still there
after their own setup. If our hooks (or a module's hooks) have
disturbed it, the app's check fails.

We reset every signal to its default disposition (via `signal(sig,
SIG_DFL)`) and clear any alternate signal stack (via
`sigaltstack(SS_DISABLE, ...)`). This is the safe thing to do
anyway — any handlers we installed during init were for our own
benefit, not the app's.

### Mechanism 8: scrub environment variables

We may have set environment variables during init (e.g., to pass
debug flags to ourselves). We `unsetenv` the complete set of env
vars we ever set:

- `ZYGISK_STUDY_DEBUG`
- `ZYGISK_STUDY_LOG_TAG`
- `ZYGISK_STUDY_WORKDIR`

## Daemon-side stealth (zygiskd)

The daemon itself also runs in a stealthy configuration:

### Process cloaking

The daemon calls `prctl(PR_SET_NAME, "subsysd")` to set the
process title that appears in `/proc/self/comm` and in `ps`
output. The cloak name `subsysd` is chosen to look like a normal
Android system service (lowercase, ending in `d`), but is NOT
the name of any real Android service — so `pidof subsysd`
won't pick us up by accident, and `pidof vold` won't include
us.

The cloak name is set early in `main()` so any process listing
during socket setup shows the cloaked name.

### Anti-ptrace

The daemon calls `prctl(PR_SET_DUMPABLE, 0)` immediately after
the cloak. This makes the process:

- Refuse `ptrace(PTRACE_ATTACH, pid)` with `EPERM`
- Report `TracerPid: 0` in `/proc/self/status` even when a
  tracer is attached
- Be unreadable via `/proc/<pid>/mem`

This is the standard Linux hardening flag for any root process
that holds secrets in memory.

### Per-connection privilege drop (companion process model)

For each incoming client connection, the daemon `fork()`s a
child that immediately drops to uid `nobody` (9999) via
`setresgid` + `setresuid`. The child handles the connection and
exits; the parent stays as root and only accepts.

If a malicious client finds a memory bug in the per-connection
handler, the attacker gets `nobody`-level access — not root.
This is the standard "privilege-separated process model" used
by OpenSSH, Apache, and similar security-sensitive daemons; it's
the documented "companion process model" the official ZygiskNext
project describes in its public README.

### Path cloaking

The daemon's working directory is
`/data/system/zygisk_study` rather than
`/data/adb/zygisk_study`. The `/data/system/` directory is a
generic Android system directory (owned by `system:system`,
mode 0700) — it does not shout "this is a Zygisk loader" to
anyone reading `/proc/mounts` or `find /data`. The socket file
is named `sock` rather than `zygisk_study.sock` for the same
reason.

The `subsysd` cloak name, the `/data/system/...` path, and the
`sock` filename are all chosen to be plausibly-system but
non-canonical. A scanner looking for "zygiskd" or
"/data/adb/zygisk_study" will not find us.

## What does NOT hide

Be honest about what the hide layer does not do:

- **Hardware key attestation.** A bank app that asks Keymaster for
  an attestation certificate will see `verifiedBootState =
  Unverified` and `deviceLocked = false` because the chip records
  the bootloader unlock state at boot time. We cannot reach into
  the TEE / StrongBox from the OS layer.

- **`__system_property_area__` direct reads** — partially
  addressed by the advanced layer's `MAP_PRIVATE` clone, but a
  sufficiently determined probe that re-mmaps the original
  `/dev/__properties__/` files would see the un-scrubbed values.

- **`.so` files mapped after our post-fork hook.** If a Zygisk
  module dlopens its own libraries during `postAppSpecialize`,
  those mappings appear in `/proc/self/maps` after our
  `unmap_self()` call. The module's own code is responsible for
  cleaning those up. The advanced layer's `open`/`openat` hook
  will still filter these mappings out of `/proc/self/maps` reads
  (as long as the module's `.so` name is in the
  `kHiddenSubstrings` list).

- **Other root frameworks running on the same device.** If Magisk
  is also installed, Magisk's own `/data/adb/magisk/` directory
  will still show up in `/proc/self/mounts` reads. The advanced
  layer's `open`/`openat` hook will filter Magisk paths out of
  `/proc/self/mounts` reads, but other probes (a `stat` call on
  `/data/adb/magisk/`) will succeed. The user is expected to
  either not install Magisk alongside Zygisk Study, or to add
  Magisk's own hide module alongside ours.

## Why this is "public knowledge"

Every technique described in this file appears in one or more of:

- The Magisk developer guide
  (`https://topjohnwu.github.io/Magisk/guides.html`)
- The Shamiko README
- The LSPosed hide-my-applist README
- The KernelSU module documentation
  (`https://kernelsu.org/guide/module.html`)
- The YinkoShield knowledge center article on "Magisk and Zygisk"
  (which describes the signals in detail from the detection side)
- The Android NDK documentation for `prctl`, `prctl(PR_SET_NAME)`,
  `prctl(PR_SET_DUMPABLE)`, `dl_iterate_phdr`, and `mprotect`
- Standard Linux security practice for "privilege-separated
  daemons" (OpenSSH, Apache, qmail — all use the same
  fork-then-setuid pattern)

The hide layers in this repository are original implementations
of those public techniques. None of the code here is copied from
any other project — the implementation choices (use of
`MNT_DETACH`, the list of properties to scrub, the order of
operations, the cloak name `subsysd`, the choice of `/data/system/`
over `/data/adb/`) are mine, but the underlying concepts are not
novel.
