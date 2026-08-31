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

We split the hide work into three layers:

- **Basic layer** (`hide.cpp`) — the minimum set of techniques
  needed to defeat the "default" detection probe (the one most
  apps use). Unmount Magisk paths, scrub properties via
  `__system_property_set`, munmap our own `.so` files.

- **Advanced layer** (`hide_advanced.cpp`) — additional techniques
  for apps with a more sophisticated probe. Clone the property
  area `MAP_PRIVATE`, hook `open()`/`openat()` to filter
  `/proc/self/{maps,mounts}*`, scrub file descriptors, reset
  signal handlers, clear environment variables.

- **Additional stealth layer** (`hide_stealth.cpp`) — defense-in-depth
  measures that target signals the basic + advanced layers don't
  address. Hook `readlink()`/`readlinkat()` to rewrite
  `/proc/self/exe` to a stock-looking path; set
  `prctl(PR_SET_PDEATHSIG, SIGKILL)` so the child dies if the
  zygote parent dies; set `prctl(PR_SET_DUMPABLE, 0)` in the
  child to refuse ptrace; set `prctl(PR_SET_NAME, "main")` so
  `/proc/self/comm` reports a neutral name during the post-fork
  window.

The three layers are applied in this order in the post-fork pipeline
(see `entry.cpp`'s `zygisk_study_payload_post_fork` function for the
call order): basic → advanced → additional stealth.

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

### Memory pinning (mlockall) and no-new-privs

The daemon now (NEW in this round) calls `mlockall(MCL_CURRENT)`
at startup to pin all its current pages in RAM. This prevents the
daemon's memory — which contains the module list, the denylist,
possibly loaded .so handles — from being paged out to `/data/swap`
(zram) where another root process or a forensics tool could read
it. See `docs/ANDROID-REALISM.md` S8.

The per-connection child also calls `prctl(PR_SET_NO_NEW_PRIVS, 1)`
after dropping to uid nobody. This blocks future `execve()` from
regaining privileges via a setuid binary (e.g. `/system/bin/su` when
installed by Magisk). The kernel refuses to honor the setuid bit on
execve when this flag is set; the attacker is permanently locked at
uid nobody. See `docs/ANDROID-REALISM.md` S9.

### Event-driven module rescan (inotify)

The daemon now (NEW in this round) uses `inotify` to watch the
module directory for create/delete/move events instead of waking
up every 30 seconds to poll the directory's mtime. The previous
polling path caused 2880 wakeups per day; the new inotify path
causes zero wakeups when nothing changes (the typical case for
most users, who install/remove modules rarely). This is a real,
measurable battery win visible in `dumpsys batterystats`. See
`docs/ANDROID-REALISM.md` T1.12.

## What does NOT hide

Be honest about what the hide layer does not do:

- **Hardware key attestation.** A bank app that asks Keymaster for
  an attestation certificate will see `verifiedBootState =
  Unverified` and `deviceLocked = false` because the chip records
  the bootloader unlock state at boot time. We cannot reach into
  the TEE / StrongBox from the OS layer.

- **`__system_property_area__` direct reads** — addressed by
  BOTH the advanced layer's `MAP_PRIVATE` clone AND the new basic
  layer direct-write property scrub. The basic layer's new path
  uses `__system_property_find` to get a const pointer into the
  shared-memory property trie, then writes empty values directly
  into the value field via `memset`. This bypasses the libc
  permission check that `__system_property_set` enforces for `ro.*`
  properties (which previously made the basic layer's scrub
  effectively a no-op for the most important properties on real
  Android). See `docs/ANDROID-REALISM.md` T1.10 for the Android
  cost-model walk-through.
  A sufficiently determined probe that re-maps the original
  `/dev/__properties__/` files would see the un-scrubbed
  values, but that requires CAP_SYS_ADMIN to bypass the existing
  mmap; non-root apps cannot.

- **`.so` files mapped after our post-fork hook.** If a Zygisk
  module dlopens its own libraries during `postAppSpecialize`,
  those mappings appear in `/proc/self/maps` after our
  `unmap_self()` call. The module's own code is responsible for
  cleaning those up. The advanced layer's `open`/`openat` hook
  will still filter these mappings out of `/proc/self/maps` reads
  (as long as the module's `.so` name is in the
  `kHiddenSubstrings` list).

- **Other root frameworks running on the same device.** If Magisk
  is also installed:
  - Magisk's own `/data/adb/magisk/` directory will still show up
    in `/proc/self/mounts` reads. The advanced layer's
    `open`/`openat` hook will filter Magisk paths out of
    `/proc/self/mounts` reads.
  - **NEW: the stat/lstat/access/faccessat hook in
    `hide_advanced.cpp`** returns `ENOENT` for `stat("/data/adb/magisk")`
    and similar Magisk/KernelSU/ZygiskNext directory probes. This
    closes a previously-documented gap: apps that did
    `stat("/data/adb/magisk")` to detect Magisk still saw the
    directory. With the new stat hook, the stat returns
    `-1 / ENOENT`, so the probe sees "no such file or directory".
    See `docs/ANDROID-REALISM.md` S5 for the Android-confidence
    walk-through.
  - The user is expected to either not install Magisk alongside
    Zygisk Study, or to add Magisk's own hide module alongside ours.

- **Daemon memory being paged out to swap.** If zram is enabled
  (default on most Android devices, 2-8 GB on typical Pixels) and
  the daemon's pages get swapped to `/data/swap`, another root
  process or a forensics tool could read them. **NEW: the daemon
  now calls `mlockall(MCL_CURRENT)` at startup** to pin all
  current pages in RAM; this prevents the swap-to-/data/swap leak.
  See `docs/ANDROID-REALISM.md` S8.

## Round 4 — additional gaps closed (this round)

- **`/proc/self/status` reading `TracerPid: <non-zero>`.** Some
  apps read `/proc/self/status` line-by-line and parse the
  `TracerPid:` field to detect an attached ptrace. The basic +
  advanced layers didn't filter `/proc/self/status`, so the
  probe could succeed even with `PR_SET_DUMPABLE=0` set by
  hide_stealth (some Android kernels, notably Android 10 and
  earlier, still report the real tracer pid in the text file).
  **NEW (S10):** `/proc/self/status` is now in `kFilteredPaths`,
  and `make_filtered_memfd` rewrites any `TracerPid:` line to
  `TracerPid:\t0` in the filtered copy. The kernel's
  `/proc/self/status` seqfile is regenerated on every read
  (same as /proc/self/maps), so the rewrite is per-read. Covered
  by 2 new tests in `test_hide_advanced.cpp`.

- **`readlink("/proc/<pid>/exe")` returning a Magisk path.** The
  previous implementation only matched the literal path
  `/proc/self/exe`. Apps can also probe via
  `/proc/<own_pid>/exe` (the same kernel symlink, accessed by
  numeric PID), or via `readlinkat(AT_FDCWD, "/proc/<pid>/exe",
  ...)`. **NEW (S12):** the `path_is_proc_exe()` matcher now
  recognizes any path that starts with `/proc/`, has a middle
  component of either `self` or a decimal number, and ends with
  `/exe`. The matcher is a cheap prefix + numeric-scan + suffix
  comparison (~20 cycles on AArch64). Covered by a new test
  in `test_hide_stealth.cpp` exercising 7 positive and 11
  negative cases.

- **Core dumps from the forked child containing our in-memory
  state.** `prctl(PR_SET_DUMPABLE, 0)` in hide_stealth prevents
  the kernel from honoring any future ptrace attach. But if a
  kernel bug or a third-party kernel module bypasses that
  check, a core dump from the forked child could contain our
  hide layer's in-memory state (module list, denylist, etc.).
  **NEW (S16):** the post-fork pipeline now also calls
  `setrlimit(RLIMIT_CORE, 0)` after `set_neutral_comm_name()`.
  The kernel checks rlimit before writing a core file, so even
  if dumpable is somehow re-enabled, core dumps are still
  suppressed. Covered by a new host-side test that verifies
  both `rlim_cur` and `rlim_max` are zero after the call.

## Round 5 — additional gaps closed (this round)

- **`/proc/self/smaps` and `/proc/self/smaps_rollup` revealing
  Magisk mappings.** Both files are extended variants of
  `/proc/self/maps` — they show per-mapping memory stats (RSS,
  PSS, private dirty, etc.) plus the path field, which is
  identical to the path field in `/proc/self/maps`. The previous
  `kFilteredPaths` list didn't include either file, so an app
  that probed `/proc/self/smaps` would see the un-scrubbed Magisk
  and libpayload entries. **NEW (S25):** both
  `/proc/self/smaps` and `/proc/self/smaps_rollup` are now in
  `kFilteredPaths`. The kernel's seqfile for both files is
  regenerated on every read (same as `/proc/self/maps`), and
  the path-field scan logic in `make_filtered_memfd` is unchanged
  — we just needed to add the two paths to the filtered set.
  Covered by a new host-side test (`make_filtered_memfd_filters_smaps_magisk_entries`)
  that feeds synthetic smaps content with Magisk and libpayload
  entries and verifies they're dropped while the libc.so entry
  is preserved (along with its detail lines).

- **Extended set of Magisk-revealing properties.** The previous
  `kMagiskRevealingProps` list had 12 entries. A re-survey of
  public Magisk / Shamiko detection documentation found 9 more
  keys that are commonly probed by detection code but were
  missing from our scrub list. **NEW (S46):** the list is now
  21 entries. The new keys are:
  - `init.svc.magisk`, `init.svc.magisk_pfsd` — Magisk's init
    services (world-readable on every Android).
  - `persist.magisk.hide` — old MagiskHide config (still
    present on devices upgraded from older Magisk).
  - `ro.boot.vbmeta.digest` — bootloader-set vbmeta digest.
  - `ro.bootmanager.veritymode` — older bootloader verity mode.
  - `service.magisk.rootdir`, `persist.sys.rootdir` — Magisk's
    internal rootdir pointer (rare but present in some forks).
  - `ro.boot.warrantybit`, `ro.warranty.bits` — OEM warranty
    bits set when the bootloader is unlocked.
  The new keys go through the existing `scrub_prop_in_memory`
  direct-write path — no new code paths, just a longer list.
  Covered by a new host-side test
  (`property_scrub_list_contains_round5_additions`) that
  verifies all 9 new keys are present in
  `kMagiskRevealingProps`.

- **Apps using `faccessat2` to bypass our `faccessat` hook.**
  `faccessat2` is the Linux 5.8+ (Android 11+) variant of
  `faccessat` that properly honors the `AT_EACCESS` flag (the
  older `faccessat` syscall silently ignored it). Bionic exposes
  `faccessat2` as a public libc function in API 30+. Apps that
  target SDK 30+ and probe Magisk paths via `access()` may go
  through `faccessat2` directly (especially apps that use newer
  NDK headers), bypassing our existing `faccessat` GOT hook.
  **NEW (S54):** we added `faccessat2` to the GOT patcher with
  the same hide logic as `faccessat` (return `ENOENT` for
  absolute paths in the hidden set). On pre-Android 11 devices
  where `faccessat2` isn't exported, our hook falls back to
  `g_real_faccessat` and then to the raw `SYS_faccessat` syscall.
  Covered by a new host-side test
  (`faccessat2_hook_returns_enoent_for_hidden_paths`).

- **Apps using `fstatat` to bypass our `stat`/`lstat` hooks.**
  On AArch64, the `stat` and `lstat` syscalls don't exist —
  every `stat()` / `lstat()` libc call goes through `fstatat`
  under the hood. We already hook `stat` and `lstat` by name
  (catches apps that use those libc names directly), but apps
  that call `fstatat` directly bypass those hooks. **NEW (S55):**
  we added `fstatat` (and its aliases `__fstatat` and
  `fstatat64`) to the GOT patcher with the same hide logic
  (return `ENOENT` for absolute paths in the hidden set,
  regardless of the `flags` value, so both stat-like and
  lstat-like behavior are covered). The hook falls back through
  `g_real_fstatat` → `SYS_fstatat` → `SYS_newfstatat` →
  `ENOSYS`, so it works on every Linux kernel we support.
  Covered by a new host-side test
  (`fstatat_hook_returns_enoent_for_hidden_paths`) that
  exercises both `flags=0` (stat-like) and
  `flags=AT_SYMLINK_NOFOLLOW` (lstat-like) behavior.

## Round 6 — additional gaps closed (this round)

- **Apps using `statx` to bypass the entire stat-family hook set.**
  `statx(2)` is the modern Linux stat interface (kernel 4.11+,
  glibc 2.28+, bionic on Android 8.0+). It is NOT routed through
  `newfstatat` — it is its own syscall — so the `stat`/`lstat`/
  `fstatat` hooks from Round 5 never see it. Detection code
  increasingly prefers `statx` because it also exposes
  `STATX_BTIME` (inode birth time), which fingerprints
  freshly-created root files. **NEW (S60):** `statx` is now in
  the GOT patcher with the same hidden-path check as the rest of
  the stat family (return `ENOENT` for absolute paths in the
  hidden set). The hook resolves `g_real_statx` via dlsym and
  falls back to the raw `SYS_statx` syscall when the libc symbol
  is unavailable. Covered by a new host-side test
  (`statx_hook_returns_enoent_for_hidden_paths`).

- **`readlink("/proc/<pid>/fd/<n>")` leaking hidden paths through
  open descriptors.** The advanced layer's `close_unknown_fds()`
  closes every fd above stdio after fork, but an app that probes
  *during* the race window (before the cleanup runs) — or that
  finds an fd the runtime legitimately holds open to a hidden
  path — could readlink `/proc/self/fd/<n>` and see
  `/data/adb/...` or our daemon socket path. **NEW (S61):** the
  readlink/readlinkat hooks now recognize
  `/proc/{self,<pid>}/fd/<n>` paths in addition to
  `/proc/{self,<pid>}/exe` (S12) and run the resolved target
  through the same suspicious-substring rewrite. The new
  `path_is_proc_fd()` matcher is the same cheap
  prefix + numeric-scan + suffix pattern as `path_is_proc_exe()`.
  Covered by two new host-side tests
  (`path_is_proc_fd_recognizes_documented_variants`,
  `rewrite_if_suspicious_covers_fd_targets`).

- **The forked child being able to re-gain privileges via
  execve().** Without `no_new_privs`, exec'ing a setuid/setgid or
  file-capability binary could grant the child more privileges
  than the hide layer assumed — a privilege-boundary escape that
  also contradicts the "confined app process" profile SELinux
  expects. **NEW (S63):** the post-fork pipeline now calls
  `prctl(PR_SET_NO_NEW_PRIVS, 1)`. This is one-way and idempotent
  (Android 12+'s zygote already sets it for app processes; a
  second set is a no-op), and the cost is one prctl syscall
  (~1 µs) per fork on the slow path. Covered by a new host-side
  test (`set_no_new_privs_sets_flag`) that verifies the flag via
  `PR_GET_NO_NEW_PRIVS`.

- **`getcwd()` / `/proc/self/cwd` reporting a deleted directory
  after the hide unmounts.** If the forked child's cwd sat on a
  Magisk/KernelSU mount that `unmount_magisk_paths()` detached,
  the kernel reports the cwd as disconnected: `getcwd()` fails
  with `ENOENT` and `/proc/self/cwd` readlinks to
  `"<path> (deleted)"`. Both are anomalous — a stock app process
  always has cwd == `/`. **NEW (S65):** the post-fork pipeline
  now calls `chdir("/")`. On the common path the cwd is already
  `/` and this is a no-op; on the anomalous path it re-pins the
  cwd to the root mount so both probes return the stock answer.
  Covered by a new host-side test
  (`ensure_cwd_is_root_sets_cwd_to_slash`).

- **Correctness fix: `wrapped_open` / `openat` hook returning a
  closed fd (B2).** The old code did `close(real_fd); return
  memfd >= 0 ? memfd : real_fd;` — if `make_filtered_memfd`
  failed, the app received the just-closed fd, and any read would
  fail with an anomalous `EBADF` (or worse, silently operate on
  an unrelated file if the fd number was reused). Both hooks now
  return `-1` with `errno = EBADF` on that path, which is how a
  genuinely failed open behaves. Covered by a new host-side test
  (`wrapped_open_returns_valid_fd_for_filtered_path`).

- **Correctness fix: out-of-bounds read in `path_is_hidden`
  (B1).** The prefix-match loop read `path[hlen]` before
  verifying the probe path was at least `hlen` bytes long. For a
  probe of `/data/adb` (shorter than the hidden entry
  `/data/adb/modules`) that read past the string's NUL
  terminator. Harmless on real systems (the NUL page is mapped)
  but UB under sanitizers; the fix adds an explicit
  `hlen < plen` guard. Covered by a new host-side test
  (`path_is_hidden_handles_prefix_of_hidden_path`).

## Round 8 — additional gaps closed (this round)

Round 8 closed the residual leaks the Round 7 ledger documented,
plus several the fresh audit found:

1. **`/proc/net/unix` (the daemon socket leak).** The daemon's
   filesystem unix socket is listed in the GLOBAL, world-readable
   socket table — directory permissions do not help, the socket
   NAME is the tell. Tier B now filters `/proc/net/unix` (and the
   `/proc/self/net/unix`, `/proc/<pid>/net/unix` aliases), dropping
   every line that names a root-framework socket (`/data/adb/...`,
   magisk/zygisk/riru strings, our own path). Residual: an app that
   `execve()`s a helper binary reads the file unhooked — the same
   exec residual every in-process hider has.

2. **`/proc/self/environ`.** `unsetenv()` rewrites the `environ`
   array; the proc file serves the ORIGINAL stack environment
   block, so our variables were readable there forever. The file
   is now filtered (NUL-separated entry drop) in addition to the
   unsetenv scrub.

3. **`ro.dalvik.vm.native.bridge`.** The injection mechanism leaves
   it set to "libzygisk.so" for every process. Hidden processes now
   see the stock state (empty value; find()/get() report absence —
   what the property looked like before the swap, which the swap
   guard guarantees was the original state).

4. **`opendir()` on hidden paths.** stat/access returned ENOENT,
   but directory ENUMERATION was never gated — `File.list()` and
   native `opendir("/data/adb")` listed entries. opendir is now a
   Tier B hook with the same ENOENT semantics. Residual: libc-
   internal callers (scandir) are not caught.

5. **Per-thread path variants.** `/proc/<pid>/task/<tid>/maps|status|environ`
   and the readlink targets `task/<tid>/exe|fd` now match the
   filters and rewriters.

6. **`/proc/mounts` (the bare alias).** The most classic way to
   read the mount table now matches the filter.

7. **App-library collision guard.** The maps scanner no longer
   claims mappings under `/data/app/`, `/data/data/`, `/data/user/`,
   `/mnt/expand/`, `/storage/` — an app shipping its own
   `libpayload.so` was crashable by name collision before.

8. **Tier A soinfo safety.** Read-only segments of hidden libraries
   are replaced by content-preserving anonymous pages instead of
   being unmapped (see ANDROID-REALISM.md Round 8): the linker's
   solist walks stay safe AND the file paths leave maps.

## Round 9 — additional gaps closed (this round)

Round 9 studied ReZygisk for guidance; the adopted/rejected ledger
with reasoning lives in ANDROID-REALISM.md.

1. **Mount propagation (the big one).** `unshare(CLONE_NEWNS)`
   alone does NOT isolate: the copied namespace stays in the same
   SHARED peer group, so our umount2s could propagate BACK to init
   (system-wide module-mount loss) and later init mounts propagate
   IN (root mounts returning after we detached them). The unmount
   pipeline now remounts `/` as `MS_SLAVE|MS_REC` right after the
   unshare, and is fail-closed: a failed unshare OR failed slave
   remount skips the unmount phase entirely. Host seam tests assert
   the ordering and both fail-closed paths.

2. **Property enumeration.** `__system_property_foreach` +
   `read_callback` (the modern read API) could walk the patched
   clone and see every "absent" key present-but-empty. foreach now
   drops absent keys before the caller's callback; read_callback
   swallows them; legacy read reports not-found. Absent-key
   prop_info addresses are recorded from the clone at hide time, so
   pointers from enumeration or pre-hide caches are all covered.

3. **scandir / scandirat.** These build their lists through
   libc-internal opendir/readdir, bypassing the opendir GOT hook
   (the Round 8 residual). Both are now hooked: hidden directories
   report ENOENT, and root-marker entry names
   (magisk/.magisk/ksu/zygisk_study/our .so names) are dropped from
   the results of any directory listing, with the caller-owned
   memory contract preserved.

4. **Leaked descriptors by link target.** Any fd whose
   `/proc/self/fd/N` link resolves under a root-framework path is
   now closed at hide time (raw getdents64 scan + real readlink —
   no recursion into our own hooks). This catches module-leaked
   descriptors the tracked-fd list never knew about, without
   reintroducing the Round 7 close-everything crash class.

5. **The zygisk_study prefix.** Both unmount prefix tables carried
   a 28 for the 26-byte `/data/system/zygisk_study/` string — the
   memcmp over-read and never matched, so our own mounts were never
   detached. Fixed + regression-tested for every prefix.

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

## Round 11 — additional gaps closed (this round)

1. **The openat dirfd bypass.** All three open paths (libc openat
   via wrapped_openat, the FORTIFY __openat_2, and raw
   syscall(SYS_openat)) gated filtering on `dirfd == AT_FDCWD`.
   POSIX says an absolute path ignores dirfd, so a detector could
   pass any arbitrary fd with an absolute /proc path and bypass
   every filter. Fixed on all three paths (the statx/faccessat/
   fstatat hooks never had the gate); regression-tested with the
   memfd-vs-procfd observable.

2. **freopen().** The last stdio entry point that bypassed the
   filters — it rebinds an existing FILE to /proc/self/maps with no
   open()/fopen() GOT call. Now hooked: the stream is rebound to
   the filtered memfd via its /proc/self/fd link, with write modes
   and non-proc paths passing through untouched.

## Round 15-17 additions

**fd observable parity** — a filtered /proc read now answers every
descriptor-level probe like a stock procfs fd:

| probe | stock procfs | pre-R15 | now |
|---|---|---|---|
| readlink `/proc/self/fd/N` | the proc path | `memfd:scudo` | the proc path (dups too) |
| fstat `st_size` | 0 | filtered byte count | 0 |
| fstat `st_mode` | `S_IFREG\|0444` | `S_IFREG\|0777` | `S_IFREG\|0444` |
| mmap | ENODEV | works | ENODEV |

**linker enumeration** — `dl_iterate_phdr` no longer lists our DSOs
(and its `dlpi_adds` counter arithmetic stays exact so a counting
detector sees a consistent, smaller universe); `dladdr` answers 0 for
addresses inside our anonymous remaps, like any stock anon mapping.

**directory contents** — `readdir`/`readdir_r`/raw `getdents64` drop
entry names of root-framework artifacts from ANY directory listing.

**relative /proc paths** — `chdir("/proc/self") + open("maps")`,
`openat(proc_dirfd, "maps")`, and `.`/`..` traversal variants are
filtered like the absolute path.

**raw openat2** — `syscall(SYS_openat2, ...)` (Android 13+ kernels,
no bionic wrapper in any release) flows through the filter.

**mounts-family /proc content (Round 19)** — the line filter is
format-agnostic now: /proc/self/mounts, mountinfo and mountstats
lines drop when ANY token (source, target, root-column, or mapped
path) is anchored under a hidden prefix, an exact bridge-library
path, or a mountinfo root-field form. The Round 8-18 filter only
understood the maps column layout and leaked every mounts-format
line.

**opendir-derived dirfds (Round 20)** — the fd opendir() hands back
is registered as a proc-dir, so `opendir("/proc/self") +
openat(dirfd, "maps")` (and fchdir through it) filters exactly like
the absolute open. opendir's internal open never crosses the GOT —
this was the last R16 relative-open hole.

**stat parity for the mounted properties file (Round 20)** —
stat/lstat/statx/fstat of /dev/__properties__/properties_serial
(through the Round 19 bind) answer the REAL file's identity: mode
0444, size identical by construction, and the pre-bind st_dev/st_ino
instead of the session file's.

**exec'd helpers (Round 19)** — fork+exec'd children inherit the
private mount namespace; the hide mount phase bind-mounts a spoofed
properties_serial over /dev/__properties__/properties_serial (self-
checked, fail-closed), so a fresh-libc helper re-maps the spoofed
values trie instead of the real one. `getprop` in an exec'd child
prints the stock device's story.

Still open (see ANDROID-REALISM residuals): dup'd memfd fstat size,
>383-byte traversal strings, present-but-empty absent keys in the
file image, on-device chcon validation.

## Round 22 — absent keys are GONE, not empty

The largest property-hiding gap left standing after Round 19 was
cosmetic-but-real: keys spoofed as absent were present-but-empty
in the exec'd-helper file image, and present-but-hook-gated in the
in-process clone. Reading bionic's actual trie sources settled it:
a node with `prop == 0` is a legal fragment-only node — zeroing a
terminal node's prop offset is a deletion every bionic reader
already understands. Both layers now do exactly that, plus a scrub
of the orphaned entry bytes, so neither the served 128 KB file
image nor the process's own memory contains the strings
"ro.magisk.version" / "libzygisk.so" / "ro.dalvik.vm.native.bridge"
in dead records.

Observable table (post-R22):

| Detector probe | Stock device | Hidden process (R22) |
|---|---|---|
| getprop ro.magisk.version (exec'd) | not listed | not listed (trie: node->prop = 0) |
| __system_property_find("ro.magisk.version") | NULL | NULL (native, no hook needed) |
| __system_property_foreach | key absent | key absent (native) |
| raw scan of the properties_serial image | no match | no match (entry scrubbed) |
| in-process memory scan for the key name | no match | no match (clone entry scrubbed) |
| setprop X && getprop X | round-trips | round-trips (set hook reflects into the clone) |

Also closed this round: the serial length-byte bug (spoofed values
longer than the device original returned truncated, potentially
non-NUL-terminated strings through __system_property_get — a
crash class in the hidden app itself); fdopendir()-built DIR*
handles from bare fds (the last directory-fd registration gap);
and over-383-byte relative-path traversals (now heap-reconstructed
and filtered, previously an explicit unfiltered fall-through).
