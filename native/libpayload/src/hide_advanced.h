// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide_advanced.h
//
// Advanced runtime stealth layer — additional hiding techniques
// layered on top of the basic hide layer in hide.h.
//
// ROUND 7 ARCHITECTURE NOTE — two hide tiers:
//
//   Tier A ("physical hide", primary on arm64/x86_64):
//     For denylisted targets we remove ourselves *physically*:
//       unmount (private mount ns) → per-process property clone with
//       spoofed values → close our fds → munmap every module .so →
//       restore every GOT slot we patched → finally munmap our own
//       .so files from an asm trampoline that never executes another
//       byte of libpayload code. After Tier A the process is
//       byte-for-byte stock: no hooks, no libs, no fds, no mounts.
//     With nothing resident, the open/stat/readlink filtering hooks
//     are NOT needed — there is nothing left to filter out of
//     /proc/self/maps. (Installing them and then unmapping ourselves
//     would leave dangling GOT entries and crash the app on its next
//     open() call — the exact failure mode the pre-Round-7 code had
//     in miniature.)
//
//   Tier B ("hook hide", fallback — 32-bit devices, or a missing
//     self-unmap record set):
//     When the trampoline is unavailable we keep libpayload mapped
//     and hide *functionally*: GOT hooks on open/openat/stat-family/
//     fopen/dlopen/readlink/__system_property_* redirect /proc reads
//     to filtered memfd copies. The hooks are installed at hide time
//     (in the forked child) — NOT in the zygote — so every other
//     process on the system, including system_server, runs 100%
//     unhooked.
//
// Public surface:
//
//   hide_advanced_init()               — register this layer's hooks
//   hide_advanced_register_got_hook()  — registry used by entry.cpp
//                                        (fork/setresuid family) and
//                                        hide_stealth (readlink)
//   hide_advanced_install_got_hooks()  — the ONE dl_iterate_phdr walk
//   hide_advanced_uninstall_got_hooks()— restore every patched slot
//   hide_advanced_set_active()         — per-process gate for Tier B
//   hide_advanced_track_fd()           — fds we own; closed on hide

#pragma once

#include <cstddef>
#include <sys/types.h>

namespace zygisk_study {

// Register hook `fn` as the GOT replacement for libc symbol `name`.
// Returns 1 on success, 0 if the table is full or args are bad.
// Call BEFORE hide_advanced_install_got_hooks(). The registry is
// written only during payload init (zygote, single-threaded) and read
// afterwards — no locking needed.
int  hide_advanced_register_got_hook(const char* name, void* fn);

// Deferred (Tier B) registration: promoted into the live registry
// only by hide_advanced_install_tier_b(), i.e. only inside a forked
// child we are actually hiding. Everything registered here stays
// completely absent from every other process on the device.
int  hide_advanced_register_tier_b_hook(const char* name, void* fn);

// Run the single merged dl_iterate_phdr walk that patches every
// registered symbol's GOT slot in every loaded module (except our
// own three .so files). Records each patched slot so
// hide_advanced_uninstall_got_hooks() can restore the originals.
void hide_advanced_install_got_hooks();

// Restore every GOT slot patched by hide_advanced_install_got_hooks()
// to its original value. MUST run before the self-unmap trampoline —
// a patched slot pointing into unmapped memory is a guaranteed crash
// on the app's next call.
void hide_advanced_uninstall_got_hooks();

// Per-process activation gate for the Tier B hooks. Set to 1 in the
// forked child we are hiding; the hooks then actually filter. Every
// other process (zygote, system_server, normal apps) sees a pure
// passthrough (one relaxed atomic load).
void hide_advanced_set_active(int active);
int  hide_advanced_is_active();

// Register an fd opened by us (e.g. the daemon socket) so the hide
// pipeline closes exactly those — and nothing else. The old
// close-everything behavior destroyed GPU/graphics descriptors
// inherited from the zygote.
void hide_advanced_track_fd(int fd);

// Round 13 — runtime registrations for the daemon's randomized
// per-boot socket directory (the path is only known at runtime; the
// session-file reader in module_dispatch.cpp calls these at payload
// init):
//   - root-path prefix: matched by the fd-link scan (closes leaked
//     descriptors whose target lives under it).
//   - unix hidden substring: matched by the /proc/net/unix filter
//     (drops the socket's line even under its new random name).
void hide_advanced_register_root_path_prefix(const char* prefix);
void hide_advanced_register_unix_hidden_substring(const char* s);

// Round 15 — fd observable parity. Called by the readlink hooks in
// hide_stealth.cpp after the REAL readlink of /proc/<pid>/fd/<n>: if
// the descriptor is one of our filtered memfds (identified by fd
// number, or by dev/ino for dup'd descriptors) and the real target is
// our "memfd:scudo" marker, writes the ORIGINAL proc path into `buf`
// (exactly what a stock procfs fd would answer) and returns its
// length. Returns 0 when no spoof applies — the caller then keeps the
// real result.
ssize_t hide_advanced_spoof_memfd_readlink(int fd,
                                           const char* real_target,
                                           size_t real_len, char* buf,
                                           size_t bufsiz);

// Round 23 — resolve a RELATIVE path against a tracked /proc dirfd
// (or the tracked /proc cwd when dirfd == AT_FDCWD) into a malloc'd,
// normalized ABSOLUTE path the caller must free(). Returns null when
// the dirfd/cwd is not tracked /proc (passthrough territory). Used by
// the readlink hooks so relative proc reads hit the same matchers as
// absolute ones (the Round 16 openat closure's readlink twin).
char* hide_advanced_resolve_proc_relative(int dirfd, const char* rel);

// One-time init: resolve real libc symbols and register this layer's
// Tier B hooks into the registry. Does NOT walk yet.
void hide_advanced_init();

// Install the Tier B hook set NOW (at hide time, in the child) and
// set the active gate. Used only on the fallback tier.
void hide_advanced_install_tier_b();

// Post-fork actions common to both tiers:
//   - property-area clone (content-preserving!) + value spoofing
//   - tracked-fd close
//   - env scrub
// The signal reset and the close-all-fds steps from earlier rounds
// are GONE: resetting signals wiped ART's SIGSEGV handler (every
// NullPointerException then crashed the app), and closing all fds
// killed the GPU driver fds every app inherits from the zygote.
void hide_advanced_apply_post_fork(const char* package_name);

// ------------------------------------------------------------------------
// Round 19 — execve-proof property spoofing (spoofed
// properties_serial FILE, bind-mounted in the child's private mount
// namespace). See the long comment block in hide_advanced.cpp
// section 4b for the full design (payload builds, daemon writes +
// labels, child mounts + self-checks).
// ------------------------------------------------------------------------

// Build the spoofed image of the property-area file at
// `prop_file_path` (production: /dev/__properties__/properties_serial).
// Returns a malloc'd buffer (caller owns, free()), or null = feature
// unavailable (no bionic find, no mapping, no file, zero patches).
// Called ONCE at payload init, in the zygote, while the live area is
// still the real one.
char* zs_build_spoofed_serial_area(const char* prop_file_path,
                                   size_t* out_size);

#ifdef ZS_HOST_TEST
// Test seams for the builder (host has no bionic property area).
void zs_test_set_prop_find(const void* (*find)(const char*));
void zs_test_reset_prop_find();

// Round 25 test seams: force the memfd path off (simulates a
// pre-3.17 kernel / ENOMEM) and point the unlinked-file fallback at
// a host directory.
void zs_test_disable_memfd(int disabled);
void zs_test_set_filter_fallback_dir(const char* dir);

// Round 25 test seam: drive the FULL production property-clone path
// (pre-map pass, scan, capture, remap, patch, delete, mprotect)
// against maps content from a GENERATOR, invoked exactly where
// production reads /proc/self/maps (i.e. after the pre-map pass).
// The fake find is supplied through zs_test_set_prop_find.
void zs_test_set_clone_maps_gen(const char* (*gen)(size_t* out_len));
void zs_test_clear_clone_maps_gen();
int  zs_test_props_cloned_latched();
void zs_test_reset_props_cloned();
#endif

// Spoof table entry (definition lives in hide_advanced.cpp).
struct ZsPropSpoof {
    const char* key;
    const char* value;   // nullptr = pretend the key does not exist
};

// Accessor for tests: the full spoof table.
const ZsPropSpoof* zs_prop_spoof_table(size_t* count);

// Tier-B-only: is `path` one of the /proc files we filter? Matches
// the /proc/self/<f>, /proc/thread-self/<f>, /proc/<pid>/<f>,
// /proc/<pid>/task/<tid>/<f>, /proc/net/<f> and /proc/self/net/<f>
// forms (most real detectors use their own numeric pid — the
// pre-Round-7 code only matched the literal "/proc/self/..." string,
// which every pid-based probe trivially bypassed).
int zs_path_is_filtered(const char* path);

// Round 8 — WHAT kind of filtering a matched path needs. The filter
// engine (streaming memfd rewrite) behaves differently per kind:
enum ZsFilterKind {
    ZS_FILTER_NONE = 0,    // not a /proc file we touch
    ZS_FILTER_PROC_LINE,   // maps/mounts/smaps/...: drop lines whose
                           // path field matches kHiddenSubstrings
    ZS_FILTER_STATUS,      // /proc/<pid>/status: rewrite TracerPid -> 0
    ZS_FILTER_ENVIRON,     // NUL-separated env entries: drop ours
    ZS_FILTER_NET_UNIX,    // /proc/net/unix: drop lines naming root-
                           // framework sockets (our daemon socket leaks
                           // its path there system-wide)
};

// Resolve the filter kind for a path (also the source of truth for
// zs_path_is_filtered — "filtered" == kind != ZS_FILTER_NONE).
ZsFilterKind zs_filter_kind_for_path(const char* path);

// Filter one record of a /proc file (a line for newline-separated
// kinds, an env entry for environ). `rec_len` excludes the separator.
// Writes the kept (possibly rewritten) bytes to `dst` (which may
// alias `rec` — in-place compaction) and returns the kept length, or
// -1 when the record must be dropped. Pure function: host tests
// exercise it directly.
ssize_t zs_filter_record(char* dst, size_t dst_cap,
                         const char* rec, size_t rec_len,
                         ZsFilterKind kind);

#ifdef ZS_HOST_TEST
// Test-only: access the live-registry matcher used by the GOT walk
// (hash-indexed since Round 8; verifies the index stays consistent
// with the registry).
void* zs_test_match_registered_hook(const char* name);

// Round 9 (B2): inject synthetic prop_info pointers as "absent
// spoof" keys and a fake __system_property_foreach, to drive the
// read_callback / read / foreach hooks without a bionic runtime.
void zs_test_set_absent_prop_infos(const void** arr, size_t n);
void zs_test_set_real_prop_foreach(
    int (*fn)(void (*)(const void*, void*), void*));

// Round 9 (S1): replace the real scandir() so tests can supply a
// synthetic dirent list to the scandir/scandirat hooks.
void zs_test_set_real_scandir(void* fn);

// Round 9 (P1): how many TLS scratch buffers the filter engine has
// allocated. Repeated filtering on one thread must not grow this.
int  zs_test_filter_scratch_allocs();

// Round 9 (S2): point the fd-link scan at a host-creatable directory
// so tests can exercise the getdents64 walk + readlink resolution
// against real file descriptors.
void zs_test_set_fd_root_prefix(const char* prefix);

// Round 22: the protection the prop-set reflect restores after
// patching (PROT_READ in production; tests relax it for heap fakes),
// plus a fake real __system_property_set.
void zs_test_set_props_clone_prot(int prot);
void zs_test_set_real_prop_set(int (*fn)(const char*, const char*));

// Round 26: register/clear clone spans from tests (the set hook's
// area-serial bump needs them; heap-fake tests do not run the
// production clone).
void zs_test_register_clone_span(unsigned long lo, unsigned long hi);
void zs_test_clear_clone_spans();
#endif

} // namespace zygisk_study
