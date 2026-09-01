// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/unmap_trampoline.h
//
// Stack-safe self-unmap machinery.
//
// WHY THIS EXISTS
// ---------------
// munmap()ing our own .so from C is impossible to do safely: the
// moment the kernel removes the executable mapping, the very next
// instruction fetch of the running loop faults. The pre-Round-7 code
// did exactly that (hide.cpp's unmap_self looped munmap over records
// that included the segment the loop itself ran from) and would have
// crashed every denylisted fork on a real device. The host tests
// never saw it because they zeroed the record set first.
//
// THE MECHANISM
// -------------
// 1. Every hook the payload installs (fork, setresgid, setresuid, ...)
//    enters through a small hand-written asm WRAPPER that saves ALL
//    callee-saved registers into its stack frame at FIXED offsets
//    (the layout below), then calls the C++ implementation.
//
// 2. When the hide pipeline finishes and it is time to disappear, the
//    C++ side builds a PIC "trampoline" blob on a private RWX page:
//      - it munmaps every record (our .so segments, the loader, the
//        bridge, loaded module .so files) via a raw svc/syscall, so it
//        never calls back into the payload;
//      - it then restores the callee-saved registers from the
//        wrapper's frame, points sp at the wrapper's return slot and
//        jumps to the ORIGINAL caller (libandroid_runtime) with the
//        hook's return value set to 0.
//    Result: control returns to the zygote specialization code as if
//    the hook had normally returned, but no libpayload code, data or
//    GOT entry remains in the process.
//
// 3. The trampoline page itself remains mapped (it cannot unmap
//    itself while executing from itself). It is renamed to "jit-cache"
//    via PR_SET_VMA — one anonymous executable page that looks like
//    ART's JIT region. This residual is documented in the README.
//
// Frame layout (aarch64), fp = x29 inside the wrapper:
//      [fp +  8]  original return address
//      [fp     ]  caller's x29
//      [fp - 16]  x19     [fp -  8] x20
//      [fp - 32]  x21     [fp - 24] x22
//      [fp - 48]  x23     [fp - 40] x24
//      [fp - 64]  x25     [fp - 56] x26
//      [fp - 80]  x27     [fp - 72] x28
//      [fp - 96]  d8      [fp - 88] d9
//      [fp -112]  d10     [fp -104] d11
//      [fp -128]  d12     [fp -120] d13
//      [fp -144]  d14     [fp -136] d15
//    final sp = fp + 16
//
// Frame layout (x86_64), fp = rbp inside the wrapper:
//      [fp +  8]  original return address
//      [fp     ]  caller's rbp
//      [fp -  8]  rbx
//      [fp - 16]  r12     [fp - 24] r13
//      [fp - 32]  r14     [fp - 40] r15
//    final sp = fp + 16
//
// The trampoline data area (on the same page, after the code):
//      offset   0: { uintptr_t base; size_t size; } records[32]
//      offset 512: size_t count
//      offset 520: uintptr_t wrapper_fp
//      offset 528: long retval (returned to the wrapper's caller)
//      offset 536: uintptr_t page_base (ROUND 34: the scrub's own
//                  mprotect needs it; the blob unprotects its page,
//                  zeroes this whole area, and re-seals R|X)

#pragma once

#include <cstddef>
#include <cstdint>

namespace zygisk_study {

// Maximum records the trampoline data area can carry (matches the
// .equ TRAMP_MAX_RECORDS in both .S files).
constexpr size_t kTrampMaxRecords = 32;

struct ZsTrampRecord {
    uintptr_t base;
    size_t    size;
};

// Build the trampoline page, copy the records, and jump into the
// blob. On success this NEVER RETURNS — control re-enters the
// original caller of the hook wrapper with `retval` as the return
// value.
//
// `wrapper_fp` is the frame pointer of the asm wrapper currently on
// the stack (passed by the C++ hook implementation, which received it
// from its wrapper).
//
// Returns -1 only if the page could not be set up (caller should fall
// back to Tier B).
int zs_trampoline_unmap(const ZsTrampRecord* records, size_t count,
                        void* wrapper_fp, long retval);

// Round 30 — the same machinery split into two phases so the Tier A
// path can order its irreversible steps safely:
//
//   zs_trampoline_prepare()  — every FAILING operation (mmap, code
//       copy, data fill). Returns the page pointer, or null on any
//       failure (caller falls back to Tier B with everything still
//       intact).
//   zs_trampoline_jump()     — the infallible tail: writes the final
//       retval into the data area, seals the page R+X, flushes the
//       icache and enters the blob. Never returns on success; a
//       return value of -1 marks an impossible-state error only
//       (null/bad page).
//
// Between the two calls the caller may run MUST-SUCCEED work that can
// no longer fall back to Tier B (the Round 30 atexit purge of the
// payload's own statics: after __cxa_finalize the C++ statics are
// destroyed, so the ONLY remaining exits are the real privilege-drop
// call and the jump).
void* zs_trampoline_prepare(const ZsTrampRecord* records, size_t count,
                            void* wrapper_fp);
int    zs_trampoline_jump(void* page, long retval);

// 1 on architectures whose blob is compiled in (arm64, x86_64),
// 0 otherwise (Tier B fallback).
int zs_trampoline_supported();

} // namespace zygisk_study

// Assembly entry points (defined in unmap_trampoline_<arch>.S).
// The wrappers save the frame, shuffle arguments to
// zs_impl_<name>(wrapper_fp, a0, a1, a2[, a3]) and restore on return.
extern "C" {
long zs_fork_wrapper(void);
long zs_setresgid_wrapper(long, long, long);
long zs_setresuid_wrapper(long, long, long);
long zs_setgid_wrapper(long);
long zs_setuid_wrapper(long);
// Round 35 — the isolated-process coverage hook. AOSP's
// SpecializeCommon calls selinux_android_setcontext(uid,
// isSystemServer, seInfo, niceName) AFTER the uid drop (verified at
// android-5.0.0_r1 AND refs/heads/main: the call shape is identical
// across the entire supported range). It is the ONLY call in the
// specialization chain that receives the FULL, UNtruncated nice_name
// together with the uid — the data the uid-only matcher cannot
// derive for Android's isolated-uid ranges (99000-99999 regular,
// 90000-98999 app-zygote; allocation is range-per-app and
// order-dependent in ProcessList, not a formula). See
// zs_impl_setcontext for the decision logic.
long zs_setcontext_wrapper(long, long, long, long);
// The PIC blob boundaries.
extern const unsigned char zs_trampoline_code_start[];
extern const unsigned char zs_trampoline_code_end[];
}
