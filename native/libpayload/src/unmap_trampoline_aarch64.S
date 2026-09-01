// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/unmap_trampoline_aarch64.S
//
// AArch64 asm wrappers + the position-independent self-unmap blob.
// See unmap_trampoline.h for the full design and the frame layout.
//
// Compiled only for arm64-v8a targets (CMake selects by ABI).

    .text
    .align 4

// ---------------------------------------------------------------------------
// Data-area offsets (must match unmap_trampoline.h)
// ---------------------------------------------------------------------------
    .equ TRAMP_COUNT_OFF, 512
    .equ TRAMP_FP_OFF,    520
    .equ TRAMP_RETVAL_OFF, 528
    .equ TRAMP_PAGE_OFF,   536

// ---------------------------------------------------------------------------
// The wrappers. Shared prologue/epilogue:
//   zs_fork_wrapper takes no arguments;
//   the setres*/set* wrappers shift their 1-3 arguments one register
//   right and insert the frame pointer as the first argument of the
//   C++ implementation.
// ---------------------------------------------------------------------------

    .global zs_fork_wrapper
    .type   zs_fork_wrapper, %function
zs_fork_wrapper:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    stp  d8,  d9,  [sp, #-16]!
    stp  d10, d11, [sp, #-16]!
    stp  d12, d13, [sp, #-16]!
    stp  d14, d15, [sp, #-16]!
    mov  x0, x29                      // impl(wrapper_fp)
    bl   zs_impl_fork
    ldp  d14, d15, [sp], #16
    ldp  d12, d13, [sp], #16
    ldp  d10, d11, [sp], #16
    ldp  d8,  d9,  [sp], #16
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .global zs_setresgid_wrapper
    .type   zs_setresgid_wrapper, %function
zs_setresgid_wrapper:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    stp  d8,  d9,  [sp, #-16]!
    stp  d10, d11, [sp, #-16]!
    stp  d12, d13, [sp, #-16]!
    stp  d14, d15, [sp, #-16]!
    mov  x3, x2                       // a2
    mov  x2, x1                       // a1
    mov  x1, x0                       // a0
    mov  x0, x29                      // impl(wrapper_fp, a0, a1, a2)
    bl   zs_impl_setresgid
    ldp  d14, d15, [sp], #16
    ldp  d12, d13, [sp], #16
    ldp  d10, d11, [sp], #16
    ldp  d8,  d9,  [sp], #16
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .global zs_setresuid_wrapper
    .type   zs_setresuid_wrapper, %function
zs_setresuid_wrapper:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    stp  d8,  d9,  [sp, #-16]!
    stp  d10, d11, [sp, #-16]!
    stp  d12, d13, [sp, #-16]!
    stp  d14, d15, [sp, #-16]!
    mov  x3, x2
    mov  x2, x1
    mov  x1, x0
    mov  x0, x29
    bl   zs_impl_setresuid
    ldp  d14, d15, [sp], #16
    ldp  d12, d13, [sp], #16
    ldp  d10, d11, [sp], #16
    ldp  d8,  d9,  [sp], #16
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .global zs_setgid_wrapper
    .type   zs_setgid_wrapper, %function
zs_setgid_wrapper:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    stp  d8,  d9,  [sp, #-16]!
    stp  d10, d11, [sp, #-16]!
    stp  d12, d13, [sp, #-16]!
    stp  d14, d15, [sp, #-16]!
    mov  x1, x0                       // a0
    mov  x0, x29                      // impl(wrapper_fp, a0)
    bl   zs_impl_setgid
    ldp  d14, d15, [sp], #16
    ldp  d12, d13, [sp], #16
    ldp  d10, d11, [sp], #16
    ldp  d8,  d9,  [sp], #16
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .global zs_setuid_wrapper
    .type   zs_setuid_wrapper, %function
zs_setuid_wrapper:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    stp  x27, x28, [sp, #-16]!
    stp  d8,  d9,  [sp, #-16]!
    stp  d10, d11, [sp, #-16]!
    stp  d12, d13, [sp, #-16]!
    stp  d14, d15, [sp, #-16]!
    mov  x1, x0
    mov  x0, x29
    bl   zs_impl_setuid
    ldp  d14, d15, [sp], #16
    ldp  d12, d13, [sp], #16
    ldp  d10, d11, [sp], #16
    ldp  d8,  d9,  [sp], #16
    ldp  x27, x28, [sp], #16
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

// ---------------------------------------------------------------------------
// The position-independent trampoline blob.
//
// Entry: x0 = data area pointer (records[], count, wrapper_fp).
// Never returns: ends by restoring the wrapper frame and jumping to
// the wrapper's original caller with x0 = 0.
//
// Register notes: on arm64 Linux the kernel preserves every register
// across svc except x0 (the return value), so the loop state below is
// safe across the munmap calls. In the restore phase x28 carries the
// wrapper fp until the end (its true value is staged through x0 and
// committed last), and x30 is loaded with the original caller's
// return address so the final `ret` lands there.
//
// ROUND 34 (the arg-register fix): the syscall ABI is x8 = number,
// x0/x1 = args (man2 syscall.2, "arm64  svc #0  w8  x0  x1"; the
// AAPCS64 calling convention the kernel adopts). The pre-R34 blob
// loaded the record's base/size into x23/x24 — registers the kernel
// never reads as syscall arguments — so every svc executed
// munmap(<stale x0>, <garbage x1>) = EINVAL, all 32 attempts, with
// no error path: Tier A silently unmapped NOTHING on every arm64
// device. The loop below now loads base/size into x0/x1, which the
// kernel clobbers with the return value — hence the reload each
// iteration. x23/x24 are repurposed as the scrub registers (their
// true values are restored from the wrapper frame anyway).
//
// Frame slots (from the wrapper above):  x19@fp-16, x20@fp-8,
// x21@fp-32, x22@fp-24, x23@fp-48, x24@fp-40, x25@fp-64, x26@fp-56,
// x27@fp-80, x28@fp-72, d8@fp-96, d9@fp-88, d10@fp-112, d11@fp-104,
// d12@fp-128, d13@fp-120, d14@fp-144, d15@fp-136, retaddr@fp+8,
// final sp = fp+16.
// ---------------------------------------------------------------------------

    .align 4
    .global zs_trampoline_code_start
    .type   zs_trampoline_code_start, %function
zs_trampoline_code_start:
    ldr  x19, [x0, #TRAMP_COUNT_OFF]  // count
    ldr  x20, [x0, #TRAMP_FP_OFF]     // wrapper fp
    ldr  x16, [x0, #TRAMP_RETVAL_OFF] // retval (staged; x16 is scratch)
    mov  x23, x0                      // data area pointer (kept for the scrub)
    cbz  x19, .Lzs_scrub
    mov  x21, x0                      // record cursor
    add  x22, x0, x19, lsl #4         // end = records + count*16
.Lzs_loop:
    cmp  x21, x22
    b.hs .Lzs_scrub
    ldr  x0, [x21], #16               // base  -> syscall arg 0
    ldr  x1, [x21, #-8]               // size  -> syscall arg 1
    mov  x8, #215                     // __NR_munmap (aarch64)
    svc  #0                           // munmap(x0, x1); retval clobbers x0
    b    .Lzs_loop
.Lzs_scrub:
    // ROUND 34 (stealth): zero the whole data area — the record
    // table (the exact ranges just unmapped), count, wrapper_fp,
    // retval and page_base — before returning to the caller. The
    // residual [anon:jit-cache] page stays readable by the app
    // itself (process_vm_readv / /proc/self/mem); a populated
    // forensic map of "where the module used to be" plus a stack
    // pointer is a signature no stock jit page has.
    //
    // zs_trampoline_jump() sealed this page R|X before entering,
    // so the scrub first mprotects it R|W (syscall 226, verified
    // from include/uapi/asm-generic/unistd.h), scrubs 544 bytes
    // (68 x 8-byte stores), and re-seals R|X. An mprotect failure
    // skips the scrub entirely (correctness over stealth). x24-x27
    // are safe as scratch: the restore phase reloads them from the
    // wrapper frame.
    add  x27, x23, #544               // data area end (sizeof ZsTrampData)
    ldr  x25, [x23, #TRAMP_PAGE_OFF]  // page base
    sub  x26, x27, x25                // page size (data occupies the tail)
    mov  x0, x25                      // mprotect(page, size, RWX)
    mov  x1, x26
    // PROT_READ|PROT_WRITE|PROT_EXEC (7) — the EXEC bit must stay:
    // we are EXECUTING from this page; dropping it (RW alone)
    // faults the next instruction fetch (verified the hard way by
    // the host trampoline test: child SIGSEGV inside the scrub).
    mov  x2, #7
    mov  x8, #226                     // __NR_mprotect (aarch64)
    svc  #0
    cmp  x0, #0
    b.ne .Lzs_restore                 // unprotect failed: skip scrub
.Lzs_scrub_loop:
    cmp  x23, x27
    b.hs .Lzs_scrub_seal
    str  xzr, [x23], #8
    b    .Lzs_scrub_loop
.Lzs_scrub_seal:
    mov  x0, x25                      // mprotect(page, size, RX)
    mov  x1, x26
    mov  x2, #5                       // PROT_READ|PROT_EXEC
    mov  x8, #226
    svc  #0                           // best effort (like jump()'s seal)
.Lzs_restore:
    ldr  x30, [x20, #8]               // original return address
    mov  x28, x20                     // x28 = wrapper fp
    ldr  x19, [x28, #-16]
    ldr  x20, [x28, #-8]
    ldr  x21, [x28, #-32]
    ldr  x22, [x28, #-24]
    ldr  x23, [x28, #-48]
    ldr  x24, [x28, #-40]
    ldr  x25, [x28, #-64]
    ldr  x26, [x28, #-56]
    ldr  x27, [x28, #-80]
    ldr  x0,  [x28, #-72]             // x28's saved value, staged in x0
    ldp  d8,  d9,  [x28, #-96]
    ldp  d10, d11, [x28, #-112]
    ldp  d12, d13, [x28, #-128]
    ldp  d14, d15, [x28, #-144]
    add  sp, x28, #16                 // final sp
    mov  x28, x0                      // commit x28's true value
    mov  x0, x16                      // hook return value
    ret                               // jump to the original caller
    .global zs_trampoline_code_end
zs_trampoline_code_end:
