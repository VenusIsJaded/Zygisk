// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/unmap_trampoline_x86_64.S
//
// x86-64 asm wrappers + the position-independent self-unmap blob.
// See unmap_trampoline.h for the full design and the frame layout.
//
// Compiled for x86_64 targets (the NDK x86_64 ABI and the host tests).

    .code64
    .text
    .align 16

// ---------------------------------------------------------------------------
// Data-area offsets (must match unmap_trampoline.h)
// ---------------------------------------------------------------------------
    .equ TRAMP_COUNT_OFF, 512
    .equ TRAMP_FP_OFF,    520
    .equ TRAMP_RETVAL_OFF, 528

// ---------------------------------------------------------------------------
// The wrappers. Frame layout (rbp = fp):
//   [fp+8]  original return address
//   [fp]    caller's rbp
//   [fp-8]  rbx
//   [fp-16] r12   [fp-24] r13   [fp-32] r14   [fp-40] r15
//   final sp = fp + 16
//
// Alignment: at entry rsp%16==8; push rbp -> 0; five more pushes
// (40 bytes) -> 8; `sub rsp,8` -> 0, which is what `call` requires.
// ---------------------------------------------------------------------------

    .global zs_fork_wrapper
    .type   zs_fork_wrapper, @function
zs_fork_wrapper:
    push %rbp
    mov  %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub  $8, %rsp
    mov  %rbp, %rdi                    # impl(wrapper_fp)
    call zs_impl_fork
    add  $8, %rsp
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    ret

    .global zs_setresgid_wrapper
    .type   zs_setresgid_wrapper, @function
zs_setresgid_wrapper:
    push %rbp
    mov  %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub  $8, %rsp
    mov  %rdx, %rcx                    # a2
    mov  %rsi, %rdx                    # a1
    mov  %rdi, %rsi                    # a0
    mov  %rbp, %rdi                    # impl(fp, a0, a1, a2)
    call zs_impl_setresgid
    add  $8, %rsp
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    ret

    .global zs_setresuid_wrapper
    .type   zs_setresuid_wrapper, @function
zs_setresuid_wrapper:
    push %rbp
    mov  %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub  $8, %rsp
    mov  %rdx, %rcx
    mov  %rsi, %rdx
    mov  %rdi, %rsi
    mov  %rbp, %rdi
    call zs_impl_setresuid
    add  $8, %rsp
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    ret

    .global zs_setgid_wrapper
    .type   zs_setgid_wrapper, @function
zs_setgid_wrapper:
    push %rbp
    mov  %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub  $8, %rsp
    mov  %rdi, %rsi                    # a0
    mov  %rbp, %rdi                    # impl(fp, a0)
    call zs_impl_setgid
    add  $8, %rsp
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    ret

    .global zs_setuid_wrapper
    .type   zs_setuid_wrapper, @function
zs_setuid_wrapper:
    push %rbp
    mov  %rsp, %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub  $8, %rsp
    mov  %rdi, %rsi
    mov  %rbp, %rdi
    call zs_impl_setuid
    add  $8, %rsp
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %rbx
    pop  %rbp
    ret

// ---------------------------------------------------------------------------
// The position-independent trampoline blob.
//
// Entry: rdi = data area pointer (records[], count, wrapper_fp, retval).
// Never returns: ends by restoring the wrapper frame and jumping to
// the wrapper's original caller with rax = retval.
//
// Register notes: the x86-64 kernel clobbers rcx, r11 and rax across
// syscall — the loop keeps its cursor in r8 and end in r9, the record
// base/size are reloaded into rdi/rsi every iteration, the wrapper fp
// sits in r12 and the staged retval in r10 (both preserved by the
// kernel across syscall, and both restored from the frame at the end
// anyway).
// ---------------------------------------------------------------------------

    .align 16
    .global zs_trampoline_code_start
    .type   zs_trampoline_code_start, @function
zs_trampoline_code_start:
    mov  TRAMP_FP_OFF(%rdi),    %r12   # wrapper fp
    mov  TRAMP_COUNT_OFF(%rdi), %r13   # count
    shl  $4, %r13                      # count*16 (byte stride)
    mov  TRAMP_RETVAL_OFF(%rdi),%r10   # staged retval
    mov  %rdi, %r8                     # record cursor
    lea  (%rdi,%r13), %r9              # end = records + count*16
.Lzs_loop:
    cmp  %r9, %r8
    jae  .Lzs_restore
    mov  (%r8), %rdi                   # base
    mov  8(%r8), %rsi                  # size
    mov  $11, %eax                     # __NR_munmap (x86-64)
    syscall
    add  $16, %r8
    jmp  .Lzs_loop
.Lzs_restore:
    # Slot map (from the wrapper prologue): [fp-8]=rbx, [fp-16]=r12,
    # [fp-24]=r13, [fp-32]=r14, [fp-40]=r15, [fp]=caller rbp,
    # [fp+8]=return address. r12 carries the fp until the end, so its
    # own saved value is staged through rax and committed last.
    # (An earlier revision of this blob loaded [fp-16] into %r13 —
    # every callee-saved register came back shifted by one slot and
    # the caller crashed on its first use of one. Caught by
    # test_unmap_trampoline on x86_64.)
    mov  -8(%r12),  %rbx
    mov  -16(%r12), %rax               # stage saved r12
    mov  -24(%r12), %r13
    mov  -32(%r12), %r14
    mov  -40(%r12), %r15
    mov  (%r12),    %rbp               # caller's rbp
    lea  8(%r12),   %rsp               # rsp -> original return address
    mov  %rax, %r12                     # commit r12's true value
    mov  %r10, %rax                    # hook return value
    ret                                # pops the return address
    .global zs_trampoline_code_end
zs_trampoline_code_end:
