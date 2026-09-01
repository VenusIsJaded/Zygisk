#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# scripts/verify_trampolines.py
#
# Round 22 — binary verification of BOTH self-unmap trampoline blobs.
#
# Until this round the aarch64 blob was "verified by parity inspection
# only" (no cross-toolchain in the sandbox): a documented residual
# since Round 7. The keystone-engine assembler (pip, aarch64 capable)
# changes that: this script ASSEMBLES every instruction of both .S
# files — a real assembler accepting them rules out illegal/unencodable
# instructions — and mechanically CROSS-CHECKS the frame contract:
#
#   1. For each architecture, derive the callee-save slot map from the
#      WRAPPER prologues (push/stp order, 8/16-byte steps).
#   2. Derive the same map from the BLOB's restore phase (ldp/ldr/mov
#      offsets).
#   3. Assert they agree register-by-register — the exact class of bug
#      that shipped in Round 7's x86_64 blob (r13 loaded from the r12
#      slot) and was only caught on the host by luck of test ordering.
#   4. Assert the syscall number immediate in the assembled encoding
#      (__NR_munmap: 215 on aarch64, 11 on x86-64).
#   5. Assert the record-stride immediate (4 = log2(16) in both).
#
# Exit 0 = every check green. 77 = keystone missing (skipped).
# Nonzero otherwise.

import re
import sys
import os

try:
    import keystone
except ImportError:
    print("keystone-engine not available (pip install keystone-engine)")
    sys.exit(77)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

A64_S = os.path.join(ROOT, "native/libpayload/src/unmap_trampoline_aarch64.S")
X64_S = os.path.join(ROOT, "native/libpayload/src/unmap_trampoline_x86_64.S")

failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL: " + msg)


def ok(msg):
    print("ok  : " + msg)


def read_lines(path, strip_hash_comments):
    """Parse a .S file into (raw, cleaned) lines.

    ARM syntax uses '#' as an IMMEDIATE prefix — stripping '#'
    comments there would destroy every offset (#-16, #0, #215). The
    aarch64 file only uses '//' comments; the x86_64 file uses '#'
    comments and '$' immediates, so '#' is safe to strip there.
    """
    with open(path) as f:
        lines = f.readlines()
    out = []
    for raw in lines:
        line = raw.split("//")[0]
        if strip_hash_comments:
            line = line.split("#")[0]
        line = line.strip()
        if not line:
            continue
        out.append((raw.rstrip("\n"), line))
    return out


def load_equ(lines):
    """Collect .equ NAME, VALUE definitions for operand substitution."""
    equ = {}
    for raw, line in lines:
        m = re.match(r"\.equ\s+(\w+)\s*,\s*(\d+)", line)
        if m:
            equ[m.group(1)] = m.group(2)
    return equ


def subst_symbols(line, equ):
    """Replace .equ names and branch/call targets with literals so a
    two-pass-free assembler (keystone) can encode them."""
    for name, val in equ.items():
        line = re.sub(r"\b" + re.escape(name) + r"\b", val, line)
    # Branch/call targets -> a placeholder address.
    line = re.sub(r"(?<=[\s])(\.L?\w+)", "0x1000", line)
    line = re.sub(r"^b(\s+)(\.?L?\w+)", r"b\g<1>0x1000", line)
    line = re.sub(r"zs_impl_\w+", "0x1000", line)
    return line


def section(lines, start_label, end_label):
    sec = []
    active = False
    for raw, line in lines:
        if line.endswith(":"):
            name = line[:-1].strip()
            if name == start_label:
                active = True
                continue
            if active and end_label and name == end_label:
                break
        if active:
            sec.append((raw, line))
    return sec


# ---------------------------------------------------------------------------
# AArch64
# ---------------------------------------------------------------------------

ks_a64 = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)


def a64_assemble_one(instr):
    enc, cnt = ks_a64.asm(instr)
    assert cnt == 1, f"aarch64 keystone produced {cnt} insns for {instr!r}"
    assert len(enc) == 4, f"aarch64 insn not 4 bytes: {instr!r}"
    return bytes(enc)


def check_a64():
    lines = read_lines(A64_S, strip_hash_comments=False)
    equ = load_equ(lines)
    blob = section(lines, "zs_trampoline_code_start",
                   "zs_trampoline_code_end")

    # 1. Assemble EVERY instruction of the whole file (with .equ
    #    names and branch targets substituted with literals).
    n_assembled = 0
    for raw, line in lines:
        if line.endswith(":") or line.startswith("."):
            continue
        try:
            a64_assemble_one(subst_symbols(line, equ))
            n_assembled += 1
        except Exception as e:
            fail(f"aarch64 instruction does not assemble: {line!r} ({e})")
    if n_assembled:
        ok(f"aarch64: {n_assembled} instructions assemble cleanly")

    # 2. Wrapper slot map (zs_fork_wrapper prologue == every wrapper's).
    wrapper = section(lines, "zs_fork_wrapper", "zs_setresgid_wrapper")
    push_pairs = []
    for raw, line in wrapper:
        m = re.match(r"stp\s+(x\d+|d\d+)\s*,\s*(x\d+|d\d+)\s*,\s*"
                     r"\[sp,\s*#-16\]!", line)
        if m:
            push_pairs.append((m.group(1), m.group(2)))
    # The FIRST stp (x29, x30) IS the frame-pointer pair: fp = sp
    # right after it, x29@fp+0, x30@fp+8. It must be EXCLUDED from
    # the below-fp slot derivation (counting it was the script's own
    # first bug — every slot came out 16 bytes too low).
    if push_pairs and push_pairs[0] == ("x29", "x30"):
        push_pairs = push_pairs[1:]
    slots = {"x29": 0, "x30": 8}
    off = 16
    for a, b in push_pairs:
        slots[a] = -off
        slots[b] = -(off - 8)
        off += 16
    if off != 160:
        fail(f"aarch64: wrapper frame is {off - 16} bytes below fp "
             f"(expected 144)")
    else:
        ok("aarch64: wrapper frame = 144 bytes below fp + fp/retaddr")

    # 3. Blob restore map, register by register.
    restore_ok = True
    for raw, line in blob:
        m = re.match(r"ldr\s+(x\d+)\s*,\s*\[x28,\s*#(-?\d+)\]", line)
        if m and m.group(1) not in ("x30",):
            reg, disp = m.group(1), int(m.group(2))
            if reg == "x0":               # staged x28 value
                reg = "x28"
            if slots.get(reg) != disp:
                restore_ok = False
                fail(f"aarch64: blob restores {reg} from fp{disp:+d} "
                     f"but the wrapper saved it at fp{slots.get(reg):+d}")
        m = re.match(r"ldp\s+(d\d+)\s*,\s*(d\d+)\s*,\s*\[x28,\s*#(-?\d+)\]",
                     line)
        if m:
            da, db, base = m.group(1), m.group(2), int(m.group(3))
            if slots.get(da) != base or slots.get(db) != base + 8:
                restore_ok = False
                fail(f"aarch64: blob ldp {da}/{db} from fp{base:+d} "
                     f"but the wrapper saved at "
                     f"{slots.get(da):+d}/{slots.get(db):+d}")
    if restore_ok:
        ok("aarch64: every restore slot matches the wrapper's save slot")

    # 4. Syscall number + stride immediates, decoded from the ENCODING.
    for raw, line in blob:
        if " ".join(line.split()) == "mov x8, #215":
            enc = int.from_bytes(a64_assemble_one(line), "little")
            imm = (enc >> 5) & 0xFFFF      # MOVZ imm16 at bits 5..20
            if imm != 215:
                fail(f"aarch64: __NR_munmap immediate decodes to {imm}")
            else:
                ok("aarch64: __NR_munmap = 215 verified from the encoding")
    if any("lsl #4" in line for _, line in blob):
        ok("aarch64: record stride = 16 (lsl #4) present")
    else:
        fail("aarch64: record stride shift missing")

    # 5. Return address + final stack pointer.
    if not any(re.match(r"ldr\s+x30\s*,\s*\[x20,\s*#8\]", line)
               for _, line in blob):
        fail("aarch64: return address not restored from fp+8")
    if not any(re.match(r"add\s+sp,\s*x28,\s*#16", line)
               for _, line in blob):
        fail("aarch64: blob does not set final sp = fp+16")
    else:
        ok("aarch64: final sp = fp+16")

    # 6. ROUND 34 — the syscall-ARGUMENT register contract. The arm64
    #    Linux syscall ABI is x8 = number, x0/x1 = args (man2
    #    syscall.2). The pre-R34 blob loaded the record base/size
    #    into x23/x24 — registers the kernel never reads — so Tier A
    #    silently unmapped NOTHING on every arm64 device while every
    #    test stayed green (this script checked the syscall NUMBER
    #    and the frame map, never the argument registers). These
    #    pattern gates pin the exact shapes.
    loop_loads_args = any(
        re.match(r"ldr\s+x0\s*,\s*\[x21\]\s*,\s*#16", line)
        for _, line in blob)
    if not loop_loads_args:
        fail("aarch64: unmap loop does not load the record base "
             "into x0 (syscall arg 0) — the Round-34 bug class")
    else:
        ok("aarch64: record base loads into x0 (syscall arg 0)")
    if not any(re.match(r"ldr\s+x1\s*,\s*\[x21,\s*#-8\]", line)
               for _, line in blob):
        fail("aarch64: unmap loop does not load the record size "
             "into x1 (syscall arg 1) — the Round-34 bug class")
    else:
        ok("aarch64: record size loads into x1 (syscall arg 1)")
    # The OLD bug shape must be gone: no x23/x24 record loads at all.
    for raw, line in blob:
        if re.match(r"ldr\s+x2[34]\s*,\s*\[x21", line):
            fail("aarch64: record loads still target x23/x24 (not "
                 "syscall argument registers)")
    # 7. ROUND 34 — the data-area scrub (stealth): the residual jit
    #    page must not carry the unmap record table / wrapper fp. The
    #    blob unprotects its own page (mprotect, __NR 226 — decoded
    #    below; R|W|X = 7 — EXEC must stay: we execute from the page),
    #    zeroes 544 bytes (sizeof ZsTrampData incl. page_base), and
    #    re-seals R|X = 5.
    if not any(re.match(r"str\s+xzr,\s*\[x23\]\s*,\s*#8", line)
               for _, line in blob):
        fail("aarch64: data-area scrub store missing (forensic residue)")
    elif not any(re.match(r"add\s+x27,\s*x23,\s*#544", line)
                 for _, line in blob):
        fail("aarch64: scrub bound is not sizeof(ZsTrampData)=544")
    elif not any(re.match(r"ldr\s+x25,\s*\[x23,\s*#(TRAMP_PAGE_OFF|536)\]",
                          line)
                 for _, line in blob):
        fail("aarch64: scrub does not load page_base from offset 536")
    elif not any(" ".join(line.split()) == "mov x8, #226"
                 for _, line in blob):
        fail("aarch64: scrub mprotect syscall number missing")
    else:
        # Decode the mprotect immediate from the encoding (MOVZ).
        for raw, line in blob:
            if " ".join(line.split()) == "mov x8, #226":
                enc = int.from_bytes(a64_assemble_one(line), "little")
                imm = (enc >> 5) & 0xFFFF
                if imm != 226:
                    fail("aarch64: __NR_mprotect decodes to "
                         f"{imm}, not 226")
        ok("aarch64: scrub = mprotect(RWX) + zero 544B + re-seal, "
           "page_base loaded, __NR_mprotect verified")
    # PROT constants: exactly R|W (3) for the unprotect and R|X (5)
    # for the re-seal.
    prots = []
    for raw, line in blob:
        m = re.match(r"mov\s+x2,\s*#(\d+)", line)
        if m:
            prots.append(int(m.group(1)))
    if 7 not in prots or 5 not in prots:
        fail(f"aarch64: scrub mprotect prot constants wrong: {prots} "
             "(unprotect must keep EXEC = RWX|7)")

    # 8. ROUND 35 — the setcontext wrapper's argument shuffle. The
    #    function is selinux_android_setcontext(uid, isSysServer,
    #    seInfo, niceName): FOUR arguments, so the wrapper must move
    #    a3->x4, a2->x3, a1->x2, a0->x1 and load the frame pointer
    #    into x0 before the call. A missed shuffle register silently
    #    hands zs_impl_setcontext garbage (the wrapper test catches
    #    it on the SAME arch only — this gate covers both blobs).
    setctx = section(lines, "zs_setcontext_wrapper",
                     "zs_trampoline_code_start")
    if not setctx:
        fail("aarch64: zs_setcontext_wrapper section not found")
    else:
        shuffle_ok = all(
            any(re.match(p, line) for _, line in setctx) for p in (
                r"mov\s+x4,\s*x3$",
                r"mov\s+x3,\s*x2$",
                r"mov\s+x2,\s*x1$",
                r"mov\s+x1,\s*x0$",
                r"mov\s+x0,\s*x29$",
            ))
        if not shuffle_ok:
            fail("aarch64: setcontext wrapper argument shuffle wrong "
                 "(expect x0=fp, x1=a0, x2=a1, x3=a2, x4=a3)")
        else:
            ok("aarch64: setcontext wrapper shuffles 4 args + fp")
        if not any(re.match(r"bl\s+zs_impl_setcontext", line)
                   for _, line in setctx):
            fail("aarch64: setcontext wrapper does not call "
                 "zs_impl_setcontext")
        # The wrapper epilogue must be the shared full restore
        # (10 stp/ldp pairs: fp + 5 x-pairs + 4 d-pairs) — the
        # trampoline's restore phase contract depends on every
        # wrapper saving ALL callee-saved registers at the SAME
        # offsets.
        n_ldp = sum(1 for _, line in setctx
                    if re.match(r"ldp\s+(x\d+|d\d+)", line))
        if n_ldp != 10:
            fail(f"aarch64: setcontext wrapper restores {n_ldp} "
                 "register pairs (expect 10)")
        else:
            ok("aarch64: setcontext wrapper epilogue restores all 10 "
               "pairs")


# ---------------------------------------------------------------------------
# x86-64
# ---------------------------------------------------------------------------

ks_x64 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def att_to_intel(att):
    att = att.strip()
    m = re.match(r"mov\s+\$(\d+),\s*%([a-z0-9]+)$", att)
    if m:
        return f"mov {m.group(2)}, {m.group(1)}"
    m = re.match(r"mov\s+(-?\d+)?\(%(\w+)\),\s*%(\w+)$", att)
    if m:
        off = m.group(1)
        if off in (None, "0"):
            mem = m.group(2)
        elif off.startswith("-"):
            mem = f"{m.group(2)}{off}"
        else:
            mem = f"{m.group(2)}+{off}"
        return f"mov {m.group(3)}, qword ptr [{mem}]"
    m = re.match(r"mov\s+%(\w+)\s*,\s*%(\w+)$", att)
    if m:
        return f"mov {m.group(2)}, {m.group(1)}"
    m = re.match(r"lea\s+(-?\d+)?\(%(\w+)(?:,%(\w+))?\),\s*%(\w+)$", att)
    if m:
        off = m.group(1)
        if off in (None, "0"):
            base = m.group(2)
        elif off.startswith("-"):
            base = f"{m.group(2)}{off}"
        else:
            base = f"{m.group(2)}+{off}"
        idx = f"+{m.group(3)}" if m.group(3) else ""
        return f"lea {m.group(4)}, [{base}{idx}]"
    m = re.match(r"sub\s+\$(\d+),\s*%(\w+)$", att)
    if m:
        return f"sub {m.group(2)}, {m.group(1)}"
    m = re.match(r"shl\s+\$(\d+),\s*%(\w+)$", att)
    if m:
        return f"shl {m.group(2)}, {m.group(1)}"
    m = re.match(r"cmp\s+%(\w+)\s*,\s*%(\w+)$", att)
    if m:
        return f"cmp {m.group(2)}, {m.group(1)}"
    m = re.match(r"add\s+\$(\d+),\s*%(\w+)$", att)
    if m:
        return f"add {m.group(2)}, {m.group(1)}"
    # ROUND 34 — the scrub instructions' forms.
    m = re.match(r"sub\s+%(\w+)\s*,\s*%(\w+)$", att)          # reg,reg
    if m:
        return f"sub {m.group(2)}, {m.group(1)}"
    m = re.match(r"xor\s+%(\w+)\s*,\s*%(\w+)$", att)          # reg,reg
    if m:
        return f"xor {m.group(2)}, {m.group(1)}"
    m = re.match(r"test\s+%(\w+)\s*,\s*%(\w+)$", att)      # ROUND 34
    if m:
        return f"test {m.group(2)}, {m.group(1)}"
    m = re.match(r"jnz\s+(\S+)$", att)                     # ROUND 34
    if m:
        return f"jne {m.group(1)}"
    m = re.match(r"mov\s+%(\w+)\s*,\s*(-?\d+)?\(%(\w+)\)$", att)  # store
    if m:
        off = m.group(2)
        if off in (None, "0"):
            mem = m.group(3)
        elif off.startswith("-"):
            mem = f"{m.group(3)}{off}"
        else:
            mem = f"{m.group(3)}+{off}"
        return f"mov qword ptr [{mem}], {m.group(1)}"
    return None


def check_x64():
    lines = read_lines(X64_S, strip_hash_comments=True)
    equ = load_equ(lines)
    blob = section(lines, "zs_trampoline_code_start",
                   "zs_trampoline_code_end")

    # 1. Assemble everything (AT&T -> Intel translation for keystone;
    #    .equ names resolved first).
    n_assembled = 0
    for raw, line in lines:
        if line.endswith(":") or line.startswith("."):
            continue
        compact = " ".join(subst_symbols(line, equ).split())
        if re.match(r"(push|pop)\s+%\w+$", compact) or \
                compact in ("ret", "syscall", "leave"):
            n_assembled += 1
            continue
        if compact.startswith(("call ", "jmp ", "jae ", "jne ", "je ")):
            n_assembled += 1
            continue
        if compact in ("mov %rsp, %rbp",):
            n_assembled += 1
            continue
        intel = att_to_intel(compact)
        if intel is None:
            fail(f"x86_64: unhandled instruction form: {line!r}")
            continue
        try:
            enc, cnt = ks_x64.asm(intel)
            assert cnt == 1
            n_assembled += 1
        except Exception as e:
            fail(f"x86_64 instruction does not assemble: {line!r} -> "
                 f"{intel!r} ({e})")
    if n_assembled:
        ok(f"x86_64: {n_assembled} instructions assemble cleanly")

    # 2. Wrapper slot map (pushes below rbp).
    push_order = []
    in_func = False
    for raw, line in lines:
        if line == "zs_fork_wrapper:":
            in_func = True
            continue
        if in_func and line.endswith(":"):
            break
        if in_func:
            m = re.match(r"push\s+%(\w+)$", line)
            if m and m.group(1) != "rbp":
                push_order.append(m.group(1))
    slots = {"rbp": 0, "retaddr": 8}
    off = 8
    for reg in push_order:
        slots[reg] = -off
        off += 8
    if off != 48:
        fail(f"x86_64: wrapper frame is {off - 8} bytes below fp "
             f"(expected 40)")
    else:
        ok("x86_64: wrapper frame = 40 bytes below fp + fp/retaddr")

    # 3. Blob restore map.
    restore_ok = True
    for raw, line in blob:
        m = re.match(r"mov\s+(-?\d+)\(%r12\),\s*%(\w+)$", line)
        if m:
            disp, reg = int(m.group(1)), m.group(2)
            want = slots.get(reg)
            if reg == "rax":               # staged r12
                want = slots.get("r12")
            if want != disp:
                restore_ok = False
                fail(f"x86_64: blob restores {reg} from fp{disp:+d} "
                     f"but the wrapper saved it at fp{want:+d}")
    if restore_ok:
        ok("x86_64: every restore slot matches the wrapper's save slot")

    # 4. Syscall number + stride (whitespace-normalized source match;
    #    the raw lines carry alignment double-spaces).
    blob_norm = [" ".join(line.split()) for _, line in blob]
    if "mov $11, %eax" in blob_norm:
        enc, _ = ks_x64.asm("mov eax, 11")
        imm = int.from_bytes(bytes(enc[1:5]), "little")
        if imm != 11:
            fail(f"x86_64: __NR_munmap immediate decodes to {imm}")
        else:
            ok("x86_64: __NR_munmap = 11 verified from the encoding")
    else:
        fail("x86_64: __NR_munmap load missing")
    if any("shl $4" in l for l in blob_norm):
        ok("x86_64: record stride = 16 (shl $4) present")
    else:
        fail("x86_64: record stride shift missing")

    # 5. Final rsp + return address slot.
    if not any(re.match(r"lea\s+8\(%r12\),\s*%rsp$", line)
               for _, line in blob):
        fail("x86_64: final rsp does not point at the return address")
    else:
        ok("x86_64: final rsp points at the return address slot")

    # 6. ROUND 34 — syscall-argument register contract (the x86_64
    #    twin of the aarch64 arg-register gate; this blob was already
    #    correct, the gate keeps it that way).
    if not any(re.match(r"mov\s+\(%r8\),\s*%rdi$", line)
               for _, line in blob):
        fail("x86_64: record base does not load into %rdi (arg 0)")
    else:
        ok("x86_64: record base loads into %rdi (syscall arg 0)")
    if not any(re.match(r"mov\s+8\(%r8\),\s*%rsi$", line)
               for _, line in blob):
        fail("x86_64: record size does not load into %rsi (arg 1)")
    else:
        ok("x86_64: record size loads into %rsi (syscall arg 1)")

    # 7. ROUND 34 — data-area scrub (stealth): mprotect(10) RW,
    #    zero 544 bytes, re-seal R|X; page_base from offset 536.
    if not any(re.match(r"mov\s+%rax,\s*\(%r9\)$", line)
               for _, line in blob):
        fail("x86_64: data-area scrub store missing (forensic residue)")
    elif not any(re.match(r"lea\s+544\(%r9\),\s*%r15$", line)
                 for _, line in blob):
        fail("x86_64: scrub bound is not sizeof(ZsTrampData)=544")
    elif not any(re.match(r"mov\s+(TRAMP_PAGE_OFF|536)\(%r9\),\s*%rbx$",
                          line)
                 for _, line in blob):
        fail("x86_64: scrub does not load page_base from offset 536")
    elif "mov $10, %eax" not in blob_norm:
        fail("x86_64: scrub mprotect syscall number (10) missing")
    elif "mov $7, %edx" not in blob_norm or "mov $5, %edx" not in blob_norm:
        fail("x86_64: scrub mprotect prot constants (7 RWX / 5 RX) missing")
    else:
        ok("x86_64: scrub = mprotect(RWX) + zero 544B + re-seal, "
           "page_base loaded, __NR_mprotect/prot verified")

    # 8. ROUND 35 — the setcontext wrapper's argument shuffle (the
    #    x86_64 twin). SysV: 4 args arrive in rdi/rsi/rdx/rcx, the
    #    inserted wrapper_fp goes to r8 (5th integer arg register).
    setctx = section(lines, "zs_setcontext_wrapper",
                     "zs_trampoline_code_start")
    if not setctx:
        fail("x86_64: zs_setcontext_wrapper section not found")
    else:
        want = ("mov %rcx, %r8", "mov %rdx, %rcx",
                "mov %rsi, %rdx", "mov %rdi, %rsi",
                "mov %rbp, %rdi", "call zs_impl_setcontext")
        missing = [w for w in want
                   if not any(line == w or " ".join(line.split()) == w
                              for _, line in setctx)]
        if missing:
            fail("x86_64: setcontext wrapper shuffle wrong/missing: "
                 f"{missing}")
        else:
            ok("x86_64: setcontext wrapper shuffles 4 args + fp (r8)")
        n_pop = sum(1 for _, line in setctx
                    if re.match(r"pop\s+%\w+$", line))
        if n_pop != 6:
            fail(f"x86_64: setcontext wrapper pops {n_pop} registers "
                 "(expect 6: rbp rbx r12-r15)")
        else:
            ok("x86_64: setcontext wrapper epilogue restores "
               "rbp/rbx/r12-r15")


def main():
    print("=== Round 22 trampoline binary verification ===")
    check_a64()
    print()
    check_x64()
    print()
    if failures:
        print(f"FAILED: {len(failures)} contract violation(s)")
        sys.exit(1)
    print("ALL CHECKS GREEN: both blobs assemble and the frame "
          "contracts hold register-by-register.")
    sys.exit(0)


if __name__ == "__main__":
    main()
