// ptrace-based zygote injection — real implementation.
//
// Algorithm:
//   1. Find the zygote PID by scanning /proc/*/cmdline.
//   2. PTRACE_SEIZE the zygote (interrupt-driven, no SIGSTOP).
//   3. Save regs (PTRACE_GETREGSET / PTRACE_GETREGS).
//   4. Read /proc/<pid>/maps to find libc.so base.
//   5. Open /proc/<pid>/root/<libc_path> as a regular file and parse
//      its ELF dynamic symbol table to find the offset of dlopen and
//      dlsym.
//   6. Compute the in-process addresses: libc_base + offset.
//   7. Pick a scratch stack area (sp - 256) and write the libzygisk
//      path string there.
//   8. Remote-call dlopen(path, RTLD_NOW | RTLD_LOCAL). Wait for the
//      trap (the call's `ret` jumps to address 0 → SIGSEGV).
//   9. Read x0/rax — that's the dlopen handle.
//  10. Write "zygisk_entry" string into scratch.
//  11. Remote-call dlsym(handle, "zygisk_entry"). Wait for trap.
//  12. Read return value — that's zygisk_entry's address.
//  13. Make a socketpair. Send one end to zygote via SCM_RIGHTS.
//  14. Remote-call zygisk_entry(fd). Wait for trap.
//      (zygisk_entry never returns in normal operation, so the trap
//       here means either success-with-block or failure; either way
//       we detach.)
//  15. Restore original regs and PTRACE_DETACH.
//
// All four Android ABIs (arm64, arm, x86_64, x86) are supported.

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"
#include "ptrace_inject.h"

// ==================================================================
//  Find the zygote PID
// ==================================================================
pid_t find_zygote(bool want_64bit) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    pid_t result = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t pid = atoi(e->d_name);
        if (pid <= 1) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';

        const char *want = want_64bit ? "zygote64" : "zygote";
        if (strcmp(buf, want) == 0) {
            result = pid;
            break;
        }
    }
    closedir(d);
    return result;
}

// ==================================================================
//  Architecture-specific remote-call helpers.
//
//  Convention: we set LR/return-address to 0. The remote function's
//  `ret` instruction then jumps to 0 → SIGSEGV. We catch the SIGSEGV
//  via waitpid() after PTRACE_CONT, and that's how we know the call
//  has returned.
// ==================================================================

#if defined(__aarch64__)

#include <asm/ptrace.h>

typedef struct user_pt_regs arch_regs_t;

static int get_regs(pid_t pid, arch_regs_t *r) {
    struct iovec iov = { .iov_base = r, .iov_len = sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}
static int set_regs(pid_t pid, const arch_regs_t *r) {
    struct iovec iov = { .iov_base = (void*)r, .iov_len = sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

// aarch64: x0..x7 = args, x30 = LR, pc = entry
static void setup_call(arch_regs_t *r, uint64_t func,
                       uint64_t args[], int n_args) {
    memset(r, 0, sizeof(*r));
    r->pc = func;
    r->regs[30] = 0;  // LR = 0 → SIGSEGV on return
    for (int i = 0; i < n_args && i < 8; i++) {
        r->regs[i] = args[i];
    }
}
static uint64_t retval(const arch_regs_t *r) {
    return r->regs[0];
}
static uint64_t stack_ptr(const arch_regs_t *r) {
    return r->sp;
}
static void set_sp(arch_regs_t *r, uint64_t v) {
    r->sp = v;
}

#elif defined(__x86_64__)

typedef struct user_regs_struct arch_regs_t;

static int get_regs(pid_t pid, arch_regs_t *r) {
    return ptrace(PTRACE_GETREGS, pid, NULL, r);
}
static int set_regs(pid_t pid, const arch_regs_t *r) {
    return ptrace(PTRACE_SETREGS, pid, NULL, (void*)r);
}

// x86_64 SysV: rdi, rsi, rdx, rcx, r8, r9 = first 6 args, rax = ret.
// We push 0 as the return address by setting rsp to a scratch area
// where we've written a 0 qword. setup_call here only sets the
// register state; the caller is responsible for writing the 0 qword
// at the chosen rsp before invoking.
static void setup_call(arch_regs_t *r, uint64_t func,
                       uint64_t args[], int n_args) {
    memset(r, 0, sizeof(*r));
    r->rip = func;
    if (n_args > 0) r->rdi = args[0];
    if (n_args > 1) r->rsi = args[1];
    if (n_args > 2) r->rdx = args[2];
    if (n_args > 3) r->rcx = args[3];
    if (n_args > 4) r->r8  = args[4];
    if (n_args > 5) r->r9  = args[5];
}
static uint64_t retval(const arch_regs_t *r) {
    return r->rax;
}
static uint64_t stack_ptr(const arch_regs_t *r) {
    return r->rsp;
}
static void set_sp(arch_regs_t *r, uint64_t v) {
    r->rsp = v;
}

#elif defined(__arm__)

typedef struct user_regs arch_regs_t;

static int get_regs(pid_t pid, arch_regs_t *r) {
    return ptrace(PTRACE_GETREGS, pid, NULL, r);
}
static int set_regs(pid_t pid, const arch_regs_t *r) {
    return ptrace(PTRACE_SETREGS, pid, NULL, (void*)r);
}

// ARM EABI: r0..r3 = first 4 args, lr = return, pc = entry
static void setup_call(arch_regs_t *r, uint32_t func,
                       uint32_t args[], int n_args) {
    memset(r, 0, sizeof(*r));
    r->ARM_pc = func;
    r->ARM_lr = 0;
    r->ARM_cpsr = 0x10; // User mode, IRQs enabled
    for (int i = 0; i < n_args && i < 4; i++) {
        (&r->ARM_r0)[i] = args[i];
    }
}
static uint32_t retval(const arch_regs_t *r) {
    return r->ARM_r0;
}
static uint32_t stack_ptr(const arch_regs_t *r) {
    return r->ARM_sp;
}
static void set_sp(arch_regs_t *r, uint32_t v) {
    r->ARM_sp = v;
}

#elif defined(__i386__)

typedef struct user_regs_struct arch_regs_t;

static int get_regs(pid_t pid, arch_regs_t *r) {
    return ptrace(PTRACE_GETREGS, pid, NULL, r);
}
static int set_regs(pid_t pid, const arch_regs_t *r) {
    return ptrace(PTRACE_SETREGS, pid, NULL, (void*)r);
}

// i386 cdecl: args on stack (right-to-left), eax = ret. The caller
// must write the args + a 0 return address to the scratch stack and
// set esp to point at the return address.
static void setup_call(arch_regs_t *r, uint32_t func,
                       uint32_t args[], int n_args) {
    memset(r, 0, sizeof(*r));
    r->eip = func;
    (void)args; (void)n_args;
}
static uint32_t retval(const arch_regs_t *r) {
    return r->eax;
}
static uint32_t stack_ptr(const arch_regs_t *r) {
    return r->esp;
}
static void set_sp(arch_regs_t *r, uint32_t v) {
    r->esp = v;
}

#else
#  error "Unsupported architecture for ptrace injection"
#endif

// ==================================================================
//  Read/write memory in the remote process via process_vm_readv/writev.
//  These DO take the remote address — process_vm_readv(pid, liov, 1,
//  riov, 1, 0) copies FROM riov (remote) TO liov (local).
// ==================================================================
static int read_mem(pid_t pid, uint64_t addr, void *out, size_t len) {
    struct iovec liov = { .iov_base = out,       .iov_len  = len };
    struct iovec riov = { .iov_base = (void*)addr, .iov_len = len };
    ssize_t n = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
    return n == (ssize_t)len ? 0 : -1;
}
static int write_mem(pid_t pid, uint64_t addr,
                     const void *data, size_t len) {
    struct iovec liov = { .iov_base = (void*)data, .iov_len = len };
    struct iovec riov = { .iov_base = (void*)addr,  .iov_len = len };
    ssize_t n = process_vm_writev(pid, &liov, 1, &riov, 1, 0);
    return n == (ssize_t)len ? 0 : -1;
}

// ==================================================================
//  Find libc.so inside /proc/<pid>/maps; return its base address and
//  filesystem path (so we can open the file and parse its ELF).
// ==================================================================
static int find_libc(pid_t pid, uint64_t *base_out,
                     char *path_out, size_t path_sz) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "re");
    if (!f) return -1;

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        // Lines look like:
        //   7e12345000-7e12456000 r-xp 00000000 fe:00 1234 /system/lib64/libc.so
        if (!strstr(line, "/libc.so") && !strstr(line, "/libc.so")) {
            // also handle "/apex/.../libc.so" path
            if (!strstr(line, "libc.so")) continue;
        }
        // Only consider the first executable mapping (r-xp).
        if (!strstr(line, " r-xp ")) continue;

        uint64_t start, end;
        if (sscanf(line, "%" SCNx64 "-%" SCNx64, &start, &end) != 2) continue;

        // Extract the path: everything after the third space.
        char *p = line;
        int sp = 0;
        while (*p && sp < 5) {
            if (*p == ' ') sp++;
            p++;
        }
        if (sp < 5) continue;
        // Trim newline
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (strlen(p) == 0) continue;

        *base_out = start;
        strncpy(path_out, p, path_sz - 1);
        path_out[path_sz - 1] = '\0';
        found = 1;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

// ==================================================================
//  Parse an ELF file to find a symbol's offset (st_value) by name.
//  We support both ELF32 and ELF64, and both .dynsym and .symtab.
//
//  For a PIE .so, st_value is already the offset from the module
//  base. So in_process_addr = module_base + st_value.
// ==================================================================
static int elf_find_symbol_offset(const char *path, const char *name,
                                  uint64_t *offset_out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    // Read ELF header (e_ident is enough to determine 32 vs 64).
    unsigned char eident[16];
    if (read(fd, eident, sizeof(eident)) != (ssize_t)sizeof(eident)) {
        close(fd);
        return -1;
    }
    if (eident[0] != 0x7f || eident[1] != 'E'
     || eident[2] != 'L'  || eident[3] != 'F') {
        close(fd);
        return -1;
    }
    int is_64 = (eident[4] == ELFCLASS64);

    // Re-read full header
    if (lseek(fd, 0, SEEK_SET) != 0) { close(fd); return -1; }

    int found = 0;
    uint64_t result = 0;

    if (is_64) {
        Elf64_Ehdr eh;
        if (read(fd, &eh, sizeof(eh)) != (ssize_t)sizeof(eh)) {
            close(fd); return -1;
        }
        // Section headers
        Elf64_Shdr *shs = (Elf64_Shdr *)malloc(eh.e_shnum * sizeof(Elf64_Shdr));
        if (!shs) { close(fd); return -1; }
        if (lseek(fd, eh.e_shoff, SEEK_SET) != (off_t)eh.e_shoff
            || read(fd, shs, eh.e_shnum * sizeof(Elf64_Shdr))
               != (ssize_t)(eh.e_shnum * sizeof(Elf64_Shdr))) {
            free(shs); close(fd); return -1;
        }
        // Section header string table
        char *shstr = NULL;
        if (shs[eh.e_shstrndx].sh_size > 0) {
            shstr = (char *)malloc(shs[eh.e_shstrndx].sh_size);
            if (shstr) {
                if (lseek(fd, shs[eh.e_shstrndx].sh_offset, SEEK_SET)
                       != (off_t)shs[eh.e_shstrndx].sh_offset
                    || read(fd, shstr, shs[eh.e_shstrndx].sh_size)
                       != (ssize_t)shs[eh.e_shstrndx].sh_size) {
                    free(shstr); shstr = NULL;
                }
            }
        }
        // Walk sections, find SHT_DYNSYM and (optionally) SHT_SYMTAB
        for (int i = 0; i < eh.e_shnum && !found; i++) {
            if (shs[i].sh_type != SHT_DYNSYM
             && shs[i].sh_type != SHT_SYMTAB) continue;
            Elf64_Shdr *sym_sh = &shs[i];
            Elf64_Shdr *str_sh = &shs[sym_sh->sh_link];
            char *strtab = (char *)malloc(str_sh->sh_size);
            Elf64_Sym *symtab = (Elf64_Sym *)malloc(sym_sh->sh_size);
            if (!strtab || !symtab) { free(strtab); free(symtab); continue; }
            if (lseek(fd, str_sh->sh_offset, SEEK_SET) != (off_t)str_sh->sh_offset
                || read(fd, strtab, str_sh->sh_size) != (ssize_t)str_sh->sh_size) {
                free(strtab); free(symtab); continue;
            }
            if (lseek(fd, sym_sh->sh_offset, SEEK_SET) != (off_t)sym_sh->sh_offset
                || read(fd, symtab, sym_sh->sh_size) != (ssize_t)sym_sh->sh_size) {
                free(strtab); free(symtab); continue;
            }
            size_t n = sym_sh->sh_size / sizeof(Elf64_Sym);
            for (size_t j = 0; j < n; j++) {
                if (ELF64_ST_TYPE(symtab[j].st_info) != STT_FUNC) continue;
                if (!symtab[j].st_value) continue;
                const char *sname = strtab + symtab[j].st_name;
                // Match "dlopen" or "__dl_dlopen" — Android's libc
                // exports dlopen directly since API 21.
                if (strcmp(sname, name) == 0) {
                    result = symtab[j].st_value;
                    found = 1;
                    break;
                }
            }
            free(strtab);
            free(symtab);
        }
        free(shstr);
        free(shs);
    } else {
        Elf32_Ehdr eh;
        if (read(fd, &eh, sizeof(eh)) != (ssize_t)sizeof(eh)) {
            close(fd); return -1;
        }
        Elf32_Shdr *shs = (Elf32_Shdr *)malloc(eh.e_shnum * sizeof(Elf32_Shdr));
        if (!shs) { close(fd); return -1; }
        if (lseek(fd, eh.e_shoff, SEEK_SET) != (off_t)eh.e_shoff
            || read(fd, shs, eh.e_shnum * sizeof(Elf32_Shdr))
               != (ssize_t)(eh.e_shnum * sizeof(Elf32_Shdr))) {
            free(shs); close(fd); return -1;
        }
        char *shstr = NULL;
        if (shs[eh.e_shstrndx].sh_size > 0) {
            shstr = (char *)malloc(shs[eh.e_shstrndx].sh_size);
            if (shstr) {
                if (lseek(fd, shs[eh.e_shstrndx].sh_offset, SEEK_SET)
                       != (off_t)shs[eh.e_shstrndx].sh_offset
                    || read(fd, shstr, shs[eh.e_shstrndx].sh_size)
                       != (ssize_t)shs[eh.e_shstrndx].sh_size) {
                    free(shstr); shstr = NULL;
                }
            }
        }
        for (int i = 0; i < eh.e_shnum && !found; i++) {
            if (shs[i].sh_type != SHT_DYNSYM
             && shs[i].sh_type != SHT_SYMTAB) continue;
            Elf32_Shdr *sym_sh = &shs[i];
            Elf32_Shdr *str_sh = &shs[sym_sh->sh_link];
            char *strtab = (char *)malloc(str_sh->sh_size);
            Elf32_Sym *symtab = (Elf32_Sym *)malloc(sym_sh->sh_size);
            if (!strtab || !symtab) { free(strtab); free(symtab); continue; }
            if (lseek(fd, str_sh->sh_offset, SEEK_SET) != (off_t)str_sh->sh_offset
                || read(fd, strtab, str_sh->sh_size) != (ssize_t)str_sh->sh_size) {
                free(strtab); free(symtab); continue;
            }
            if (lseek(fd, sym_sh->sh_offset, SEEK_SET) != (off_t)sym_sh->sh_offset
                || read(fd, symtab, sym_sh->sh_size) != (ssize_t)sym_sh->sh_size) {
                free(strtab); free(symtab); continue;
            }
            size_t n = sym_sh->sh_size / sizeof(Elf32_Sym);
            for (size_t j = 0; j < n; j++) {
                if (ELF32_ST_TYPE(symtab[j].st_info) != STT_FUNC) continue;
                if (!symtab[j].st_value) continue;
                const char *sname = strtab + symtab[j].st_name;
                if (strcmp(sname, name) == 0) {
                    result = symtab[j].st_value;
                    found = 1;
                    break;
                }
            }
            free(strtab);
            free(symtab);
        }
        free(shstr);
        free(shs);
    }
    close(fd);
    if (!found) return -1;
    *offset_out = result;
    return 0;
}

// Find the in-process address of `symbol` inside the zygote's libc.
static int find_symbol_addr(pid_t pid, const char *symbol,
                            uint64_t *addr_out) {
    uint64_t libc_base = 0;
    char libc_path[PATH_MAX] = {0};
    if (find_libc(pid, &libc_base, libc_path, sizeof(libc_path)) < 0) {
        LOGE("could not find libc.so in /proc/%d/maps", pid);
        return -1;
    }
    LOGI("libc at 0x%" PRIx64 " (%s) in pid %d",
         libc_base, libc_path, pid);

    // Open the libc file from the zygote's mount namespace so the
    // ELF we parse matches the one actually mapped.
    char pidroot_path[PATH_MAX * 2];
    snprintf(pidroot_path, sizeof(pidroot_path),
             "/proc/%d/root%s", pid, libc_path);

    uint64_t offset = 0;
    if (elf_find_symbol_offset(pidroot_path, symbol, &offset) < 0) {
        // Try the host path as a fallback (works if the device's
        // libc.so is also readable from here).
        if (elf_find_symbol_offset(libc_path, symbol, &offset) < 0) {
            LOGE("could not find symbol %s in %s", symbol, libc_path);
            return -1;
        }
    }
    *addr_out = libc_base + offset;
    return 0;
}

// ==================================================================
//  Wait for the next ptrace event after PTRACE_CONT. The remote
//  call will trap (SIGSEGV) when it tries to return to address 0.
//  Returns 0 on a clean trap, -1 on unexpected exit.
// ==================================================================
static int wait_for_trap(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status) || WIFSIGNALED(status)) return -1;
    if (!WIFSTOPPED(status)) return -1;
    int sig = WSTOPSIG(status);
    // The trap should be SIGSEGV (jump to 0) or SIGTRAP (breakpoint).
    // For SIGSEGV, the si_addr will be 0; we just continue past.
    if (sig == SIGSEGV || sig == SIGTRAP) return 0;
    // Any other signal — let it be delivered on next continue.
    return 0;
}

// ==================================================================
//  Inject libzygisk.so into the zygote and call zygisk_entry(fd).
//
//  Steps:
//   1. PTRACE_SEIZE the zygote.
//   2. PTRACE_INTERRUPT to bring it to a clean stop.
//   3. Save regs.
//   4. find_symbol_addr("dlopen") and find_symbol_addr("dlsym").
//   5. Write libzygisk path + "zygisk_entry" string to scratch stack.
//   6. Call dlopen(path, RTLD_NOW | RTLD_LOCAL).
//   7. Read return — the handle.
//   8. Call dlsym(handle, "zygisk_entry").
//   9. Read return — zygisk_entry's address.
//  10. socketpair(). Send one end to zygote via SCM_RIGHTS on the
//      bridge_fd.
//  11. Call zygisk_entry(remote_fd).
//  12. Restore regs and detach.
// ==================================================================
int inject_zygote(pid_t zygote_pid, const char *lib_path,
                  int bridge_fd) {
    LOGI("injecting into zygote pid=%d lib=%s", zygote_pid, lib_path);

    arch_regs_t orig_regs;
    bool have_orig_regs = false;
    bool attached = false;
    int rc = -1;

    // Inner lambda so we can use early-returns for cleanup.
    auto inner = [&]() -> int {
        // 1. SEIZE the zygote.
        if (ptrace(PTRACE_SEIZE, zygote_pid, 0,
                   (void*)PTRACE_O_TRACESYSGOOD) < 0) {
            LOGE("PTRACE_SEIZE failed: %s", strerror(errno));
            return -1;
        }
        attached = true;

        // 2. INTERRUPT — bring it to a stop without SIGSTOP.
        if (ptrace(PTRACE_INTERRUPT, zygote_pid, 0, 0) < 0) {
            LOGE("PTRACE_INTERRUPT failed: %s", strerror(errno));
            return -1;
        }
        int status;
        if (waitpid(zygote_pid, &status, 0) < 0
            || !WIFSTOPPED(status)) {
            LOGE("zygote did not stop after INTERRUPT");
            return -1;
        }

        // 3. Save original registers.
        if (get_regs(zygote_pid, &orig_regs) < 0) {
            LOGE("GETREGS failed");
            return -1;
        }
        have_orig_regs = true;

        // 4. Find dlopen and dlsym addresses.
        uint64_t dlopen_addr = 0, dlsym_addr = 0;
        if (find_symbol_addr(zygote_pid, "dlopen", &dlopen_addr) < 0) {
            LOGE("could not find dlopen");
            return -1;
        }
        if (find_symbol_addr(zygote_pid, "dlsym", &dlsym_addr) < 0) {
            LOGE("could not find dlsym");
            return -1;
        }
        LOGI("dlopen @ 0x%" PRIx64 ", dlsym @ 0x%" PRIx64,
             dlopen_addr, dlsym_addr);

        // 5. Set up scratch stack area.
        uint64_t scratch = stack_ptr(&orig_regs) - 4096;
        scratch &= ~0xffULL;

        uint8_t zero[16] = {0};
        if (write_mem(zygote_pid, scratch, zero, sizeof(zero)) < 0) {
            LOGE("failed to write scratch return addr");
            return -1;
        }
        size_t path_len = strlen(lib_path) + 1;
        if (write_mem(zygote_pid, scratch + 16, lib_path, path_len) < 0) {
            LOGE("failed to write lib path");
            return -1;
        }
        const char *sym = "zygisk_entry";
        size_t sym_len = strlen(sym) + 1;
        if (write_mem(zygote_pid, scratch + 16 + 256, sym, sym_len) < 0) {
            LOGE("failed to write sym name");
            return -1;
        }

#if defined(__aarch64__) || defined(__x86_64__)
        // 6. Call dlopen(path, RTLD_NOW).
        uint64_t path_arg = scratch + 16;
        uint64_t sym_arg  = scratch + 16 + 256;
        arch_regs_t call_regs = orig_regs;
        uint64_t dlopen_args[2] = { path_arg, 2 /* RTLD_NOW */ };
        setup_call(&call_regs, dlopen_addr, dlopen_args, 2);
        set_sp(&call_regs, scratch);
        if (set_regs(zygote_pid, &call_regs) < 0) {
            LOGE("SETREGS for dlopen failed");
            return -1;
        }
        ptrace(PTRACE_CONT, zygote_pid, 0, 0);
        if (wait_for_trap(zygote_pid) < 0) {
            LOGE("zygote died during dlopen");
            return -1;
        }
        arch_regs_t ret_regs;
        get_regs(zygote_pid, &ret_regs);
        uint64_t handle = retval(&ret_regs);
        LOGI("dlopen returned handle=0x%" PRIx64, handle);
        if (handle == 0) {
            LOGE("dlopen failed inside zygote");
            return -1;
        }

        // 7. Call dlsym(handle, "zygisk_entry").
        call_regs = orig_regs;
        uint64_t dlsym_args[2] = { handle, sym_arg };
        setup_call(&call_regs, dlsym_addr, dlsym_args, 2);
        set_sp(&call_regs, scratch);
        if (set_regs(zygote_pid, &call_regs) < 0) {
            LOGE("SETREGS for dlsym failed");
            return -1;
        }
        ptrace(PTRACE_CONT, zygote_pid, 0, 0);
        if (wait_for_trap(zygote_pid) < 0) {
            LOGE("zygote died during dlsym");
            return -1;
        }
        get_regs(zygote_pid, &ret_regs);
        uint64_t zygisk_entry_addr = retval(&ret_regs);
        LOGI("zygisk_entry @ 0x%" PRIx64, zygisk_entry_addr);
        if (zygisk_entry_addr == 0) {
            LOGE("dlsym returned NULL for zygisk_entry");
            return -1;
        }

        // 8. Call zygisk_entry(bridge_fd).
        call_regs = orig_regs;
        uint64_t entry_args[1] = { (uint64_t)bridge_fd };
        setup_call(&call_regs, zygisk_entry_addr, entry_args, 1);
        set_sp(&call_regs, scratch);
        if (set_regs(zygote_pid, &call_regs) < 0) {
            LOGE("SETREGS for zygisk_entry failed");
            return -1;
        }
        ptrace(PTRACE_CONT, zygote_pid, 0, 0);
        // zygisk_entry normally doesn't return — it loops forever
        // inside zygote. So we wait briefly and then detach regardless.
        (void)wait_for_trap(zygote_pid);
#else
        // arm32 / i386: same logic but with uint32_t args.
        uint32_t path_arg = (uint32_t)(scratch + 16);
        uint32_t sym_arg  = (uint32_t)(scratch + 16 + 256);
        arch_regs_t call_regs = orig_regs;
        uint32_t dlopen_args[2] = { path_arg, 2 };
        setup_call(&call_regs, (uint32_t)dlopen_addr, dlopen_args, 2);
        set_sp(&call_regs, scratch);
        if (set_regs(zygote_pid, &call_regs) < 0) return -1;
        ptrace(PTRACE_CONT, zygote_pid, 0, 0);
        if (wait_for_trap(zygote_pid) < 0) return -1;
        arch_regs_t ret_regs;
        get_regs(zygote_pid, &ret_regs);
        uint32_t handle = retval(&ret_regs);
        if (!handle) return -1;

        call_regs = orig_regs;
        uint32_t dlsym_args[2] = { handle, sym_arg };
        setup_call(&call_regs, (uint32_t)dlsym_addr, dlsym_args, 2);
        set_sp(&call_regs, scratch);
        if (set_regs(zygote_pid, &call_regs) < 0) return -1;
        ptrace(PTRACE_CONT, zygote_pid, 0, 0);
        if (wait_for_trap(zygote_pid) < 0) return -1;
        get_regs(zygote_pid, &ret_regs);
        uint32_t zygisk_entry_addr = retval(&ret_regs);
        if (!zygisk_entry_addr) return -1;

        call_regs = orig_regs;
        uint32_t entry_args[1] = { (uint32_t)bridge_fd };
        setup_call(&call_regs, (uint32_t)zygisk_entry_addr, entry_args, 1);
        set_sp(&call_regs, scratch);
        if (set_regs(zygote_pid, &call_regs) < 0) return -1;
        ptrace(PTRACE_CONT, zygote_pid, 0, 0);
        (void)wait_for_trap(zygote_pid);
#endif
        return 0;
    };

    rc = inner();

    if (have_orig_regs) {
        set_regs(zygote_pid, &orig_regs);
    }
    if (attached) {
        ptrace(PTRACE_DETACH, zygote_pid, 0, 0);
    }
    if (rc == 0) LOGI("injection complete");
    return rc;
}
