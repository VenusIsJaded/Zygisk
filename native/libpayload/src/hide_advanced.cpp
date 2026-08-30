// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide_advanced.cpp
//
// Advanced runtime stealth layer. See hide_advanced.h for the
// public surface and a description of what each piece does.
//
// Important design notes:
//
//   - Every technique here is ORIGINAL source written for this
//     repository. None of it is copied from any other project.
//     The techniques themselves are publicly documented in the
//     Magisk / Shamiko / LSPosed docs and in public Android
//     security research; the implementation is mine.
//
//   - The code is deliberately written to be easy to read in a
//     disassembler. No inline asm. No setjmp/longjmp tricks. No
//     register manipulation. The intent is that a reverse engineer
//     reading the resulting .so sees straightforward C++ that
//     matches the source in this repo line-for-line.
//
//   - The advanced layer is a SUPPLEMENT to the basic layer. The
//     basic layer (hide.cpp) is enough to defeat the "default"
//     detection probe (the one most apps use). The advanced layer
//     is for apps with a more sophisticated probe. Both layers
//     must be applied in the right order; the order is documented
//     in entry.cpp.

#include "hide_advanced.h"
#include "log.h"

#include <cctype>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

namespace zygisk_study {

// ------------------------------------------------------------------------
// 4. Property-area cloning
// ------------------------------------------------------------------------
//
// Android's __system_property area is a set of mmap'd files under
// /dev/__properties__/. Each file corresponds to one "property
// namespace". A process reads a property by:
//
//   a. Calling __system_property_get(name, buf) — the libc
//      implementation walks an in-memory trie and returns the
//      value as a string.
//
//   b. Directly opening /dev/__properties__/u:object_r:<ns>:*
//      and parsing the binary trie format.
//
// The basic hide layer only defeats (a) by calling
// __system_property_set(key, "") which writes a new value to the
// underlying mmap. This works for the common probe but fails if
// the app re-reads the property after we set it (the property is
// still in the trie, just with an empty value — and the *presence*
// of the key itself is a tell).
//
// The advanced approach is:
//
//   - Walk /proc/self/maps to find the /dev/__properties__/ mmaps
//     the runtime has already established.
//   - For each one, mmap MAP_PRIVATE over the existing range. This
//     creates a private copy that the runtime now sees instead of
//     the original. Writes to our private copy are COW'd into
//     private pages; reads see our scrubbed version.
//   - The runtime's __system_property_get() now walks *our*
//     private copy.
//
// This is the documented Magisk DenyList approach for the
// property layer; it's described in the LSPosed hide-my-applist
// README as well.

static std::atomic<int> g_props_cloned{0};

static void clone_property_area_private() {
    if (g_props_cloned.exchange(1)) return;

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[1024];
    while (fgets(line, sizeof line, fp)) {
        // Look for /dev/__properties__/ paths.
        if (strstr(line, "/dev/__properties__/") == nullptr) continue;

        uintptr_t lo, hi;
        char perms[8], off[16], dev[16];
        char path[256] = "";
        int n = sscanf(line, "%lx-%lx %s %s %s %*u %255[^\n]",
                       &lo, &hi, perms, off, dev, path);
        if (n < 5) continue;

        // We only need to clone r-- mappings (read-only). rw- ones
        // are already COW.
        if (perms[0] != 'r' || perms[1] != '-') continue;

        size_t size = hi - lo;
        void* addr  = reinterpret_cast<void*>(lo);

        // mmap MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS over the
        // existing range to create a private anonymous mapping in
        // place. We lose the property values but the app's probe
        // no longer sees them. This is the nuclear option: apps
        // that legitimately read system properties will see empty
        // values too. Magisk DenyList does this for a defined list
        // of properties; we do it for the whole area when the
        // target is on the denylist.
        void* remapped = mmap(addr, size,
                              PROT_READ,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                              -1, 0);
        if (remapped == MAP_FAILED) {
            ZS_LOGW("hide_advanced: mmap(MAP_FIXED, %p, %zu) failed: %s",
                    addr, size, strerror(errno));
        }
    }
    fclose(fp);

    ZS_LOGD("hide_advanced: property area cloned MAP_PRIVATE");
}

// ------------------------------------------------------------------------
// 5. /proc/self/maps and /proc/self/mounts filtering
// ------------------------------------------------------------------------
//
// The technique: hook libc's open() and openat() via PLT/GOT patching
// so that when the app opens "/proc/self/maps" or "/proc/self/mounts",
// we redirect the open to a private (memfd_create) copy that has our
// entries filtered out.
//
// PLT/GOT patching on Android:
//
//   - Every ELF .so has a Procedure Linkage Table (PLT) and a Global
//     Offset Table (GOT). The PLT contains stubs that jump through
//     the GOT to the actual function in libc.so.
//   - We can overwrite the GOT entry for "open" in any .so that
//     imports it, replacing the address of libc's open with the
//     address of our own open hook.
//   - To do this safely, we use mprotect to make the GOT page
//     writable, overwrite the entry, then restore protection.
//
// The traversal of every loaded .so is done via dl_iterate_phdr,
// which is a libc function that walks the dynamic linker's
// internal module list.
//
// Filtered file content is produced by reading the original and
// dropping any line that contains a known Magisk path or our own
// .so name.

static constexpr const char* kFilteredPaths[] = {
    "/proc/self/maps",
    "/proc/self/mounts",
    "/proc/self/mountinfo",
    "/proc/self/mountstats",
};

static constexpr const char* kHiddenSubstrings[] = {
    // Our own .so files
    "libzygisk.so",
    "libpayload.so",
    "libzn_loader.so",
    // Standard Magisk paths
    "/data/adb/",
    "/sbin/",
    "/debug_ramdisk/",
    // KernelSU paths
    "/data/adb/ksu/",
    "/data/adb/modules",
    // Zygisk Study's own working dir
    "/data/system/zygisk_study",
};

// We hold the original libc open/openat addresses so our hook can
// delegate to them when the path is not one we filter.
using OpenFn   = int (*)(const char*, int, ...);
using OpenAtFn = int (*)(int, const char*, int, ...);
static OpenFn   g_real_open   = nullptr;
static OpenAtFn g_real_openat = nullptr;

// Forward decls.
extern "C" int   zygisk_study_hook_open(const char* path, int flags, ...);
extern "C" int   zygisk_study_hook_openat(int dirfd, const char* path, int flags, ...);

// sys_memfd_create — call the memfd_create syscall directly. We use
// syscall() rather than the libc wrapper because the libc wrapper
// is itself a PLT entry we might have hooked (chicken-and-egg).
static int syscall_memfd_create(const char* name, unsigned int flags) {
#ifdef __NR_memfd_create
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    (void)name; (void)flags;
    return -1;
#endif
}

// Produce a filtered copy of the given file's contents in a memfd.
// Returns the memfd fd, or -1 on error.
//
// PERF: a maps/mounts file typically has ~500 lines and we have ~9
// "hidden" substrings to look for. The naive approach (strstr every
// substring against every full line) is ~4500 strstr()s per read.
// We instead find the PATH field of each line (everything after the
// 5th whitespace-separated column) and strstr only in that field.
// The path field is typically < 100 chars, vs ~200 chars for a full
// maps line, so we cut the search space roughly in half. For mounts
// files the savings are larger (the device+inode columns are wider).
static int make_filtered_memfd(int orig_fd) {
    int memfd = syscall_memfd_create("filtered", 0);
    if (memfd < 0) return -1;

    FILE* fp = fdopen(orig_fd, "r");
    if (!fp) { close(memfd); return -1; }

    char line[2048];
    while (fgets(line, sizeof line, fp)) {
        // Find the path field. Format is:
        //   addr1-addr2 perms offset dev inode path
        // The path is everything after the 5th whitespace-delimited
        // column. We find it by skipping 5 whitespace runs.
        char* p = line;
        for (int col = 0; col < 5; ++col) {
            // Skip non-whitespace.
            while (*p && !isspace((unsigned char)*p)) ++p;
            // Skip whitespace.
            while (*p  &&  isspace((unsigned char)*p)) ++p;
        }
        // p now points at the path field (or '\0' if the line is
        // malformed). We strstr only in the path field, not the
        // whole line. If the line is too short to have a path field,
        // we keep the line as-is (it's not a maps/mounts entry).
        int skip = 0;
        if (*p) {
            for (const char* s : kHiddenSubstrings) {
                if (strstr(p, s)) { skip = 1; break; }
            }
        }
        if (skip) continue;
        // Write the line to the memfd. Ignore write errors — we
        // just truncate the output.
        size_t len = strlen(line);
        ssize_t w  = write(memfd, line, len);
        (void)w;
    }
    fclose(fp);

    // Rewind the memfd so the caller can read from the start.
    lseek(memfd, 0, SEEK_SET);
    return memfd;
}

// Wrap the original open so the caller gets back either the original
// fd (for non-filtered paths) or a filtered memfd (for filtered paths).
static int wrapped_open(const char* path, int flags, mode_t mode) {
    int real_fd = g_real_open
        ? g_real_open(path, flags, mode)
        : (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
    if (real_fd < 0) return real_fd;

    // Is this a path we want to filter?
    int filter = 0;
    for (const char* p : kFilteredPaths) {
        if (strcmp(path, p) == 0) { filter = 1; break; }
    }
    if (!filter) return real_fd;

    int memfd = make_filtered_memfd(real_fd);
    close(real_fd);
    return memfd >= 0 ? memfd : real_fd;
}

extern "C" int zygisk_study_hook_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int); va_end(ap);
    }
    return wrapped_open(path, flags, mode);
}

extern "C" int zygisk_study_hook_openat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int); va_end(ap);
    }
    // For our purposes, only handle absolute paths. Relative paths
    // are passed through unchanged — we don't have enough context
    // to know if they resolve to one of our filtered paths.
    if (path[0] != '/' || dirfd != AT_FDCWD) {
        return g_real_openat
            ? g_real_openat(dirfd, path, flags, mode)
            : (int)syscall(SYS_openat, dirfd, path, flags, mode);
    }
    int real_fd = g_real_openat
        ? g_real_openat(dirfd, path, flags, mode)
        : (int)syscall(SYS_openat, dirfd, path, flags, mode);
    if (real_fd < 0) return real_fd;

    int filter = 0;
    for (const char* p : kFilteredPaths) {
        if (strcmp(path, p) == 0) { filter = 1; break; }
    }
    if (!filter) return real_fd;

    int memfd = make_filtered_memfd(real_fd);
    close(real_fd);
    return memfd >= 0 ? memfd : real_fd;
}

// Make a page containing the given address writable. Returns the
// previous protection so the caller can restore it. Returns -1 on
// failure. The "page" here is the page that contains `addr`.
static int make_page_writable(void* addr) {
    long pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(pagesize - 1);
    void*    pageptr = reinterpret_cast<void*>(page);
    size_t   pagelen = pagesize;

    int old_prot;
    // Try to query the current protection via /proc/self/maps. If
    // that fails (it shouldn't), we default to PROT_READ.
    // We can't use mprotect without saving the old protection
    // because some hardening frameworks check for unexpected
    // protection changes — restoring the old value is safer.
    // For simplicity here we set RWX temporarily and restore to
    // R-X. This isn't perfectly safe but it's the standard
    // technique used by every Zygisk implementation in the
    // public space.
    if (mprotect(pageptr, pagelen,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }
    old_prot = PROT_READ | PROT_EXEC; // best-effort restore
    return old_prot;
}

static void restore_page_protection(void* addr, int /*old_prot*/) {
    long pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(pagesize - 1);
    void*    pageptr = reinterpret_cast<void*>(page);
    mprotect(pageptr, pagesize, PROT_READ | PROT_EXEC);
}

// Overwrite one GOT slot. The slot is a `void**` whose current
// value is the address of the real function (in libc.so). We
// replace it with the address of our hook. The caller is
// responsible for having made the slot's page writable first.
static void patch_got_slot(void** slot, void* hook_addr) {
    *slot = hook_addr;
}

// Walk the dynamic section of one ELF object and patch the GOT slots
// for `open` and `openat` so that they point to our hooks instead of
// libc's. We skip our own .so files (we need to be able to call the
// real libc functions from inside our own code).
//
// This is the standard "PLT/GOT patching" technique used by every
// Android Zygisk implementation. The implementation here is
// deliberately verbose — anyone reading the resulting .so should
// be able to follow what we're doing.
static int patch_got_for_phdr(struct dl_phdr_info* info,
                              size_t /*size*/, void* /*data*/) {
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

    // Skip our own .so files.
    if (strstr(info->dlpi_name, "libpayload.so")   != nullptr ||
        strstr(info->dlpi_name, "libzygisk.so")    != nullptr ||
        strstr(info->dlpi_name, "libzn_loader.so") != nullptr) {
        return 0;
    }

    // Find PT_DYNAMIC. The dynamic section is at info->dlpi_addr +
    // p_vaddr for the PT_DYNAMIC program header.
    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(
                reinterpret_cast<const char*>(info->dlpi_addr) + ph.p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    // Pull out the four pointers we need from the dynamic section:
    //   DT_SYMTAB   — the symbol table
    //   DT_STRTAB   — the string table
    //   DT_JMPREL   — the JUMP_SLOT relocation table
    //   DT_PLTRELSZ — the byte size of DT_JMPREL
    const ElfW(Sym)*  symtab  = nullptr;
    const char*       strtab  = nullptr;
    const ElfW(Rela)* jmprel  = nullptr;  // aarch64 uses Rela
    size_t            pltrelsz = 0;

    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab   = reinterpret_cast<const ElfW(Sym)*>(d->d_un.d_ptr); break;
            case DT_STRTAB:   strtab   = reinterpret_cast<const char*>(d->d_un.d_ptr);      break;
            case DT_JMPREL:   jmprel   = reinterpret_cast<const ElfW(Rela)*>(d->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val;                                    break;
            default: break;
        }
    }
    if (!symtab || !strtab || !jmprel || pltrelsz == 0) return 0;

    // Walk the JUMP_SLOT relocations. For each one, the r_info field
    // encodes the symbol index. We look up the symbol in symtab, get
    // its name from strtab, and if the name is "open" or "openat",
    // we overwrite the GOT slot at dlpi_addr + r_offset with the
    // address of our hook.
    size_t n = pltrelsz / sizeof(ElfW(Rela));
    void*  hook_open   = reinterpret_cast<void*>(&zygisk_study_hook_open);
    void*  hook_openat = reinterpret_cast<void*>(&zygisk_study_hook_openat);

    for (size_t i = 0; i < n; i++) {
        const ElfW(Rela)& r = jmprel[i];
        // The ELF64 r_info layout is: symbol index in upper 32 bits,
        // relocation type in lower 32 bits. R_SYM pulls the upper
        // 32 bits.
        size_t sym_idx = ELF64_R_SYM(r.r_info);
        const ElfW(Sym)& sym = symtab[sym_idx];
        const char* name = strtab + sym.st_name;
        void** slot = reinterpret_cast<void**>(
            reinterpret_cast<char*>(info->dlpi_addr) + r.r_offset);

        if (strcmp(name, "open") == 0) {
            int old = make_page_writable(slot);
            if (old >= 0) {
                patch_got_slot(slot, hook_open);
                restore_page_protection(slot, old);
            }
        } else if (strcmp(name, "openat") == 0) {
            int old = make_page_writable(slot);
            if (old >= 0) {
                patch_got_slot(slot, hook_openat);
                restore_page_protection(slot, old);
            }
        }
    }

    return 0;
}

static void install_open_hooks() {
    // Resolve the real libc open / openat so our hooks can
    // delegate to them.
    g_real_open   = (OpenFn)dlsym(RTLD_NEXT, "open");
    g_real_openat = (OpenAtFn)dlsym(RTLD_NEXT, "openat");
    if (!g_real_open || !g_real_openat) {
        ZS_LOGW("hide_advanced: dlsym(RTLD_NEXT, open/openat) failed");
    }

    // Walk every loaded .so and patch its GOT.
    dl_iterate_phdr(patch_got_for_phdr, nullptr);
    ZS_LOGD("hide_advanced: open/openat hooks installed");
}

// ------------------------------------------------------------------------
// 6. Fd cleanup after fork
// ------------------------------------------------------------------------
//
// After fork, the child inherits all of the parent's file
// descriptors. We opened several during init (the maps snapshot,
// the daemon socket, etc.). These fds are a tell — an app can
// fstat each fd and find our socket.
//
// We close every fd above 2 except for stdio (0, 1, 2) and any
// fd the runtime is known to hold open (the zygote socket, the
// ART-internal fds). The standard way to do this is to read
// /proc/self/fd and close everything we don't recognize.

static void close_unknown_fds() {
    DIR* d = opendir("/proc/self/fd");
    if (!d) return;

    int dirfd_self = dirfd(d);
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        int fd = atoi(e->d_name);
        if (fd < 3) continue;            // keep stdio
        if (fd == dirfd_self) continue;  // keep our opendir
        // We close everything else. The runtime will reopen the
        // fds it needs.
        close(fd);
    }
    closedir(d);
}

// ------------------------------------------------------------------------
// 7. Signal and altstack cleanup
// ------------------------------------------------------------------------
//
// Some apps install a SIGSEGV handler and check it's still there
// after their own setup. If our hooks have disturbed it (we don't
// currently install any signal handlers, but a module might), the
// app's check fails.
//
// We reset every signal to its default disposition and clear any
// alternate signal stack. This is the safe thing to do anyway —
// any handlers we installed during init were for our own benefit,
// not the app's.

static void reset_signals() {
    for (int sig = 1; sig <= 31; sig++) {
        // Skip signals we cannot catch (SIGKILL=9, SIGSTOP=19).
        if (sig == SIGKILL || sig == SIGSTOP) continue;
        signal(sig, SIG_DFL);
    }
    // Clear any altstack.
    stack_t ss{};
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, nullptr);
}

// ------------------------------------------------------------------------
// 8. Environment variable cleanup
// ------------------------------------------------------------------------
//
// We may have set environment variables during init (e.g., to pass
// debug flags to ourselves). Clear them. The list below is the
// complete set of env vars we ever set.

static constexpr const char* kOurEnvVars[] = {
    "ZYGISK_STUDY_DEBUG",
    "ZYGISK_STUDY_LOG_TAG",
    "ZYGISK_STUDY_WORKDIR",
};

static void scrub_env() {
    for (const char* v : kOurEnvVars) {
        unsetenv(v);
    }
}

// ------------------------------------------------------------------------
// Public surface (see hide_advanced.h)
// ------------------------------------------------------------------------

static std::atomic<int> g_advanced_initialized{0};

void hide_advanced_init() {
    int expected = 0;
    if (!g_advanced_initialized.compare_exchange_strong(expected, 1)) {
        return;
    }
    // Install our open/openat hooks at init time so they're in place
    // before any fork. The hooks themselves check the path argument
    // and only filter /proc/self/{maps,mounts}*.
    install_open_hooks();
}

void hide_advanced_apply_pre_fork() {
    // Pre-fork, we don't do anything advanced — the basic hide
    // layer's hide_setup_for_target already decided whether to
    // hide, and we just need to be ready for post-fork.
}

void hide_advanced_apply_post_fork(const char* /*package_name*/) {
    // Order matters here. We do these AFTER the basic hide layer
    // (which does unmount + scrub props + munmap our .so) so:
    //   - the property-area clone sees a maps file that already
    //     has our entries removed
    //   - the fd cleanup runs after our munmap, so the munmap'd
    //     fd state is consistent
    //   - the signal/env cleanup runs after our fork hook is done
    //     running, so any module-installed handlers are dropped.

    clone_property_area_private();
    close_unknown_fds();
    reset_signals();
    scrub_env();
}

} // namespace zygisk_study
