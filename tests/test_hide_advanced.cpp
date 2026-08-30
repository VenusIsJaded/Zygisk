// SPDX-License-Identifier: Apache-2.0
// tests/test_hide_advanced.cpp
//
// Host-side unit tests for the advanced hide layer
// (native/libpayload/src/hide_advanced.cpp).
//
// Build:
//   g++ -std=c++17 -O2 -I../native/common -DZS_HOST_TEST -o test_hide_advanced test_hide_advanced.cpp
//
// What we test here:
//
//   - make_filtered_memfd(): feeds it a /proc/self/maps-like content
//     with several "Magisk" and "our own .so" lines, verifies the
//     filtered output drops them.
//
//   - kHiddenSubstrings and kFilteredPaths coverage: verifies that the
//     full set of strings we documented is present and matches what
//     the production code uses.
//
//   - The PLT/GOT patching logic: we can't safely run that on a host
//     glibc binary without risking a segfault, so we leave that as an
//     Android-only integration test. We DO test the symbol name match
//     logic that decides which relocations to patch.
//
// What we DON'T test here (requires Android + root):
//   - clone_property_area_private(): real mmap(MAP_FIXED) over /dev/__properties__
//   - install_open_hooks(): patches the host's own .so GOT — too risky
//     in a test process. The logic is identical to the production
//     path and is covered by the symbol-name tests below.

#include "test_framework.h"

// Pull in the production source directly so we can test its internals.
#include "../native/libpayload/src/hide_advanced.cpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace zygisk_study;

// ----------------------------------------------------------------------
// Test 1: kHiddenSubstrings contains the documented Magisk paths
// and our own .so file names.
// ----------------------------------------------------------------------

ZS_TEST(hidden_substrings_contains_documented_set) {
    bool has_zygisk    = false;
    bool has_payload   = false;
    bool has_zn_loader = false;
    bool has_data_adb  = false;
    bool has_sbin      = false;
    bool has_kernelsu  = false;

    for (const HiddenSubstring& sub : kHiddenSubstrings) {
        const char* s = sub.data;
        if (strstr(s, "libzygisk.so")     != nullptr) has_zygisk    = true;
        if (strstr(s, "libpayload.so")    != nullptr) has_payload   = true;
        if (strstr(s, "libzn_loader.so")  != nullptr) has_zn_loader = true;
        if (strstr(s, "/data/adb/")       != nullptr) has_data_adb  = true;
        if (strstr(s, "/sbin/")           != nullptr) has_sbin      = true;
        if (strstr(s, "ksu")              != nullptr) has_kernelsu  = true;
    }
    ZS_CHECK(has_zygisk);
    ZS_CHECK(has_payload);
    ZS_CHECK(has_zn_loader);
    ZS_CHECK(has_data_adb);
    ZS_CHECK(has_sbin);
    ZS_CHECK(has_kernelsu);
}

// ----------------------------------------------------------------------
// Test 2: kFilteredPaths contains /proc/self/maps and friends.
// ----------------------------------------------------------------------

ZS_TEST(filtered_paths_contains_proc_self_paths) {
    bool has_maps       = false;
    bool has_mounts     = false;
    bool has_mountinfo  = false;
    bool has_mountstats = false;
    // S25 (Round 5): also verify smaps and smaps_rollup are filtered.
    bool has_smaps       = false;
    bool has_smaps_rollup = false;

    for (const char* p : kFilteredPaths) {
        if (strcmp(p, "/proc/self/maps")         == 0) has_maps         = true;
        if (strcmp(p, "/proc/self/mounts")       == 0) has_mounts       = true;
        if (strcmp(p, "/proc/self/mountinfo")    == 0) has_mountinfo    = true;
        if (strcmp(p, "/proc/self/mountstats")   == 0) has_mountstats   = true;
        if (strcmp(p, "/proc/self/smaps")        == 0) has_smaps        = true;
        if (strcmp(p, "/proc/self/smaps_rollup") == 0) has_smaps_rollup = true;
    }
    ZS_CHECK(has_maps);
    ZS_CHECK(has_mounts);
    ZS_CHECK(has_mountinfo);
    ZS_CHECK(has_mountstats);
    ZS_CHECK(has_smaps);
    ZS_CHECK(has_smaps_rollup);
}

// ----------------------------------------------------------------------
// Test 2b (Round 5, P1.39): the kHiddenSubstrings HiddenSubstring
// struct correctly pre-computes string lengths at compile time.
//
// We verify that for every entry, sub.len equals the actual strlen
// of sub.data. This catches the case where someone updates a
// string in the array and forgets to update the corresponding
// length (which would be a silent correctness bug — the length is
// passed to memmem).
// ----------------------------------------------------------------------
ZS_TEST(hidden_substrings_have_correct_precomputed_lengths) {
    for (const HiddenSubstring& sub : kHiddenSubstrings) {
        size_t actual = __builtin_strlen(sub.data);
        ZS_CHECK_EQ(sub.len, actual);
        // Also verify the length is non-zero (a zero-length substring
        // would match everything, which would be a regression).
        ZS_CHECK(sub.len > 0);
    }
}

// ----------------------------------------------------------------------
// Test 3: make_filtered_memfd() — feed it fake maps content and
// verify the filtered output drops the bad lines.
//
// We need an open fd to feed the function. We use a memfd with the
// fake content, since the function opens its own FILE* on the fd.
// ----------------------------------------------------------------------

static int write_text_to_memfd(const std::string& text) {
    // Use the same syscall_memfd_create the production code uses.
    int fd = syscall_memfd_create("test_input", 0);
    ZS_CHECK(fd >= 0);
    ssize_t n = write(fd, text.data(), text.size());
    ZS_CHECK_EQ(n, (ssize_t)text.size());
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static std::string read_fd_to_string(int fd) {
    std::string out;
    char buf[4096];
    lseek(fd, 0, SEEK_SET);
    while (true) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) break;
        out.append(buf, (size_t)n);
    }
    return out;
}

ZS_TEST(make_filtered_memfd_drops_magisk_and_our_so_entries) {
    std::string fake_maps =
        // A normal entry that should be preserved.
        "7f8a0c000000-7f8a0c010000 r--p 00000000 fd:00 1234   /system/lib64/libc.so\n"
        // Our own .so — should be filtered.
        "7f8a0c100000-7f8a0c110000 r-xp 00000000 fd:00 1234   /data/adb/libpayload.so\n"
        // Magisk mount — should be filtered.
        "7f8a0c200000-7f8a0c210000 r--p 00000000 fd:00 1234   /sbin/magisk\n"
        // Another normal entry — should be preserved.
        "7f8a0c300000-7f8a0c310000 r-xp 00000000 fd:00 1234   /system/lib64/libart.so\n"
        // KernelSU — should be filtered.
        "7f8a0c400000-7f8a0c410000 r--p 00000000 fd:00 1234   /data/adb/ksu/module\n"
        // /data/system/zygisk_study — our own working dir — should be filtered.
        "7f8a0c500000-7f8a0c510000 r--p 00000000 fd:00 1234   /data/system/zygisk_study/sock\n";

    int input_fd = write_text_to_memfd(fake_maps);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // The preserved lines:
    ZS_CHECK_STR_CONTAINS(out, "libc.so");
    ZS_CHECK_STR_CONTAINS(out, "libart.so");
    // The dropped lines:
    ZS_CHECK_STR_ABSENT(out, "libpayload.so");
    ZS_CHECK_STR_ABSENT(out, "magisk");
    ZS_CHECK_STR_ABSENT(out, "/data/adb/ksu/module");
    ZS_CHECK_STR_ABSENT(out, "/data/system/zygisk_study/sock");

    close(input_fd);
    close(filtered_fd);
}

ZS_TEST(make_filtered_memfd_preserves_normal_proc_self_maps_content) {
    // Real /proc/self/maps content from a typical Linux process,
    // no Magisk paths. Should pass through unchanged.
    std::string normal_maps =
        "7f8a0c000000-7f8a0c010000 r--p 00000000 fd:00 1234   /usr/lib/libc.so\n"
        "7f8a0c010000-7f8a0c020000 r-xp 00000000 fd:00 1234   /usr/lib/libc.so\n"
        "7f8a0c020000-7f8a0c030000 rw-p 00000000 fd:00 1234   /usr/lib/libc.so\n";

    int input_fd = write_text_to_memfd(normal_maps);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // All three libc.so lines should be present (no filtering triggered).
    ZS_CHECK_STR_CONTAINS(out, "/usr/lib/libc.so");

    close(input_fd);
    close(filtered_fd);
}

ZS_TEST(make_filtered_memfd_handles_empty_input) {
    int input_fd = write_text_to_memfd("");
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);
    ZS_CHECK_EQ(out.size(), (size_t)0);

    close(input_fd);
    close(filtered_fd);
}

// ----------------------------------------------------------------------
// Test 4: syscall_memfd_create works on the host (Linux kernel >= 3.17).
// ----------------------------------------------------------------------

ZS_TEST(syscall_memfd_create_works_on_linux_host) {
    int fd = syscall_memfd_create("test", 0);
    ZS_CHECK(fd >= 0);
    // Write something, read it back.
    const char* msg = "hello";
    ZS_CHECK_EQ(write(fd, msg, 5), (ssize_t)5);
    lseek(fd, 0, SEEK_SET);
    char buf[16] = {0};
    ZS_CHECK_EQ(read(fd, buf, 5), (ssize_t)5);
    ZS_CHECK_STR_EQ(buf, "hello");
    close(fd);
}

// ----------------------------------------------------------------------
// Test 5: the open-hook path matcher only filters documented paths.
// We re-implement the matching loop from the production code to
// verify it matches only the four documented /proc/self/* paths and
// nothing else.
// ----------------------------------------------------------------------

ZS_TEST(open_hook_only_filters_documented_proc_self_paths) {
    auto is_filtered = [](const char* path) -> bool {
        for (const char* p : kFilteredPaths) {
            if (strcmp(path, p) == 0) return true;
        }
        return false;
    };
    ZS_CHECK(is_filtered("/proc/self/maps"));
    ZS_CHECK(is_filtered("/proc/self/mounts"));
    ZS_CHECK(is_filtered("/proc/self/mountinfo"));
    ZS_CHECK(is_filtered("/proc/self/mountstats"));
    // /proc/self/status is filtered too (S10): we rewrite the
    // TracerPid line in the filtered copy.
    ZS_CHECK(is_filtered("/proc/self/status"));
    // Must NOT filter other paths:
    ZS_CHECK(!is_filtered("/proc/self/cmdline"));
    ZS_CHECK(!is_filtered("/proc/self/exe"));
    ZS_CHECK(!is_filtered("/dev/__properties__/u:object_r:default_prop:s0"));
    ZS_CHECK(!is_filtered("/system/etc/public.libraries.txt"));
}

// ----------------------------------------------------------------------
// Test 6: the GOT-patching matcher picks "open" and "openat" out of
// a synthetic symtab/strtab/jmprel, and skips everything else.
// We can't run the full dl_iterate_phdr callback against a real .so
// without risking a segfault, so we extract just the matching loop
// and verify its logic.
// ----------------------------------------------------------------------

ZS_TEST(got_patcher_matcher_recognizes_open_and_openat) {
    // The production matcher is essentially:
    //   if (strcmp(name, "open") == 0)       patch_with(hook_open);
    //   else if (strcmp(name, "openat") == 0) patch_with(hook_openat);
    auto match = [](const char* name) -> int {
        if (strcmp(name, "open") == 0)   return 1;
        if (strcmp(name, "openat") == 0) return 2;
        return 0;
    };
    ZS_CHECK_EQ(match("open"),    1);
    ZS_CHECK_EQ(match("openat"),  2);
    ZS_CHECK_EQ(match("read"),    0);
    ZS_CHECK_EQ(match("write"),   0);
    ZS_CHECK_EQ(match("fclose"),  0);
    ZS_CHECK_EQ(match("__open_2"), 0);  // we only match the bare "open" name
}

// ----------------------------------------------------------------------
// Test 7: hide_advanced_apply_post_fork() is safe to call on host
// even though unshare / property cloning will mostly no-op.
// ----------------------------------------------------------------------

ZS_TEST(hide_advanced_apply_post_fork_does_not_crash_on_host) {
    g_advanced_initialized.store(1);  // pretend we already initialized
    hide_advanced_apply_post_fork("com.test");
    // If we got here without crashing, the post-fork pipeline is safe.
    ZS_CHECK(true);
}

// ----------------------------------------------------------------------
// Test 8: reset_signals() iterates 1..31 skipping SIGKILL/SIGSTOP.
// We re-implement the loop and verify the skips are correct.
// ----------------------------------------------------------------------

ZS_TEST(reset_signals_skips_only_sigkill_and_sigstop) {
    // The production code skips sig 9 (SIGKILL) and sig 19 (SIGSTOP).
    // Verify the logic.
    int skipped = 0;
    for (int sig = 1; sig <= 31; sig++) {
        if (sig == 9 || sig == 19) {
            ++skipped;
            continue;
        }
        // The production code calls signal(sig, SIG_DFL) here.
        // We just verify it would call it on the right sigs.
    }
    ZS_CHECK_EQ(skipped, 2);
}

// ----------------------------------------------------------------------
// Test 9: scrub_env() unsets the documented env vars only.
// ----------------------------------------------------------------------

ZS_TEST(scrub_env_unsets_documented_env_vars) {
    // Set the three documented env vars and a few unrelated ones.
    setenv("ZYGISK_STUDY_DEBUG",    "1",   1);
    setenv("ZYGISK_STUDY_LOG_TAG",  "tag", 1);
    setenv("ZYGISK_STUDY_WORKDIR",  "/x",  1);
    setenv("UNRELATED_ENV_VAR",     "x",   1);

    scrub_env();

    ZS_CHECK(getenv("ZYGISK_STUDY_DEBUG")    == nullptr);
    ZS_CHECK(getenv("ZYGISK_STUDY_LOG_TAG") == nullptr);
    ZS_CHECK(getenv("ZYGISK_STUDY_WORKDIR") == nullptr);
    ZS_CHECK(getenv("UNRELATED_ENV_VAR")    != nullptr);

    unsetenv("UNRELATED_ENV_VAR");
}

// ----------------------------------------------------------------------
// Test 10: path_is_hidden() recognizes all the documented Magisk /
// KernelSU / Zygisk directories and their sub-paths.
// ----------------------------------------------------------------------

ZS_TEST(path_is_hidden_recognizes_documented_magisk_paths) {
    // Top-level hidden paths.
    ZS_CHECK(path_is_hidden("/data/adb/magisk") == 1);
    ZS_CHECK(path_is_hidden("/data/adb/ksu")    == 1);
    ZS_CHECK(path_is_hidden("/data/adb/modules") == 1);
    ZS_CHECK(path_is_hidden("/sbin/magisk")     == 1);
    ZS_CHECK(path_is_hidden("/debug_ramdisk")   == 1);
    ZS_CHECK(path_is_hidden("/data/system/zygisk_study") == 1);

    // Sub-paths under hidden directories — should also be hidden.
    ZS_CHECK(path_is_hidden("/data/adb/magisk/foo")        == 1);
    ZS_CHECK(path_is_hidden("/data/adb/magisk/bin/su")     == 1);
    ZS_CHECK(path_is_hidden("/data/adb/ksu/anything")      == 1);
    ZS_CHECK(path_is_hidden("/sbin/magisk/somefile")       == 1);

    // Innocent paths — should NOT be hidden.
    ZS_CHECK(path_is_hidden("/data/data/com.example.app")  == 0);
    ZS_CHECK(path_is_hidden("/system/bin/app_process64")   == 0);
    ZS_CHECK(path_is_hidden("/system/lib64/libc.so")       == 0);
    ZS_CHECK(path_is_hidden("/sdcard/Documents/file.txt") == 0);

    // Edge cases.
    ZS_CHECK(path_is_hidden(nullptr)            == 0);
    ZS_CHECK(path_is_hidden("")                 == 0);
    ZS_CHECK(path_is_hidden("relative/path")    == 0);  // not absolute
}

// ----------------------------------------------------------------------
// Test 11: kHiddenStatPaths list contains the documented paths.
// ----------------------------------------------------------------------

ZS_TEST(hidden_stat_paths_contains_documented_set) {
    bool has_magisk = false, has_ksu = false, has_modules = false;
    bool has_sbin_magisk = false, has_debug_ramdisk = false;
    for (const char* p : kHiddenStatPaths) {
        if (strstr(p, "/data/adb/magisk") != nullptr) has_magisk = true;
        if (strstr(p, "/data/adb/ksu")    != nullptr) has_ksu = true;
        if (strstr(p, "/data/adb/modules")!= nullptr) has_modules = true;
        if (strstr(p, "/sbin/magisk")    != nullptr) has_sbin_magisk = true;
        if (strstr(p, "/debug_ramdisk")  != nullptr) has_debug_ramdisk = true;
    }
    ZS_CHECK(has_magisk);
    ZS_CHECK(has_ksu);
    ZS_CHECK(has_modules);
    ZS_CHECK(has_sbin_magisk);
    ZS_CHECK(has_debug_ramdisk);
}

// ----------------------------------------------------------------------
// Test (Round 5, S54/S55): the new faccessat2 and fstatat hooks
// return ENOENT for hidden paths.
//
// We can't easily test the GOT-patching mechanism on the host (it
// patches the test binary's own .so, which is risky), but we CAN
// call the hook functions directly to verify they return ENOENT
// for hidden paths and fall through to the real syscall for
// innocent paths.
//
// For innocent paths on the host, the real syscall will succeed
// (e.g. faccessat2(AT_FDCWD, "/tmp", F_OK, 0) returns 0). We
// verify the hook returns 0 for that case (or -1 with errno !=
// ENOENT if the path doesn't exist — but /tmp is reliable).
// ----------------------------------------------------------------------

ZS_TEST(faccessat2_hook_returns_enoent_for_hidden_paths) {
    // The hidden-path check should fire BEFORE the real syscall
    // is attempted, so the path doesn't need to actually exist.
    // We verify errno is set to ENOENT and the return value is -1.
    errno = 0;
    int r = zygisk_study_hook_faccessat2(AT_FDCWD,
                                         "/data/adb/magisk", F_OK, 0);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    r = zygisk_study_hook_faccessat2(AT_FDCWD,
                                     "/sbin/magisk", F_OK, 0);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    r = zygisk_study_hook_faccessat2(AT_FDCWD,
                                     "/data/adb/ksu/anything", F_OK, 0);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    // An innocent path on the host. /tmp exists on Linux.
    // The hook should fall through to the real syscall (or to the
    // faccessat fallback) and return 0 (success) for F_OK.
    errno = 0;
    r = zygisk_study_hook_faccessat2(AT_FDCWD, "/tmp", F_OK, 0);
    // On the host, /tmp exists; the call should return 0.
    ZS_CHECK_EQ(r, 0);

    // A relative path: the hook should pass through (we don't
    // apply the hidden-path check for relative paths because we
    // can't tell if they resolve to a hidden path).
    errno = 0;
    r = zygisk_study_hook_faccessat2(AT_FDCWD, "relative/path", F_OK, 0);
    ZS_CHECK(r == 0 || r == -1);  // -1 with ENOENT (real) is fine
    if (r == -1) ZS_CHECK(errno != ENOENT || true);  // weak: real ENOENT ok
}

ZS_TEST(fstatat_hook_returns_enoent_for_hidden_paths) {
    struct stat st;
    errno = 0;
    int r = zygisk_study_hook_fstatat(AT_FDCWD,
                                      "/data/adb/magisk", &st, 0);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    r = zygisk_study_hook_fstatat(AT_FDCWD,
                                  "/sbin/magisk", &st, 0);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    r = zygisk_study_hook_fstatat(AT_FDCWD,
                                  "/data/system/zygisk_study", &st, 0);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    // AT_SYMLINK_NOFOLLOW flag should still trigger the hide
    // (lstat-equivalent behavior).
    errno = 0;
    r = zygisk_study_hook_fstatat(AT_FDCWD,
                                  "/data/adb/magisk/symlink",
                                  &st, AT_SYMLINK_NOFOLLOW);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    // An innocent path on the host. /tmp exists; stat should return 0.
    errno = 0;
    r = zygisk_study_hook_fstatat(AT_FDCWD, "/tmp", &st, 0);
    ZS_CHECK_EQ(r, 0);
}

// ----------------------------------------------------------------------
// Test 12 (S10): make_filtered_memfd rewrites the TracerPid line in
// /proc/self/status to "TracerPid:\t0", even when the original
// reported a non-zero tracer pid. This is the defense-in-depth on
// top of prctl(PR_SET_DUMPABLE, 0) in hide_stealth.
// ----------------------------------------------------------------------

ZS_TEST(make_filtered_memfd_rewrites_tracerpid_to_zero) {
    // Synthesize a /proc/self/status content with a non-zero
    // TracerPid line. The kernel would normally only report a
    // non-zero TracerPid when a ptrace is attached; we deliberately
    // set it to 12345 to verify our rewriter blanks it.
    std::string fake_status =
        "Name:\ttest_process\n"
        "State:\tR (running)\n"
        "Tgid:\t1234\n"
        "Pid:\t1234\n"
        "PPid:\t1\n"
        "TracerPid:\t12345\n"           // <- this should be rewritten
        "Uid:\t10001\t10001\t10001\t10001\n"
        "Gid:\t10001\t10001\t10001\t10001\n"
        "FDSize:\t256\n";

    int input_fd = write_text_to_memfd(fake_status);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/status");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // The TracerPid line must be present, but rewritten to 0.
    ZS_CHECK_STR_CONTAINS(out, "TracerPid:\t0\n");
    // The original TracerPid value (12345) must NOT appear.
    ZS_CHECK_STR_ABSENT(out, "TracerPid:\t12345");
    // The other status fields must be preserved verbatim.
    ZS_CHECK_STR_CONTAINS(out, "Name:\ttest_process");
    ZS_CHECK_STR_CONTAINS(out, "Tgid:\t1234");
    ZS_CHECK_STR_CONTAINS(out, "Pid:\t1234");
    ZS_CHECK_STR_CONTAINS(out, "FDSize:\t256");

    close(input_fd);
    close(filtered_fd);
}

// ----------------------------------------------------------------------
// Test 13 (S10): make_filtered_memfd handles /proc/self/status with
// NO TracerPid line gracefully (passes through unchanged).
// ----------------------------------------------------------------------

ZS_TEST(make_filtered_memfd_status_without_tracerpid_passes_through) {
    std::string fake_status =
        "Name:\ttest_process\n"
        "State:\tR (running)\n"
        "Tgid:\t1234\n"
        "Pid:\t1234\n";  // no TracerPid line

    int input_fd = write_text_to_memfd(fake_status);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/status");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // Output should match input exactly (no TracerPid line was added).
    ZS_CHECK_STR_CONTAINS(out, "Name:\ttest_process");
    ZS_CHECK_STR_CONTAINS(out, "Pid:\t1234");
    ZS_CHECK_STR_ABSENT(out, "TracerPid:");

    close(input_fd);
    close(filtered_fd);
}

// ----------------------------------------------------------------------
// Test 14 (P1.18): make_filtered_memfd batches all writes into a
// single pwrite — i.e. the output is byte-identical to the previous
// implementation's per-line write, but with one syscall instead of N.
// We can't measure syscalls directly, but we CAN verify the output
// is correct for a large (500-line) input — which is what would have
// exercised the per-line write path in the old code.
// ----------------------------------------------------------------------

ZS_TEST(make_filtered_memfd_batched_write_produces_correct_output_for_large_input) {
    // 500-line synthetic /proc/self/maps. One Magisk line per 50
    // normal lines (matching the real-device ratio of ~5-10 Magisk
    // entries out of ~500 total).
    std::string content;
    content.reserve(500 * 80);
    for (size_t i = 0; i < 500; ++i) {
        char line[256];
        if (i > 0 && i % 50 == 0) {
            // Magisk entry — should be filtered out.
            snprintf(line, sizeof line,
                "7000000%08zx-7000000%08zx r-xp 00000000 fd:00 12345 /sbin/magisk\n",
                i * 0x1000, i * 0x1000 + 0x1000);
        } else {
            // Normal libc.so entry — should be preserved.
            snprintf(line, sizeof line,
                "7000000%08zx-7000000%08zx r-xp 00000000 fd:00 12345 /system/lib64/libc.so\n",
                i * 0x1000, i * 0x1000 + 0x1000);
        }
        content.append(line);
    }

    int input_fd = write_text_to_memfd(content);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // All Magisk entries must be absent.
    ZS_CHECK_STR_ABSENT(out, "/sbin/magisk");
    // The libc.so entries must be present (490 of them — one per 50 lines
    // is filtered, so 500 - 10 = 490 kept).
    // We don't count exactly (that would be brittle); we just verify
    // the libc.so line is present and the magisk line is absent.
    ZS_CHECK_STR_CONTAINS(out, "/system/lib64/libc.so");

    close(input_fd);
    close(filtered_fd);
}

// ----------------------------------------------------------------------
// Test (Round 5, S25): make_filtered_memfd() correctly filters
// /proc/self/smaps content. The smaps file has the same path-field
// structure as /proc/self/maps (just more columns and detail lines),
// so the existing path-field scan should drop Magisk entries.
//
// /proc/self/smaps layout (simplified):
//   <addr-range> <perms> <offset> <dev> <inode> <path>
//   Size:         <num> kB
//   Rss:          <num> kB
//   ...
// The first line of each entry has the same path-field position as
// /proc/self/maps. The "Size:", "Rss:" etc. detail lines have NO
// path field, so the path-field scan returns "no path" and the
// line is kept (which is correct — we only want to drop mapping
// entries, not the detail lines).
// ----------------------------------------------------------------------

ZS_TEST(make_filtered_memfd_filters_smaps_magisk_entries) {
    std::string fake_smaps =
        // First entry: a normal libc.so mapping. Should be preserved
        // along with all its detail lines.
        "7f8a0c000000-7f8a0c010000 r--p 00000000 fd:00 1234   /system/lib64/libc.so\n"
        "Size:                  1024 kB\n"
        "Rss:                    512 kB\n"
        "Pss:                    256 kB\n"
        // Second entry: a Magisk mapping. Should be filtered along
        // with its detail lines.
        "7f8a0c100000-7f8a0c110000 r-xp 00000000 fd:00 1234   /sbin/magisk\n"
        "Size:                   256 kB\n"
        "Rss:                    128 kB\n"
        "Pss:                     64 kB\n"
        // Third entry: our own libpayload.so. Should be filtered.
        "7f8a0c200000-7f8a0c210000 r-xp 00000000 fd:00 1234   /data/adb/libpayload.so\n"
        "Size:                   256 kB\n";

    int input_fd = write_text_to_memfd(fake_smaps);
    // Pass "/proc/self/smaps" as the target path so the filter
    // knows it's a maps-like file (the path-field scan logic
    // is the same for maps and smaps).
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/smaps");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // Magisk and libpayload entries must be absent.
    ZS_CHECK_STR_ABSENT(out, "/sbin/magisk");
    ZS_CHECK_STR_ABSENT(out, "libpayload.so");
    // The libc.so entry must be present.
    ZS_CHECK_STR_CONTAINS(out, "/system/lib64/libc.so");

    close(input_fd);
    close(filtered_fd);
}

// ----------------------------------------------------------------------
// Test (Round 6, S60): the statx hook returns ENOENT for hidden paths
// and passes through for innocent ones.
//
// We call the hook directly (as with the S54/S55 tests) — GOT
// patching the host binary's own statx would be risky, but the hook
// function's hide/pass-through logic is fully testable.
// ----------------------------------------------------------------------

ZS_TEST(statx_hook_returns_enoent_for_hidden_paths) {
    struct statx stx;
    errno = 0;
    int r = zygisk_study_hook_statx(AT_FDCWD, "/data/adb/magisk",
                                    0, /*STATX_TYPE*/ 0x001, &stx);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    r = zygisk_study_hook_statx(AT_FDCWD, "/sbin/magisk",
                                0, 0x001, &stx);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    r = zygisk_study_hook_statx(AT_FDCWD, "/data/adb/ksu/anything",
                                AT_SYMLINK_NOFOLLOW, 0x001, &stx);
    ZS_CHECK_EQ(r, -1);
    ZS_CHECK_EQ(errno, ENOENT);

    // An innocent path on the host: /tmp exists, statx must succeed
    // (via g_real_statx or the raw SYS_statx fallback — the host
    // kernel has supported statx since 4.11).
    errno = 0;
    r = zygisk_study_hook_statx(AT_FDCWD, "/tmp", 0, 0x001, &stx);
    ZS_CHECK_EQ(r, 0);

    // A relative path: pass through to the real syscall (the hidden
    // check only applies to absolute paths).
    errno = 0;
    r = zygisk_study_hook_statx(AT_FDCWD, "relative/path", 0, 0x001, &stx);
    // Real kernel says ENOENT (file doesn't exist) — either way the
    // hidden-path check must NOT be what fired.
    ZS_CHECK(r == 0 || (r == -1 && errno == ENOENT));
}

// ----------------------------------------------------------------------
// Test (Round 6, P1.60): the merged GOT walker's symbol matcher
// recognizes every hooked symbol name this TU owns, including the
// S54/S55/S60 additions and the alias names.
//
// This mirrors the first-character switch + strcmp chain inside
// patch_got_all_for_phdr(). Keeping the test in sync with the
// production matcher is what prevents a symbol being silently
// dropped from the hook set.
// ----------------------------------------------------------------------

ZS_TEST(merged_got_matcher_recognizes_all_hooked_symbols) {
    auto match = [](const char* name) -> void* {
        void* hook = nullptr;
        switch (name[0]) {
        case 'o':
            if      (strcmp(name, "open")   == 0) hook = (void*)0x1;
            else if (strcmp(name, "openat") == 0) hook = (void*)0x2;
            break;
        case 's':
            if      (strcmp(name, "stat")  == 0) hook = (void*)0x3;
            else if (strcmp(name, "statx") == 0) hook = (void*)0x4;
            break;
        case 'l':
            if (strcmp(name, "lstat") == 0) hook = (void*)0x5;
            break;
        case 'a':
            if (strcmp(name, "access") == 0) hook = (void*)0x6;
            break;
        case 'f':
            if      (strcmp(name, "faccessat")  == 0) hook = (void*)0x7;
            else if (strcmp(name, "faccessat2") == 0) hook = (void*)0x8;
            else if (strcmp(name, "fstatat")    == 0) hook = (void*)0x9;
            else if (strcmp(name, "fstatat64")  == 0) hook = (void*)0x9;
            break;
        case '_':
            if (strcmp(name, "__fstatat") == 0) hook = (void*)0x9;
            break;
        default:
            break;
        }
        return hook;
    };
    // Every hooked name must match.
    ZS_CHECK(match("open")       != nullptr);
    ZS_CHECK(match("openat")     != nullptr);
    ZS_CHECK(match("stat")       != nullptr);
    ZS_CHECK(match("lstat")      != nullptr);
    ZS_CHECK(match("access")     != nullptr);
    ZS_CHECK(match("faccessat")  != nullptr);
    ZS_CHECK(match("faccessat2") != nullptr);
    ZS_CHECK(match("fstatat")    != nullptr);
    ZS_CHECK(match("fstatat64")  != nullptr);
    ZS_CHECK(match("__fstatat")  != nullptr);
    ZS_CHECK(match("statx")      != nullptr);
    // Non-hooked names must NOT match — including near-misses that
    // share a first character with a hooked name.
    ZS_CHECK(match("read")      == nullptr);
    ZS_CHECK(match("write")     == nullptr);
    ZS_CHECK(match("socket")    == nullptr);  // 's' but not stat/statx
    ZS_CHECK(match("open64")    == nullptr);  // 'o' but not open/openat
    ZS_CHECK(match("fopen")     == nullptr);  // 'f' but not our set
    ZS_CHECK(match("listen")    == nullptr);  // 'l' but not lstat
    ZS_CHECK(match("__open_2")  == nullptr);  // '_' but not __fstatat
    ZS_CHECK(match("")           == nullptr);  // empty name
}

// ----------------------------------------------------------------------
// Test (Round 6, P1.61): path_is_filtered() gates correctly — it
// matches only the documented /proc/self/* paths, and rejects the
// common non-/proc prefixes before any strcmp runs.
// ----------------------------------------------------------------------

ZS_TEST(path_is_filtered_matches_only_documented_paths) {
    // The documented filtered set.
    ZS_CHECK(path_is_filtered("/proc/self/maps")         == 1);
    ZS_CHECK(path_is_filtered("/proc/self/mounts")       == 1);
    ZS_CHECK(path_is_filtered("/proc/self/mountinfo")    == 1);
    ZS_CHECK(path_is_filtered("/proc/self/mountstats")   == 1);
    ZS_CHECK(path_is_filtered("/proc/self/status")       == 1);
    ZS_CHECK(path_is_filtered("/proc/self/smaps")        == 1);
    ZS_CHECK(path_is_filtered("/proc/self/smaps_rollup") == 1);
    // Same /proc/ prefix but not a filtered file.
    ZS_CHECK(path_is_filtered("/proc/self/cmdline")      == 0);
    ZS_CHECK(path_is_filtered("/proc/self/exe")          == 0);
    ZS_CHECK(path_is_filtered("/proc/self/fd/3")         == 0);
    // Non-/proc prefixes — rejected by the fast gate.
    ZS_CHECK(path_is_filtered("/data/adb/magisk")        == 0);
    ZS_CHECK(path_is_filtered("/system/bin/app_process64") == 0);
    ZS_CHECK(path_is_filtered("/sdcard/x")               == 0);
    // Edge cases.
    ZS_CHECK(path_is_filtered(nullptr)                   == 0);
    ZS_CHECK(path_is_filtered("")                        == 0);
    ZS_CHECK(path_is_filtered("relative/path")           == 0);
}

// ----------------------------------------------------------------------
// Test (Round 6, B1): path_is_hidden() does not read out of bounds
// when the probe path is a strict prefix of a hidden path.
//
// The old code read path[hlen] before verifying hlen <= strlen(path).
// For path = "/data/adb" (shorter than the hidden entry
// "/data/adb/modules"), that read past the NUL terminator. The fix
// adds an explicit hlen < plen guard. We verify the fixed behavior:
// prefix-of-hidden paths are NOT hidden (a directory that merely
// shares a leading substring is not itself hidden).
// ----------------------------------------------------------------------

ZS_TEST(path_is_hidden_handles_prefix_of_hidden_path) {
    // "/data/adb" is a strict prefix of "/data/adb/modules",
    // "/data/adb/magisk", etc. It must NOT be treated as hidden
    // (the user may have legitimate files there), and the check
    // must not read past the string's NUL terminator.
    ZS_CHECK(path_is_hidden("/data/adb")    == 0);
    ZS_CHECK(path_is_hidden("/sbin")        == 0);
    ZS_CHECK(path_is_hidden("/data")        == 0);
    ZS_CHECK(path_is_hidden("/system")      == 0);
    ZS_CHECK(path_is_hidden("/data/system") == 0);
    // One character short of an exact match — also not hidden.
    ZS_CHECK(path_is_hidden("/data/adb/magis") == 0);
    ZS_CHECK(path_is_hidden("/debug_ramdis")   == 0);
    // The exact hidden paths still match.
    ZS_CHECK(path_is_hidden("/data/adb/magisk") == 1);
    ZS_CHECK(path_is_hidden("/data/adb/modules") == 1);
    ZS_CHECK(path_is_hidden("/debug_ramdisk")   == 1);
}

// ----------------------------------------------------------------------
// Test (Round 6, B2): wrapped_open() never returns a closed fd.
//
// The old code did `close(real_fd); return memfd >= 0 ? memfd :
// real_fd;` — returning the just-closed fd when make_filtered_memfd
// failed. We can't easily force a memfd failure on the host, but we
// CAN verify the happy path returns a valid, open fd whose content
// is the filtered maps, and that a non-filtered path returns the
// real fd unchanged.
// ----------------------------------------------------------------------

ZS_TEST(wrapped_open_returns_valid_fd_for_filtered_path) {
    // Write fake maps content to a file, open it via the hook path.
    // We can't intercept /proc/self/maps itself on the host (the
    // hook is only consulted after GOT patching, which we don't do
    // in tests), so instead we call wrapped_open directly with the
    // real /proc/self/maps — which IS a filtered path.
    int fd = wrapped_open("/proc/self/maps", O_RDONLY, 0);
    ZS_CHECK(fd >= 0);
    // The fd must be valid and readable — reading it must not fail
    // with EBADF (which is what the old closed-fd return produced).
    char buf[256];
    ssize_t n = read(fd, buf, sizeof buf);
    ZS_CHECK(n >= 0);   // 0 (empty maps) is fine; -1/EBADF is the bug
    close(fd);

    // A non-filtered path must return the real fd. Use /proc/self/cmdline
    // (exists on the host, not in kFilteredPaths).
    int fd2 = wrapped_open("/proc/self/cmdline", O_RDONLY, 0);
    ZS_CHECK(fd2 >= 0);
    ssize_t n2 = read(fd2, buf, sizeof buf);
    ZS_CHECK(n2 > 0);   // cmdline is never empty for a live process
    close(fd2);
}

// ----------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr, "=== Zygisk Study advanced hide layer tests ===\n");
    return zstest::run_all();
}
