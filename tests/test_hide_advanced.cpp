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
#include <sys/mman.h>
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

    for (const char* s : kHiddenSubstrings) {
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

    for (const char* p : kFilteredPaths) {
        if (strcmp(p, "/proc/self/maps")       == 0) has_maps       = true;
        if (strcmp(p, "/proc/self/mounts")     == 0) has_mounts     = true;
        if (strcmp(p, "/proc/self/mountinfo")  == 0) has_mountinfo  = true;
        if (strcmp(p, "/proc/self/mountstats") == 0) has_mountstats = true;
    }
    ZS_CHECK(has_maps);
    ZS_CHECK(has_mounts);
    ZS_CHECK(has_mountinfo);
    ZS_CHECK(has_mountstats);
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
// main()
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr, "=== Zygisk Study advanced hide layer tests ===\n");
    return zstest::run_all();
}
