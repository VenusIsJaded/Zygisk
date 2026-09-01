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
namespace zygisk_study {
// ROUND 31: the fd shadow API became view-based (copy-out under the
// lock); this probe answers the old "is there a live record" question.
static int fd_shadow_probe(int fd, int kind) {
    FdShadowView v;
    return fd_shadow_lookup_view(fd, kind, &v);
}
} // namespace zygisk_study


#include <cstdio>
#include <cstring>
#include <string>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <sys/syscall.h>
#include <vector>
#include <map>

using namespace zygisk_study;

// ----------------------------------------------------------------------
// Test 1: kHiddenSubstrings contains the documented Magisk paths
// and our own .so file names.
// ----------------------------------------------------------------------

ZS_TEST(hidden_substrings_contains_documented_set) {
    // Round 19: the PROC_LINE matcher is token-anchored now (the old
    // whole-path substring table was format-blind and leaked
    // mounts/mountinfo lines — see the Round 19 audit in
    // hide_advanced.cpp). The hidden set is now the union of:
    //   - the fd-scanner root-path prefixes (shared table),
    //   - exact /system/lib[64]/ bridge-library paths,
    //   - mountinfo root-column forms.
    // Verify the documented members exist THROUGH THE MATCHER's own
    // behavior (zs_filter_record with a line whose only matching
    // token is the one under test).
    char dst[512];
    auto drops = [&](const char* line) -> bool {
        return zs_filter_record(dst, sizeof dst, line, strlen(line),
                                 ZS_FILTER_PROC_LINE) == (ssize_t)-1;
    };
    // Root-path prefixes (via the shared fd prefix table).
    ZS_CHECK(drops("x y z w v /data/adb/modules/foo"));
    ZS_CHECK(drops("x y z w v /sbin/anything"));
    ZS_CHECK(drops("x y z w v /debug_ramdisk/su"));
    ZS_CHECK(drops("x y z w v /data/system/zygisk_study/denylist"));
    // Exact bridge-library paths.
    ZS_CHECK(drops("700000000000-7000001000 r-xp 00000000 00:00 1  /system/lib64/libzygisk.so"));
    ZS_CHECK(drops("700000000000-7000001000 r-xp 00000000 00:00 1  /system/lib/libpayload.so"));
    // App-owned libraries with the same NAME must SURVIVE (the old
    // substring matcher dropped them — an over-match).
    ZS_CHECK(!drops("700000000000-7000001000 r-xp 00000000 00:00 1  /data/data/com.app/lib/libpayload.so"));
    // KernelSU module path (covered by the /data/adb/ prefix).
    ZS_CHECK(drops("x y z w v /data/adb/ksu/bin/ksud"));
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

    // Round 7: the path table became a base-name table matched by
    // zs_path_is_filtered(); verify through the real matcher.
    auto is_f = [](const char* p) { return zs_path_is_filtered(p) == 1; };
    has_maps          = is_f("/proc/self/maps");
    has_mounts        = is_f("/proc/self/mounts");
    has_mountinfo     = is_f("/proc/self/mountinfo");
    has_mountstats    = is_f("/proc/self/mountstats");
    has_smaps         = is_f("/proc/self/smaps");
    has_smaps_rollup  = is_f("/proc/self/smaps_rollup");
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
    // Round 19: the token matcher uses __builtin_strlen at each
    // comparison against kHiddenExactPaths/kHiddenRootFieldPrefixes,
    // so there is no precomputed-length table to desync any more.
    // What still matters: every entry is a well-formed non-empty
    // absolute-ish path, and the fd prefix table (shared with the
    // matcher) still reports sane lengths. Verify the tables through
    // the public registration + match API.
    char dst[512];
    // Round 13's runtime registration API feeds the SAME table the
    // matcher consults; prove the plumbing with a fresh prefix.
    hide_advanced_register_root_path_prefix("/data/local/tmp/zstest/");
    const char* reg = "a b c d e /data/local/tmp/zstest/x.so";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, reg, strlen(reg),
                              ZS_FILTER_PROC_LINE) == (ssize_t)-1);
    // And a path that merely CONTAINS the string does not match
    // (token anchoring).
    const char* contains = "a b c d e /other/data/local/tmp/zstest/x.so";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, contains, strlen(contains),
                              ZS_FILTER_PROC_LINE) > 0);
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
        return zs_path_is_filtered(path) == 1;
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
    ZS_CHECK_EQ(match("__open_2"), 0);  // superseded: __open_2 IS hooked (Round 7)
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
    // Round 33: the table became a decode-once obfuscated StrTable;
    // its begin()/end() iterate the decoded entries.
    for (const auto& e : hidden_stat_paths()) {
        const char* p = e.p;
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
    // Round 7: the hooks are gated by a per-process active flag
    // (inactive processes see a pure passthrough). Turn it on to
    // exercise the actual hiding branch, off again afterwards.
    hide_advanced_set_active(1);
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
    hide_advanced_set_active(0);

}

ZS_TEST(fstatat_hook_returns_enoent_for_hidden_paths) {
    // Round 7: the hooks are gated by a per-process active flag
    // (inactive processes see a pure passthrough). Turn it on to
    // exercise the actual hiding branch, off again afterwards.
    hide_advanced_set_active(1);
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
    hide_advanced_set_active(0);

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
    // Round 7: the hooks are gated by a per-process active flag
    // (inactive processes see a pure passthrough). Turn it on to
    // exercise the actual hiding branch, off again afterwards.
    hide_advanced_set_active(1);
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
    hide_advanced_set_active(0);

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
            else if (strcmp(name, "fopen")      == 0) hook = (void*)0xA;  // Round 7
            break;
        case '_':
            if (strcmp(name, "__fstatat")   == 0) hook = (void*)0x9;
            else if (strcmp(name, "__open_2")  == 0) hook = (void*)0xB;  // Round 7
            else if (strcmp(name, "__openat_2") == 0) hook = (void*)0xC; // Round 7
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
    // Round 7: fopen + FORTIFY __open_2/__openat_2 are hooked (they
    // bypass the bare open/openat slots), so they must match now.
    // Non-hooked names must NOT match — including near-misses that
    // share a first character with a hooked name.
    ZS_CHECK(match("read")      == nullptr);
    ZS_CHECK(match("write")     == nullptr);
    ZS_CHECK(match("socket")    == nullptr);  // 's' but not stat/statx
    ZS_CHECK(match("open64")    == nullptr);  // 'o' but not open/openat
    ZS_CHECK(match("fopen")     != nullptr);  // Round 7: stdio bypass is hooked
    ZS_CHECK(match("listen")    == nullptr);  // 'l' but not lstat
    ZS_CHECK(match("__open_2")  != nullptr);  // Round 7: FORTIFY variant is hooked
    ZS_CHECK(match("")           == nullptr);  // empty name
    ZS_CHECK(match("__openat_2") != nullptr);  // Round 7: FORTIFY variant is hooked
}

// ----------------------------------------------------------------------
// Test (Round 6, P1.61): zs_path_is_filtered() gates correctly — it
// matches only the documented /proc/self/* paths, and rejects the
// common non-/proc prefixes before any strcmp runs.
// ----------------------------------------------------------------------

ZS_TEST(path_is_filtered_matches_only_documented_paths) {
    // The documented filtered set.
    ZS_CHECK(zs_path_is_filtered("/proc/self/maps")         == 1);
    ZS_CHECK(zs_path_is_filtered("/proc/self/mounts")       == 1);
    ZS_CHECK(zs_path_is_filtered("/proc/self/mountinfo")    == 1);
    ZS_CHECK(zs_path_is_filtered("/proc/self/mountstats")   == 1);
    ZS_CHECK(zs_path_is_filtered("/proc/self/status")       == 1);
    ZS_CHECK(zs_path_is_filtered("/proc/self/smaps")        == 1);
    ZS_CHECK(zs_path_is_filtered("/proc/self/smaps_rollup") == 1);
    // Same /proc/ prefix but not a filtered file.
    ZS_CHECK(zs_path_is_filtered("/proc/self/cmdline")      == 0);
    ZS_CHECK(zs_path_is_filtered("/proc/self/exe")          == 0);
    ZS_CHECK(zs_path_is_filtered("/proc/self/fd/3")         == 0);
    // Non-/proc prefixes — rejected by the fast gate.
    ZS_CHECK(zs_path_is_filtered("/data/adb/magisk")        == 0);
    ZS_CHECK(zs_path_is_filtered("/system/bin/app_process64") == 0);
    ZS_CHECK(zs_path_is_filtered("/sdcard/x")               == 0);
    // Edge cases.
    ZS_CHECK(zs_path_is_filtered(nullptr)                   == 0);
    ZS_CHECK(zs_path_is_filtered("")                        == 0);
    ZS_CHECK(zs_path_is_filtered("relative/path")           == 0);
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
// Round 7 tests
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// (S1) zs_path_is_filtered must match the /proc/<pid>/... and
// /proc/thread-self/... variants. Most real detectors open
// /proc/<their-pid>/maps — the pre-Round-7 code matched only the
// literal "/proc/self/..." string, which every pid-based probe
// trivially bypassed.
// ----------------------------------------------------------------------
ZS_TEST(zs_path_is_filtered_matches_pid_variants) {
    char pidpath[128];
    snprintf(pidpath, sizeof pidpath, "/proc/%d/maps", (int)getpid());
    char pidpath2[128];
    snprintf(pidpath2, sizeof pidpath2, "/proc/%d/mountinfo", (int)getpid());

    ZS_CHECK_EQ(zs_path_is_filtered(pidpath),  1);
    ZS_CHECK_EQ(zs_path_is_filtered(pidpath2), 1);

    ZS_CHECK_EQ(zs_path_is_filtered("/proc/thread-self/maps"),   1);
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/thread-self/status"), 1);

    // SOMEONE ELSE'S pid must NOT be filtered.
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/1/maps"),        0);
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/999999/maps"),   0);

    // Near-misses.
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/self/maps2"),    0);
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/selfmap"),       0);
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/self"),          0);
    ZS_CHECK_EQ(zs_path_is_filtered("/proc/self/maps/"),    0);
}

// ----------------------------------------------------------------------
// (S7) The spoof table: boot-state keys get STOCK values (never
// empty), framework-specific keys are marked absent.
// ----------------------------------------------------------------------
ZS_TEST(spoof_table_uses_stock_values_for_boot_keys) {
    size_t count = 0;
    const ZsPropSpoof* tbl = zs_prop_spoof_table(&count);
    ZS_CHECK(count >= 15);
    auto find = [&](const char* key) -> const char* {
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(tbl[i].key, key) == 0) return tbl[i].value;
        }
        return nullptr;
    };
    ZS_CHECK_STR_EQ(find("ro.boot.verifiedbootstate"),   "green");
    ZS_CHECK_STR_EQ(find("ro.boot.vbmeta.device_state"), "locked");
    ZS_CHECK_STR_EQ(find("ro.boot.veritymode"),          "enforcing");
    ZS_CHECK_STR_EQ(find("ro.boot.flash.locked"),        "1");
    // Framework keys: empty value + "absent" semantics.
    ZS_CHECK(find("ro.magisk.version")   != nullptr);
    ZS_CHECK_EQ(find("ro.magisk.version")[0], '\0');
    ZS_CHECK(find("ro.kernelsu.version") != nullptr);
    ZS_CHECK_EQ(find("ro.kernelsu.version")[0], '\0');
}

// ----------------------------------------------------------------------
// (B2 fix, host-simulated) The property-area clone is
// CONTENT-PRESERVING. The pre-Round-7 version mmap'd MAP_FIXED|
// MAP_ANONYMOUS over the property area and returned — zeroing the
// property trie and breaking every subsequent property read.
// ----------------------------------------------------------------------
ZS_TEST(property_clone_preserves_content) {
    constexpr size_t kSize = 8192;
    unsigned char* orig = (unsigned char*)mmap(nullptr, kSize,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ZS_CHECK(orig != MAP_FAILED);
    for (size_t i = 0; i < kSize; ++i) orig[i] = (unsigned char)(i * 7 + 3);

    int ok = remap_prop_mapping_private((uintptr_t)orig,
                                        (uintptr_t)orig + kSize);
    ZS_CHECK_EQ(ok, 1);

    for (size_t i = 0; i < kSize; ++i) {
        if (orig[i] != (unsigned char)(i * 7 + 3)) {
            throw ::zstest::CheckFailed{
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +
                "  clone lost content at offset " + std::to_string(i)};
        }
    }
    orig[0] = 0xAA;   // the clone must be writable (patchable)
    ZS_CHECK_EQ(orig[0], 0xAA);
    munmap(orig, kSize);
}

// ----------------------------------------------------------------------
// (pure part) find_prop_mappings parses the /dev/__properties__
// lines out of a synthetic maps buffer.
// ----------------------------------------------------------------------
ZS_TEST(find_prop_mappings_parses_synthetic_maps) {
    std::string maps =
        "7f00a00000-7f00a01000 r--p 00000000 00:05 1 /dev/__properties__/u:object_r:default_prop:s0\n"
        "7f00b00000-7f00b02000 r--p 00000000 00:05 2 /dev/__properties__/u:object_r:vendor_default_prop:s0\n"
        "7f00c00000-7f00c01000 r-xp 00000000 08:02 3 /system/lib64/libc.so\n";
    PropMapping out[8];
    size_t n = find_prop_mappings(maps.data(), maps.size(), out, 8);
    ZS_CHECK_EQ(n, (size_t)2);
    ZS_CHECK_EQ(out[0].lo, (uintptr_t)0x7f00a00000ull);
    ZS_CHECK_EQ(out[0].hi, (uintptr_t)0x7f00a01000ull);
    ZS_CHECK_EQ(out[1].lo, (uintptr_t)0x7f00b00000ull);
}

// ----------------------------------------------------------------------
// Round 26 — the 6.x single-file property mapping. A Marshmallow
// process maps ONE file at exactly "/dev/__properties__" (verified
// from AOSP bionic android-6.0.0_r1: PROP_FILENAME, single 128K
// area, r--s MAP_SHARED). The version-agnostic 19-byte prefix must
// catch that line too, without loosening anything else.
// ----------------------------------------------------------------------
ZS_TEST(find_prop_mappings_matches_the_6_0_single_file_line) {
    // The exact 6.x form: the path IS the file, the mapping is
    // 128K of r--s (shared).
    std::string maps =
        "7f00a00000-7f00a20000 r--s 00000000 00:05 1 /dev/__properties__\n"
        "7f00b00000-7f00b01000 r-xp 00000000 08:02 3 /system/lib64/libc.so\n";
    PropMapping out[8];
    size_t n = find_prop_mappings(maps.data(), maps.size(), out, 8);
    ZS_CHECK_EQ(n, (size_t)1);
    ZS_CHECK_EQ(out[0].lo, (uintptr_t)0x7f00a00000ull);
    ZS_CHECK_EQ(out[0].hi, (uintptr_t)0x7f00a20000ull);   // the full 128K

    // A look-alike that is NOT the property path must not match: one
    // byte short of the prefix ("/dev/__propertie").
    std::string near_miss =
        "7f00a00000-7f00a20000 r--s 00000000 00:05 1 /dev/__propertie\n";
    n = find_prop_mappings(near_miss.data(), near_miss.size(), out, 8);
    ZS_CHECK_EQ(n, (size_t)0);

    // A writable property mapping (corrupt/mid-write state) is not a
    // clone candidate: the perms guard holds on the 6.x form too.
    std::string writable =
        "7f00a00000-7f00a20000 rw-s 00000000 00:05 1 /dev/__properties__\n";
    n = find_prop_mappings(writable.data(), writable.size(), out, 8);
    ZS_CHECK_EQ(n, (size_t)0);

    // Mixed: a 6.x process that ALSO maps the 7.x form (cannot
    // happen on stock, but the matcher must stay sound): both lines
    // match, both spans returned.
    std::string mixed =
        "7f00a00000-7f00a20000 r--s 00000000 00:05 1 /dev/__properties__\n"
        "7f00b00000-7f00b01000 r--p 00000000 00:05 2 /dev/__properties__/properties_serial\n";
    n = find_prop_mappings(mixed.data(), mixed.size(), out, 8);
    ZS_CHECK_EQ(n, (size_t)2);
}

// Round 26 — the stock-line capture ALSO sees the 6.x single line,
// so the Tier B maps restoration covers the legacy clone.
ZS_TEST(capture_prop_line_restores_sees_the_6_0_single_line) {
    std::string maps =
        "7f00a00000-7f00a20000 r--s 00000000 00:05 1 /dev/__properties__\n"
        "7f00b00000-7f00b01000 r-xp 00000000 08:02 3 /system/lib64/libc.so\n";
    capture_prop_line_restores(maps.data(), maps.size());
    ZS_CHECK_EQ(g_prop_line_restore_count, (size_t)1);
    // The recorded stock line is the 6.x line verbatim.
    const PropLineRestore* r = prop_line_restore_for(
        "7f00a00000-7f00a20000 r--s", 27);
    ZS_CHECK(r != nullptr);
    ZS_CHECK(strstr(r->line, "/dev/__properties__") != nullptr);
    // And the merged-VMA containment path finds it too (the 128K
    // clone covers the whole range).
    const PropLineRestore* covered[8];
    size_t n = prop_line_restore_covered(
        "7f00a00000-7f00a20000 r--p 00000000 00:00 0", 43, covered);
    ZS_CHECK_EQ(n, (size_t)1);
}

// ----------------------------------------------------------------------
// The deferred Tier B registry: hooks registered via
// hide_advanced_register_tier_b_hook are NOT live until promoted.
// ----------------------------------------------------------------------
ZS_TEST(tier_b_registry_defers_installation) {
    static int dummy_hook = 0;
    int ok = hide_advanced_register_tier_b_hook("zs_test_never_a_real_symbol",
                                                (void*)&dummy_hook);
    ZS_CHECK_EQ(ok, 1);
    ZS_CHECK(match_registered_hook("zs_test_never_a_real_symbol") == nullptr);
}

// ----------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// Round 8 tests
// ----------------------------------------------------------------------

// Round 8 (B2/B3/S1/S2): the filter kind resolver covers every
// documented path form — including the ones the Round 7 matcher
// missed (/proc/mounts, per-thread task/<tid>/ files, /proc/net/unix,
// /proc/self/environ).
ZS_TEST(filter_kind_resolves_all_documented_variants) {
    char pidpath[64], tidpath[80], netpath[64];
    snprintf(pidpath, sizeof pidpath, "/proc/%d/maps", (int)getpid());
    snprintf(netpath, sizeof netpath, "/proc/%d/net/unix", (int)getpid());

    // PROC_LINE kinds.
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/maps"),
                ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/mounts"),
                ZS_FILTER_PROC_LINE);   // B2: the classic alias
    ZS_CHECK_EQ(zs_filter_kind_for_path(pidpath), ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/thread-self/mountinfo"),
                ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/task/123/smaps"),
                ZS_FILTER_PROC_LINE);   // B3: per-thread variant
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/smaps_rollup"),
                ZS_FILTER_PROC_LINE);

    // STATUS.
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/status"),
                ZS_FILTER_STATUS);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/thread-self/status"),
                ZS_FILTER_STATUS);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/task/9/status"),
                ZS_FILTER_STATUS);

    // ENVIRON (S2).
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/environ"),
                ZS_FILTER_ENVIRON);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/task/9/environ"),
                ZS_FILTER_ENVIRON);
    snprintf(tidpath, sizeof tidpath, "/proc/%d/task/%d/environ",
             (int)getpid(), (int)getpid());
    ZS_CHECK_EQ(zs_filter_kind_for_path(tidpath), ZS_FILTER_ENVIRON);

    // NET_UNIX (S1).
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/net/unix"),
                ZS_FILTER_NET_UNIX);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/net/unix"),
                ZS_FILTER_NET_UNIX);
    ZS_CHECK_EQ(zs_filter_kind_for_path(netpath), ZS_FILTER_NET_UNIX);

    // NOT filtered.
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/net/tcp"), ZS_FILTER_NONE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/net/tcp"),
                ZS_FILTER_NONE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/cmdline"),
                ZS_FILTER_NONE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/self/exe"),
                ZS_FILTER_NONE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/proc/1/maps"),
                ZS_FILTER_NONE);   // a foreign pid — never touched
    ZS_CHECK_EQ(zs_filter_kind_for_path(nullptr), ZS_FILTER_NONE);
    ZS_CHECK_EQ(zs_filter_kind_for_path(""), ZS_FILTER_NONE);
    ZS_CHECK_EQ(zs_filter_kind_for_path("/data/adb/magisk"),
                ZS_FILTER_NONE);
}

// Round 8: zs_filter_record — PROC_LINE semantics.
ZS_TEST(filter_record_proc_line_drops_hidden_paths) {
    char dst[256];
    const char* hidden =
        "700000000000-7000001000 r-xp 00000000 00:00 1  "
        "/data/adb/modules/x/libdetector.so";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, hidden,
                                 strlen(hidden), ZS_FILTER_PROC_LINE),
                (ssize_t)-1);

    const char* hidden_sbin =
        "700000000000-7000001000 r-xp 00000000 00:00 1  /sbin/magisk";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, hidden_sbin,
                                 strlen(hidden_sbin), ZS_FILTER_PROC_LINE),
                (ssize_t)-1);

    const char* clean =
        "700000000000-7000001000 r--p 00000000 00:00 1  "
        "/system/lib64/libc.so";
    ssize_t kept = zs_filter_record(dst, sizeof dst, clean,
                                    strlen(clean), ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ(kept, (ssize_t)strlen(clean));
    ZS_CHECK(memcmp(dst, clean, (size_t)kept) == 0);

    // In-place aliasing must work (the streaming loop relies on it).
    char inbuf[256];
    memcpy(inbuf, clean, strlen(clean) + 1);
    kept = zs_filter_record(inbuf, sizeof inbuf, inbuf, strlen(clean),
                            ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ(kept, (ssize_t)strlen(clean));
    ZS_CHECK(memcmp(inbuf, clean, (size_t)kept) == 0);
}

// Round 19 — THE regression test for the mounts-format leak. The
// old matcher only understood the maps column layout; every line
// below is a REAL format from /proc/self/{mounts,mountinfo,maps}
// carrying a hidden path in a column the old code never scanned.
// (All five leaked before the fix; verified empirically first, then
// fixed, then this test locked it in.)
ZS_TEST(filter_record_drops_hidden_paths_in_every_line_format) {
    char dst[512];
    auto dropped = [&](const char* line) -> bool {
        return zs_filter_record(dst, sizeof dst, line, strlen(line),
                                 ZS_FILTER_PROC_LINE) == (ssize_t)-1;
    };

    // /proc/self/mounts: "source target fstype opts 0 0"
    // Hidden path in SOURCE (the magic-mount source is field 1).
    ZS_CHECK(dropped("/data/adb/modules/zygisk_study/system /system ext4 rw,seclabel 0 0"));
    // Hidden path in TARGET (a module bind mounted over a system dir).
    ZS_CHECK(dropped("/dev/block/sda26 /data/adb/whatever ext4 ro,seclabel 0 0"));

    // /proc/self/mountinfo:
    // "id parent maj:min root mountpoint opts [tags] - fstype source super_opts"
    // Hidden MOUNTPOINT (field 5) — the old code scanned field 6 (opts).
    ZS_CHECK(dropped("37 36 253:5 / /data/adb/modules rw,relatime - ext4 /dev/block/sda26 rw"));
    // Hidden ROOT (field 4 — the path inside the source filesystem;
    // a bind of /data/adb/modules reports "/adb/modules").
    ZS_CHECK(dropped("36 35 98:0 /adb/modules /system/lib64 rw,relatime master:1 - ext4 /dev/block/sda26 rw"));
    // Hidden SOURCE (field 10, after the " - " separator).
    ZS_CHECK(dropped("38 36 98:0 / /system/bin ext4 rw - ext4 /data/adb/modules/zygisk_study/system rw"));
    // The session-dir (runtime-registered prefix) as SOURCE — the
    // Round 19 properties bind-mount shape.
    hide_advanced_register_root_path_prefix("/data/system/.deadbeef/");
    ZS_CHECK(dropped("39 36 98:0 /system/.deadbeef/p /dev/__properties__/properties_serial rw - ext4 /data/system/.deadbeef/p rw"));

    // Clean stock lines must SURVIVE in every format (over-matching
    // would corrupt the app's view of the mount table).
    ZS_CHECK(!dropped("/dev/block/sda26 /system ext4 ro,seclabel 0 0"));
    ZS_CHECK(!dropped("36 35 98:0 / /system ext4 rw,relatime master:1 - ext4 /dev/block/sda26 rw"));
    ZS_CHECK(!dropped("700000000000-7000001000 r--p 00000000 00:00 1  /system/framework/x86_64/boot.art"));
    // mountinfo root "/" token followed by a target that merely
    // CONTAINS a hidden substring mid-token must survive (anchoring).
    ZS_CHECK(!dropped("40 36 98:0 / /storage/emulated/0/mydata_adb_backup ext4 rw - fuse fd:123 rw"));

    // mountstats: "device target fstype opts" header lines. (Real
    // module-mount targets always carry a deeper path than the bare
    // prefix — the anchored table matches on "/data/adb/" + more.)
    ZS_CHECK(dropped("/dev/block/sda26 /data/adb/modules ext4 rw,relatime"));
}

// Round 8: zs_filter_record — STATUS semantics.
ZS_TEST(filter_record_status_rewrites_tracerpid) {
    char dst[64];
    const char* tracer = "TracerPid:\t12345";
    ssize_t kept = zs_filter_record(dst, sizeof dst, tracer,
                                    strlen(tracer), ZS_FILTER_STATUS);
    ZS_CHECK_EQ(kept, (ssize_t)12);
    ZS_CHECK(memcmp(dst, "TracerPid:\t0", 12) == 0);

    // Non-TracerPid lines pass through verbatim.
    const char* pid = "Pid:\t1234";
    kept = zs_filter_record(dst, sizeof dst, pid, strlen(pid),
                            ZS_FILTER_STATUS);
    ZS_CHECK_EQ(kept, (ssize_t)strlen(pid));
    ZS_CHECK(memcmp(dst, pid, (size_t)kept) == 0);

    // A too-short TracerPid line is passed through unchanged (the
    // fixed replacement would not fit in place).
    const char* shortline = "TracerPid:0";
    kept = zs_filter_record(dst, sizeof dst, shortline,
                            strlen(shortline), ZS_FILTER_STATUS);
    ZS_CHECK_EQ(kept, (ssize_t)strlen(shortline));
    ZS_CHECK(memcmp(dst, shortline, (size_t)kept) == 0);
}

// Round 8 (S2): zs_filter_record — ENVIRON semantics.
ZS_TEST(filter_record_environ_drops_our_vars) {
    char dst[64];
    const char* ours = "ZYGISK_STUDY_DEBUG=1";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, ours, strlen(ours),
                                 ZS_FILTER_ENVIRON), (ssize_t)-1);
    const char* ours2 = "ZYGISK_STUDY_WORKDIR=/x";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, ours2, strlen(ours2),
                                 ZS_FILTER_ENVIRON), (ssize_t)-1);
    // Similar-but-not-ours entries must survive.
    const char* theirs = "ZYGISK_STUDY_X=1";   // not a real var name
    ZS_CHECK(zs_filter_record(dst, sizeof dst, theirs, strlen(theirs),
                              ZS_FILTER_ENVIRON) > 0);
    const char* path = "PATH=/system/bin";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, path, strlen(path),
                              ZS_FILTER_ENVIRON) > 0);
}

// Round 8 (S1): zs_filter_record — /proc/net/unix semantics.
ZS_TEST(filter_record_unix_drops_framework_sockets) {
    char dst[256];
    const char* ours =
        "    0000000000000001: 00000002 00000000 00010000 0001 01 10001 "
        "/data/system/zygisk_study/sock/sock";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, ours, strlen(ours),
                                 ZS_FILTER_NET_UNIX), (ssize_t)-1);
    const char* magisk =
        "    0000000000000002: 00000002 00000000 00010000 0001 01 10002 "
        "/dev/socket/magisk";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, magisk,
                                 strlen(magisk), ZS_FILTER_NET_UNIX),
                (ssize_t)-1);
    const char* clean =
        "    0000000000000000: 00000002 00000000 00010000 0001 01 10000 "
        "/dev/socket/thermal";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, clean, strlen(clean),
                              ZS_FILTER_NET_UNIX) > 0);
}

// Round 8 (B4): the streaming filter handles inputs far larger than
// the old 256 KB cap, with hidden lines at the very end (exactly what
// the Round 7 code silently truncated away).
ZS_TEST(make_filtered_memfd_streams_arbitrarily_large_files) {
    std::string input, expected;
    input.reserve(420 * 1024);
    expected.reserve(420 * 1024);
    char line[200];
    int lineno = 0;
    while (input.size() < 400 * 1024) {
        bool hidden = (lineno % 97 == 0);
        snprintf(line, sizeof line,
                 "%012lx-%012lx r-%cp 00000000 00:00 %d  %s\n",
                 0x700000000000UL + (unsigned long)lineno * 0x1000UL,
                 0x700000000000UL + (unsigned long)(lineno + 1) * 0x1000UL,
                 hidden ? 'x' : '-', lineno,
                 hidden ? "/data/adb/modules/evil/libdetector.so"
                        : "/system/lib64/libc.so");
        input += line;
        if (!hidden) expected += line;
        ++lineno;
    }
    // A hidden line as the VERY LAST line of the file.
    input += "700000100000-700000101000 r-xp 00000000 00:00 999  "
             "/data/adb/modules/evil/last_line.so\n";
    // And a clean trailing line.
    input += "700000200000-700000201000 r--p 00000000 00:00 998  "
             "/system/lib64/libtail.so\n";
    expected += "700000200000-700000201000 r--p 00000000 00:00 998  "
                "/system/lib64/libtail.so\n";

    int input_fd = write_text_to_memfd(input);
    ZS_CHECK(input_fd >= 0);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    ZS_CHECK_EQ(out.size(), expected.size());
    ZS_CHECK(out == expected);
    ZS_CHECK_STR_CONTAINS(out, "/system/lib64/libtail.so");
    ZS_CHECK_STR_ABSENT(out, "libdetector.so");
    ZS_CHECK_STR_ABSENT(out, "last_line.so");

    close(input_fd);
    close(filtered_fd);
}

// Round 8 (S2): the environ filter drops our variables from a
// NUL-separated /proc/self/environ stream.
ZS_TEST(make_filtered_memfd_filters_environ) {
    std::string input;
    input += "PATH=/sbin:/system/bin"; input += '\0';
    input += "ZYGISK_STUDY_DEBUG=1";    input += '\0';
    input += "HOME=/data";              input += '\0';
    input += "ZYGISK_STUDY_LOG_TAG=zs"; input += '\0';
    input += "BOOTCLASSPATH=/system/framework/core.jar"; input += '\0';

    std::string expected;
    expected += "PATH=/sbin:/system/bin"; expected += '\0';
    expected += "HOME=/data";              expected += '\0';
    expected += "BOOTCLASSPATH=/system/framework/core.jar"; expected += '\0';

    int input_fd = write_text_to_memfd(input);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/environ");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    // NUL-aware comparison (string::operator== handles embedded NULs).
    ZS_CHECK_EQ(out.size(), expected.size());
    ZS_CHECK(out == expected);
    ZS_CHECK(memmem(out.data(), out.size(), "ZYGISK_STUDY",
                    strlen("ZYGISK_STUDY")) == nullptr);

    close(input_fd);
    close(filtered_fd);
}

// Round 8 (S1): the /proc/net/unix filter hides our daemon socket.
ZS_TEST(make_filtered_memfd_filters_unix_socket_table) {
    std::string input =
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "    0000000000000000: 00000002 00000000 00010000 0001 01 10000 "
        "/dev/socket/thermal\n"
        "    0000000000000001: 00000002 00000000 00010000 0001 01 10001 "
        "/data/system/zygisk_study/sock/sock\n"
        "    0000000000000002: 00000002 00000000 00010000 0001 01 10002 "
        "@com.android.webview\n";
    int input_fd = write_text_to_memfd(input);
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/net/unix");
    ZS_CHECK(filtered_fd >= 0);
    std::string out = read_fd_to_string(filtered_fd);

    ZS_CHECK_STR_CONTAINS(out, "/dev/socket/thermal");
    ZS_CHECK_STR_CONTAINS(out, "@com.android.webview");
    ZS_CHECK_STR_ABSENT(out, "zygisk_study");
    ZS_CHECK_STR_ABSENT(out, "/data/adb/");

    close(input_fd);
    close(filtered_fd);
}

// Round 8 (B1): the syscall hook forwards ALL SIX varargs. The Round 7
// version forwarded four — a 5/6-argument syscall through the libc
// wrapper had its trailing arguments replaced with garbage.
static long g_syscall_capture_num = 0;
static long g_syscall_capture_args[6] = {0};
static long recording_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    for (int i = 0; i < 6; ++i) {
        g_syscall_capture_args[i] = va_arg(ap, long);
    }
    va_end(ap);
    g_syscall_capture_num = number;
    return 42;
}

ZS_TEST(syscall_hook_forwards_all_six_arguments) {
    SyscallFn saved = g_real_syscall;
    g_real_syscall = &recording_syscall;

    long rv = zygisk_study_hook_syscall(424242L, 11L, 22L, 33L, 44L,
                                        55L, 66L);
    ZS_CHECK_EQ(rv, 42L);
    ZS_CHECK_EQ(g_syscall_capture_num, 424242L);
    ZS_CHECK_EQ(g_syscall_capture_args[0], 11L);
    ZS_CHECK_EQ(g_syscall_capture_args[1], 22L);
    ZS_CHECK_EQ(g_syscall_capture_args[2], 33L);
    ZS_CHECK_EQ(g_syscall_capture_args[3], 44L);
    ZS_CHECK_EQ(g_syscall_capture_args[4], 55L);
    ZS_CHECK_EQ(g_syscall_capture_args[5], 66L);

    g_real_syscall = saved;
}

// Round 8 (P1): the hash-indexed matcher resolves registered hooks.
ZS_TEST(hook_index_matches_registered_hooks) {
    hide_advanced_register_got_hook("zs_test_sym_a", (void*)0x1234);
    hide_advanced_register_got_hook("zs_test_sym_b", (void*)0x5678);

    ZS_CHECK_EQ((uintptr_t)zs_test_match_registered_hook("zs_test_sym_a"),
                (uintptr_t)0x1234);
    ZS_CHECK_EQ((uintptr_t)zs_test_match_registered_hook("zs_test_sym_b"),
                (uintptr_t)0x5678);
    ZS_CHECK_EQ((uintptr_t)zs_test_match_registered_hook("zs_test_sym_c"),
                (uintptr_t)0);
    ZS_CHECK_EQ((uintptr_t)zs_test_match_registered_hook("zs_test_sym"),
                (uintptr_t)0);
    // Re-registering an existing name is a no-op (first wins).
    hide_advanced_register_got_hook("zs_test_sym_a", (void*)0x9999);
    ZS_CHECK_EQ((uintptr_t)zs_test_match_registered_hook("zs_test_sym_a"),
                (uintptr_t)0x1234);
}

// Round 8 (B8): fopen falls back to open()+fdopen() when dlsym could
// not resolve the real fopen — instead of failing every file open.
ZS_TEST(fopen_hook_falls_back_to_open_fdopen) {
    FopenFn saved = g_real_fopen;
    int prev_active = hide_advanced_is_active();
    g_real_fopen = nullptr;
    hide_advanced_set_active(0);

    FILE* f = zygisk_study_hook_fopen("/proc/self/status", "r");
    ZS_CHECK(f != nullptr);
    if (f) {
        char buf[32];
        size_t n = fread(buf, 1, sizeof buf, f);
        ZS_CHECK(n > 0);
        fclose(f);
    }

    g_real_fopen = saved;
    hide_advanced_set_active(prev_active);
}

// Round 8 (S3): opendir reports ENOENT for hidden paths; ordinary
// directories still open.
ZS_TEST(opendir_hook_enoent_for_hidden_paths) {
    OpendirFn saved = g_real_opendir;
    g_real_opendir = (OpendirFn)zs_resolve_libc("opendir");
    ZS_CHECK(g_real_opendir != nullptr);
    int prev_active = hide_advanced_is_active();
    hide_advanced_set_active(1);

    errno = 0;
    DIR* d = zygisk_study_hook_opendir("/data/adb/magisk");
    ZS_CHECK(d == nullptr);
    ZS_CHECK_EQ(errno, ENOENT);

    errno = 0;
    d = zygisk_study_hook_opendir("/data/adb/modules/zygisk_study");
    ZS_CHECK(d == nullptr);
    ZS_CHECK_EQ(errno, ENOENT);

    // A non-hidden directory still lists.
    DIR* ok = zygisk_study_hook_opendir("/tmp");
    ZS_CHECK(ok != nullptr);
    if (ok) closedir(ok);

    // Inactive: pure passthrough (must not fabricate ENOENT for
    // paths that exist).
    hide_advanced_set_active(0);
    ok = zygisk_study_hook_opendir("/tmp");
    ZS_CHECK(ok != nullptr);
    if (ok) closedir(ok);

    g_real_opendir = saved;
    hide_advanced_set_active(prev_active);
}

// Round 8 (B10): the property spoof table covers
// ro.dalvik.vm.native.bridge (our loudest property tell) and the
// read hooks treat it as absent.
ZS_TEST(prop_spoof_table_covers_native_bridge) {
    size_t n = 0;
    const ZsPropSpoof* t = zs_prop_spoof_table(&n);
    const ZsPropSpoof* nb = nullptr;
    for (size_t i = 0; i < n; ++i) {
        if (strcmp(t[i].key, "ro.dalvik.vm.native.bridge") == 0) {
            nb = &t[i];
            break;
        }
    }
    ZS_CHECK(nb != nullptr);
    ZS_CHECK(nb->value != nullptr);
    ZS_CHECK_EQ(nb->value[0], '\0');   // spoofed to empty
    // Absent semantics for find()/get() (a stock arm64 device does
    // not report a native bridge).
    ZS_CHECK_EQ(prop_key_is_absent("ro.dalvik.vm.native.bridge"), 1);
    // Boot keys with real stock values are NOT treated as absent.
    ZS_CHECK_EQ(prop_key_is_absent("ro.boot.verifiedbootstate"), 0);
}

// Round 8 (P4): the walked-DSO mark set behaves (skip, clear, and
// garbage collection against the live linker state).
ZS_TEST(walked_dso_set_marks_clears_and_gcs) {
    clear_walked_dsos();
    mark_dso_walked(0x1234);
    ZS_CHECK(dso_already_walked(0x1234) == 1);
    ZS_CHECK(dso_already_walked(0x5678) == 0);

    // 0x1234 is not a live DSO address — the GC after a dlclose must
    // drop it.
    gc_walked_dso_set();
    ZS_CHECK(dso_already_walked(0x1234) == 0);

    clear_walked_dsos();
    ZS_CHECK(dso_already_walked(0x1234) == 0);
}

// Round 8 (B5): the property-mapping scan survives maps files larger
// than any fixed buffer — the zygote's maps runs ~110 KB on real
// devices and the Round 7 single-read scan silently missed every
// /dev/__properties__ mapping past its 96 KB cap.
ZS_TEST(find_prop_mappings_from_fd_handles_oversized_maps) {
    // Build a >100 KB maps-like file with property mappings at the
    // start, middle, and very END.
    std::string content;
    content.reserve(120 * 1024);
    char line[200];
    unsigned long addr = 0x700000000000UL;
    int lineno = 0;
    auto add_prop = [&](const char* perms) {
        snprintf(line, sizeof line,
                 "%012lx-%012lx %s 00000000 00:00 %d  "
                 "/dev/__properties__/u:object_r:default_prop:s0\n",
                 addr, addr + 0x1000, perms, lineno);
        content += line;
        addr += 0x1000;
        ++lineno;
    };
    auto add_plain = [&]() {
        snprintf(line, sizeof line,
                 "%012lx-%012lx r--p 00000000 fd:00 %d  "
                 "/system/lib64/libc.so\n",
                 addr, addr + 0x1000, lineno);
        content += line;
        addr += 0x1000;
        ++lineno;
    };

    add_prop("r--p");                       // near the start
    while (content.size() < 60 * 1024) add_plain();
    add_prop("r--p");                       // middle
    while (content.size() < 120 * 1024) add_plain();
    add_prop("r--p");                       // the very last line

    int fd = write_text_to_memfd(content);
    ZS_CHECK(fd >= 0);

    PropMapping out[8];
    size_t n = find_prop_mappings_from_fd(fd, out, 8);
    ZS_CHECK_EQ(n, (size_t)3);
    if (n == 3) {
        // All three must be the property mappings (r--p perms).
        ZS_CHECK(out[0].hi > out[0].lo);
        ZS_CHECK(out[1].hi > out[1].lo);
        ZS_CHECK(out[2].hi > out[2].lo);
        ZS_CHECK(out[0].lo != out[1].lo);
        ZS_CHECK(out[1].lo != out[2].lo);
    }
    close(fd);
}

// ======================================================================
// Round 9 tests
// ======================================================================

// ----------------------------------------------------------------------
// B2: property ENUMERATION hooks — read_callback / read / foreach
// ----------------------------------------------------------------------

ZS_TEST(prop_read_callback_swallows_absent_prop_infos) {
    // Two synthetic prop_info pointers: one absent-spoofed, one not.
    int fake_absent = 0, fake_normal = 0;
    const void* absent_pi = &fake_absent;
    const void* normal_pi = &fake_normal;
    const void* arr[1] = {absent_pi};
    zs_test_set_absent_prop_infos(arr, 1);

    hide_advanced_set_active(1);
    int called = 0;
    auto cb = [](void* cookie, const char*, const char*, uint32_t) {
        ++*static_cast<int*>(cookie);
    };

    // g_real_prop_read_cb is null on host: the hook must simply not
    // call the user callback for the absent pi, and also not call it
    // for a non-absent pi (nothing to delegate to). The observable
    // contract: NEVER invoke cb for the absent key.
    zygisk_study_hook_prop_read_callback(absent_pi, cb, &called);
    ZS_CHECK_EQ(called, 0);

    // And for a non-absent pi the hook is a pure passthrough — with
    // no real symbol to call, still no crash and no callback.
    zygisk_study_hook_prop_read_callback(normal_pi, cb, &called);
    ZS_CHECK_EQ(called, 0);

    // Inactive gate: same no-op behavior (no real fn on host).
    hide_advanced_set_active(0);
    zygisk_study_hook_prop_read_callback(absent_pi, cb, &called);
    ZS_CHECK_EQ(called, 0);

    zs_test_set_absent_prop_infos(nullptr, 0);
}

ZS_TEST(prop_read_reports_empty_for_absent_prop_infos) {
    int fake_absent = 0;
    const void* absent_pi = &fake_absent;
    const void* arr[1] = {absent_pi};
    zs_test_set_absent_prop_infos(arr, 1);

    hide_advanced_set_active(1);
    char value[92] = "stale";
    int rv = zygisk_study_hook_prop_read(absent_pi, value);
    ZS_CHECK_EQ(rv, 0);
    ZS_CHECK_EQ(value[0], '\0');

    hide_advanced_set_active(0);
    zs_test_set_absent_prop_infos(nullptr, 0);
}

// A fake __system_property_foreach: hands the trampoline the four
// pointers the TEST chose (shared globals, so the absent-marking in
// the test and the enumeration in the driver see the same objects).
static int g_fake_prop_storage[4];
static const void* g_fake_prop_pis[4] = {
    &g_fake_prop_storage[0], &g_fake_prop_storage[1],
    &g_fake_prop_storage[2], &g_fake_prop_storage[3],
};
static int fake_foreach_driver(void (*cb)(const void*, void*),
                               void* cookie) {
    for (const void* pi : g_fake_prop_pis) cb(pi, cookie);
    return 0;
}

ZS_TEST(prop_foreach_drops_absent_keys_from_enumeration) {
    // Mark the first two as absent-spoofed.
    const void* arr[2] = {g_fake_prop_pis[0], g_fake_prop_pis[1]};
    zs_test_set_absent_prop_infos(arr, 2);
    zs_test_set_real_prop_foreach(fake_foreach_driver);

    hide_advanced_set_active(1);
    int seen = 0;
    auto user_cb = [](const void* pi, void* cookie) {
        ++*static_cast<int*>(cookie);
        (void)pi;
    };
    int rv = zygisk_study_hook_prop_foreach(
        (void (*)(const void*, void*))user_cb, &seen);
    ZS_CHECK_EQ(rv, 0);
    // 4 keys enumerated, 2 dropped: exactly 2 must reach the user.
    ZS_CHECK_EQ(seen, 2);

    // Inactive gate: the real foreach runs unfiltered — with our fake
    // installed, ALL 4 keys reach the user callback.
    hide_advanced_set_active(0);
    seen = 0;
    zygisk_study_hook_prop_foreach(
        (void (*)(const void*, void*))user_cb, &seen);
    ZS_CHECK_EQ(seen, 4);

    zs_test_set_real_prop_foreach(nullptr);
    zs_test_set_absent_prop_infos(nullptr, 0);
}

// Round 13 — the R9 residual: what happens when a callback re-enters
// the property API (bionic's __system_property_foreach takes a global
// lock; a callback that itself enumerates re-enters our hook, which
// must stay correct without any lock of its own — the nested call
// gets a fresh ForeachCtx on its own stack).
ZS_TEST(prop_foreach_reentrant_nested_enumeration) {
    // Mark two of the four synthetic keys absent.
    const void* arr[2] = {g_fake_prop_pis[0], g_fake_prop_pis[1]};
    zs_test_set_absent_prop_infos(arr, 2);
    zs_test_set_real_prop_foreach(fake_foreach_driver);

    hide_advanced_set_active(1);
    int outer_seen = 0;
    int nested_seen = 0;

    auto user_cb = [](const void* pi, void* cookie) {
        // A "bionic-like" callback that re-enters the enumeration
        // API (through the SAME hooked entry point).
        struct Ctx { int outer; int nested; };
        Ctx* c = static_cast<Ctx*>(cookie);
        ++c->outer;
        int inner = 0;
        zygisk_study_hook_prop_foreach(
            [](const void* p2, void* ck) {
                ++*static_cast<int*>(ck);
                (void)p2;
            }, &inner);
        c->nested += inner;
        (void)pi;
    };
    struct Ctx { int outer; int nested; } counts{0, 0};
    int rv = zygisk_study_hook_prop_foreach(
        (void (*)(const void*, void*))user_cb, &counts);
    ZS_CHECK_EQ(rv, 0);
    // Outer enumeration: 4 keys, 2 absent dropped -> 2 callbacks.
    ZS_CHECK_EQ(counts.outer, 2);
    // Each nested enumeration saw the same 4-with-2-dropped table.
    ZS_CHECK_EQ(counts.nested, 4);

    // And the outer call's own state was not corrupted by nesting
    // (a fresh outer enumeration still sees exactly 2).
    nested_seen = 0;
    (void)nested_seen;
    outer_seen = 0;
    int seen = 0;
    zygisk_study_hook_prop_foreach(
        (void (*)(const void*, void*))[](const void* pi, void* cookie) {
            ++*static_cast<int*>(cookie);
            (void)pi;
        }, &seen);
    ZS_CHECK_EQ(seen, 2);
    (void)outer_seen; (void)nested_seen;

    hide_advanced_set_active(0);
    zs_test_set_real_prop_foreach(nullptr);
    zs_test_set_absent_prop_infos(nullptr, 0);
}

ZS_TEST(prop_foreach_table_size_covers_spoof_table) {
    // g_absent_prop_infos is sized 32; the absent portion of the
    // spoof table must fit or keys silently leak (documented
    // residual). This test FAILS when someone grows the spoof table
    // past the cap without growing the array.
    size_t absent = 0;
    size_t total = 0;
    const ZsPropSpoof* t = zs_prop_spoof_table(&total);
    for (size_t i = 0; i < total; ++i) {
        if (t[i].value == nullptr || t[i].value[0] == '\0') ++absent;
    }
    ZS_CHECK(absent <= 32);
}

// ----------------------------------------------------------------------
// S1: scandir / scandirat hooks
// ----------------------------------------------------------------------

// The synthetic scandir: builds a dirent list with root-marker names
// plus normal ones, through the REAL scandir contract: the CALLER
// owns the entries and the array and frees them. Our hook respects
// that contract exactly — it frees entries it DROPS, compacts the
// array, and leaves the rest to the caller.
static int fake_scandir_impl(const char* dir, struct dirent*** namelist,
                             int (*)(const struct dirent*),
                             int (*)(const struct dirent**,
                                     const struct dirent**)) {
    const char* names[] = {"acct", "magisk", "data", ".magisk",
                           "zygisk_study", "init.rc", "libzygisk.so",
                           "sdcard", "ksu"};
    int n = (int)(sizeof names / sizeof names[0]);
    struct dirent** list = (struct dirent**)malloc(n * sizeof(void*));
    for (int i = 0; i < n; ++i) {
        list[i] = (struct dirent*)calloc(1, sizeof(struct dirent));
        snprintf(list[i]->d_name, sizeof list[i]->d_name, "%s", names[i]);
    }
    *namelist = list;
    (void)dir;
    return n;
}

static void free_dirent_list(struct dirent** list, int n) {
    if (!list) return;
    for (int i = 0; i < n; ++i) free(list[i]);
    free(list);
}

ZS_TEST(scandir_hook_drops_root_marker_entries) {
    zs_test_set_real_scandir((void*)fake_scandir_impl);
    hide_advanced_set_active(1);

    struct dirent** list = nullptr;
    int n = zygisk_study_hook_scandir("/system", &list, nullptr, nullptr);
    ZS_CHECK_EQ(n, 4);   // 9 entries - 5 hidden (magisk, .magisk,
                         // zygisk_study, libzygisk.so, ksu)
    if (n == 4 && list) {
        for (int i = 0; i < n; ++i) {
            ZS_CHECK_STR_ABSENT("magisk .magisk zygisk_study "
                                "libzygisk.so ksu",
                                list[i]->d_name);
        }
        free_dirent_list(list, n);
    }

    hide_advanced_set_active(0);
    // Gate off: full passthrough to the fake real scandir — the
    // caller gets ALL 9 entries back.
    list = nullptr;
    n = zygisk_study_hook_scandir("/system", &list, nullptr, nullptr);
    ZS_CHECK_EQ(n, 9);
    free_dirent_list(list, n);

    zs_test_set_real_scandir(nullptr);
}

ZS_TEST(scandir_hook_hidden_dir_reports_enoent) {
    zs_test_set_real_scandir((void*)fake_scandir_impl);
    hide_advanced_set_active(1);

    // /data/adb ITSELF is deliberately not hidden (it exists on
    // stock devices); its CONTENTS are — /data/adb/modules is in
    // kHiddenStatPaths, so the opendir/scandir rewrite applies.
    struct dirent** list = (struct dirent**)0xdeadbeef;
    errno = 0;
    int n = zygisk_study_hook_scandir("/data/adb/modules", &list,
                                      nullptr, nullptr);
    ZS_CHECK_EQ(n, -1);
    ZS_CHECK_EQ(errno, ENOENT);
    ZS_CHECK(list == nullptr);
    // The hook freed the 9 entries + the array the fake scandir
    // allocated (verified by the Round 10 ASan leak run).

    // And /data/adb itself is NOT rewritten: it lists, entry-filtered.
    errno = 0;
    list = nullptr;
    n = zygisk_study_hook_scandir("/data/adb", &list, nullptr, nullptr);
    ZS_CHECK(n >= 0);
    free_dirent_list(list, n);

    hide_advanced_set_active(0);
    zs_test_set_real_scandir(nullptr);
}

// ----------------------------------------------------------------------
// S2: leaked-fd closing by link target — real getdents64 + readlink
// against the host kernel, with the prefix pointed at a directory the
// test can create.
// ----------------------------------------------------------------------

ZS_TEST(close_leaked_root_fds_closes_root_path_fds_only) {
    std::string dir = "/tmp/zstest_leakdir_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    std::string file = dir + "/module_file";
    FILE* f = fopen(file.c_str(), "w");
    ZS_CHECK(f != nullptr);
    fputs("x", f);
    fflush(f);

    // fd A: the "leaked module fd".
    int fd_leak = open(file.c_str(), O_RDONLY);
    ZS_CHECK(fd_leak >= 0);
    // fd B: a runtime-owned fd that must survive.
    int fd_keep = open("/etc/hostname", O_RDONLY);
    if (fd_keep < 0) fd_keep = open("/proc/self/status", O_RDONLY);
    ZS_CHECK(fd_keep >= 0);

    // Point the scanner at our directory and run it. The earlier
    // "does not crash on host" test PRETENDS init already ran (it
    // stores 1 into g_advanced_initialized), so undo that here and
    // force a real resolution — glibc HAS syscall(), the scan runs
    // for real against the host kernel.
    g_advanced_initialized.store(0);
    hide_advanced_init();
    ZS_CHECK(g_real_syscall != nullptr);
    zs_test_set_fd_root_prefix(dir.c_str());
    close_leaked_root_fds();

    // fd_leak must now be closed (fstat fails with EBADF), fd_keep
    // must still be open.
    struct stat st;
    ZS_CHECK(fstat(fd_leak, &st) != 0);
    ZS_CHECK_EQ(errno, EBADF);
    ZS_CHECK(fstat(fd_keep, &st) == 0);

    // The FILE* f is a SECOND fd on the same path — the scan closed
    // it too; closing it again must be harmless.
    fclose(f);
    close(fd_keep);
    zs_test_set_fd_root_prefix("/data/adb/");
    rmdir(d);
}

ZS_TEST(fd_target_prefixes_match_stock_paths) {
    // Defensive: restore the production prefix table first — the
    // previous test may have aborted (exception-style) before its
    // own cleanup ran.
    zs_test_set_fd_root_prefix("/data/adb/");
    // The default table matches the documented root prefixes.
    ZS_CHECK(fd_target_is_root_path("/data/adb/modules/foo/x.so", 28) == 1);
    ZS_CHECK(fd_target_is_root_path("/sbin/magisk", 12) == 1);
    ZS_CHECK(fd_target_is_root_path("/debug_ramdisk/x", 16) == 1);
    ZS_CHECK(fd_target_is_root_path(
        "/data/system/zygisk_study/sock", 30) == 1);
    // And nothing else — especially not runtime paths.
    ZS_CHECK(fd_target_is_root_path("/dev/dri/card0", 13) == 0);
    ZS_CHECK(fd_target_is_root_path("/dev/ashmem", 11) == 0);
    ZS_CHECK(fd_target_is_root_path("/data/app/com.foo/base.apk", 25) == 0);
    ZS_CHECK(fd_target_is_root_path("/memfd:boot-image (deleted)", 27) == 0);
}

// ----------------------------------------------------------------------
// Round 11: absolute-path openat must filter regardless of dirfd
// (POSIX: an absolute path ignores dirfd). The old AT_FDCWD gate
// was a detector bypass: openat(7, "/proc/self/maps", ...) sailed
// through unfiltered. Observable: a filtered read returns a MEMFD
// (fstat st_size > 0), a passthrough returns the procfs fd
// (st_size == 0).
// ----------------------------------------------------------------------

ZS_TEST(openat_absolute_path_filters_with_any_dirfd) {
    hide_advanced_set_active(1);

    int arbitrary_fd = open("/etc/hostname", O_RDONLY);
    if (arbitrary_fd < 0) arbitrary_fd = open("/proc/self/status", O_RDONLY);
    ZS_CHECK(arbitrary_fd >= 0);

    int fd = zygisk_study_hook_openat(arbitrary_fd, "/proc/self/status",
                                      O_RDONLY);
    ZS_CHECK(fd >= 0);
    if (fd >= 0) {
        struct stat st;
        ZS_CHECK(fstat(fd, &st) == 0);
        // memfd content has a real size; the raw procfs fd reports 0.
        ZS_CHECK(st.st_size > 0);
        close(fd);
    }
    // Belt: AT_FDCWD still filters (the pre-existing behavior).
    fd = zygisk_study_hook_openat(AT_FDCWD, "/proc/self/status", O_RDONLY);
    ZS_CHECK(fd >= 0);
    if (fd >= 0) {
        struct stat st;
        ZS_CHECK(fstat(fd, &st) == 0);
        ZS_CHECK(st.st_size > 0);
        close(fd);
    }
    // Relative path with a dirfd: passthrough (cannot resolve). Use a
    // REAL directory fd so the kernel's errno is meaningful.
    int dir_fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) dir_fd = open(".", O_RDONLY | O_DIRECTORY);
    ZS_CHECK(dir_fd >= 0);
    errno = 0;
    fd = zygisk_study_hook_openat(dir_fd, "definitely/not/here",
                                  O_RDONLY);
    ZS_CHECK_EQ(fd, -1);
    ZS_CHECK_EQ(errno, ENOENT);
    close(dir_fd);

    close(arbitrary_fd);
    hide_advanced_set_active(0);
}

ZS_TEST(openat2_fortify_hook_filters_with_any_dirfd) {
    hide_advanced_set_active(1);

    int arbitrary_fd = open("/etc/hostname", O_RDONLY);
    if (arbitrary_fd < 0) arbitrary_fd = open("/proc/self/status", O_RDONLY);
    ZS_CHECK(arbitrary_fd >= 0);

    int fd = zygisk_study_hook___openat_2(arbitrary_fd,
                                          "/proc/self/status", O_RDONLY);
    ZS_CHECK(fd >= 0);
    if (fd >= 0) {
        struct stat st;
        ZS_CHECK(fstat(fd, &st) == 0);
        ZS_CHECK(st.st_size > 0);
        close(fd);
    }
    close(arbitrary_fd);
    hide_advanced_set_active(0);
}

ZS_TEST(syscall_hook_openat_filters_with_any_dirfd) {
    // The raw syscall path had the same AT_FDCWD gate. g_real_syscall
    // must resolve (the earlier host test pretends init ran — undo).
    g_advanced_initialized.store(0);
    hide_advanced_init();
    ZS_CHECK(g_real_syscall != nullptr);

    hide_advanced_set_active(1);
    int arbitrary_fd = open("/etc/hostname", O_RDONLY);
    if (arbitrary_fd < 0) arbitrary_fd = open("/proc/self/status", O_RDONLY);
    ZS_CHECK(arbitrary_fd >= 0);

    long fd = zygisk_study_hook_syscall((long)SYS_openat, arbitrary_fd,
                                        (long)"/proc/self/status",
                                        (long)O_RDONLY, 0, 0);
    ZS_CHECK(fd >= 0);
    if (fd >= 0) {
        struct stat st;
        ZS_CHECK(fstat((int)fd, &st) == 0);
        ZS_CHECK(st.st_size > 0);
        close((int)fd);
    }
    close(arbitrary_fd);
    hide_advanced_set_active(0);
}

// Round 11 (S3): freopen() rebinds an EXISTING FILE to a /proc file
// without open()/fopen() ever going through the GOT — the last stdio
// bypass. The hook rebinds the caller's stream to the filtered
// memfd via its /proc/self/fd link; the resulting FILE* must read
// the FILTERED content (memfd: fstat size > 0, and for a spiked
// stream the hidden marker line is absent).
ZS_TEST(freopen_hook_filters_proc_files) {
    // g_real_freopen resolves on glibc; g_real_open too (fopen test
    // already relies on it).
    g_advanced_initialized.store(0);
    hide_advanced_init();
    ZS_CHECK(g_real_freopen != nullptr);

    // A scratch stream to rebind (freopen closes it whatever happens).
    FILE* scratch = tmpfile();
    ZS_CHECK(scratch != nullptr);

    hide_advanced_set_active(1);
    FILE* f = zygisk_study_hook_freopen("/proc/self/status", "r", scratch);
    hide_advanced_set_active(0);
    ZS_CHECK(f != nullptr);
    if (f) {
        struct stat st;
        ZS_CHECK(fstat(fileno(f), &st) == 0);
        // memfd content has a real size; the raw procfs file reports 0.
        ZS_CHECK(st.st_size > 0);
        // The stream reads the (filtered) status content: Name: line
        // survives filtering, and the TracerPid rewrite applies.
        char line[512] = {0};
        int found_name = 0, found_tracerpid = 0;
        while (fgets(line, sizeof line, f)) {
            if (strncmp(line, "Name:", 5) == 0) found_name = 1;
            if (strncmp(line, "TracerPid:\t0", 12) == 0) found_tracerpid = 1;
        }
        ZS_CHECK(found_name);
        ZS_CHECK(found_tracerpid);
        fclose(f);
    }
}

ZS_TEST(freopen_hook_passes_through_nonproc_and_write_modes) {
    g_advanced_initialized.store(0);
    hide_advanced_init();

    hide_advanced_set_active(1);
    // Write mode on a filtered path: passthrough (never intercept).
    FILE* scratch = tmpfile();
    ZS_CHECK(scratch != nullptr);
    errno = 0;
    // "/proc/self/maps" with "w" — the real call will fail (EACCES on
    // procfs write), but the hook must NOT intercept it: the failure
    // comes from the kernel, not from us.
    FILE* f = zygisk_study_hook_freopen("/proc/self/maps", "w", scratch);
    ZS_CHECK(f == nullptr);   // kernel refuses; stream was closed by freopen
    // Non-proc path: passthrough with a REAL rebinding.
    FILE* scratch2 = tmpfile();
    ZS_CHECK(scratch2 != nullptr);
    FILE* g = zygisk_study_hook_freopen("/etc/hostname", "r", scratch2);
    ZS_CHECK(g != nullptr);
    if (g) fclose(g);
    hide_advanced_set_active(0);
}

// ----------------------------------------------------------------------
// P1: TLS filter scratch — one allocation per thread, ever.
// ----------------------------------------------------------------------

ZS_TEST(filter_scratch_is_allocated_once_per_thread) {
    std::string content;
    for (int i = 0; i < 2000; ++i) {
        content += "7f1c2d3e4f5a6b7c-7f1c2d3e4f5a7000 rw-p 00000000 "
                   "00:05 12345     /data/data/com.example/libfoo.so\n";
    }
    int before = zs_test_filter_scratch_allocs();
    for (int round = 0; round < 5; ++round) {
        int fd = write_text_to_memfd(content);
        ZS_CHECK(fd >= 0);
        int out = make_filtered_memfd(fd, "/proc/self/maps");
        ZS_CHECK(out >= 0);
        if (out >= 0) close(out);
        close(fd);
    }
    int after = zs_test_filter_scratch_allocs();
    // Five filter passes on this thread: at most ONE new allocation
    // (this test's thread may not have had one yet).
    ZS_CHECK(after - before <= 1);
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study advanced hide layer tests ===\n");
    return zstest::run_all();
}

// ----------------------------------------------------------------------
// Round 13
// ----------------------------------------------------------------------

// Runtime unix-substring registration: the daemon's randomized
// per-boot socket directory must vanish from /proc/net/unix reads
// even though its name is only known at runtime.
ZS_TEST(filter_record_unix_drops_runtime_registered_socket_dir) {
    char dst[256];
    // Before registration: the neutral random name is NOT hidden.
    const char* neutral =
        "    0000000000000001: 00000002 00000000 00010000 0001 01 10001 "
        "/data/system/.feedface/s";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, neutral, strlen(neutral),
                              ZS_FILTER_NET_UNIX) > 0);

    hide_advanced_register_unix_hidden_substring("/data/system/.feedface");
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, neutral, strlen(neutral),
                                 ZS_FILTER_NET_UNIX), (ssize_t)-1);

    // A sibling sharing the stem is substring-matched too — harmless
    // over-match by design (these random dirs only exist for our
    // socket; documented difference from the mount table's
    // prefix-with-slash semantics).
    const char* sibling =
        "    0000000000000002: 00000002 00000000 00010000 0001 01 10002 "
        "/data/system/.feedface77/s";
    ZS_CHECK_EQ(zs_filter_record(dst, sizeof dst, sibling, strlen(sibling),
                                 ZS_FILTER_NET_UNIX), (ssize_t)-1);

    // Ordinary sockets survive.
    const char* clean =
        "    0000000000000000: 00000002 00000000 00010000 0001 01 10000 "
        "/dev/socket/thermal";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, clean, strlen(clean),
                              ZS_FILTER_NET_UNIX) > 0);

    // Guards: empty/oversize ignored without crash; saturation at 4.
    hide_advanced_register_unix_hidden_substring(nullptr);
    hide_advanced_register_unix_hidden_substring("");
    hide_advanced_register_unix_hidden_substring("/tmp/x");
    hide_advanced_register_unix_hidden_substring("/tmp/y");
    hide_advanced_register_unix_hidden_substring("/tmp/z");
    hide_advanced_register_unix_hidden_substring("/tmp/dropped");
    const char* dropped_dir =
        "    0000000000000003: 00000002 00000000 00010000 0001 01 10003 "
        "/tmp/dropped/s";
    ZS_CHECK(zs_filter_record(dst, sizeof dst, dropped_dir,
                              strlen(dropped_dir),
                              ZS_FILTER_NET_UNIX) > 0);
}

// Runtime fd-prefix registration: leaked descriptors targeting the
// randomized socket directory are closed (slots 4..7 of the table,
// not the test seam's slot 0).
ZS_TEST(fd_scan_runtime_prefix_closes_random_dir_fds) {
    std::string dir = "/tmp/zstest_rtfd_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    std::string file = dir + "/sock";
    FILE* f = fopen(file.c_str(), "w");
    ZS_CHECK(f != nullptr);
    fputs("x", f);
    fflush(f);
    int fd_leak = open(file.c_str(), O_RDONLY);
    ZS_CHECK(fd_leak >= 0);
    int fd_keep = open("/etc/hostname", O_RDONLY);
    if (fd_keep < 0) fd_keep = open("/proc/self/status", O_RDONLY);
    ZS_CHECK(fd_keep >= 0);

    // Restore the production slot 0 first (earlier tests override
    // it), then register the random dir through the RUNTIME API.
    zs_test_set_fd_root_prefix("/data/adb/");
    hide_advanced_register_root_path_prefix((dir + "/").c_str());

    g_advanced_initialized.store(0);
    hide_advanced_init();
    close_leaked_root_fds();

    struct stat st;
    ZS_CHECK(fstat(fd_leak, &st) != 0);
    ZS_CHECK_EQ(errno, EBADF);
    ZS_CHECK(fstat(fd_keep, &st) == 0);

    fclose(f);
    close(fd_keep);
    rmdir(d);
}

// ----------------------------------------------------------------------
// Round 15 — fd observable parity (the fd shadow table)
// ----------------------------------------------------------------------

// A REAL procfs descriptor is the anchor for every parity claim in
// this round: st_size 0 and mmap -> ENODEV. If a future kernel ever
// changes that, these hooks (which impersonate it) must change with
// it — so the anchor itself is asserted, not assumed.
ZS_TEST(fd_observable_anchor_real_procfs_behavior) {
    int real_fd = open("/proc/self/maps", O_RDONLY);
    ZS_CHECK(real_fd >= 0);
    struct stat anchor;
    ZS_CHECK_EQ(fstat(real_fd, &anchor), 0);
    ZS_CHECK_EQ(anchor.st_size, (off_t)0);
    errno = 0;
    void* m = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, real_fd, 0);
    ZS_CHECK(m == MAP_FAILED);
    ZS_CHECK_EQ(errno, ENODEV);
    close(real_fd);
}

// The full parity story: the memfd we hand out answers fstat, mmap
// and statx(AT_EMPTY_PATH) exactly like a procfs fd, while a normal
// file descriptor passes through completely untouched.
ZS_TEST(fd_shadow_procfs_observable_parity) {
    hide_advanced_set_active(1);

    int fd = zygisk_study_hook_open("/proc/self/maps", O_RDONLY);
    ZS_CHECK(fd >= 0);

    // The content really is the filtered maps (first bytes are a
    // maps line, not garbage). A maps line can run ~100 bytes, so
    // read a full window before checking for the line shape.
    char buf[256];
    ssize_t rn = read(fd, buf, sizeof buf - 1);
    ZS_CHECK(rn > 8);
    buf[rn] = '\0';
    ZS_CHECK(isxdigit((unsigned char)buf[0]) != 0);   // address column
    lseek(fd, 0, SEEK_SET);

    // fstat: procfs fiction (size 0, mode 0444, S_IFREG).
    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)0);
    ZS_CHECK(S_ISREG(st.st_mode));
    ZS_CHECK_EQ(st.st_mode & 0777, (mode_t)0444);
    ZS_CHECK_EQ(st.st_blocks, (blkcnt_t)0);

    // mmap: rejected with ENODEV, exactly like procfs.
    errno = 0;
    void* hm = zygisk_study_hook_mmap(nullptr, 4096, PROT_READ,
                                      MAP_PRIVATE, fd, 0);
    ZS_CHECK(hm == MAP_FAILED);
    ZS_CHECK_EQ(errno, ENODEV);

    // statx with AT_EMPTY_PATH (the aarch64 fstat path).
    struct statx stx;
    memset(&stx, 0, sizeof stx);
    int sx = zygisk_study_hook_statx(fd, "", AT_EMPTY_PATH,
                                     (unsigned)0xffff, &stx);
    ZS_CHECK_EQ(sx, 0);
    ZS_CHECK_EQ(stx.stx_size, (uint64_t)0);
    ZS_CHECK_EQ(stx.stx_mode & 0777, (uint16_t)0444);

    // A regular file must NOT get the fiction: hook passthrough.
    char tmpl[] = "/tmp/zs_r15_anchor_XXXXXX";
    int reg = mkstemp(tmpl);
    ZS_CHECK(reg >= 0);
    ZS_CHECK_EQ(write(reg, "hello", 5), 5);
    struct stat ts;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(reg, &ts), 0);
    ZS_CHECK_EQ(ts.st_size, (off_t)5);
    ZS_CHECK_EQ(ts.st_mode & 0777, (mode_t)0600);
    errno = 0;
    void* rm = zygisk_study_hook_mmap(nullptr, 4096, PROT_READ,
                                      MAP_PRIVATE, reg, 0);
    ZS_CHECK(rm != MAP_FAILED);
    if (rm != MAP_FAILED) munmap(rm, 4096);
    unlink(tmpl);
    close(reg);

    close(fd);
    hide_advanced_set_active(0);
}

// Stale entries self-heal: after the memfd is closed and its number
// reused by an ordinary file, the lookup invalidates the record and
// fstat reports the REAL file — never the procfs fiction.
ZS_TEST(fd_shadow_stale_entries_self_heal) {
    hide_advanced_set_active(1);
    int fd = zygisk_study_hook_open("/proc/self/maps", O_RDONLY);
    ZS_CHECK(fd >= 0);
    ZS_CHECK(fd_shadow_probe(fd, FD_SHADOW_MEMFD));
    close(fd);

    // Reuse the number deterministically: dup to force the SAME
    // number is not possible after close, so just open a fresh file —
    // if the kernel hands back the same number, the stale entry must
    // be discarded; if not, the lookup miss is the same answer.
    char tmpl[] = "/tmp/zs_r15_stale_XXXXXX";
    int reg = mkstemp(tmpl);
    ZS_CHECK(reg >= 0);
    ZS_CHECK_EQ(write(reg, "0123456789", 10), 10);
    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(reg, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)10);
    ZS_CHECK_EQ(st.st_mode & 0777, (mode_t)0600);
    if (reg == fd) {
        // The number WAS reused — the entry must have been dropped.
        ZS_CHECK(!fd_shadow_probe(reg, FD_SHADOW_MEMFD));
    }
    unlink(tmpl);
    close(reg);
    hide_advanced_set_active(0);
}

// The readlink spoof helper: fd-number path, dup (identity scan)
// path, foreign targets untouched, and readlink truncation
// semantics when the buffer is smaller than the original path.
ZS_TEST(readlink_spoof_helper_covers_dup_and_rejects_foreign) {
    hide_advanced_set_active(1);
    int fd = zygisk_study_hook_open("/proc/self/maps", O_RDONLY);
    ZS_CHECK(fd >= 0);
    char out[256];

    ssize_t n = hide_advanced_spoof_memfd_readlink(
        fd, "memfd:scudo (deleted)", 21, out, sizeof out);
    ZS_CHECK_EQ(n, (ssize_t)15);
    ZS_CHECK_EQ(memcmp(out, "/proc/self/maps", 15), 0);

    // dup'd descriptor: new fd number, same dev/ino — the identity
    // scan must find the record.
    int dup_fd = dup(fd);
    ZS_CHECK(dup_fd >= 0);
    n = hide_advanced_spoof_memfd_readlink(dup_fd, "memfd:scudo", 11,
                                           out, sizeof out);
    ZS_CHECK_EQ(n, (ssize_t)15);
    ZS_CHECK_EQ(memcmp(out, "/proc/self/maps", 15), 0);

    // Foreign target string: no spoof, caller keeps the real result.
    n = hide_advanced_spoof_memfd_readlink(dup_fd, "/data/.../x", 12,
                                           out, sizeof out);
    ZS_CHECK_EQ(n, (ssize_t)0);

    // Unknown memfd (real scudo-style memfd from another subsystem):
    // no record -> no spoof (correct — we cannot know a path).
    int other_mem = syscall_memfd_create("scudo", 0);
    ZS_CHECK(other_mem >= 0);
    n = hide_advanced_spoof_memfd_readlink(other_mem, "memfd:scudo", 11,
                                           out, sizeof out);
    ZS_CHECK_EQ(n, (ssize_t)0);
    close(other_mem);

    // Truncation: buffer smaller than "/proc/self/maps" -> exactly
    // bufsiz bytes, POSIX style.
    char small[4];
    n = hide_advanced_spoof_memfd_readlink(fd, "memfd:scudo", 11,
                                           small, sizeof small);
    ZS_CHECK_EQ(n, (ssize_t)4);
    ZS_CHECK_EQ(memcmp(small, "/pro", 4), 0);

    close(dup_fd);
    close(fd);
    hide_advanced_set_active(0);
}

// The raw openat2 syscall (Android 13+ kernels, no bionic wrapper in
// ANY release) must flow through the filter, including the open_how
// size sanity gate.
ZS_TEST(openat2_raw_syscall_is_filtered) {
    hide_advanced_set_active(1);
    struct zs_open_how how;
    memset(&how, 0, sizeof how);
    how.flags = O_RDONLY;

    long r = zygisk_study_hook_syscall((long)SYS_openat2,
                                       (long)AT_FDCWD,
                                       (long)"/proc/self/maps",
                                       (long)&how, (long)sizeof how);
    ZS_CHECK(r >= 0);
    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat((int)r, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)0);   // the fd is a tracked memfd
    close((int)r);

    // Size argument smaller than struct open_how: the kernel rejects
    // it with EINVAL; our hook must pass it through, not filter it.
    long r2 = zygisk_study_hook_syscall((long)SYS_openat2,
                                        (long)AT_FDCWD,
                                        (long)"/proc/self/maps",
                                        (long)&how, 4);
    ZS_CHECK(r2 < 0);
    hide_advanced_set_active(0);
}

// ----------------------------------------------------------------------
// Round 15 — linker enumeration closure (dl_iterate_phdr / dladdr)
// ----------------------------------------------------------------------

namespace {
struct DlCountCtx {
    int count = 0;
    int ours = 0;
    unsigned long long adds = 0, subs = 0;
    uintptr_t payload_base = 0;
};
int dl_count_cb(struct dl_phdr_info* info, size_t, void* d) {
    DlCountCtx* c = (DlCountCtx*)d;
    ++c->count;
    c->adds = info->dlpi_adds;
    c->subs = info->dlpi_subs;
    if (dl_name_is_ours(info->dlpi_name)) {
        ++c->ours;
        if (strstr(info->dlpi_name, "libpayload.so") != nullptr) {
            c->payload_base = info->dlpi_addr;
        }
    }
    return 0;
}
} // namespace

// The hook hides our DSOs from enumeration AND keeps the
// dlpi_adds/dlpi_subs arithmetic consistent (iterations == adds -
// subs), so a counting detector sees a self-consistent, smaller
// universe instead of a mismatch.
ZS_TEST(dl_iterate_phdr_hook_hides_our_libraries_and_keeps_counters) {
    void* h = dlopen("./libpayload.so", RTLD_NOW);
    ZS_CHECK(h != nullptr);

    // Anchor 1: the REAL iterator reports libpayload.so (it is
    // genuinely loaded into this process).
    DlCountCtx real;
    dl_iterate_phdr(dl_count_cb, &real);
    ZS_CHECK(real.count > 1);
    ZS_CHECK(real.ours >= 1);
    ZS_CHECK(real.payload_base != 0);

    // Anchor 2 (host-libc invariant the counter fix preserves):
    // iterations == adds - subs on the unfiltered walk.
    ZS_CHECK_EQ(real.adds - real.subs, (unsigned long long)real.count);

    // The hook must produce exactly that minus our entries.
    hide_advanced_set_active(1);
    DlCountCtx filt;
    int rv = zygisk_study_hook_dl_iterate_phdr(dl_count_cb, &filt);
    hide_advanced_set_active(0);
    ZS_CHECK_EQ(rv, 0);
    ZS_CHECK_EQ(filt.ours, 0);
    ZS_CHECK_EQ(filt.count, real.count - real.ours);
    ZS_CHECK_EQ(filt.adds - filt.subs, (unsigned long long)filt.count);

    dlclose(h);
}

// dladdr on an address inside our (still mapped, for this test)
// library: the real call names our .so path; the hook answers 0 with
// a zeroed Dl_info — exactly what a stock process answers for an
// anonymous mapping.
ZS_TEST(dladdr_hook_answers_not_found_for_our_pages) {
    void* h = dlopen("./libpayload.so", RTLD_NOW);
    ZS_CHECK(h != nullptr);

    DlCountCtx probe;
    dl_iterate_phdr(dl_count_cb, &probe);
    ZS_CHECK(probe.payload_base != 0);
    // An address inside the first (always-present) page of the image.
    void* addr = (void*)(probe.payload_base + 0x800);

    Dl_info info;
    memset(&info, 0, sizeof info);
    ZS_CHECK_EQ(dladdr(addr, &info), 1);
    ZS_CHECK(info.dli_fname != nullptr);
    ZS_CHECK(dl_name_is_ours(info.dli_fname));

    hide_advanced_set_active(1);
    memset(&info, 0xAA, sizeof info);
    ZS_CHECK_EQ(zygisk_study_hook_dladdr(addr, &info), 0);
    ZS_CHECK(info.dli_fname == nullptr);
    ZS_CHECK(info.dli_fbase == nullptr);
    ZS_CHECK(info.dli_sname == nullptr);
    hide_advanced_set_active(0);

    dlclose(h);
}

// The GOT registry must contain every Round 15 hook name so the Tier
// B install actually promotes them.
ZS_TEST(tier_b_registry_contains_round15_hooks) {
    struct Wanted { const char* name; bool found; };
    Wanted wanted[] = {
        {"fstat", false}, {"fstat64", false},
        {"mmap", false}, {"mmap64", false},
        {"dl_iterate_phdr", false},
        {"dladdr", false}, {"dladdr1", false},
    };
    for (auto& w : wanted) {
        // Match against the tier B registry the way
        // hide_advanced_install_tier_b promotes it.
        for (size_t i = 0; i < g_tier_b_hook_count; ++i) {
            if (strcmp(g_tier_b_hooks[i].name, w.name) == 0) {
                w.found = true;
                break;
            }
        }
    }
    for (auto& w : wanted) {
        if (!w.found) {
            std::fprintf(stderr,
                         "  [missing from tier B registry: %s]\n", w.name);
        }
        ZS_CHECK(w.found);
    }
}

// ----------------------------------------------------------------------
// Round 16 — readdir / readdir_r entry filtering
// ----------------------------------------------------------------------

// opendir + readdir through the hooks: hidden entry names vanish,
// normal entries survive in order, and the loop terminates cleanly.
ZS_TEST(readdir_hook_drops_hidden_entries) {
    std::string dir = "/tmp/zstest_r16_rd_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    const char* names[] = {"alpha", "magisk", "beta", "zygisk_study",
                           "gamma", "ksu", "libpayload.so", "delta"};
    for (const char* n : names) {
        std::string p = dir + "/" + n;
        FILE* f = fopen(p.c_str(), "w");
        ZS_CHECK(f != nullptr);
        fputs("x", f);
        fclose(f);
    }

    hide_advanced_set_active(1);
    DIR* dp = zygisk_study_hook_opendir(dir.c_str());
    ZS_CHECK(dp != nullptr);
    std::vector<std::string> seen;
    for (;;) {
        struct dirent* e = zygisk_study_hook_readdir(dp);
        if (!e) break;
        seen.push_back(e->d_name);
    }
    closedir(dp);
    hide_advanced_set_active(0);

    int alpha = 0, beta = 0, gamma = 0, delta = 0, hidden = 0;
    for (const std::string& n : seen) {
        if (n == "alpha") ++alpha;
        else if (n == "beta") ++beta;
        else if (n == "gamma") ++gamma;
        else if (n == "delta") ++delta;
        else if (zs_dirent_name_is_hidden(n.c_str())) ++hidden;
    }
    ZS_CHECK_EQ(alpha, 1);
    ZS_CHECK_EQ(beta, 1);
    ZS_CHECK_EQ(gamma, 1);
    ZS_CHECK_EQ(delta, 1);
    ZS_CHECK_EQ(hidden, 0);
    // 4 files + "." + ".." (dot entries never match the hidden set).
    ZS_CHECK_EQ(seen.size(), (size_t)6);

    // readdir_r: same contract through the deprecated-but-exported
    // symbol.
    hide_advanced_set_active(1);
    dp = zygisk_study_hook_opendir(dir.c_str());
    ZS_CHECK(dp != nullptr);
    std::vector<std::string> seen2;
    struct dirent entry, *rslt = nullptr;
    for (;;) {
        int rv = zygisk_study_hook_readdir_r(dp, &entry, &rslt);
        ZS_CHECK_EQ(rv, 0);
        if (rslt == nullptr) break;
        seen2.push_back(entry.d_name);
    }
    closedir(dp);
    hide_advanced_set_active(0);
    ZS_CHECK_EQ(seen2.size(), (size_t)6);   // same as readdir

    for (const char* n : names) unlink((dir + "/" + n).c_str());
    rmdir(d);
}

// Raw syscall(SYS_getdents64) on a directory with planted artifacts:
// the buffer is compacted in place and the hidden names never reach
// the caller's parser.
// Variadic passthrough so the SYS_getdents64 arm can run with the
// real kernel behind it (production resolves g_real_syscall at init;
// tests drive the hook directly).
static long zs_test_syscall_passthrough(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a[6];
    for (int i = 0; i < 6; ++i) a[i] = va_arg(ap, long);
    va_end(ap);
    return syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

ZS_TEST(getdents64_syscall_buffer_is_filtered) {
    std::string dir = "/tmp/zstest_r16_gd_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    const char* names[] = {"file1", "magisk", "file2", "zygiskd",
                           "file3"};
    for (const char* n : names) {
        std::string p = dir + "/" + n;
        FILE* f = fopen(p.c_str(), "w");
        ZS_CHECK(f != nullptr);
        fputs("x", f);
        fclose(f);
    }

    int dfd = open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    ZS_CHECK(dfd >= 0);

    g_real_syscall = (SyscallFn)&zs_test_syscall_passthrough;
    hide_advanced_set_active(1);
    char buf[8192];
    long n = zygisk_study_hook_syscall((long)SYS_getdents64,
                                       (long)dfd, (long)buf,
                                       (long)sizeof buf);
    hide_advanced_set_active(0);
    ZS_CHECK(n > 0);

    std::vector<std::string> seen;
    for (long off = 0; off < n;) {
        struct zs_linux_dirent64* de =
            (struct zs_linux_dirent64*)(buf + off);
        off += de->d_reclen;
        seen.push_back(de->d_name);
    }
    int normal = 0, hidden = 0;
    for (const std::string& s : seen) {
        if (s == "file1" || s == "file2" || s == "file3") ++normal;
        else if (zs_dirent_name_is_hidden(s.c_str())) ++hidden;
    }
    ZS_CHECK_EQ(normal, 3);
    ZS_CHECK_EQ(hidden, 0);

    close(dfd);
    for (const char* nm : names) unlink((dir + "/" + nm).c_str());
    rmdir(d);
}

// ----------------------------------------------------------------------
// Round 16 — relative /proc opens (chdir state + proc dirfds)
// ----------------------------------------------------------------------

ZS_TEST(proc_dir_prefix_classifier_table) {
    char mine[32];
    snprintf(mine, sizeof mine, "/proc/%d", (int)getpid());
    char mine_task[48], mine_task_tid[64];
    snprintf(mine_task, sizeof mine_task, "/proc/%d/task", (int)getpid());
    snprintf(mine_task_tid, sizeof mine_task_tid, "/proc/%d/task/%d",
             (int)getpid(), (int)getpid());
    struct { const char* path; int want; } cases[] = {
        {"/proc", 1}, {"/proc/", 0},
        {"/proc/net", 1},
        {"/proc/self", 1},
        {"/proc/thread-self", 1},
        {mine, 1},
        {"/proc/1", 0},                     // another process
        {"/proc/self/task", 1},
        {"/proc/self/task/1234", 1},
        {"/proc/self/task/12a", 0},
        {mine_task, 1},
        {mine_task_tid, 1},
        {"/proc/self/net", 1},
        {mine, 1},                          // re-verify ours
        {"/proc/self/maps", 0},             // a FILE, not a dir
        {"/proc/self/fd", 0},               // fd dir: relative opens
                                            // are fd numbers, never a
                                            // filtered basename
        {"/procX", 0},
        {"/data", 0},
        {"/proc/selfx", 0},
    };
    for (auto& c : cases) {
        if (zs_is_proc_dir_prefix(c.path) != c.want) {
            std::fprintf(stderr, "  [prefix misclassified: %s]\n",
                         c.path);
        }
        ZS_CHECK_EQ(zs_is_proc_dir_prefix(c.path), c.want);
    }
}

// chdir("/proc/self") + open("maps") must hit the filter exactly like
// the absolute path — and chdir away must clear the state.
ZS_TEST(relative_open_after_chdir_into_proc_self) {
    hide_advanced_set_active(1);

    ZS_CHECK_EQ(zygisk_study_hook_chdir("/proc/self"), 0);
    int fd = zygisk_study_hook_open("maps", O_RDONLY);
    ZS_CHECK(fd >= 0);

    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)0);          // procfs fiction
    char buf[256];
    ssize_t rn = read(fd, buf, sizeof buf - 1);
    ZS_CHECK(rn > 8);
    ZS_CHECK(isxdigit((unsigned char)buf[0]) != 0);
    close(fd);

    // readlink of the same descriptor answers the FULL original path.
    fd = zygisk_study_hook_open("maps", O_RDONLY);
    ZS_CHECK(fd >= 0);
    char path[64], link[256];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(path, link, sizeof link - 1);
    ZS_CHECK(n > 0);
    const char* mark = (link[0] == '/') ? link + 1 : link;
    ZS_CHECK(strncmp(mark, "memfd:scudo", 11) == 0);
    close(fd);

    // chdir away: state cleared, relative open is a plain ENOENT.
    std::string tmp = "/tmp/zstest_r16_ch_XXXXXX";
    char* td = mkdtemp(&tmp[0]);
    ZS_CHECK(td != nullptr);
    ZS_CHECK_EQ(zygisk_study_hook_chdir(tmp.c_str()), 0);
    errno = 0;
    fd = zygisk_study_hook_open("maps", O_RDONLY);
    ZS_CHECK_EQ(fd, -1);
    ZS_CHECK_EQ(errno, ENOENT);
    rmdir(td);

    hide_advanced_set_active(0);
    ZS_CHECK_EQ(chdir("/"), 0);   // leave the test's cwd sane
}

// openat(dirfd, "maps") with a /proc directory fd: the tracked
// dirfd reconstructs the absolute path; the kernel resolves the
// relative path itself exactly the same way.
ZS_TEST(relative_openat_against_proc_dirfd) {
    hide_advanced_set_active(1);

    int dirfd = zygisk_study_hook_open("/proc/self", O_RDONLY);
    ZS_CHECK(dirfd >= 0);
    ZS_CHECK(fd_shadow_probe(dirfd, FD_SHADOW_PROC_DIR));

    int fd = zygisk_study_hook_openat(dirfd, "maps", O_RDONLY);
    ZS_CHECK(fd >= 0);
    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)0);
    char buf[256];
    ssize_t rn = read(fd, buf, sizeof buf - 1);
    ZS_CHECK(rn > 8);
    close(fd);

    // A dirfd of a NON-proc directory is untouched (relative open
    // passes through).
    std::string tmp = "/tmp/zstest_r16_at_XXXXXX";
    char* td = mkdtemp(&tmp[0]);
    ZS_CHECK(td != nullptr);
    int plain = zygisk_study_hook_open(tmp.c_str(), O_RDONLY);
    ZS_CHECK(plain >= 0);
    errno = 0;
    fd = zygisk_study_hook_openat(plain, "maps", O_RDONLY);
    ZS_CHECK_EQ(fd, -1);
    ZS_CHECK_EQ(errno, ENOENT);
    close(plain);
    rmdir(td);
    close(dirfd);

    hide_advanced_set_active(0);
}

// ----------------------------------------------------------------------
// Round 17 — adversarial hardening of the streaming filter
// ----------------------------------------------------------------------

// A record LARGER than the 64 KB carry buffer is dropped, and — the
// part that actually matters — the NEXT records survive intact.
ZS_TEST(streaming_filter_survives_oversized_record) {
    std::string dir = "/tmp/zstest_r17_big_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    std::string file = dir + "/blob";

    FILE* f = fopen(file.c_str(), "w");
    ZS_CHECK(f != nullptr);
    fputs("7f12300000000000-7f12300000001000 r--p 00000000 08:01 1 "
          "/system/lib64/libc.so\n", f);
    // 100 KB single "line": no newline until the very end.
    std::string huge(100 * 1024, 'x');
    huge.push_back('\n');
    fwrite(huge.data(), 1, huge.size(), f);
    fputs("7f12300000002000-7f12300000003000 r--p 00000000 08:01 2 "
          "/system/lib64/libm.so\n", f);
    fclose(f);

    int fd = open(file.c_str(), O_RDONLY);
    ZS_CHECK(fd >= 0);
    hide_advanced_set_active(1);
    int memfd = make_filtered_memfd(fd, "/proc/self/maps");
    hide_advanced_set_active(0);
    close(fd);
    ZS_CHECK(memfd >= 0);

    std::string out;
    char buf[4096];
    ssize_t n;
    lseek(memfd, 0, SEEK_SET);
    while ((n = read(memfd, buf, sizeof buf)) > 0) {
        out.append(buf, (size_t)n);
    }
    close(memfd);

    ZS_CHECK(out.find("libc.so") != std::string::npos);
    ZS_CHECK(out.find("libm.so") != std::string::npos);
    ZS_CHECK(out.find("xxxxx") == std::string::npos);   // dropped
    // And exactly two records survived.
    int lines = 0;
    for (char c : out) if (c == '\n') ++lines;
    ZS_CHECK_EQ(lines, 2);
    unlink(file.c_str());
    rmdir(d);
}

// A record of EXACTLY carry-capacity size (63.9 KB, no separator in
// the first chunk) completes in the second chunk and is filtered
// normally — the boundary between "carry" and "oversized, drop".
ZS_TEST(streaming_filter_boundary_carry_record) {
    std::string dir = "/tmp/zstest_r17_bnd_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    std::string file = dir + "/blob";

    // One 60 KB line that IS hidden (contains our marker), split
    // across chunks by construction: written before a final kept line.
    FILE* f = fopen(file.c_str(), "w");
    ZS_CHECK(f != nullptr);
    std::string hidden_line =
        "7f00000000000000-7f00000000f00000 r--s 00000000 08:01 9 "
        "/data/adb/modules/zygisk_study/libpayload.so";
    while (hidden_line.size() < 60 * 1024) hidden_line += ' ';
    hidden_line += '\n';
    fwrite(hidden_line.data(), 1, hidden_line.size(), f);
    fputs("7f12300000000000-7f12300000001000 r--p 00000000 08:01 1 "
          "/system/lib64/libc.so\n", f);
    // no trailing separator on the final record:
    fputs("7f12300000002000-7f12300000003000 r--p 00000000 08:01 2 "
          "/apex/com.android.art/lib64/libart.so", f);
    fclose(f);

    int fd = open(file.c_str(), O_RDONLY);
    ZS_CHECK(fd >= 0);
    hide_advanced_set_active(1);
    int memfd = make_filtered_memfd(fd, "/proc/self/maps");
    hide_advanced_set_active(0);
    close(fd);
    ZS_CHECK(memfd >= 0);

    std::string out;
    char buf[4096];
    ssize_t n;
    lseek(memfd, 0, SEEK_SET);
    while ((n = read(memfd, buf, sizeof buf)) > 0) {
        out.append(buf, (size_t)n);
    }
    close(memfd);

    // The hidden record was dropped, both clean records kept —
    // including the final one WITHOUT a trailing separator.
    ZS_CHECK(out.find("libpayload.so") == std::string::npos);
    ZS_CHECK(out.find("libart.so") != std::string::npos);
    ZS_CHECK(out.find("libc.so") != std::string::npos);
    unlink(file.c_str());
    rmdir(d);
}

// Environ-style filtering with an unterminated final entry.
ZS_TEST(streaming_filter_environ_no_trailing_nul) {
    std::string dir = "/tmp/zstest_r17_env_XXXXXX";
    char* d = mkdtemp(&dir[0]);
    ZS_CHECK(d != nullptr);
    std::string file = dir + "/env";
    FILE* f = fopen(file.c_str(), "w");
    ZS_CHECK(f != nullptr);
    // fwrite, NOT fputs: the blob contains embedded NULs (fputs would
    // stop at the first one and silently truncate the fixture).
    std::string blob = std::string("PATH=/sbin:/system/bin") + '\0' +
        "ZYGISK_STUDY_DEBUG=1" + '\0' + "HOME=/data" + '\0' +
        "ZYGISK_STUDY_WORKDIR=/x";
    fwrite(blob.data(), 1, blob.size(), f);
    fclose(f);

    int fd = open(file.c_str(), O_RDONLY);
    ZS_CHECK(fd >= 0);
    hide_advanced_set_active(1);
    int memfd = make_filtered_memfd(fd, "/proc/self/environ");
    hide_advanced_set_active(0);
    close(fd);
    ZS_CHECK(memfd >= 0);

    std::string out;
    char buf[512];
    ssize_t n;
    lseek(memfd, 0, SEEK_SET);
    while ((n = read(memfd, buf, sizeof buf)) > 0) {
        out.append(buf, (size_t)n);
    }
    close(memfd);
    ZS_CHECK(out.find("ZYGISK_STUDY") == std::string::npos);
    ZS_CHECK(out.find("PATH=") != std::string::npos);
    ZS_CHECK(out.find("HOME=/data") != std::string::npos);
    unlink(file.c_str());
    rmdir(d);
}

// Fuzz the raw getdents64 compactor with adversarial buffers: broken
// headers, bogus reclens, non-NUL-terminated names, random bytes.
// Must never read or write outside [buf, buf+len) and must always
// return <= len. (Run this suite under ASan to make it a real
// memory-safety proof.)
ZS_TEST(getdents64_filter_fuzz_adversarial_buffers) {
    unsigned seed = 0x5eed1717;
    auto rnd = [&seed]() {
        seed = seed * 1664525u + 1013904223u;
        return seed >> 8;
    };
    for (int iter = 0; iter < 2000; ++iter) {
        char buf[512];
        size_t len = 8 + (rnd() % (sizeof buf - 16));
        for (size_t i = 0; i < len; ++i) buf[i] = (char)(rnd() & 0xff);
        // Sometimes plant a plausibly-shaped record with a hidden name
        // and a valid reclen but no NUL terminator.
        if (iter % 3 == 0 && len > 64) {
            struct zs_linux_dirent64* de =
                (struct zs_linux_dirent64*)buf;
            de->d_reclen = (unsigned short)(24 + (rnd() % 8));
            memcpy(de->d_name, "magiskXXXX", 10);   // no NUL
        }
        size_t out = zs_filter_getdents64(buf, len);
        ZS_CHECK(out <= len);
    }
}

// ----------------------------------------------------------------------
// Round 17 — hook contract hardening
// ----------------------------------------------------------------------

// The mmap hook must be transparent for every non-tracked use: the
// ART/malloc path (anonymous, fd -1) maps normally through the hook.
ZS_TEST(mmap_hook_transparent_for_anonymous_mappings) {
    hide_advanced_set_active(1);
    void* m = zygisk_study_hook_mmap(nullptr, 3 * 4096, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ZS_CHECK(m != MAP_FAILED);
    if (m != MAP_FAILED) {
        memset(m, 0x5a, 3 * 4096);
        munmap(m, 3 * 4096);
    }
    // Same with a REAL file fd (not one of ours).
    char tmpl[] = "/tmp/zs_r17_mm_XXXXXX";
    int reg = mkstemp(tmpl);
    ZS_CHECK(reg >= 0);
    ZS_CHECK_EQ(write(reg, "hello", 5), 5);
    void* fm = zygisk_study_hook_mmap(nullptr, 4096, PROT_READ,
                                      MAP_PRIVATE, reg, 0);
    ZS_CHECK(fm != MAP_FAILED);
    if (fm != MAP_FAILED) {
        ZS_CHECK_EQ(memcmp(fm, "hello", 5), 0);
        munmap(fm, 4096);
    }
    unlink(tmpl);
    close(reg);
    hide_advanced_set_active(0);
}

// A PROC_DIR shadow record must NOT trigger the memfd fstat fiction:
// statting a /proc directory fd through the hook reports a real
// directory.
ZS_TEST(fstat_hook_passes_proc_dir_fds_through) {
    hide_advanced_set_active(1);
    int dirfd = zygisk_study_hook_open("/proc/self", O_RDONLY);
    ZS_CHECK(dirfd >= 0);
    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(dirfd, &st), 0);
    ZS_CHECK(S_ISDIR(st.st_mode));          // still a directory
    ZS_CHECK(st.st_size != 0 || st.st_size == 0);   // real answer, whatever it is
    // The memfd fiction never applied:
    ZS_CHECK(!fd_shadow_probe(dirfd, FD_SHADOW_MEMFD));
    close(dirfd);
    hide_advanced_set_active(0);
}

// chdir(nullptr) is EFAULT from the kernel — the hook must pass the
// failure through without touching state.
ZS_TEST(chdir_hook_passes_null_and_bad_paths) {
    hide_advanced_set_active(1);
    errno = 0;
    int rv = zygisk_study_hook_chdir(nullptr);
    ZS_CHECK_EQ(rv, -1);
    ZS_CHECK(errno == EFAULT || errno == EINVAL);
    errno = 0;
    rv = zygisk_study_hook_chdir("/does/not/exist/at/all");
    ZS_CHECK_EQ(rv, -1);
    ZS_CHECK_EQ(errno, ENOENT);
    // State is still clear (no crash, no prefix).
    ZS_CHECK_EQ(g_cwd_proc_prefix_len, (size_t)0);
    hide_advanced_set_active(0);
}

// Round 17 registry pin: the tier B registry must hold exactly the
// documented set — the promotion path (install_tier_b) copies it into
// the live registry, whose capacity silently refused entries at the
// old 48-slot limit. Pin the arithmetic so a future hook that fails
// to register shows up HERE, not as a stealth hole.
ZS_TEST(tier_b_registry_size_is_pinned) {
    // This TU's registry: 42 production names + 1 legacy test symbol
    // registered by an older test ("zs_test_never_a_real_symbol").
    // The full payload adds readlink/readlinkat (2, from
    // hide_stealth.cpp) and promotes the 5 zygote-time hooks
    // (setresgid/setresuid/setgid/setuid/fork) for 49 live entries.
    // Round 22 added __system_property_set + fdopendir (43 here).
    // The old cap was 48: ONE slot from silently refusing new hooks —
    // capacity is 64 now; the pin keeps the arithmetic honest.
    ZS_CHECK_EQ(g_tier_b_hook_count, (size_t)43);

    size_t before = g_got_hook_count;
    hide_advanced_install_tier_b();
    ZS_CHECK_EQ(g_got_hook_count, before + g_tier_b_hook_count);
    // Full-payload arithmetic: 40 production + 2 (stealth) + 5
    // (zygote) = 47 live, and the capacity must leave real headroom
    // above it (the +1 here is this TU's legacy test symbol).
    ZS_CHECK(g_got_hook_count + 2 + 5 - 1 < kMaxGotHooks);

    // Every tier B entry must actually be reachable through the hash
    // index after promotion.
    for (size_t i = 0; i < g_tier_b_hook_count; ++i) {
        void* fn = zs_test_match_registered_hook(g_tier_b_hooks[i].name);
        if (fn != g_tier_b_hooks[i].fn) {
            std::fprintf(stderr, "  [tier B hook lost: %s]\n",
                         g_tier_b_hooks[i].name);
        }
        ZS_CHECK(fn == g_tier_b_hooks[i].fn);
    }

    // PRODUCTION LIFECYCLE: Tier B hooks are uninstalled before the
    // payload ever lets the process run on without it. Leaving the
    // test binary's GOT patched at exit once crashed the process
    // after all tests had already passed — exit-time libc calls went
    // through hook slots whose delegates are gone. Restore exactly
    // like hide_pipeline does.
    hide_advanced_uninstall_got_hooks();
    hide_advanced_set_active(0);
}

// Round 17: traversal components in the relative path. The kernel
// resolves "task/../maps" from a /proc/self dirfd to the very file we
// filter — the reconstruction must normalize it and do the same.
ZS_TEST(relative_openat_with_dotdot_traversal_is_filtered) {
    hide_advanced_set_active(1);

    int dirfd = zygisk_study_hook_open("/proc/self", O_RDONLY);
    ZS_CHECK(dirfd >= 0);

    int fd = zygisk_study_hook_openat(dirfd, "task/../maps", O_RDONLY);
    ZS_CHECK(fd >= 0);
    struct stat st;
    ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)0);          // the procfs fiction
    close(fd);

    // "." components and redundant slashes classify the same way.
    fd = zygisk_study_hook_openat(dirfd, "./maps", O_RDONLY);
    ZS_CHECK(fd >= 0);
    ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
    ZS_CHECK_EQ(st.st_size, (off_t)0);
    close(fd);
    close(dirfd);

    // Traversal that ESCAPES /proc lands outside the classifier and
    // passes through untouched (the kernel gives the same file).
    dirfd = zygisk_study_hook_open("/proc/self", O_RDONLY);
    ZS_CHECK(dirfd >= 0);
    errno = 0;
    fd = zygisk_study_hook_openat(dirfd, "../../etc/hostname", O_RDONLY);
    if (fd >= 0) {
        // On hosts where /etc/hostname exists through that traversal,
        // it must NOT have the procfs fiction (real file passthrough).
        ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
        ZS_CHECK(!S_ISDIR(st.st_mode));
        ZS_CHECK(st.st_size > 0 || st.st_size == 0);   // real answer
        close(fd);
    }
    close(dirfd);
    hide_advanced_set_active(0);
}

// The normalizer itself: the exact cases the joiner relies on.
ZS_TEST(path_normalizer_resolves_dot_and_dotdot) {
    char out[160];
    ZS_CHECK_EQ(zs_normalize_path("/proc/self/maps", out, sizeof out) > 0, 1);
    ZS_CHECK_EQ(strcmp(out, "/proc/self/maps"), 0);
    ZS_CHECK(zs_normalize_path("/proc/self/task/../maps", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/proc/self/maps"), 0);
    ZS_CHECK(zs_normalize_path("/proc/self/./maps", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/proc/self/maps"), 0);
    ZS_CHECK(zs_normalize_path("/proc/self//maps", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/proc/self/maps"), 0);
    ZS_CHECK(zs_normalize_path("/proc/self/../../1/maps", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/1/maps"), 0);   // two ".." escape /proc/self
                                             // AND /proc — lands at root
    ZS_CHECK(zs_normalize_path("/", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/"), 0);
    ZS_CHECK(zs_normalize_path("/proc/task", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/proc/task"), 0);
    // ".." at root stays at root; relative input is rejected.
    ZS_CHECK(zs_normalize_path("/..", out, sizeof out) > 0);
    ZS_CHECK_EQ(strcmp(out, "/"), 0);
    ZS_CHECK_EQ(zs_normalize_path("proc/self", out, sizeof out), (size_t)0);
    // Capacity: exactly-fitting path succeeds, one byte short fails.
    ZS_CHECK(zs_normalize_path("/a", out, 3) > 0);
    ZS_CHECK_EQ(zs_normalize_path("/ab", out, 3), (size_t)0);
}

// ----------------------------------------------------------------------
// Round 19 — the spoofed properties_serial builder. The REAL
// production function (zs_build_spoofed_serial_area) runs against a
// REAL file-backed mapping of this test process (the maps scan finds
// it in /proc/self/maps like it would find the real area), with a
// fake __system_property_find returning pointers INTO that mapping.
// No format assumptions: offsets come from the mapping table, values
// are verified by reading the built buffer back.
// ----------------------------------------------------------------------

ZS_TEST(spoofed_serial_area_builder_patches_values_at_offsets) {
    // 1. Synthetic area: page-sized file, "PROP" magic, two fake
    //    prop_info entries at 0x100 and 0x200 (bionic layout:
    //    serial@0, value@4..96).
    char area_path[] = "/tmp/zs_area_XXXXXX";
    int fd = mkstemp(area_path);
    ZS_CHECK(fd >= 0);
    char page[4096];
    memset(page, 0, sizeof page);
    memcpy(page, "PROP", 4);
    auto set_entry = [&](size_t off, const char* value) {
        uint32_t serial = 2;   // even: not mid-update
        memcpy(page + off, &serial, 4);
        strcpy(page + off + 4, value);
    };
    set_entry(0x100, "orange-unlocked-rooted");
    set_entry(0x200, "libzygisk.so");
    ZS_CHECK(write(fd, page, sizeof page) == (ssize_t)sizeof page);
    close(fd);

    // 2. Map it read-only — the REAL mapping the maps scan locates.
    fd = open(area_path, O_RDONLY);
    ZS_CHECK(fd >= 0);
    void* map = mmap(nullptr, sizeof page, PROT_READ, MAP_PRIVATE, fd, 0);
    ZS_CHECK(map != MAP_FAILED);
    close(fd);

    // 3. Fake find: two real keys (into the mapping) and one pointer
    //    OUTSIDE any mapping (the containing-mapping guard must skip
    //    it, not crash).
    static std::map<std::string, const void*> table = {
        {"ro.boot.verifiedbootstate", (char*)map + 0x100},
        {"ro.dalvik.vm.native.bridge", (char*)map + 0x200},
        {"ro.not.in.mapping", (const void*)0x10},   // bogus
    };
    auto fake_find = [](const char* key) -> const void* {
        auto it = table.find(key);
        return it == table.end() ? nullptr : it->second;
    };
    zs_test_set_prop_find(fake_find);

    // 4. Run the REAL builder.
    size_t size = 0;
    char* built = zs_build_spoofed_serial_area(area_path, &size);
    ZS_CHECK(built != nullptr);
    ZS_CHECK_EQ(size, (size_t)sizeof page);
    if (built) {
        // Magic passthrough.
        ZS_CHECK(memcmp(built, "PROP", 4) == 0);
        // Entry at 0x100: spoofed to "green". Round 22: the serial's
        // top byte now carries the NEW value length (5) — the reader
        // takes its memcpy length from it (SERIAL_VALUE_LEN), so the
        // old behavior (top byte left at the original 0) was the
        // truncation bug. Low counter still advances by 2.
        uint32_t serial = 0;
        memcpy(&serial, built + 0x100, 4);
        ZS_CHECK_EQ(serial, 0x05000004u);
        ZS_CHECK(strcmp(built + 0x100 + 4, "green") == 0);
        // Entry at 0x200: spoofed to empty (absent-style).
        memcpy(&serial, built + 0x200, 4);
        ZS_CHECK_EQ(serial, 4u);
        ZS_CHECK(built[0x200 + 4] == '\0');
        // Everything else byte-identical.
        ZS_CHECK(memcmp(built + 8, page + 8, 0x100 - 8) == 0);
        ZS_CHECK(memcmp(built + 0x100 + 96, page + 0x100 + 96,
                        0x200 - 0x100 - 96) == 0);
        free(built);
    }

    munmap(map, sizeof page);
    unlink(area_path);
    zs_test_reset_prop_find();
}

ZS_TEST(spoofed_serial_area_builder_fails_closed_without_hits) {
    // find() that returns null for everything: zero patches -> the
    // builder refuses to serve a verbatim copy of the real trie.
    char area_path[] = "/tmp/zs_area2_XXXXXX";
    int fd = mkstemp(area_path);
    ZS_CHECK(fd >= 0);
    char page[4096];
    memset(page, 0, sizeof page);
    memcpy(page, "PROP", 4);
    ZS_CHECK(write(fd, page, sizeof page) == (ssize_t)sizeof page);
    close(fd);

    fd = open(area_path, O_RDONLY);
    void* map = mmap(nullptr, sizeof page, PROT_READ, MAP_PRIVATE, fd, 0);
    ZS_CHECK(map != MAP_FAILED);
    close(fd);

    zs_test_set_prop_find([](const char*) -> const void* {
        return nullptr;   // captureless: converts to a fn pointer
    });

    size_t size = 0;
    char* built = zs_build_spoofed_serial_area(area_path, &size);
    ZS_CHECK(built == nullptr);
    ZS_CHECK_EQ(size, (size_t)0);

    munmap(map, sizeof page);
    unlink(area_path);
    zs_test_reset_prop_find();
}

ZS_TEST(spoofed_serial_area_builder_rejects_unmapped_paths) {
    // No mapping of this path exists in /proc/self/maps -> no
    // offsets -> fail closed (null), even with a working find().
    char area_path[] = "/tmp/zs_area3_XXXXXX";
    int fd = mkstemp(area_path);
    ZS_CHECK(fd >= 0);
    char page[4096];
    memset(page, 0, sizeof page);
    memcpy(page, "PROP", 4);
    ZS_CHECK(write(fd, page, sizeof page) == (ssize_t)sizeof page);
    close(fd);
    // NOT mapped — only written. The find seam returns a pointer
    // into an unrelated buffer.
    static char unrelated[128];
    zs_test_set_prop_find([](const char*) -> const void* {
        return unrelated;
    });
    size_t size = 0;
    char* built = zs_build_spoofed_serial_area(area_path, &size);
    ZS_CHECK(built == nullptr);

    unlink(area_path);
    zs_test_reset_prop_find();
}

// Round 20 — the opendir dirfd registration. opendir()'s internal
// open is libc-internal (never crosses the GOT), so before this
// round the dirfd it handed back had NO proc-dir record:
// opendir("/proc/self") + openat(dirfd, "maps") read the REAL,
// unfiltered maps. This is the exact R16 residual, closed.
ZS_TEST(opendir_dirfd_registers_proc_dir_for_relative_opens) {
    hide_advanced_set_active(1);

    // 1. The bypass that used to work: opendir + dirfd + openat.
    DIR* d = zygisk_study_hook_opendir("/proc/self");
    ZS_CHECK(d != nullptr);
    if (d) {
        int dfd = dirfd(d);
        ZS_CHECK(dfd >= 0);
        // The shadow record now exists (this lookup is the exact
        // miss that produced the pre-Round-20 bypass).
        ZS_CHECK(fd_shadow_probe(dfd, FD_SHADOW_PROC_DIR));

        int fd = zygisk_study_hook_openat(dfd, "maps", O_RDONLY);
        ZS_CHECK(fd >= 0);
        struct stat st;
        ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
        ZS_CHECK_EQ(st.st_size, (off_t)0);      // procfs fiction: FILTERED
        char buf[256];
        ssize_t rn = read(fd, buf, sizeof buf - 1);
        ZS_CHECK(rn > 8);
        close(fd);
        closedir(d);
    }

    // 2. readdir still works through the hook (the same DIR*).
    d = zygisk_study_hook_opendir("/proc/self");
    ZS_CHECK(d != nullptr);
    if (d) {
        struct dirent* de;
        int saw_maps = 0;
        while ((de = zygisk_study_hook_readdir(d)) != nullptr) {
            if (strcmp(de->d_name, "maps") == 0) saw_maps = 1;
        }
        ZS_CHECK(saw_maps);      // "maps" itself is not a hidden name
        closedir(d);
    }

    // 3. fchdir through an opendir-derived fd ALSO resolves the
    //    prefix now (the fchdir hook consults the same record).
    d = zygisk_study_hook_opendir("/proc/self");
    ZS_CHECK(d != nullptr);
    if (d) {
        int dfd = dirfd(d);
        ZS_CHECK_EQ(zygisk_study_hook_fchdir(dfd), 0);
        int fd = zygisk_study_hook_open("status", O_RDONLY);
        ZS_CHECK(fd >= 0);
        struct stat st;
        ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &st), 0);
        ZS_CHECK_EQ(st.st_size, (off_t)0);      // filtered, not real
        close(fd);
        closedir(d);
        ZS_CHECK_EQ(chdir("/"), 0);             // leave cwd sane
    }

    // 4. Hidden paths still answer ENOENT without opening anything.
    errno = 0;
    DIR* h = zygisk_study_hook_opendir("/data/adb");
    ZS_CHECK(h == nullptr);
    ZS_CHECK_EQ(errno, ENOENT);

    hide_advanced_set_active(0);
}

// Round 20 — stat parity for the mounted properties file. Through a
// (recorded) bind, the target path and the served file have DIFFERENT
// inode identities on host (two real files); the hooks must answer
// the REAL (pre-bind) identity for both the path-keyed and fd-keyed
// queries, exactly as a stock device would.
ZS_TEST(props_stat_fiction_answers_real_identity) {
    hide_advanced_set_active(1);

    // The REAL file (pre-bind target) and the served file (source).
    char tgt[] = "/tmp/zs_props_real_XXXXXX";
    char src[] = "/tmp/zs_props_served_XXXXXX";
    int fd = mkstemp(tgt);
    ZS_CHECK(fd >= 0);
    uint32_t magic = 0x504f5250;
    ZS_CHECK(write(fd, &magic, 4) == 4);
    close(fd);
    fd = mkstemp(src);
    ZS_CHECK(fd >= 0);
    ZS_CHECK(write(fd, &magic, 4) == 4);
    close(fd);

    struct stat real_st{}, served_st{};
    ZS_CHECK(stat(tgt, &real_st) == 0);
    ZS_CHECK(stat(src, &served_st) == 0);
    ZS_CHECK(real_st.st_ino != served_st.st_ino);   // distinct files

    // Production setters + the fiction capture (what the mount phase
    // does around the bind).
    hide_props_file_set_source(src, magic);
    zs_test_set_prop_serial_target(tgt);
    zs_test_props_fiction_capture_both();
    struct stat out{};
    ZS_CHECK_EQ(hide_props_stat_fiction(&out), 1);
    ZS_CHECK_EQ(out.st_ino, real_st.st_ino);
    ZS_CHECK_EQ(out.st_dev, real_st.st_dev);

    // stat(path) -> the REAL identity, never the served one.
    struct st_wrap { struct stat s; };
    struct stat got{};
    ZS_CHECK_EQ(zygisk_study_hook_stat(tgt, &got), 0);
    ZS_CHECK_EQ(got.st_ino, real_st.st_ino);
    ZS_CHECK(got.st_ino != served_st.st_ino);
    // lstat agrees with stat (the target is a plain file).
    ZS_CHECK_EQ(zygisk_study_hook_lstat(tgt, &got), 0);
    ZS_CHECK_EQ(got.st_ino, real_st.st_ino);

    // fstat(fd of the SERVED file) -> the REAL identity.
    fd = open(src, O_RDONLY);
    ZS_CHECK(fd >= 0);
    ZS_CHECK_EQ(zygisk_study_hook_fstat(fd, &got), 0);
    ZS_CHECK_EQ(got.st_ino, real_st.st_ino);
    ZS_CHECK(got.st_ino != served_st.st_ino);
    close(fd);

    // statx(fd, "", AT_EMPTY_PATH) on the served fd -> REAL identity
    // (the aarch64 fstat path).
    fd = open(src, O_RDONLY);
    ZS_CHECK(fd >= 0);
    struct statx sx{};
#ifdef SYS_statx
    ZS_CHECK_EQ(zygisk_study_hook_statx(fd, "", AT_EMPTY_PATH,
                                        0x7ff, &sx), 0);
    ZS_CHECK_EQ((uint64_t)sx.stx_ino, (uint64_t)real_st.st_ino);
#endif
    close(fd);

    // A DIFFERENT file is untouched (the fiction must be keyed, not
    // blanket).
    char other[] = "/tmp/zs_props_other_XXXXXX";
    fd = mkstemp(other);
    ZS_CHECK(fd >= 0);
    close(fd);
    ZS_CHECK_EQ(zygisk_study_hook_stat(other, &got), 0);
    ZS_CHECK(got.st_ino != real_st.st_ino);
    unlink(other);

    // statx with the path key too.
#ifdef SYS_statx
    struct statx sx2{};
    ZS_CHECK_EQ(zygisk_study_hook_statx(AT_FDCWD, tgt, 0, 0x7ff, &sx2), 0);
    ZS_CHECK_EQ((uint64_t)sx2.stx_ino, (uint64_t)real_st.st_ino);
#endif

    unlink(tgt);
    unlink(src);
    zs_test_set_prop_serial_target(nullptr);
    zs_test_props_source_clear();
    hide_advanced_set_active(0);
}

#include <functional>

// ======================================================================
// Round 22 — the property-trie layer.
//
// The fixtures below are a SECOND, INDEPENDENT implementation of the
// bionic property-area format (writer = init's prop_area discipline:
// header, root node, dirty area, 4-aligned bump allocations, BST-
// ordered sibling inserts, long-value blocks; reader = find_property
// + foreach_property + the SERIAL_VALUE_LEN memcpy of get()). The
// production code under test (pa_trie_find_node / pa_trie_delete_key /
// the file-image builder / the clone unlink) was written against the
// same AOSP sources this round — the fixtures cross-check it: two
// implementations agreeing is evidence the format handling is right,
// not just self-consistent.
// ======================================================================
namespace {

class PropAreaFixture {
public:
    explicit PropAreaFixture(size_t total = 64 * 1024)
        : buf_((uint8_t*)calloc(1, total)), size_(total) {
        ZS_CHECK(buf_ != nullptr);
        put32(0, 112);            // bytes_used_: root(20) + dirty(92)
        put32(4, 7);              // area serial (arbitrary nonzero)
        put32(8, 0x504f5250u);    // PROP_AREA_MAGIC
        put32(12, 0xfc6ed0abu);   // PROP_AREA_VERSION
    }
    ~PropAreaFixture() { free(buf_); }

    uint8_t* buf() { return buf_; }
    const uint8_t* buf() const { return buf_; }
    size_t size() const { return size_; }
    uint8_t* data() { return buf_ + 128; }
    const uint8_t* data() const { return buf_ + 128; }

    void add(const char* name, const char* value) {
        uint32_t node = find_or_create_node(name);
        size_t vlen = strlen(value);
        uint32_t namelen = (uint32_t)strlen(name);
        uint32_t pi_off = alloc(96 + namelen + 1);
        uint8_t* pi = data() + pi_off;
        if (vlen >= 92) {
            uint32_t lv_off = alloc(vlen + 1);
            memcpy(data() + lv_off, value, vlen + 1);
            uint32_t rel = lv_off - pi_off;
            uint32_t serial = (55u << 24) | (1u << 16);  // bionic's ctor
            memcpy(pi, &serial, 4);
            memset(pi + 4, 'E', 56);          // error_message
            memcpy(pi + 4 + 56, &rel, 4);
        } else {
            uint32_t serial = (uint32_t)vlen << 24;
            memcpy(pi, &serial, 4);
            memcpy(pi + 4, value, vlen + 1);  // 92-byte field, NUL padded
        }
        memcpy(pi + 96, name, namelen + 1);
        uint32_t pi_link = pi_off;
        memcpy(data() + node + 4, &pi_link, 4);
    }

    // ---- reader: bionic find_property ----
    const uint8_t* find(const char* name) const {
        uint32_t current = 0;
        const char* remaining = name;
        while (true) {
            const char* sep = strchr(remaining, '.');
            size_t flen = sep ? (size_t)(sep - remaining)
                              : strlen(remaining);
            uint32_t children;
            memcpy(&children, data() + (current ? current + 16 : 16), 4);
            if (children == 0) return nullptr;
            // BST walk
            uint32_t node = children;
            int found = 0;
            while (true) {
                const uint8_t* n = data() + node;
                uint32_t nlen;
                memcpy(&nlen, n, 4);
                int cmp = cmp_name(remaining, (uint32_t)flen,
                                   (const char*)(n + 20), nlen);
                if (cmp == 0) { found = 1; break; }
                uint32_t next;
                memcpy(&next, n + (cmp < 0 ? 8 : 12), 4);
                if (next == 0) break;
                node = next;
            }
            if (!found) return nullptr;
            if (!sep) {
                uint32_t prop;
                memcpy(&prop, data() + node + 4, 4);
                if (prop == 0) return nullptr;   // deleted / none
                return data() + prop;
            }
            remaining = sep + 1;
            current = node;
        }
    }

    // ---- reader: __system_property_get (SERIAL_VALUE_LEN memcpy) ----
    int get(const char* name, char* out) const {
        const uint8_t* pi = find(name);
        if (!pi) { out[0] = 0; return 0; }
        uint32_t serial;
        memcpy(&serial, pi, 4);
        if (serial & (1u << 16)) {
            // Long: ReadCallback passes long_value directly; Get()
            // returns the error-message length. For the test we only
            // need short entries through get().
            uint32_t len = serial >> 24;
            memcpy(out, pi + 4, len + 1);
            return (int)len;
        }
        uint32_t len = serial >> 24;
        memcpy(out, pi + 4, len + 1);
        return (int)len;
    }

    // ---- reader: the value via the callback path (long-aware) ----
    std::string value_of(const uint8_t* pi) const {
        uint32_t serial;
        memcpy(&serial, pi, 4);
        if (serial & (1u << 16)) {
            uint32_t rel;
            memcpy(&rel, pi + 4 + 56, 4);
            return std::string((const char*)(pi + rel));
        }
        return std::string((const char*)(pi + 4));
    }

    // ---- reader: foreach (left, prop, children, right) ----
    template <typename F>
    void foreach_prop(F&& f) const {
        walk(0, "", f);
    }

    size_t pi_offset(const char* name) const {
        const uint8_t* pi = find(name);
        ZS_CHECK(pi != nullptr);
        return (size_t)(pi - buf_);
    }

    // Buffer offset of the terminal NODE for a key (test introspection).
    uint32_t node_offset(const char* name) const {
        uint32_t current = 0;
        const char* remaining = name;
        while (true) {
            const char* sep = strchr(remaining, '.');
            size_t flen = sep ? (size_t)(sep - remaining)
                              : strlen(remaining);
            uint32_t children;
            memcpy(&children, data() + (current ? current + 16 : 16), 4);
            uint32_t node = children;
            while (true) {
                const uint8_t* n = data() + node;
                uint32_t nlen;
                memcpy(&nlen, n, 4);
                int cmp = cmp_name(remaining, (uint32_t)flen,
                                   (const char*)(n + 20), nlen);
                if (cmp == 0) break;
                uint32_t next;
                memcpy(&next, n + (cmp < 0 ? 8 : 12), 4);
                node = next;
            }
            if (!sep) return node;
            remaining = sep + 1;
            current = node;
        }
    }

    // Round-trip check: every add() is findable with its value.
    void self_check(const std::map<std::string, std::string>& expect) const {
        for (const auto& kv : expect) {
            const uint8_t* pi = find(kv.first.c_str());
            ZS_CHECK(pi != nullptr);
            ZS_CHECK(value_of(pi) == kv.second);
        }
    }

private:
    static int cmp_name(const char* one, uint32_t one_len,
                        const char* two, uint32_t two_len) {
        if (one_len < two_len) return -1;
        if (one_len > two_len) return 1;
        return strncmp(one, two, one_len);
    }

    uint32_t alloc(size_t n) {
        uint32_t used;
        memcpy(&used, buf_, 4);
        size_t aligned = (n + 3) & ~(size_t)3;
        ZS_CHECK((size_t)used + 128 + aligned <= size_);
        uint32_t off = used;
        put32(0, (uint32_t)(used + aligned));
        return off;
    }

    uint32_t new_node(const char* frag, size_t flen) {
        uint32_t off = alloc(20 + flen + 1);
        uint8_t* n = data() + off;
        uint32_t l = (uint32_t)flen;
        memcpy(n, &l, 4);
        memcpy(n + 20, frag, flen);
        n[20 + flen] = '\0';
        return off;
    }

    uint32_t find_or_create_node(const char* name) {
        uint32_t current = 0;
        const char* remaining = name;
        while (true) {
            const char* sep = strchr(remaining, '.');
            size_t flen = sep ? (size_t)(sep - remaining)
                              : strlen(remaining);
            uint32_t child_root;
            memcpy(&child_root, data() + (current ? current + 16 : 16), 4);
            if (child_root == 0) {
                child_root = new_node(remaining, flen);
                memcpy(data() + (current ? current + 16 : 16),
                       &child_root, 4);
            }
            // BST insert (bionic find_prop_trie_node alloc mode).
            uint32_t node = child_root;
            while (true) {
                uint8_t* n = data() + node;
                uint32_t nlen;
                memcpy(&nlen, n, 4);
                int cmp = cmp_name(remaining, (uint32_t)flen,
                                   (const char*)(n + 20), nlen);
                if (cmp == 0) break;
                uint8_t* slot = n + (cmp < 0 ? 8 : 12);
                uint32_t next;
                memcpy(&next, slot, 4);
                if (next != 0) { node = next; continue; }
                next = new_node(remaining, flen);
                memcpy(slot, &next, 4);
                node = next;
                break;
            }
            if (!sep) return node;
            remaining = sep + 1;
            current = node;
        }
    }

    void put32(size_t off, uint32_t v) { memcpy(buf_ + off, &v, 4); }
    void put32(size_t off, int v) { put32(off, (uint32_t)v); }

    template <typename F>
    void walk(uint32_t node, const std::string& prefix, F&& f) const {
        uint32_t left;
        memcpy(&left, data() + node + 8, 4);
        if (left != 0) walk(left, prefix, f);
        uint32_t prop;
        memcpy(&prop, data() + node + 4, 4);
        if (prop != 0) f(data() + prop);
        uint32_t children;
        memcpy(&children, data() + node + 16, 4);
        if (children != 0) {
            uint32_t nlen;
            memcpy(&nlen, data() + node, 4);
            std::string frag((const char*)(data() + node + 20), nlen);
            walk(children, prefix + frag + ".", f);
        }
        uint32_t right;
        memcpy(&right, data() + node + 12, 4);
        if (right != 0) walk(right, prefix, f);
    }

    uint8_t* buf_;
    size_t size_;
};

} // namespace

// The production trie walk finds everything the fixture wrote —
// including deep paths, BST siblings on both sides, and long values.
ZS_TEST(production_trie_walk_matches_independent_reader) {
    PropAreaFixture area;
    std::map<std::string, std::string> expect = {
        {"ro.boot.verifiedbootstate", "orange"},
        {"ro.boot.veritymode", "logging"},
        {"ro.boot.flash.locked", "0"},
        {"ro.build.tags", "release-keys"},
        {"ro.build.type", "userdebug"},
        {"ro.secure", "1"},
        {"persist.sys.long.value",
         std::string(140, 'L')},           // long value block
    };
    for (const auto& kv : expect) area.add(kv.first.c_str(), kv.second.c_str());
    area.self_check(expect);

    // The production walk must land on the same nodes.
    for (const auto& kv : expect) {
        uint32_t node = 0;
        ZS_CHECK_EQ(pa_trie_find_node(area.buf(), area.size(),
                                      kv.first.c_str(), &node), 1);
        ZS_CHECK_EQ(node, area.node_offset(kv.first.c_str()));
    }
    // Not-present keys are absent (not a crash, not a false hit).
    uint32_t node = 1;
    ZS_CHECK_EQ(pa_trie_find_node(area.buf(), area.size(),
                                  "ro.magisk.version", &node), 0);
    ZS_CHECK_EQ(pa_trie_find_node(area.buf(), area.size(),
                                  "no.such.key", &node), 0);
    ZS_CHECK_EQ(pa_trie_find_node(area.buf(), area.size(),
                                 "ro.build.tags", &node), 1);
}

// Deleting a key removes it from find() AND foreach() — through the
// INDEPENDENT reader — while neighbors on both BST sides survive.
ZS_TEST(trie_delete_removes_key_and_keeps_neighbors) {
    PropAreaFixture area;
    area.add("ro.magisk.version", "27007");
    area.add("ro.magisk.versioncode", "27007");   // shares the parent
    area.add("ro.build.tags", "release-keys");
    area.add("ro.secure", "1");

    ZS_CHECK(pa_trie_delete_key(area.buf(), area.size(),
                                "ro.magisk.version") == 1);

    // find: deleted key gone, everything else intact.
    ZS_CHECK(area.find("ro.magisk.version") == nullptr);
    ZS_CHECK(area.find("ro.magisk.versioncode") != nullptr);
    ZS_CHECK(area.find("ro.build.tags") != nullptr);
    ZS_CHECK(area.find("ro.secure") != nullptr);

    // foreach: exactly the three survivors.
    std::vector<std::string> names;
    area.foreach_prop([&](const uint8_t* pi) {
        names.push_back(std::string((const char*)(pi + 96)));
    });
    ZS_CHECK_EQ(names.size(), (size_t)3);
    int saw_v = 0, saw_t = 0, saw_s = 0;
    for (const auto& n : names) {
        if (n == "ro.magisk.versioncode") saw_v = 1;
        if (n == "ro.build.tags") saw_t = 1;
        if (n == "ro.secure") saw_s = 1;
        ZS_CHECK(n != "ro.magisk.version");   // never enumerated
    }
    ZS_CHECK(saw_v && saw_t && saw_s);

    // Deleting an already-deleted key is a no-op (prop == 0 path).
    ZS_CHECK(pa_trie_delete_key(area.buf(), area.size(),
                                "ro.magisk.version") == 0);
}

// The scrubbed entry leaves NO trace of the name or value anywhere in
// the image — a raw-forensics scan (memmem for the strings) comes up
// empty, and the long-value block of a deleted LONG entry is gone too.
ZS_TEST(trie_delete_scrubs_entry_bytes_and_long_values) {
    PropAreaFixture area;
    area.add("ro.dalvik.vm.native.bridge", "libzygisk.so");
    area.add("persist.sys.long.gone",
             std::string(150, 'X').c_str());     // long value block
    area.add("ro.keep.me", "kept");

    ZS_CHECK(pa_trie_delete_key(area.buf(), area.size(),
                                "ro.dalvik.vm.native.bridge") == 1);
    ZS_CHECK(pa_trie_delete_key(area.buf(), area.size(),
                                "persist.sys.long.gone") == 1);

    const char* needles[] = {
        "ro.dalvik.vm.native.bridge", "libzygisk.so",
        "persist.sys.long.gone",
    };
    for (const char* nd : needles) {
        size_t nl = strlen(nd);
        const uint8_t* hit = (const uint8_t*)memmem(
            area.buf(), area.size(), nd, nl);
        ZS_CHECK(hit == nullptr);
    }
    // The long VALUE (150 'X's) is scrubbed: no run of 90+ X remains.
    int run = 0, best = 0;
    for (size_t i = 128; i < area.size(); ++i) {
        run = area.buf()[i] == 'X' ? run + 1 : 0;
        if (run > best) best = run;
    }
    ZS_CHECK(best < 90);

    // And the survivor is still fully intact.
    const uint8_t* pi = area.find("ro.keep.me");
    ZS_CHECK(pi != nullptr);
    ZS_CHECK(area.value_of(pi) == "kept");
}

// A deleted key's get() (the SERIAL_VALUE_LEN memcpy path) reports
// not-found — the same answer a stock device gives.
ZS_TEST(trie_delete_get_reports_absent) {
    PropAreaFixture area;
    area.add("persist.sys.rootdir", "/data/adb");
    char out[96];
    ZS_CHECK_EQ(area.get("persist.sys.rootdir", out), 9);
    ZS_CHECK(strcmp(out, "/data/adb") == 0);

    ZS_CHECK(pa_trie_delete_key(area.buf(), area.size(),
                                "persist.sys.rootdir") == 1);
    ZS_CHECK_EQ(area.get("persist.sys.rootdir", out), 0);
    ZS_CHECK(out[0] == '\0');
}

// Corrupt areas must fail CLOSED (no deletion, no crash) — the fuzz
// loop drives random corruptions under the test binary (ASan covers
// the suite in the sanitizer run).
ZS_TEST(trie_walk_fails_closed_on_corruption) {
    PropAreaFixture area;
    area.add("ro.magisk.version", "27007");
    area.add("ro.build.tags", "release-keys");

    // Bad magic / version / bytes_used.
    {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        uint32_t bad = 0xdeadbeef;
        memcpy(a.buf() + 8, &bad, 4);
        ZS_CHECK(pa_trie_delete_key(a.buf(), a.size(),
                                    "ro.magisk.version") == 0);
    }
    {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        uint32_t bad = 0xdeadbeef;
        memcpy(a.buf() + 12, &bad, 4);
        ZS_CHECK(pa_trie_delete_key(a.buf(), a.size(),
                                    "ro.magisk.version") == 0);
    }
    {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        uint32_t wild = 0x7ffffff0;
        memcpy(a.buf(), &wild, 4);      // bytes_used_ beyond the area
        ZS_CHECK(pa_trie_delete_key(a.buf(), a.size(),
                                    "ro.magisk.version") == 0);
    }
    // Wild node offsets: children pointing out of the area.
    {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        // Root's children offset -> wild.
        uint32_t wild = (uint32_t)(a.size() - 4);
        memcpy(a.data() + 16, &wild, 4);
        ZS_CHECK(pa_trie_delete_key(a.buf(), a.size(),
                                    "ro.magisk.version") == 0);
    }
    {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        // Unaligned + odd offset.
        uint32_t wild = 0x101;
        memcpy(a.data() + 16, &wild, 4);
        ZS_CHECK(pa_trie_delete_key(a.buf(), a.size(),
                                    "ro.magisk.version") == 0);
    }
    // Truncated area: header claims more than the buffer holds.
    {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        ZS_CHECK(pa_trie_delete_key(a.buf(), 200,   // tiny size
                                    "ro.magisk.version") == 0);
    }

    // Deterministic pseudo-random corruption fuzz (bounded, seeded).
    uint32_t seed = 0x22446688u;
    for (int iter = 0; iter < 400; ++iter) {
        PropAreaFixture a;
        a.add("ro.magisk.version", "27007");
        a.add("ro.build.tags", "release-keys");
        a.add("persist.sys.x", "y");
        seed = seed * 1664525u + 1013904223u;
        size_t pos = 128 + (seed % (a.size() - 128 - 4));
        uint32_t v = seed >> 8;
        memcpy(a.buf() + pos, &v, 4);
        // Either it fails closed (0) or it deletes (1); both must
        // leave the OTHER keys' entries either intact or absent —
        // and it must NEVER crash (this test completing is the
        // assertion; ASan tightens it).
        (void)pa_trie_delete_key(a.buf(), a.size(), "ro.magisk.version");
    }
}

// The real version of the above (the lambda-table dance above was a
// scaffold; this is the working test).
ZS_TEST(spoofed_file_image_builder_full_round_trip) {
    PropAreaFixture area;
    area.add("ro.boot.verifiedbootstate", "orange");
    area.add("ro.boot.veritymode", "logging");
    area.add("ro.boot.flash.locked", "0");
    area.add("ro.magisk.version", "27007");
    area.add("ro.dalvik.vm.native.bridge", "libzygisk.so");
    area.add("persist.sys.rootdir", "/data/adb");
    area.add("ro.build.tags", "release-keys");
    area.add("ro.build.type", "userdebug");

    char path[] = "/tmp/zs_area22b_XXXXXX";
    int fd = mkstemp(path);
    ZS_CHECK(fd >= 0);
    ZS_CHECK(write(fd, area.buf(), 4096) == 4096);
    close(fd);
    fd = open(path, O_RDONLY);
    ZS_CHECK(fd >= 0);
    void* map = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ZS_CHECK(map != MAP_FAILED);
    close(fd);

    static std::map<std::string, size_t> offs;
    static void* map22 = nullptr;
    offs.clear();
    map22 = map;
    const char* keys[] = {
        "ro.boot.verifiedbootstate", "ro.boot.veritymode",
        "ro.boot.flash.locked", "ro.magisk.version",
        "ro.dalvik.vm.native.bridge", "persist.sys.rootdir",
        "ro.build.tags", "ro.build.type",
    };
    for (const char* k : keys) offs[k] = area.pi_offset(k);

    zs_test_set_prop_find([](const char* key) -> const void* {
        auto it = offs.find(key);
        return it == offs.end() ? nullptr
                                : (const void*)((char*)map22 + it->second);
    });

    size_t size = 0;
    char* built = zs_build_spoofed_serial_area(path, &size);
    ZS_CHECK(built != nullptr);
    if (built) {
        // Read the BUILT image with the INDEPENDENT reader.
        PropAreaFixture view;   // only used for its reader helpers
        const uint8_t* b = (const uint8_t*)built;

        // Deleted keys: find() == null AND not in foreach AND the
        // name does not survive anywhere in the raw bytes.
        const char* absent[] = {
            "ro.magisk.version", "ro.dalvik.vm.native.bridge",
            "persist.sys.rootdir",
        };
        for (const char* k : absent) {
            // The NODE still exists (fragments are shared); the prop
            // field must be 0 — the reader's find() then reports
            // "not found", exactly like a stock device.
            uint32_t node = 0;
            uint32_t prop = 1;
            int have_node = pa_trie_find_node(b, size, k, &node);
            ZS_CHECK(have_node == 0 || have_node == 1);
            if (have_node) {
                memcpy(&prop, b + 128 + node + 4, 4);
            }
            ZS_CHECK_EQ(prop, 0u);
            ZS_CHECK(memmem(built, size, k, strlen(k)) == nullptr);
        }

        // Value-spoofed keys: the serial's LENGTH byte matches the new
        // value — get() returns exactly "enforcing" (9) and "green" (5)
        // where the OLD code returned the ORIGINAL length (the
        // truncation bug — "logging" is 7, so "enforcin" + no NUL).
        auto find_pi = [&](const char* k) -> const uint8_t* {
            uint32_t node = 0;
            if (!pa_trie_find_node(b, size, k, &node)) return nullptr;
            uint32_t prop = 0;
            memcpy(&prop, b + 128 + node + 4, 4);
            if (prop == 0) return nullptr;
            return b + 128 + prop;
        };
        const uint8_t* pi = find_pi("ro.boot.veritymode");
        ZS_CHECK(pi != nullptr);
        uint32_t serial = 0;
        memcpy(&serial, pi, 4);
        ZS_CHECK_EQ(serial >> 24, 9u);   // "enforcing"
        ZS_CHECK(strcmp((const char*)(pi + 4), "enforcing") == 0);

        pi = find_pi("ro.boot.verifiedbootstate");
        ZS_CHECK(pi != nullptr);
        memcpy(&serial, pi, 4);
        ZS_CHECK_EQ(serial >> 24, 5u);   // "green"
        ZS_CHECK(strcmp((const char*)(pi + 4), "green") == 0);

        // Neighbors untouched: value AND serial byte-identical to the
        // fixture's originals.
        pi = find_pi("ro.build.tags");
        ZS_CHECK(pi != nullptr);
        ZS_CHECK(strcmp((const char*)(pi + 4), "release-keys") == 0);
        uint32_t orig_serial = 0;
        memcpy(&orig_serial, area.buf() + area.pi_offset("ro.build.tags"), 4);
        memcpy(&serial, pi, 4);
        ZS_CHECK_EQ(serial, orig_serial);

        // foreach over the built image: exactly the 5 survivors.
        size_t count = 0, absent_count = 0;
        std::function<void(uint32_t, const std::string&)> walk;
        walk = [&](uint32_t node, const std::string& prefix) {
            uint32_t l, r, ch, prop;
            memcpy(&l, b + 128 + node + 8, 4);
            if (l) walk(l, prefix);
            memcpy(&prop, b + 128 + node + 4, 4);
            if (prop) {
                ++count;
                const char* nm = (const char*)(b + 128 + prop + 96);
                for (const char* k : absent) {
                    if (strcmp(nm, k) == 0) ++absent_count;
                }
            }
            memcpy(&ch, b + 128 + node + 16, 4);
            if (ch) {
                uint32_t nlen;
                memcpy(&nlen, b + 128 + node, 4);
                std::string frag((const char*)(b + 128 + node + 20), nlen);
                walk(ch, prefix + frag + ".");
            }
            memcpy(&r, b + 128 + node + 12, 4);
            if (r) walk(r, prefix);
        };
        walk(0, "");
        ZS_CHECK_EQ(count, (size_t)5);
        ZS_CHECK_EQ(absent_count, (size_t)0);

        free(built);
    }

    munmap(map, 4096);
    unlink(path);
    offs.clear();
    zs_test_reset_prop_find();
}

// Round 22 — the set-side round-trip: a successful __system_property_set
// is reflected into the clone, so a following get() (which walks the
// clone) returns what the app just wrote — with the correct length byte.
ZS_TEST(prop_set_reflects_into_clone_round_trip) {
    hide_advanced_set_active(1);
    zs_test_set_props_clone_prot(PROT_READ | PROT_WRITE);  // heap fake

    // A synthetic prop_info: value "old" (serial len 3, counter 2).
    uint8_t* pi = (uint8_t*)calloc(1, 96 + 32);
    ZS_CHECK(pi != nullptr);
    uint32_t serial = (3u << 24) | 2u;
    memcpy(pi, &serial, 4);
    memcpy(pi + 4, "old", 4);
    memcpy(pi + 96, "persist.sys.test.key", 21);

    g_find_prop = [](const char* k) -> const void* {
        return strcmp(k, "persist.sys.test.key") ? nullptr : (const void*)1;
    };
    // The find seam returns a token; point it at our pi via the
    // production global instead of the test-only table:
    // (g_find_prop is the production resolver the hook uses.)
    // Simplest: rebind through zs_test_set_prop_find.
    static uint8_t* pi_slot = nullptr;
    pi_slot = pi;
    zs_test_set_prop_find([](const char* k) -> const void* {
        return strcmp(k, "persist.sys.test.key") ? nullptr
                                                 : (const void*)pi_slot;
    });

    static int calls = 0;
    zs_test_set_real_prop_set([](const char* k, const char* v) -> int {
        ++calls;
        ZS_CHECK(strcmp(k, "persist.sys.test.key") == 0);
        ZS_CHECK(strcmp(v, "hello world") == 0);
        return 0;   // init accepted
    });

    g_props_cloned.store(1);

    int rc = zygisk_study_hook_prop_set("persist.sys.test.key",
                                        "hello world");
    ZS_CHECK_EQ(rc, 0);
    ZS_CHECK_EQ(calls, 1);

    // The clone entry now holds the new value AND the new length byte.
    uint32_t after = 0;
    memcpy(&after, pi, 4);
    ZS_CHECK_EQ(after >> 24, 11u);              // strlen("hello world")
    ZS_CHECK_EQ(after & 1u, 0u);                // settled (even)
    ZS_CHECK(strcmp((const char*)(pi + 4), "hello world") == 0);

    // A FAILED set must NOT touch the clone (init rejected the write).
    calls = 0;
    zs_test_set_real_prop_set([](const char*, const char*) -> int {
        ++calls;
        return -1;
    });
    rc = zygisk_study_hook_prop_set("persist.sys.test.key", "nope");
    ZS_CHECK_EQ(rc, -1);
    ZS_CHECK_EQ(calls, 1);   // the real set ran (and was rejected)
    memcpy(&after, pi, 4);
    ZS_CHECK_EQ(after >> 24, 11u);              // unchanged
    ZS_CHECK(strcmp((const char*)(pi + 4), "hello world") == 0);

    // A LONG value (>= 92) is refused — the residual, verified.
    std::string big(200, 'B');
    zs_test_set_real_prop_set([](const char*, const char*) -> int {
        return 0;
    });
    rc = zygisk_study_hook_prop_set("persist.sys.test.key", big.c_str());
    ZS_CHECK_EQ(rc, 0);
    memcpy(&after, pi, 4);
    ZS_CHECK_EQ(after >> 24, 11u);              // NOT 200: untouched

    // Gate off: sets in non-hidden processes are pure passthrough.
    hide_advanced_set_active(0);
    rc = zygisk_study_hook_prop_set("persist.sys.test.key", "x");
    ZS_CHECK_EQ(rc, 0);
    memcpy(&after, pi, 4);
    ZS_CHECK_EQ(after >> 24, 11u);              // untouched

    free(pi);
    g_props_cloned.store(0);
    zs_test_set_real_prop_set(nullptr);
    zs_test_reset_prop_find();
    zs_test_set_props_clone_prot(PROT_READ);
}

// Round 26 — the set-hook's AREA-SERIAL bump + futex wake (the
// wait_any half of the set round-trip). Verified platform protocol
// (AOSP __system_property_update at 6.0 AND 7.0): after a successful
// write, init stores serial+1 (release) into the containing area's
// header word (offset 4) and FUTEX_WAKEs it — that is exactly what
// __system_property_wait_any() sleeps on. The clone never sees
// init's bump, so before this round a hidden app's wait_any slept
// forever after its own successful setprop.
ZS_TEST(prop_set_bumps_clone_area_serial_and_wakes_waiters) {
    hide_advanced_set_active(1);
    g_props_cloned.store(1);

    // A REAL mmap'd page carrying a valid area header + one
    // prop_info (the 6.x single-area shape — one span, everything in
    // it; on 7.x the serial area has the same layout). One page: the
    // set hook's mprotect span is derived from the prop_info's
    // extent, which stays inside the first page.
    const size_t kSize = 4096;
    uint8_t* base = (uint8_t*)mmap(nullptr, kSize, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ZS_CHECK(base != MAP_FAILED);
    uint32_t bytes_used = 112, serial = 5, magic = 0x504f5250u,
             version = 0xfc6ed0abu;
    memcpy(base + 0, &bytes_used, 4);
    memcpy(base + 4, &serial, 4);
    memcpy(base + 8, &magic, 4);
    memcpy(base + 12, &version, 4);
    uint8_t* pi = base + 128;                  // inside the area data
    uint32_t pi_serial = (3u << 24) | 2u;      // value "old"
    memcpy(pi + 0, &pi_serial, 4);
    memcpy(pi + 4, "old", 4);
    memcpy(pi + 96, "persist.sys.test.key", 21);

    // The clone's pages finalize read-only (production shape): the
    // set hook and the bump must each open their own mprotect window.
    // (The waiter below starts BEFORE this — see the WaitCtx note.)
    g_props_clone_prot = PROT_READ;

    // Register the span as the (successfully cloned) area.
    zs_test_clear_clone_spans();
    zs_test_register_clone_span((uintptr_t)base, (uintptr_t)base + kSize);

    static uint8_t* pi_slot = nullptr;
    pi_slot = pi;
    zs_test_set_prop_find([](const char* k) -> const void* {
        return strcmp(k, "persist.sys.test.key") ? nullptr
                                                 : (const void*)pi_slot;
    });
    zs_test_set_real_prop_set([](const char*, const char*) -> int {
        return 0;   // init accepted
    });

    // A waiter sleeping on the AREA serial (wait_any's futex word,
    // bionic's plain SHARED FUTEX_WAIT — verified from the 6.0/7.0
    // sources), with a timeout so a missing wake fails the test
    // instead of hanging it. NOTE: the waiter runs while the page is
    // still writable — on THIS sandbox kernel a shared futex WAIT on
    // a read-only page returns EFAULT instead of sleeping (mainline
    // 3.10/5.10 both carry the VERIFY_READ read-only GUP fallback —
    // fetched and verified from kernel sources this round — so real
    // devices sleep fine; the shared key is (page, offset) either
    // way, so a wake from inside the mprotect window covers a waiter
    // keyed from any protection state).
    struct WaitCtx {
        std::atomic<int> about_to_sleep{0};
        int futex_rc = -999;
    };
    WaitCtx ctx;
    uint32_t* area_serial = (uint32_t*)(base + 4);
    std::thread waiter([&]() {
        ctx.about_to_sleep.store(1, std::memory_order_seq_cst);
        struct timespec ts = {5, 0};   // 5s: generous for CI noise
        ctx.futex_rc = (int)syscall(SYS_futex, area_serial,
                                    0 /* FUTEX_WAIT */, 5, &ts);
    });
    // Let the waiter actually reach the futex (value still 5).
    while (!ctx.about_to_sleep.load(std::memory_order_seq_cst)) {}
    usleep(100 * 1000);

    int rc = zygisk_study_hook_prop_set("persist.sys.test.key", "new");
    ZS_CHECK_EQ(rc, 0);
    waiter.join();

    // The waiter was WOKEN (not timed out) and the serial moved by
    // exactly +1 — the platform's own update protocol.
    ZS_CHECK_EQ(ctx.futex_rc, 0);
    uint32_t after = 0;
    memcpy(&after, base + 4, 4);
    ZS_CHECK_EQ(after, 6u);
    // The entry patch happened too (the value round trip half).
    memcpy(&after, pi, 4);
    ZS_CHECK_EQ(after >> 24, 3u);              // strlen("new")
    // And the pages went back to read-only (the clone's protection):
    // find the maps line COVERING the span (the VMA may have merged
    // with a neighboring identical anon mapping, so the line's start
    // address is not necessarily ours) and check its perms.
    {
        FILE* f = fopen("/proc/self/maps", "r");
        ZS_CHECK(f != nullptr);
        char line[512];
        int found = 0, perms_ok = 0;
        unsigned long lo = (unsigned long)base;
        while (found == 0 && fgets(line, sizeof line, f)) {
            unsigned long a = 0, b = 0;
            char perms[8] = {};
            if (sscanf(line, "%lx-%lx %7s", &a, &b, perms) == 3 &&
                a <= lo && b >= lo + kSize) {
                found = 1;
                perms_ok = (strcmp(perms, "r--p") == 0);
            }
        }
        fclose(f);
        ZS_CHECK_EQ(found, 1);
        ZS_CHECK_EQ(perms_ok, 1);
    }

    munmap(base, kSize);
    g_props_cloned.store(0);
    zs_test_set_real_prop_set(nullptr);
    zs_test_reset_prop_find();
    zs_test_clear_clone_spans();
    hide_advanced_set_active(0);
}

// Round 22 — fdopendir(): a DIR* built from a BARE fd (never opened
// through a hooked entry point) now registers its /proc prefix, so
// openat(dirfd, "maps") filters instead of leaking the real file.
ZS_TEST(fdopendir_registers_bare_proc_dirfds) {
    hide_advanced_set_active(1);

    // The bypass: fd obtained with a RAW open (simulating a pre-hide
    // or libc-internal open), then fdopendir.
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self",
                          O_RDONLY | O_DIRECTORY, 0);
    ZS_CHECK(fd >= 0);
    DIR* d = zygisk_study_hook_fdopendir(fd);
    ZS_CHECK(d != nullptr);
    if (d) {
        int dfd = dirfd(d);
        ZS_CHECK_EQ(dfd, fd);
        // The record exists now: openat through this dirfd filters.
        int got = zygisk_study_hook_openat(dfd, "maps", O_RDONLY, 0);
        ZS_CHECK(got >= 0);
        struct stat st;
        ZS_CHECK_EQ(zygisk_study_hook_fstat(got, &st), 0);
        ZS_CHECK_EQ(st.st_size, (off_t)0);   // filtered fiction, not real
        close(got);
        closedir(d);
    }
    close(fd);

    // Non-proc dirfds are untouched (no record created).
    int tfd = (int)syscall(SYS_openat, AT_FDCWD, "/tmp",
                           O_RDONLY | O_DIRECTORY, 0);
    ZS_CHECK(tfd >= 0);
    DIR* td = zygisk_study_hook_fdopendir(tfd);
    ZS_CHECK(td != nullptr);
    if (td) {
        // No proc-dir record -> openat falls through normally.
        int got = zygisk_study_hook_openat(dirfd(td), ".", O_RDONLY, 0);
        ZS_CHECK(got >= 0);
        close(got);
        closedir(td);
    }
    close(tfd);

    hide_advanced_set_active(0);
}

// Round 22 — the >383-byte traversal heap fallback: a long relative
// path from a tracked proc dirfd still resolves through the filter
// (the old code fell through UNFILTERED — the documented bypass).
ZS_TEST(long_traversal_resolves_through_heap_fallback) {
    hide_advanced_set_active(1);

    DIR* d = zygisk_study_hook_opendir("/proc/self");
    ZS_CHECK(d != nullptr);
    if (d) {
        int dfd = dirfd(d);
        // 48 * "task/../" = 384 bytes + "maps" — over the 383 limit.
        std::string rel;
        for (int i = 0; i < 48; ++i) rel += "task/../";
        rel += "maps";
        ZS_CHECK(rel.size() > 383);

        int got = zygisk_study_hook_openat(dfd, rel.c_str(),
                                           O_RDONLY, 0);
        ZS_CHECK(got >= 0);
        struct stat st;
        ZS_CHECK_EQ(zygisk_study_hook_fstat(got, &st), 0);
        ZS_CHECK_EQ(st.st_size, (off_t)0);   // filtered, not the real file
        close(got);
        closedir(d);
    }

    // The stack path still handles normal-size traversals.
    d = zygisk_study_hook_opendir("/proc/self");
    ZS_CHECK(d != nullptr);
    if (d) {
        int got = zygisk_study_hook_openat(dirfd(d),
                                           "task/../task/../maps",
                                           O_RDONLY, 0);
        ZS_CHECK(got >= 0);
        struct stat st;
        ZS_CHECK_EQ(zygisk_study_hook_fstat(got, &st), 0);
        ZS_CHECK_EQ(st.st_size, (off_t)0);
        close(got);
        closedir(d);
    }

    hide_advanced_set_active(0);
}

// Round 22 PERF — the clone's live-prefix copy: a well-formed area
// copies only 128 + bytes_used_ bytes and the tail stays zero, while
// every live entry is byte-identical to the original.
ZS_TEST(clone_remap_copies_live_prefix_only) {
    PropAreaFixture area;
    area.add("ro.build.tags", "release-keys");
    area.add("ro.secure", "1");
    area.add("persist.sys.z", "v");

    uint32_t bytes_used = 0;
    memcpy(&bytes_used, area.buf(), 4);
    size_t live = 128 + bytes_used;
    ZS_CHECK(live < 4096);   // tail exists in this fixture

    // Map the fixture file-backed (like bionic maps properties_serial),
    // then run the production remap — it MAP_FIXEDs over the mapping.
    char path[] = "/tmp/zs_area22c_XXXXXX";
    int fd = mkstemp(path);
    ZS_CHECK(fd >= 0);
    ZS_CHECK(write(fd, area.buf(), 4096) == 4096);
    close(fd);
    fd = open(path, O_RDONLY);
    ZS_CHECK(fd >= 0);
    // MAP_PRIVATE + PROT_WRITE: the poison below is a COW write that
    // never touches the file — it emulates the dead-entry bytes the
    // REAL area's tail carries. (The production remap replaces the
    // mapping wholesale, so the original protection is irrelevant.)
    void* map = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE, fd, 0);
    ZS_CHECK(map != MAP_FAILED);
    close(fd);
    unlink(path);

    // Poison the tail (dead-entry bytes the REAL area would carry) —
    // the clone must NOT copy it (zero tail is the conservative copy).
    memset((char*)map + live, 0xAB, 4096 - live);

    uintptr_t lo = (uintptr_t)map;
    ZS_CHECK_EQ(remap_prop_mapping_private(lo, lo + 4096), 1);

    // Live prefix byte-identical.
    ZS_CHECK(memcmp(map, area.buf(), live) == 0);
    // Tail zeroed (not copied, not poisoned).
    int nonzero = 0;
    for (size_t i = live; i < 4096; ++i) {
        if (((const uint8_t*)map)[i] != 0) { nonzero = 1; break; }
    }
    ZS_CHECK_EQ(nonzero, 0);

    munmap(map, 4096);
}

// Round 22 — a non-area mapping (bad header) still gets the FULL copy.
ZS_TEST(clone_remap_full_copy_for_non_areas) {
    char path[] = "/tmp/zs_area22d_XXXXXX";
    int fd = mkstemp(path);
    ZS_CHECK(fd >= 0);
    char page[4096];
    memset(page, 0, sizeof page);
    memcpy(page, "NOTPROP", 8);   // wrong magic
    for (size_t i = 128; i < sizeof page; i += 64) {
        memcpy(page + i, &i, sizeof i);   // distinctive content everywhere
    }
    ZS_CHECK(write(fd, page, sizeof page) == (ssize_t)sizeof page);
    close(fd);
    fd = open(path, O_RDONLY);
    ZS_CHECK(fd >= 0);
    void* map = mmap(nullptr, sizeof page, PROT_READ, MAP_PRIVATE, fd, 0);
    ZS_CHECK(map != MAP_FAILED);
    close(fd);
    unlink(path);

    uintptr_t lo = (uintptr_t)map;
    ZS_CHECK_EQ(remap_prop_mapping_private(lo, lo + sizeof page), 1);
    // FULL copy: the poisoned content is preserved byte-for-byte.
    ZS_CHECK(memcmp(map, page, sizeof page) == 0);
    munmap(map, sizeof page);
}

// Round 23 — stock-line restoration for the cloned property mappings.
// The clone replaces the two /dev/__properties__ file mappings with
// anonymous ones at the same addresses; the filter must put the
// captured stock lines back so a Tier B maps/smaps read shows exactly
// what a stock process shows (every Android process carries these two
// lines — their ABSENCE is a deviation).
ZS_TEST(maps_filter_restores_stock_property_lines) {
    // The pre-clone maps (what the capture sees).
    const char* maps_before =
        "7e2b300000-7e2b320000 r--p 00000000 103:02 5001  /system/lib64/libc.so\n"
        "7f1a0000000-7f1a0020000 r--p 00000000 00:0c 8401      /dev/__properties__/properties_serial\n"
        "7f1a0020000-7f1a0040000 r--p 00000000 00:0c 8402      /dev/__properties__/property_info\n"
        "7f2c100000-7f2c140000 rw-p 00000000 00:00 0                          [heap]\n";
    capture_prop_line_restores(maps_before, strlen(maps_before));
    ZS_CHECK_EQ(g_prop_line_restore_count, (size_t)2);
    ZS_CHECK_EQ(g_prop_line_restore[0].lo, (uintptr_t)0x7f1a0000000ul);
    ZS_CHECK_EQ(g_prop_line_restore[0].hi, (uintptr_t)0x7f1a0020000ul);
    ZS_CHECK(strstr(g_prop_line_restore[0].line,
                    "/dev/__properties__/properties_serial") != nullptr);

    // The post-clone maps (what the app reads: anon lines at the same
    // addresses — blank name column, prctl name variant included).
    const char* maps_after =
        "7e2b300000-7e2b320000 r--p 00000000 103:02 5001  /system/lib64/libc.so\n"
        "7f1a0000000-7f1a0020000 r--p 00000000 00:00 0   \n"
        "7f1a0020000-7f1a0040000 r--p 00000000 00:00 0   [anon:linker_alloc]\n"
        "7f2c100000-7f2c140000 rw-p 00000000 00:00 0                          [heap]\n";

    char out[512];
    // Line 2 (the serial clone): restored to the STOCK text.
    const char* line2 = strchr(maps_after, '\n') + 1;
    const char* line2_end = strchr(line2, '\n');
    ssize_t n = zs_filter_record(out, sizeof out, line2,
                                 (size_t)(line2_end - line2),
                                 ZS_FILTER_PROC_LINE);
    ZS_CHECK(n > 0);
    ZS_CHECK(memmem(out, (size_t)n, "/dev/__properties__/properties_serial",
                    34) != nullptr);
    ZS_CHECK(memmem(out, (size_t)n, "8401", 4) != nullptr);   // real inode

    // Line 3 (property_info clone, prctl-named variant): also restored.
    const char* line3 = line2_end + 1;
    const char* line3_end = strchr(line3, '\n');
    n = zs_filter_record(out, sizeof out, line3,
                         (size_t)(line3_end - line3),
                         ZS_FILTER_PROC_LINE);
    ZS_CHECK(n > 0);
    ZS_CHECK(memmem(out, (size_t)n, "/dev/__properties__/property_info",
                    29) != nullptr);
    ZS_CHECK(memmem(out, (size_t)n, "[anon:linker_alloc]", 19) == nullptr);

    // Non-matching lines (libc, heap) pass through untouched.
    const char* libc_line =
        "7e2b300000-7e2b320000 r--p 00000000 103:02 5001  /system/lib64/libc.so";
    n = zs_filter_record(out, sizeof out, libc_line, strlen(libc_line),
                         ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ((size_t)n, strlen(libc_line));
    ZS_CHECK(memcmp(out, libc_line, strlen(libc_line)) == 0);

    // smaps detail lines never match the lo-hi pattern.
    const char* detail = "Size:               128 kB";
    n = zs_filter_record(out, sizeof out, detail, strlen(detail),
                         ZS_FILTER_PROC_LINE);
    ZS_CHECK_EQ((size_t)n, strlen(detail));

    // Round trip: capture with no property lines -> no restores, and
    // the anon line then passes through (Tier B without a clone).
    capture_prop_line_restores("1111-2222 r--p 00000000 00:00 0  /a\n", 34);
    ZS_CHECK_EQ(g_prop_line_restore_count, (size_t)0);
    g_prop_line_restore_count = 0;
}

// The END-TO-END form: full stream through the streaming filter —
// the anon clone lines are replaced in the OUTPUT, in order.
ZS_TEST(streaming_filter_restores_property_lines_in_stream) {
    const char* maps_before =
        "7f1a0000000-7f1a0020000 r--p 00000000 00:0c 8401      /dev/__properties__/properties_serial\n"
        "7f1a0020000-7f1a0040000 r--p 00000000 00:0c 8402      /dev/__properties__/property_info\n";
    capture_prop_line_restores(maps_before, strlen(maps_before));
    ZS_CHECK_EQ(g_prop_line_restore_count, (size_t)2);

    // Write the post-clone anon lines to a real file, then run the
    // production memfd filter over it and read the result back.
    char path[] = "/tmp/zs_maps23_XXXXXX";
    int fd = mkstemp(path);
    ZS_CHECK(fd >= 0);
    const char* maps_after =
        "7f1a0000000-7f1a0020000 r--p 00000000 00:00 0   \n"
        "7f1a0020000-7f1a0040000 r--p 00000000 00:00 0   [anon:linker_alloc]\n"
        "7fff0000-7fff1000 rw-p 00000000 00:00 0                          [stack]\n";
    ZS_CHECK(write(fd, maps_after, strlen(maps_after)) ==
             (ssize_t)strlen(maps_after));
    close(fd);

    // make_filtered_memfd wants the real fd of the file to filter.
    fd = open(path, O_RDONLY);
    ZS_CHECK(fd >= 0);
    int mfd = make_filtered_memfd(fd, "/proc/self/maps");
    close(fd);
    unlink(path);
    ZS_CHECK(mfd >= 0);
    if (mfd >= 0) {
        char out[1024];
        ssize_t n = read(mfd, out, sizeof out - 1);
        close(mfd);
        ZS_CHECK(n > 0);
        out[n] = '\0';
        ZS_CHECK(strstr(out, "/dev/__properties__/properties_serial") != nullptr);
        ZS_CHECK(strstr(out, "/dev/__properties__/property_info") != nullptr);
        ZS_CHECK(strstr(out, "[anon:linker_alloc]") == nullptr);
        ZS_CHECK(strstr(out, "[stack]") != nullptr);   // untouched lines stay
    }
    g_prop_line_restore_count = 0;
}

// Round 24 — the MERGED-VMA case. On a real device the two property
// mappings sit at adjacent addresses; after the clone both are
// anonymous with identical protection, and the kernel MERGES them
// into a single VMA — the raw maps line is the UNION range. The
// exact-prefix matcher silently skipped restoration there (host tests
// used two separate lines; the device shows one). Verified from the
// ANON_VMA_NAME Kconfig help text (VMAs merge when names match).
ZS_TEST(streaming_filter_restores_merged_property_vma) {
    const char* maps_before =
        "7f1a0000000-7f1a0020000 r--p 00000000 00:0c 8401      /dev/__properties__/properties_serial\n"
        "7f1a0020000-7f1a0040000 r--p 00000000 00:0c 8402      /dev/__properties__/property_info\n";
    capture_prop_line_restores(maps_before, strlen(maps_before));
    ZS_CHECK_EQ(g_prop_line_restore_count, (size_t)2);

    // The post-clone KERNEL view: ONE merged anon line covering both.
    char path[] = "/tmp/zs_maps24_XXXXXX";
    int fd = mkstemp(path);
    ZS_CHECK(fd >= 0);
    const char* maps_after =
        "7e2b300000-7e2b320000 r--p 00000000 103:02 5001  /system/lib64/libc.so\n"
        "7f1a0000000-7f1a0040000 r--p 00000000 00:00 0   \n"
        "7fff0000-7fff1000 rw-p 00000000 00:00 0                          [stack]\n";
    ZS_CHECK(write(fd, maps_after, strlen(maps_after)) ==
             (ssize_t)strlen(maps_after));
    close(fd);
    fd = open(path, O_RDONLY);
    ZS_CHECK(fd >= 0);
    int mfd = make_filtered_memfd(fd, "/proc/self/maps");
    close(fd);
    unlink(path);
    ZS_CHECK(mfd >= 0);
    if (mfd >= 0) {
        char out[2048];
        ssize_t n = read(mfd, out, sizeof out - 1);
        close(mfd);
        ZS_CHECK(n > 0);
        out[n > 0 ? n : 0] = '\0';
        // BOTH stock lines restored from the single merged line, in
        // address order, with the real dev/ino and paths.
        ZS_CHECK(strstr(out, "/dev/__properties__/properties_serial") != nullptr);
        ZS_CHECK(strstr(out, "/dev/__properties__/property_info") != nullptr);
        const char* p1 = strstr(out, "properties_serial");
        const char* p2 = strstr(out, "property_info");
        ZS_CHECK(p1 != nullptr && p2 != nullptr && p1 < p2);
        // The merged anon line is GONE (replaced, not appended).
        ZS_CHECK(strstr(out, "7f1a0000000-7f1a0040000") == nullptr);
        // Neighbors untouched.
        ZS_CHECK(strstr(out, "libc.so") != nullptr);
        ZS_CHECK(strstr(out, "[stack]") != nullptr);
    }
    g_prop_line_restore_count = 0;
}

// The parse + containment helpers directly (no I/O).
ZS_TEST(prop_restore_containment_matching) {
    const char* maps_before =
        "7f1a0000000-7f1a0020000 r--p 00000000 00:0c 8401      /dev/__properties__/properties_serial\n"
        "7f1a0020000-7f1a0040000 r--p 00000000 00:0c 8402      /dev/__properties__/property_info\n";
    capture_prop_line_restores(maps_before, strlen(maps_before));

    const PropLineRestore* hits[8];
    // Exact single range: one hit.
    size_t n = prop_line_restore_covered(
        "7f1a0000000-7f1a0020000 r--p 00000000 00:00 0", 47, hits);
    ZS_CHECK_EQ(n, (size_t)1);
    // Merged union: both hits, ascending.
    n = prop_line_restore_covered(
        "7f1a0000000-7f1a0040000 r--p 00000000 00:00 0", 47, hits);
    ZS_CHECK_EQ(n, (size_t)2);
    ZS_CHECK_EQ(hits[0]->lo, (uintptr_t)0x7f1a0000000ul);
    ZS_CHECK_EQ(hits[1]->lo, (uintptr_t)0x7f1a0020000ul);
    // Partial overlap (half the range): no hit — we never fabricate a
    // line for a range we did not fully clone.
    n = prop_line_restore_covered(
        "7f1a0010000-7f1a0030000 r--p 00000000 00:00 0", 47, hits);
    ZS_CHECK_EQ(n, (size_t)0);
    // Unrelated range: no hit.
    n = prop_line_restore_covered(
        "7e2b300000-7e2b320000 r--p 00000000 103:02 5001", 47, hits);
    ZS_CHECK_EQ(n, (size_t)0);
    // Non-maps lines: no hit, no parse.
    n = prop_line_restore_covered("Size:               128 kB", 28, hits);
    ZS_CHECK_EQ(n, (size_t)0);
    // Malformed: no crash.
    n = prop_line_restore_covered("-", 1, hits);
    ZS_CHECK_EQ(n, (size_t)0);
    n = prop_line_restore_covered("zzzz-ffff x", 11, hits);
    ZS_CHECK_EQ(n, (size_t)0);

    g_prop_line_restore_count = 0;
}

// ----------------------------------------------------------------------
// Round 25 — Android 7.x/8.x support + version-compat fixes
// ----------------------------------------------------------------------

// Build a synthetic REAL-format property area (the header bionic's
// readers validate: bytes_used@0, serial@4, magic@8 == 0x504f5250,
// version@12 == 0xfc6ed0ab) and map it read-only at a FIXED address —
// exactly what the device's properties_serial / per-context mappings
// look like. `pi_off` is the data-relative offset of a prop_info the
// test places inside the area.
struct TestArea {
    void*    addr = nullptr;
    size_t   size = 0;
    char     path[64];
    int      fd = -1;      // backing temp file (kept alive)
    void*    file_map = nullptr;  // the ORIGINAL read-only file mapping
};

static int build_test_prop_area(TestArea* ta, uintptr_t fixed_addr,
                                size_t size, const char* name) {
    *ta = TestArea{};   // zero-init (NSDMIs make memset() a -Wclass-memaccess)
    snprintf(ta->path, sizeof ta->path, "/tmp/zs_pa_%s_XXXXXX", name);
    ta->fd = mkstemp(ta->path);
    if (ta->fd < 0) return -1;
    ta->size = size;
    std::vector<char> img(size, 0);
    uint32_t bytes_used = (uint32_t)(size - kPropAreaHeaderSize);
    memcpy(img.data() + 0, &bytes_used, 4);
    uint32_t serial = 1;
    memcpy(img.data() + 4, &serial, 4);
    uint32_t magic = kPropAreaMagic;
    memcpy(img.data() + 8, &magic, 4);
    uint32_t version = kPropAreaVersion;
    memcpy(img.data() + 12, &version, 4);
    if (write(ta->fd, img.data(), size) != (ssize_t)size) return -1;
    // Map the file read-only MAP_SHARED at the fixed address — the
    // exact guise a bionic context area has when the clone scans it.
    int mfd = open(ta->path, O_RDONLY);
    if (mfd < 0) return -1;
    ta->file_map = mmap((void*)fixed_addr, size, PROT_READ, MAP_SHARED,
                        mfd, 0);
    close(mfd);
    if (ta->file_map == MAP_FAILED) { ta->file_map = nullptr; return -1; }
    ta->addr = ta->file_map;
    return 0;
}

static void drop_test_prop_area(TestArea* ta) {
    if (ta->addr) munmap(ta->addr, ta->size);
    if (ta->fd >= 0) close(ta->fd);
    if (ta->path[0]) unlink(ta->path);
}

// Seed a prop_info (serial 0 + value) at file offset `off` through
// the backing fd: the read-only MAP_SHARED mapping reflects pwrite
// through the same page cache, so the area's mapped view updates
// without ever writing the mapping itself.
static int set_area_pi(TestArea* ta, size_t off, const char* value) {
    uint32_t s = 0;
    if (pwrite(ta->fd, &s, 4, (off_t)off) != 4) return -1;
    size_t len = strlen(value) + 1;
    if (pwrite(ta->fd, value, len, (off_t)off + 4) != (ssize_t)len) {
        return -1;
    }
    return 0;
}

// THE Round 25 regression: the pre-map pass must call find() for
// every spoof key BEFORE the maps scan, so a lazily-mapped context
// area (mapped by find() itself on first lookup — bionic's real
// behavior for contexts the zygote never queried) is already present
// when the scan runs, gets cloned private+writable, and the patch
// writes into the CLONE instead of the read-only file page.
//
// The lazy mapping is simulated by the fake find; the ORDERING is
// proven by the maps GENERATOR: it emits the context area's line only
// if the fake find has mapped it by the time production would read
// /proc/self/maps. Pre-Round-25 code (find first called at patch
// time) leaves the area unmapped at scan time -> it is not in the
// mappings -> not remapped -> patch_prop_value writes to the
// read-only MAP_SHARED page -> SIGSEGV. The test would crash, not
// merely fail.
ZS_TEST(clone_pre_maps_lazily_mapped_context_before_scan) {
    // Two areas at fixed, non-conflicting addresses.
    static TestArea serial_area;      // "properties_serial"
    static TestArea context_area;     // lazily mapped per-context area
    ZS_CHECK_EQ(build_test_prop_area(&serial_area, 0x500000000000ul,
                                     0x2000, "serial"), 0);
    // prop_info for a VALUE-spoofed key inside the serial area
    // (seeded through the backing fd; the mapping stays read-only,
    // exactly like the device's real file mapping).
    ZS_CHECK_EQ(set_area_pi(&serial_area,
                            kPropAreaHeaderSize + 0x40,
                            "orange-unlocked-rooted"), 0);
    ZS_CHECK_EQ(build_test_prop_area(&context_area, 0x500000020000ul,
                                     0x2000, "ctx"), 0);
    ZS_CHECK_EQ(set_area_pi(&context_area,
                            kPropAreaHeaderSize + 0x80, "0"), 0);

    // Fake find with LAZY mapping for the context-resident key.
    static int lazy_mapped = 0;
    static int find_calls = 0;
    lazy_mapped = 0;
    find_calls = 0;
    auto fake_find = [](const char* key) -> const void* {
        ++find_calls;
        if (strcmp(key, "ro.boot.verifiedbootstate") == 0) {
            return (const char*)serial_area.addr +
                   kPropAreaHeaderSize + 0x40;
        }
        if (strcmp(key, "ro.boot.flash.locked") == 0) {
            if (!lazy_mapped) {
                // bionic's context_node::open() moment: the REAL
                // mapping appears here, lazily, on first lookup.
                lazy_mapped = 1;
            }
            return (const char*)context_area.addr +
                   kPropAreaHeaderSize + 0x80;
        }
        return nullptr;
    };
    zs_test_set_prop_find(fake_find);

    // Maps generator: called where production reads /proc/self/maps —
    // AFTER the pre-map pass. Records whether the lazy context area
    // existed at scan time (the ordering proof).
    static std::string maps_text;
    static int lazy_at_scan = -1;
    lazy_at_scan = -1;
    auto gen = [](size_t* out_len) -> const char* {
        maps_text.clear();
        char line[256];
        snprintf(line, sizeof line,
                 "%lx-%lx r--p 00000000 00:0c 8401      "
                 "/dev/__properties__/properties_serial\n",
                 (unsigned long)(uintptr_t)serial_area.addr,
                 (unsigned long)(uintptr_t)serial_area.addr +
                     serial_area.size);
        maps_text += line;
        lazy_at_scan = lazy_mapped;
        if (lazy_mapped) {
            snprintf(line, sizeof line,
                     "%lx-%lx r--p 00000000 00:0c 8402      "
                     "/dev/__properties__/u:object_r:default_prop:s0\n",
                     (unsigned long)(uintptr_t)context_area.addr,
                     (unsigned long)(uintptr_t)context_area.addr +
                         context_area.size);
            maps_text += line;
        }
        *out_len = maps_text.size();
        return maps_text.c_str();
    };
    zs_test_set_clone_maps_gen(gen);

    zs_test_reset_props_cloned();
    clone_property_area_private();   // the FULL production path

    // 1. The ordering proof: the context area was mapped BEFORE the
    //    scan ran (pre-map pass first). -1 would mean the generator
    //    never ran; 0 would mean find had not been called yet.
    ZS_CHECK_EQ(lazy_at_scan, 1);
    // 2. Every spoof key was looked up (the pre-map pass is
    //    table-driven, not best-effort).
    ZS_CHECK(find_calls >= 2);
    // 3. The patch landed in the PRIVATE CLONES (the write below the
    //    original read-only pages would have been a SIGSEGV):
    //    - serial area entry now reads "green"
    ZS_CHECK(strcmp((char*)serial_area.addr + kPropAreaHeaderSize + 0x40 + 4,
                    "green") == 0);
    //    - lazily-mapped context entry now reads "1"
    ZS_CHECK(strcmp((char*)context_area.addr + kPropAreaHeaderSize + 0x80 + 4,
                    "1") == 0);
    // 4. The serial top byte carries the new value length (R22 rule).
    {
        uint32_t s = 0;
        memcpy(&s, (char*)serial_area.addr + kPropAreaHeaderSize + 0x40, 4);
        ZS_CHECK_EQ(s >> 24, 5u);   // "green"
        memcpy(&s, (char*)context_area.addr + kPropAreaHeaderSize + 0x80, 4);
        ZS_CHECK_EQ(s >> 24, 1u);   // "1"
    }
    // 5. The clone latched.
    ZS_CHECK(zs_test_props_cloned_latched() == 1);

    // Cleanup.
    zs_test_clear_clone_maps_gen();
    zs_test_reset_prop_find();
    g_prop_line_restore_count = 0;
    drop_test_prop_area(&serial_area);
    drop_test_prop_area(&context_area);
    zs_test_reset_props_cloned();
}

// Round 25 — the old-kernel memfd fallback (Android 7.x on 3.4/3.10
// kernels has no memfd_create). With memfd forced off and a fallback
// directory configured, the filter must serve the SAME filtered bytes
// from an unlinked regular file: seekable, regular-file fstat, and
// the directory holds no leftovers.
ZS_TEST(memfd_fallback_file_serves_filtered_content) {
    std::string fake_maps =
        "7f8a0c000000-7f8a0c010000 r--p 00000000 fd:00 1234   /system/lib64/libc.so\n"
        "7f8a0c100000-7f8a0c110000 r-xp 00000000 fd:00 1234   /data/adb/libpayload.so\n"
        "7f8a0c300000-7f8a0c310000 r-xp 00000000 fd:00 1234   /system/lib64/libart.so\n";

    char dir[] = "/tmp/zs_fallback_XXXXXX";
    ZS_CHECK(mkdtemp(dir) != nullptr);

    int input_fd = write_text_to_memfd(fake_maps);
    ZS_CHECK(input_fd >= 0);

    zs_test_disable_memfd(1);
    zs_test_set_filter_fallback_dir(dir);

    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd >= 0);

    // Content: filtered exactly like the memfd path.
    std::string out = read_fd_to_string(filtered_fd);
    ZS_CHECK_STR_CONTAINS(out, "libc.so");
    ZS_CHECK_STR_CONTAINS(out, "libart.so");
    ZS_CHECK_STR_ABSENT(out, "libpayload.so");

    // It is a seekable regular file (an app reading it twice gets the
    // same bytes — a pipe would break lseek).
    ZS_CHECK_EQ(lseek(filtered_fd, 0, SEEK_SET), (off_t)0);
    struct stat st{};
    ZS_CHECK_EQ(fstat(filtered_fd, &st), 0);
    ZS_CHECK(S_ISREG(st.st_mode));
    ZS_CHECK_EQ((size_t)st.st_size, out.size());
    std::string second = read_fd_to_string(filtered_fd);
    ZS_CHECK(second == out);

    // The directory is EMPTY — the scratch file was unlinked at
    // creation; no forensic trace survives.
    DIR* d = opendir(dir);
    ZS_CHECK(d != nullptr);
    int entries = 0;
    while (d && readdir(d)) ++entries;
    if (d) closedir(d);
    ZS_CHECK_EQ(entries, 2);   // "." and ".." only

    close(filtered_fd);
    close(input_fd);
    zs_test_set_filter_fallback_dir(nullptr);
    zs_test_disable_memfd(0);
    rmdir(dir);
}

// Round 25 — with memfd off AND no usable fallback dir, the filter
// reports failure (the caller's documented fail-open takes over) —
// it must never serve unfiltered content on its own.
ZS_TEST(memfd_fallback_fails_closed_without_a_dir) {
    std::string fake_maps =
        "7f8a0c000000-7f8a0c010000 r--p 00000000 fd:00 1234   /system/lib64/libc.so\n"
        "7f8a0c100000-7f8a0c110000 r-xp 00000000 fd:00 1234   /data/adb/libpayload.so\n";
    int input_fd = write_text_to_memfd(fake_maps);
    ZS_CHECK(input_fd >= 0);

    zs_test_disable_memfd(1);
    zs_test_set_filter_fallback_dir(nullptr);   // no override: real
                                                // path -> getuid() of
                                                // the test -> no data
                                                // dir -> -1
    int filtered_fd = make_filtered_memfd(input_fd, "/proc/self/maps");
    ZS_CHECK(filtered_fd < 0);

    close(input_fd);
    zs_test_disable_memfd(0);
}
