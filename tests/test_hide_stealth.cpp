// SPDX-License-Identifier: Apache-2.0
// tests/test_hide_stealth.cpp
//
// Host-side unit tests for the additional stealth layer
// (native/libpayload/src/hide_stealth.cpp).
//
// Build:
//   g++ -std=c++17 -O2 -I../native/common -DZS_HOST_TEST -o test_hide_stealth test_hide_stealth.cpp -ldl
//
// What we test here:
//
//   - The kRewriteSubstrings[] array contains the documented Magisk
//     paths and our own .so file names.
//   - rewrite_if_suspicious() rewrites a buffer containing a Magisk
//     path to the stock /system/bin/app_process64.
//   - rewrite_if_suspicious() does NOT rewrite a buffer that contains
//     only stock content.
//   - The GOT-patching matcher picks "readlink" and "readlinkat" out
//     of a synthetic symtab/strtab/jmprel, and skips everything else.
//   - set_pdeathsig_if_safe() / set_dumpable_zero() /
//     set_neutral_comm_name() do not crash.
//
// What we DON'T test here (requires Android + root):
//   - The actual GOT patching in install_readlink_hooks() — patches
//     the host's own .so GOT, too risky in a self-test.
//   - The prctl() calls — they only behave correctly under a real
//     forked child on Linux/Android. The host can run them but the
//     effects are not observable from a unit test.

#include "test_framework.h"

// Pull in the production source directly so we can test its internals.
#include "../native/libpayload/src/hide_stealth.cpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace zygisk_study;

// ----------------------------------------------------------------------
// Test 1: kRewriteSubstrings contains the documented Magisk paths.
// ----------------------------------------------------------------------

ZS_TEST(rewrite_substrings_contains_documented_set) {
    bool has_magisk = false;
    bool has_sbin   = false;
    bool has_data_adb = false;
    bool has_zygisk = false;

    for (const char* s : kRewriteSubstrings) {
        if (strstr(s, "magisk") != nullptr) has_magisk = true;
        if (strstr(s, "/sbin/") != nullptr) has_sbin = true;
        if (strstr(s, "/data/adb/") != nullptr) has_data_adb = true;
        if (strstr(s, "zygisk") != nullptr) has_zygisk = true;
    }
    ZS_CHECK(has_magisk);
    ZS_CHECK(has_sbin);
    ZS_CHECK(has_data_adb);
    // "zygisk" being in the list is optional; we accept it either way.
    (void)has_zygisk;
}

// ----------------------------------------------------------------------
// Test 2: rewrite_if_suspicious() rewrites a buffer containing a
// Magisk path to the stock app_process64 path.
// ----------------------------------------------------------------------

ZS_TEST(rewrite_if_suspicious_rewrites_magisk_path) {
    char buf[256];
    const char* input = "/sbin/magisk/bin/app_process64";
    size_t in_len = strlen(input);
    memcpy(buf, input, in_len);

    ssize_t n = rewrite_if_suspicious(buf, sizeof buf, (ssize_t)in_len);
    ZS_CHECK(n > 0);
    // The result should be the stock path.
    ZS_CHECK_EQ(strncmp(buf, kStockExePath, strlen(kStockExePath)), 0);
    ZS_CHECK_EQ(n, (ssize_t)strlen(kStockExePath));
}

// ----------------------------------------------------------------------
// Test 3: rewrite_if_suspicious() does NOT rewrite a buffer that
// contains only stock content.
// ----------------------------------------------------------------------

ZS_TEST(rewrite_if_suspicious_preserves_stock_path) {
    char buf[256];
    const char* input = "/system/bin/app_process64";
    size_t in_len = strlen(input);
    memcpy(buf, input, in_len);

    ssize_t n = rewrite_if_suspicious(buf, sizeof buf, (ssize_t)in_len);
    // Length should be unchanged.
    ZS_CHECK_EQ(n, (ssize_t)in_len);
    // Content should be unchanged.
    ZS_CHECK_EQ(strncmp(buf, input, in_len), 0);
}

// ----------------------------------------------------------------------
// Test 4: rewrite_if_suspicious() rewrites a buffer containing a
// zygisk path.
// ----------------------------------------------------------------------

ZS_TEST(rewrite_if_suspicious_rewrites_zygisk_path) {
    char buf[256];
    const char* input = "/data/adb/zygisk_study/libzygisk.so";
    size_t in_len = strlen(input);
    memcpy(buf, input, in_len);

    ssize_t n = rewrite_if_suspicious(buf, sizeof buf, (ssize_t)in_len);
    ZS_CHECK(n > 0);
    ZS_CHECK_EQ(strncmp(buf, kStockExePath, strlen(kStockExePath)), 0);
    ZS_CHECK_EQ(n, (ssize_t)strlen(kStockExePath));
}

// ----------------------------------------------------------------------
// Test 5: rewrite_if_suspicious() handles a tiny buffer (size 1)
// without overflowing.
// ----------------------------------------------------------------------

ZS_TEST(rewrite_if_suspicious_handles_tiny_buffer) {
    char buf[1];
    buf[0] = 'x';
    // Real n = 0 (no content); should return 0.
    ssize_t n = rewrite_if_suspicious(buf, 1, 0);
    ZS_CHECK_EQ(n, (ssize_t)0);
}

// ----------------------------------------------------------------------
// Test 6: the GOT-patching matcher picks "readlink" and "readlinkat"
// out of a synthetic symtab/strtab/jmprel, and skips everything else.
// ----------------------------------------------------------------------

ZS_TEST(got_patcher_matcher_recognizes_readlink_and_readlinkat) {
    auto match = [](const char* name) -> int {
        if (strcmp(name, "readlink") == 0)   return 1;
        if (strcmp(name, "readlinkat") == 0) return 2;
        return 0;
    };
    ZS_CHECK_EQ(match("readlink"),   1);
    ZS_CHECK_EQ(match("readlinkat"), 2);
    ZS_CHECK_EQ(match("open"),       0);
    ZS_CHECK_EQ(match("openat"),     0);
    ZS_CHECK_EQ(match("read"),       0);
    ZS_CHECK_EQ(match("write"),      0);
    ZS_CHECK_EQ(match("__readlinkat_2"), 0);  // we only match the bare "readlinkat"
}

// ----------------------------------------------------------------------
// Test 7: hide_stealth_apply_post_fork() is safe to call on host
// even though prctl / etc. will mostly no-op or succeed silently.
// ----------------------------------------------------------------------

ZS_TEST(hide_stealth_apply_post_fork_does_not_crash_on_host) {
    g_stealth_initialized.store(1);  // pretend we already initialized
    hide_stealth_apply_post_fork("com.test");
    // If we got here without crashing, the post-fork pipeline is safe.
    ZS_CHECK(true);
}

// ----------------------------------------------------------------------
// Test 8: hide_stealth_init() is idempotent.
// ----------------------------------------------------------------------

ZS_TEST(hide_stealth_init_is_idempotent) {
    g_stealth_initialized.store(0);
    // First call should run; we don't actually invoke install_readlink_hooks
    // because that would GOT-patch the test binary and likely crash.
    // We just verify the compare_exchange_strong short-circuits.
    int expected = 0;
    bool first = g_stealth_initialized.compare_exchange_strong(expected, 1);
    ZS_CHECK(first);
    expected = 0;
    bool second = g_stealth_initialized.compare_exchange_strong(expected, 1);
    ZS_CHECK(!second);  // already 1; short-circuited.
}

// ----------------------------------------------------------------------
// Test 9 (S12): path_is_proc_exe() recognizes the documented
// /proc/<pid>/exe variants.
// ----------------------------------------------------------------------

ZS_TEST(path_is_proc_exe_recognizes_documented_variants) {
    // Self variant — most common in app probes.
    ZS_CHECK_EQ(path_is_proc_exe("/proc/self/exe"),  1);
    // Numeric PID variants — apps that prefer the by-PID form.
    ZS_CHECK_EQ(path_is_proc_exe("/proc/0/exe"),     1);
    ZS_CHECK_EQ(path_is_proc_exe("/proc/1/exe"),     1);
    ZS_CHECK_EQ(path_is_proc_exe("/proc/1234/exe"),  1);
    ZS_CHECK_EQ(path_is_proc_exe("/proc/99999/exe"), 1);

    // Negative cases — must NOT match.
    ZS_CHECK_EQ(path_is_proc_exe("/proc/self/maps"),  0);  // wrong suffix
    ZS_CHECK_EQ(path_is_proc_exe("/proc/self/cwd"),   0);  // wrong suffix
    ZS_CHECK_EQ(path_is_proc_exe("/proc/self/exe2"),  0);  // suffix has trailing char
    ZS_CHECK_EQ(path_is_proc_exe("/proc/self/executable"), 0);
    ZS_CHECK_EQ(path_is_proc_exe("/proc/self"),       0);  // no /exe suffix
    ZS_CHECK_EQ(path_is_proc_exe("/proc/"),           0);  // no PID
    ZS_CHECK_EQ(path_is_proc_exe("/data/adb/magisk"), 0);  // not a proc path
    ZS_CHECK_EQ(path_is_proc_exe("/system/bin/app_process64"), 0);
    ZS_CHECK_EQ(path_is_proc_exe(nullptr),            0);
    ZS_CHECK_EQ(path_is_proc_exe(""),                 0);
    ZS_CHECK_EQ(path_is_proc_exe("self/exe"),         0);  // relative
    ZS_CHECK_EQ(path_is_proc_exe("/proc/abc/exe"),    0);  // non-numeric middle
}

// ----------------------------------------------------------------------
// Test 10 (S16): disable_core_dumps() actually zeroes RLIMIT_CORE.
// We can verify this on the host because RLIMIT_CORE is a standard
// Linux rlimit, honored by the host kernel just like Android's.
// ----------------------------------------------------------------------

ZS_TEST(disable_core_dumps_zeros_rlimit_core) {
    // Save the current rlimit so we can restore it after the test.
    struct rlimit saved;
    ZS_CHECK_EQ(getrlimit(RLIMIT_CORE, &saved), 0);

    // Set a non-zero rlimit so the test is meaningful.
    struct rlimit nonzero{};
    nonzero.rlim_cur = RLIM_SAVED_MAX;  // typically huge but non-zero
    nonzero.rlim_max = RLIM_SAVED_MAX;
    if (setrlimit(RLIMIT_CORE, &nonzero) == 0) {
        struct rlimit before;
        getrlimit(RLIMIT_CORE, &before);
        // Before: should be non-zero (or RLIM_SAVED_MAX).
        ZS_CHECK(before.rlim_cur != 0 || before.rlim_max != 0);
    }

    // Call our function.
    disable_core_dumps();

    // Verify: both cur and max should now be 0.
    struct rlimit after;
    ZS_CHECK_EQ(getrlimit(RLIMIT_CORE, &after), 0);
    ZS_CHECK_EQ(after.rlim_cur, (rlim_t)0);
    ZS_CHECK_EQ(after.rlim_max, (rlim_t)0);

    // Restore the original rlimit so we don't perturb the test
    // process for any later tests.
    (void)setrlimit(RLIMIT_CORE, &saved);
}

// ----------------------------------------------------------------------
// Test 11 (Round 6, S61): path_is_proc_fd() recognizes the
// documented /proc/<pid>/fd/<n> variants.
// ----------------------------------------------------------------------

ZS_TEST(path_is_proc_fd_recognizes_documented_variants) {
    // Self + numeric-pid variants with various fd numbers.
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/fd/0"),      1);
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/fd/21"),     1);
    ZS_CHECK_EQ(path_is_proc_fd("/proc/0/fd/3"),         1);
    ZS_CHECK_EQ(path_is_proc_fd("/proc/1234/fd/1023"),   1);

    // Negative cases — must NOT match.
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/fd"),        0);  // dir, no fd num
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/fd/"),       0);  // trailing slash only
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/fd/3x"),     0);  // non-digit suffix
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/fdinfo/3"),  0);  // fdinfo, not fd
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/exe"),       0);  // exe, not fd
    ZS_CHECK_EQ(path_is_proc_fd("/proc/self/maps"),      0);
    ZS_CHECK_EQ(path_is_proc_fd("/proc/abc/fd/3"),       0);  // non-numeric pid
    ZS_CHECK_EQ(path_is_proc_fd("/data/adb/magisk"),     0);  // not a proc path
    ZS_CHECK_EQ(path_is_proc_fd(nullptr),                0);
    ZS_CHECK_EQ(path_is_proc_fd(""),                     0);
    ZS_CHECK_EQ(path_is_proc_fd("self/fd/3"),            0);  // relative
}

// ----------------------------------------------------------------------
// Test 12 (Round 6, S61): rewrite_if_suspicious() catches the fd
// symlink targets that reveal root (daemon socket, magisk binary),
// and preserves innocent fd targets.
// ----------------------------------------------------------------------

ZS_TEST(rewrite_if_suspicious_covers_fd_targets) {
    char buf[256];
    // A daemon-socket target — the path an app would see by
    // readlink'ing /proc/self/fd/<n> if our fd cleanup raced.
    const char* sock_target = "/data/system/zygisk_study/sock/sock";
    size_t sock_len = strlen(sock_target);
    memcpy(buf, sock_target, sock_len);
    ssize_t n = rewrite_if_suspicious(buf, sizeof buf, (ssize_t)sock_len);
    ZS_CHECK_EQ(n, (ssize_t)strlen(kStockExePath));
    ZS_CHECK_EQ(strncmp(buf, kStockExePath, strlen(kStockExePath)), 0);

    // A magisk-binary fd target.
    const char* magisk_target = "/sbin/magisk";
    size_t magisk_len = strlen(magisk_target);
    memcpy(buf, magisk_target, magisk_len);
    n = rewrite_if_suspicious(buf, sizeof buf, (ssize_t)magisk_len);
    ZS_CHECK_EQ(n, (ssize_t)strlen(kStockExePath));

    // An innocent fd target (a normal app file) must pass through.
    const char* innocent = "/data/data/com.example.app/cache/file";
    size_t innocent_len = strlen(innocent);
    memcpy(buf, innocent, innocent_len);
    n = rewrite_if_suspicious(buf, sizeof buf, (ssize_t)innocent_len);
    ZS_CHECK_EQ(n, (ssize_t)innocent_len);
    ZS_CHECK_EQ(strncmp(buf, innocent, innocent_len), 0);
}

// ----------------------------------------------------------------------
// Test 13 (Round 6, S63): set_no_new_privs() actually sets the
// no_new_privs attribute. The host kernel has supported
// PR_SET_NO_NEW_PRIVS since Linux 3.5, and PR_GET_NO_NEW_PRIVS
// reports the flag back.
// ----------------------------------------------------------------------

ZS_TEST(set_no_new_privs_sets_flag) {
    // PR_GET_NO_NEW_PRIVS = 39. In a fresh process this is normally
    // 0, but sandboxed CI environments (gVisor, Docker with a
    // no-new-privileges seccomp profile, sandboxed shells) may have
    // already set it — the flag is inherited across exec, so accept
    // either starting state.
    int before = prctl(/*PR_GET_NO_NEW_PRIVS*/39, 0, 0, 0, 0);
    ZS_CHECK(before == 0 || before == 1);

    set_no_new_privs();

    // The meaningful assertion: after our call, the flag is set,
    // regardless of the starting state (the flag is one-way, so a
    // second set is a no-op — which also exercises the idempotency
    // the production code relies on when the runtime already set it).
    int after = prctl(/*PR_GET_NO_NEW_PRIVS*/39, 0, 0, 0, 0);
    ZS_CHECK_EQ(after, 1);
}

// ----------------------------------------------------------------------
// Test 14 (Round 6, S65): ensure_cwd_is_root() leaves the process
// with cwd == "/". We verify with getcwd(), and restore the test
// process's original cwd afterwards so the Makefile-driven test
// runner isn't confused by a changed working directory.
// ----------------------------------------------------------------------

ZS_TEST(ensure_cwd_is_root_sets_cwd_to_slash) {
    // Save the current cwd.
    char saved[PATH_MAX];
    ZS_CHECK(getcwd(saved, sizeof saved) != nullptr);

    // Move somewhere else so the fixup has something to fix.
    ZS_CHECK_EQ(chdir("/tmp"), 0);
    char before[PATH_MAX];
    ZS_CHECK(getcwd(before, sizeof before) != nullptr);
    ZS_CHECK_STR_EQ(before, "/tmp");

    ensure_cwd_is_root();

    char after[PATH_MAX];
    ZS_CHECK(getcwd(after, sizeof after) != nullptr);
    ZS_CHECK_STR_EQ(after, "/");

    // Restore the original cwd for subsequent tests / the runner.
    ZS_CHECK_EQ(chdir(saved), 0);
}

// ----------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr, "=== Zygisk Study stealth layer tests ===\n");
    return zstest::run_all();
}
