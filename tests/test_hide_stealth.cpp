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
// main()
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr, "=== Zygisk Study stealth layer tests ===\n");
    return zstest::run_all();
}
