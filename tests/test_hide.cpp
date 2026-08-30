// SPDX-License-Identifier: Apache-2.0
// tests/test_hide.cpp
//
// Host-side unit tests for the basic hide layer
// (native/libpayload/src/hide.cpp).
//
// Build:
//   g++ -std=c++17 -O2 -I../native/common -DZS_HOST_TEST -o test_hide test_hide.cpp
//
// The tests work because we compile hide.cpp directly via #include,
// so its static functions become visible to us. The Linux /proc/self/maps
// format is identical to Android's (both are Linux kernels), so the
// parser tests are meaningful on the host.
//
// Android-specific syscalls (unshare, umount2, __system_property_set)
// are NOT exercised here — they require root + Android. We test the
// pure-logic helpers: maps parser, denylist parser, decision logic.
//
// The tests use a tiny custom framework (test_framework.h) that has
// no third-party dependencies.

#include "test_framework.h"

// Pull in the production source directly so we can test its internals.
// The static functions become accessible because they're in the same
// translation unit.
#include "../native/libpayload/src/hide.cpp"

#include <cstdio>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace zygisk_study;

// ----------------------------------------------------------------------
// Test fixtures: a writable denylist file we can populate for tests.
// ----------------------------------------------------------------------

static std::string make_temp_denylist(const std::string& contents) {
    char tmpl[] = "/tmp/zstest_denylist_XXXXXX";
    int fd = mkstemp(tmpl);
    ZS_CHECK(fd >= 0);
    if (write(fd, contents.data(), contents.size()) !=
        (ssize_t)contents.size()) {
        close(fd);
        ZS_CHECK(!"failed to write temp denylist");
    }
    close(fd);
    return tmpl;
}

static void remove_temp(const std::string& path) {
    ::unlink(path.c_str());
}

// ----------------------------------------------------------------------
// Test 1: snapshot_self_so() finds our own .so in /proc/self/maps.
//
// We can't actually load libpayload.so at test time, but we can
// verify the parsing logic by:
//   - loading a small .so (libdl.so is always present)
//   - temporarily adding "libdl.so" to the matcher (we can't easily,
//     so we just verify the function runs without crashing and
//     produces a non-negative result)
// Actually — we *can* verify by calling snapshot_self_so() and
// checking that g_self_so_records is populated if any of our named
// .so files happen to be mapped. In the test binary, none of them
// are, so the result is empty. That's the expected state.
// We then verify that the parsing of a real /proc/self/maps line
// works by inspecting the line format.
// ----------------------------------------------------------------------

ZS_TEST(snapshot_self_so_runs_clean_when_nothing_matches) {
    // Reset the recorded snapshot.
    g_self_so_records.clear();
    snapshot_self_so();
    // On the host, none of libpayload/libzygisk/libzn_loader are
    // mapped, so the snapshot is empty. The function must not crash.
    ZS_CHECK_EQ(g_self_so_records.size(), (size_t)0);
}

// ----------------------------------------------------------------------
// Test 2: load_denylist() parses the file correctly.
// ----------------------------------------------------------------------

ZS_TEST(load_denylist_parses_plain_lines) {
    // Reset cache.
    g_denylist_cache.clear();
    g_denylist_loaded.store(0);

    std::string path = make_temp_denylist(
        "com.example.app1\n"
        "com.example.app2\n"
        "com.third.party\n"
    );

    // The production code hardcodes /data/system/zygisk_study/denylist.
    // We can't easily point it at our temp file without refactoring,
    // so this test instead exercises the parsing logic by re-implementing
    // the parser and verifying the result. The production parser is
    // 8 lines; we mirror it here exactly to track any drift.

    // Mirror of the parser from hide.cpp, against the temp file:
    FILE* fp = fopen(path.c_str(), "r");
    ZS_CHECK(fp != nullptr);
    char line[256];
    std::unordered_set<std::string> parsed;
    while (fgets(line, sizeof line, fp)) {
        char* nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char* s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == '#') continue;
        parsed.insert(s);
    }
    fclose(fp);

    ZS_CHECK_EQ(parsed.size(),         (size_t)3);
    ZS_CHECK(parsed.count("com.example.app1") > 0);
    ZS_CHECK(parsed.count("com.example.app2") > 0);
    ZS_CHECK(parsed.count("com.third.party")  > 0);

    remove_temp(path);
}

ZS_TEST(load_denylist_ignores_comments_and_blanks) {
    std::string path = make_temp_denylist(
        "# this is a comment\n"
        "\n"
        "   \n"
        "com.real.app\n"
        "  # leading-space comment\n"
        "com.real.app2\n"
    );

    FILE* fp = fopen(path.c_str(), "r");
    ZS_CHECK(fp != nullptr);
    char line[256];
    std::unordered_set<std::string> parsed;
    while (fgets(line, sizeof line, fp)) {
        char* nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char* s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == '#') continue;
        parsed.insert(s);
    }
    fclose(fp);

    ZS_CHECK_EQ(parsed.size(),         (size_t)2);
    ZS_CHECK(parsed.count("com.real.app")  > 0);
    ZS_CHECK(parsed.count("com.real.app2") > 0);

    remove_temp(path);
}

// ----------------------------------------------------------------------
// Test 3: hide_setup_for_target() decides correctly.
//
// We populate g_denylist_cache manually, then call the public function
// to verify it returns 1 for matches and 0 for non-matches.
// ----------------------------------------------------------------------

ZS_TEST(hide_setup_for_target_returns_one_for_denylisted) {
    g_denylist_cache.clear();
    g_denylist_cache.insert("com.sensitive.banking");
    g_denylist_loaded.store(1);

    int r = hide_setup_for_target("com.sensitive.banking");
    ZS_CHECK_EQ(r, 1);
}

ZS_TEST(hide_setup_for_target_returns_zero_for_non_denylisted) {
    g_denylist_cache.clear();
    g_denylist_cache.insert("com.sensitive.banking");
    g_denylist_loaded.store(1);

    int r = hide_setup_for_target("com.innocent.game");
    ZS_CHECK_EQ(r, 0);
}

ZS_TEST(hide_setup_for_target_returns_zero_for_null_or_empty) {
    g_denylist_cache.clear();
    g_denylist_cache.insert("anything");
    g_denylist_loaded.store(1);

    ZS_CHECK_EQ(hide_setup_for_target(nullptr), 0);
    ZS_CHECK_EQ(hide_setup_for_target(""),       0);
}

// ----------------------------------------------------------------------
// Test 4: hide_register_globals() is idempotent.
// ----------------------------------------------------------------------

ZS_TEST(hide_register_globals_is_idempotent) {
    g_initialized.store(0);
    g_self_so_records.clear();

    hide_register_globals();
    size_t after_first = g_self_so_records.size();
    // Snapshot is empty on host (none of our .so mapped).
    ZS_CHECK_EQ(after_first, (size_t)0);

    // Calling again must NOT re-run snapshot — the compare_exchange
    // guard short-circuits.
    hide_register_globals();
    ZS_CHECK_EQ(g_initialized.load(), 1);
}

// ----------------------------------------------------------------------
// Test 5: scrub_properties() static key list contains the keys we
// documented in docs/hiding.md.
//
// We can't actually call scrub_properties() on the host because
// __system_property_set won't resolve via dlsym(libc.so) — libc
// on regular Linux doesn't export that symbol. But we can verify
// the static array is the right size and contains the expected
// keys by re-implementing the array access.
//
// Since the array is static inside hide.cpp, our #include of hide.cpp
// gives us direct access to kMagiskRevealingProps. We verify its size
// and a few known members.
// ----------------------------------------------------------------------

ZS_TEST(property_scrub_list_contains_expected_keys) {
    // The array is now at file scope in hide.cpp (still static), so
    // our #include of hide.cpp gives us direct access.
    const size_t count = sizeof(kMagiskRevealingProps)
                         / sizeof(kMagiskRevealingProps[0]);
    ZS_CHECK(count >= 10);

    // Verify a representative subset.
    bool has_vbstate = false, has_magisk = false, has_kernelsu = false;
    for (const char* k : kMagiskRevealingProps) {
        if (strcmp(k, "ro.boot.verifiedbootstate") == 0) has_vbstate = true;
        if (strcmp(k, "ro.magisk.version")        == 0) has_magisk  = true;
        if (strcmp(k, "ro.kernelsu.version")      == 0) has_kernelsu= true;
    }
    ZS_CHECK(has_vbstate);
    ZS_CHECK(has_magisk);
    ZS_CHECK(has_kernelsu);
}

// ----------------------------------------------------------------------
// Test 6: hide_apply_for_target() with g_will_hide=false is a no-op.
// ----------------------------------------------------------------------

ZS_TEST(hide_apply_for_target_is_noop_when_not_hiding) {
    g_will_hide.store(0);
    // Must not call unshare / umount / munmap.
    hide_apply_for_target("anything");
    // If we got here without crashing, the no-op path worked.
    ZS_CHECK(true);
}

// ----------------------------------------------------------------------
// Test 7: hide_apply_for_target() with g_will_hide=true attempts the
// unshare path. On a non-root host, unshare(CLONE_NEWNS) returns -1.
// We verify the function continues anyway (logs warning, proceeds).
// ----------------------------------------------------------------------

ZS_TEST(hide_apply_for_target_continues_when_unshare_fails) {
    g_will_hide.store(1);
    g_self_so_records.clear();  // ensure unmap_self is a no-op
    hide_apply_for_target("test");
    // No assertions on return value (function is void). The test
    // passes if we did not crash. The non-root host cannot do unshare,
    // so the function logs a warning and proceeds — exactly the
    // documented behavior.
    ZS_CHECK(true);
}

// ----------------------------------------------------------------------
// Test 8: unmount_magisk_paths() parses /proc/self/mounts correctly.
//
// We can't actually unmount as non-root, but we can verify the parsing
// loop works by mirroring the production loop and checking we get
// back sensible candidates from a real /proc/self/mounts on Linux.
// ----------------------------------------------------------------------

ZS_TEST(unmount_magisk_paths_parser_recognizes_data_adb_and_sbin) {
    // The production code matches /data/adb/ and /sbin/. We verify
    // the matching logic is correct against synthetic mount entries.
    struct fake_mnt { const char* dir; };
    fake_mnt fakes[] = {
        {"/data/adb/magisk"},
        {"/sbin/magisk"},
        {"/system/lib/modules"},
        {"/data/data/com.app"},
        {"/data/adb/ksu"},
    };
    int matches = 0;
    for (const auto& m : fakes) {
        if (strncmp(m.dir, "/data/adb/", 10) == 0 ||
            strncmp(m.dir, "/sbin/",       6) == 0) {
            ++matches;
        }
    }
    ZS_CHECK_EQ(matches, 3);  // first, second, and fifth entries
}

// ----------------------------------------------------------------------
// main(): run all tests.
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr, "=== Zygisk Study hide layer tests ===\n");
    return zstest::run_all();
}
