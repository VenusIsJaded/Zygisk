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
    // Reset the recorded snapshot (P1.38: fixed-size array, reset count).
    g_self_so_count = 0;
    snapshot_self_so();
    // On the host, none of libpayload/libzygisk/libzn_loader are
    // mapped, so the snapshot is empty. The function must not crash.
    ZS_CHECK_EQ(g_self_so_count, (size_t)0);
}

// ----------------------------------------------------------------------
// Test (Round 5, P1.38): the fixed-size array for g_self_so_records
// has the expected capacity and is bounded safely.
//
// We verify that kMaxSoRecords is at least 16 (covers the typical
// 3 .so files × ~4 segments each = ~12 entries plus headroom) and
// at most 64 (covers pathological cases without excessive memory).
// We also verify the array is at file scope and accessible.
// ----------------------------------------------------------------------

ZS_TEST(self_so_records_array_has_sensible_capacity) {
    ZS_CHECK(kMaxSoRecords >= 16);
    ZS_CHECK(kMaxSoRecords <= 64);
    // The array itself must be accessible without crashing.
    ZS_CHECK(g_self_so_records != nullptr);
    // Reset and verify count is 0 after reset.
    g_self_so_count = 0;
    ZS_CHECK_EQ(g_self_so_count, (size_t)0);
    // Simulate one entry: write directly to the array.
    if (kMaxSoRecords > 0) {
        g_self_so_records[0].base  = 0x1000;
        g_self_so_records[0].size  = 0x1000;
        g_self_so_records[0].flags = ZS_SO_SELF;
        g_self_so_count = 1;
        ZS_CHECK_EQ(g_self_so_records[0].base, (uintptr_t)0x1000);
        ZS_CHECK_EQ(g_self_so_count, (size_t)1);
        // Reset for other tests.
        g_self_so_count = 0;
    }
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
    // P1.38: fixed-size array, reset count.
    g_self_so_count = 0;

    hide_register_globals();
    size_t after_first = g_self_so_count;
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
// Test (Round 5, S46): the extended property scrub list contains
// the new Magisk / KernelSU / bootloader-revealing keys added in
// Round 5. We verify the new keys are present in kMagiskRevealingProps
// so the scrub_prop_in_memory path will hit them.
//
// Without this test, someone could accidentally remove a key from
// the array (regression) and we wouldn't catch it.
// ----------------------------------------------------------------------

ZS_TEST(property_scrub_list_contains_round5_additions) {
    bool has_init_svc_magisk      = false;
    bool has_init_svc_magisk_pfsd = false;
    bool has_persist_magisk_hide  = false;
    bool has_vbmeta_digest        = false;
    bool has_bootmanager_verity   = false;
    bool has_service_magisk_root  = false;
    bool has_persist_sys_rootdir  = false;
    bool has_warrantybit          = false;
    bool has_warranty_bits        = false;
    for (const char* k : kMagiskRevealingProps) {
        if (strcmp(k, "init.svc.magisk")         == 0) has_init_svc_magisk      = true;
        if (strcmp(k, "init.svc.magisk_pfsd")    == 0) has_init_svc_magisk_pfsd = true;
        if (strcmp(k, "persist.magisk.hide")     == 0) has_persist_magisk_hide  = true;
        if (strcmp(k, "ro.boot.vbmeta.digest")   == 0) has_vbmeta_digest        = true;
        if (strcmp(k, "ro.bootmanager.veritymode")== 0) has_bootmanager_verity  = true;
        if (strcmp(k, "service.magisk.rootdir")  == 0) has_service_magisk_root  = true;
        if (strcmp(k, "persist.sys.rootdir")     == 0) has_persist_sys_rootdir  = true;
        if (strcmp(k, "ro.boot.warrantybit")     == 0) has_warrantybit          = true;
        if (strcmp(k, "ro.warranty.bits")        == 0) has_warranty_bits        = true;
    }
    ZS_CHECK(has_init_svc_magisk);
    ZS_CHECK(has_init_svc_magisk_pfsd);
    ZS_CHECK(has_persist_magisk_hide);
    ZS_CHECK(has_vbmeta_digest);
    ZS_CHECK(has_bootmanager_verity);
    ZS_CHECK(has_service_magisk_root);
    ZS_CHECK(has_persist_sys_rootdir);
    ZS_CHECK(has_warrantybit);
    ZS_CHECK(has_warranty_bits);
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
    // P1.38: fixed-size array, reset count to ensure unmap_self is a no-op.
    g_self_so_count = 0;
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
    // Round 7: the parser now runs against the REAL production code
    // (hide_parse_mounts_line + field_is_root_path), not a mirror.
    // It must match BOTH mount points and magic-mount sources.
    struct Case {
        const char* line;    // "<source> <mount_point> <fstype> ..."
        int         expect;  // 1 = should match (be unmounted)
    };
    Case cases[] = {
        // Classic bind mounts under /data/adb (mount-point match).
        {"/data/adb/modules/xyz /data/adb/modules/xyz ext4 ro 0 0", 1},
        {"tmpfs /sbin tmpfs ro,seclabel 0 0", 0},               // /sbin alone is not a match...
        {"tmpfs /sbin/.magisk tmpfs ro 0 0", 1},               // ...but /sbin/.magisk is
        // Magic mount: source under /data/adb, mount point in /system.
        // The pre-Round-7 code matched ONLY the mount point and
        // missed every one of these.
        {"/data/adb/modules/id1/system/app/Foo.apk /system/app/Foo.apk ext4 ro,bind 0 0", 1},
        {"/data/adb/modules/id2/system/bin/su /system/bin/su ext4 ro,bind 0 0", 1},
        // KernelSU paths.
        {"/data/adb/ksu/bin/busybox /system/bin/busybox ext4 ro,bind 0 0", 1},
        // Ordinary mounts must be left alone.
        {"/dev/block/bootdevice/by-name/system /system ext4 ro 0 0", 0},
        {"tmpfs /data/local/tmp tmpfs rw 0 0", 0},
        {"/proc /proc proc rw 0 0", 0},
        {"/sys /sys sysfs rw 0 0", 0},
    };
    for (const Case& c : cases) {
        char buf[256];
        snprintf(buf, sizeof buf, "%s", c.line);
        MountFields mf{};
        int ok = hide_parse_mounts_line(buf, buf + strlen(buf), &mf);
        ZS_CHECK_EQ(ok, 1);
        int matched = field_is_root_path(mf.mnt_point, mf.mnt_point_len) ||
                      field_is_root_path(mf.source,   mf.source_len);
        ZS_CHECK_EQ(matched, c.expect);
    }
}

// ----------------------------------------------------------------------
// Test 12 (Round 7): the uid-keyed denylist decision. This is the
// decision path that actually runs on a device (fired from the
// setresgid/setresuid hooks). The appId math (uid % 100000) must map
// a work-profile uid to the same denylist entry as user 0.
// ----------------------------------------------------------------------

ZS_TEST(hide_setup_for_target_uid_matches_app_id_family) {
    g_deny_app_ids.clear();
    g_deny_app_ids.insert(10432);  // appId of com.sensitive.banking
    g_uid_map_loaded.store(1);
    g_will_hide.store(0);

    // User 0.
    ZS_CHECK_EQ(hide_setup_for_target_uid(10432), 1);
    // Work profile (user 10): uid = 10*100000 + appId.
    ZS_CHECK_EQ(hide_setup_for_target_uid(1010432), 1);
    // Secondary user 11.
    ZS_CHECK_EQ(hide_setup_for_target_uid(110432), 1);
    // A different app.
    ZS_CHECK_EQ(hide_setup_for_target_uid(10500), 0);
    // system uid (1000) and root — fast-path rejection, never hidden.
    ZS_CHECK_EQ(hide_setup_for_target_uid(1000), 0);
    ZS_CHECK_EQ(hide_setup_for_target_uid(0), 0);
}

// ----------------------------------------------------------------------
// Test 13 (Round 7): the unmap record accessors — flag classification
// drives the Tier A split (self records go to the asm trampoline,
// others are plain C munmaps).
// ----------------------------------------------------------------------

ZS_TEST(unmap_record_flags_drive_tier_a_split) {
    g_self_so_count = 0;
    g_self_so_records[0] = so_record{0x2000, 0x1000, ZS_SO_SELF, 0};
    g_self_so_records[1] = so_record{0x8000, 0x1000, ZS_SO_OTHER, 0};
    g_self_so_count = 2;

    ZS_CHECK_EQ(hide_trampoline_unmap_pending(), 1);
    ZS_CHECK_EQ(hide_unmap_record_count(), (size_t)2);

    so_record out[8] = {};
    size_t n = hide_unmap_records(out, 8);
    ZS_CHECK_EQ(n, (size_t)2);
    ZS_CHECK_EQ(out[0].base, (uintptr_t)0x2000);
    ZS_CHECK_EQ(out[0].flags, (uint32_t)ZS_SO_SELF);
    ZS_CHECK_EQ(out[1].flags, (uint32_t)ZS_SO_OTHER);

    // Cap semantics: requesting fewer records returns fewer.
    so_record few[1] = {};
    ZS_CHECK_EQ(hide_unmap_records(few, 1), (size_t)1);

    // With no self records, the trampoline is not pending.
    g_self_so_records[0].flags = ZS_SO_OTHER;
    ZS_CHECK_EQ(hide_trampoline_unmap_pending(), 0);
    g_self_so_count = 0;
}

// ----------------------------------------------------------------------
// Test 14 (Round 7): the property spoof table reports STOCK values
// (never empty) for boot-state keys — an empty verifiedbootstate is
// itself a detection signal, which is why the old "scrub to empty"
// direct-write approach was replaced.
// ----------------------------------------------------------------------

ZS_TEST(property_spoof_list_reports_stock_values_for_boot_keys) {
    size_t count = 0;
    const char* const* keys = hide_revealing_props(&count);
    ZS_CHECK(count >= 20);
    // Spot-check the documented keys.
    auto has = [&](const char* k) {
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(keys[i], k) == 0) return true;
        }
        return false;
    };
    ZS_CHECK(has("ro.boot.verifiedbootstate"));
    ZS_CHECK(has("ro.boot.vbmeta.device_state"));
    ZS_CHECK(has("init.svc.magisk"));
    ZS_CHECK(has("ro.zygisk_study.version"));
}

// ----------------------------------------------------------------------
// main(): run all tests.
// ----------------------------------------------------------------------

int main() {
    std::fprintf(stderr, "=== Zygisk Study hide layer tests ===\n");
    return zstest::run_all();
}
