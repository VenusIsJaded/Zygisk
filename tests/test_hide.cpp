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
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cxxabi.h>   // __cxa_atexit / __cxa_finalize (Round 30)

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
// Test 7: hide_apply_for_target() with g_will_hide=true and a FAILING
// unshare (non-root host) skips the unmount phase entirely.
//
// Round 9 (B1): the old code fell through to the umount loop after a
// failed unshare — which, on a real rooted device, would umount the
// INIT namespace's module mounts system-wide. Now the function is
// fail-closed: no unmount after any namespace-setup failure.
// ----------------------------------------------------------------------

ZS_TEST(hide_apply_for_target_skips_unmounts_when_unshare_fails) {
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_mount_log_reset();
    hide_apply_for_target("test");
    // On the host the REAL unshare fails (no CAP_SYS_ADMIN), so the
    // log must contain the failure marker 'U' and NO umount2 'm'.
    const char* log = zs_test_mount_log();
    ZS_CHECK_STR_CONTAINS(log, "U");
    ZS_CHECK_STR_ABSENT(log, "m");
    ZS_CHECK_STR_ABSENT(log, "s");  // slave remount never runs either
}

// ----------------------------------------------------------------------
// Round 9 (B1) mount-namespace ordering + fail-closed tests, driven
// through the syscall seam (no root required).
// ----------------------------------------------------------------------

// Recorder versions of the three syscalls. They append their own
// markers to the mount log so the ordering assertions are meaningful
// regardless of which fn set is installed.
static int rec_unshare_ok(int) { zs_test_mount_log_append('u'); return 0; }
static int rec_slave_ok()     { zs_test_mount_log_append('s'); return 0; }
static int rec_umount_ok(const char*, int) {
    zs_test_mount_log_append('m');
    return 0;
}

// unshare succeeds, slave remount FAILS (e.g. propagation already
// detached differently, or an LSM denied mount(2)).
static int rec_unshare_ok_slave_fails() {
    // Used as the SLAVE fn: log the slave-failure marker 'S'.
    zs_test_mount_log_append('S');
    errno = EPERM;
    return -1;
}

ZS_TEST(hide_apply_unmount_order_is_unshare_then_slave_then_umounts) {
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_set_mount_fns(rec_unshare_ok, rec_slave_ok, rec_umount_ok);
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    // The happy path: unshare -> slave -> (>= 1 umount on the real
    // host mount table, which always has /data mounted... or none if
    // this container's mount table matches nothing — the ORDER is
    // what matters, so assert the prefix exactly).
    ZS_CHECK_STR_CONTAINS(log, "us");
    // And nothing after a failure marker.
    ZS_CHECK_STR_ABSENT(log, "U");
    ZS_CHECK_STR_ABSENT(log, "S");
    // If any umounts happened, they all follow the slave remount.
    const char* first_m = strchr(log, 'm');
    if (first_m) {
        ZS_CHECK((size_t)(first_m - log) >= 2);
    }

    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
}

ZS_TEST(hide_apply_skips_unmounts_when_slave_remount_fails) {
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_set_mount_fns(rec_unshare_ok, rec_unshare_ok_slave_fails,
                          rec_umount_ok);
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    ZS_CHECK_STR_CONTAINS(log, "u");   // unshare itself succeeded
    ZS_CHECK_STR_CONTAINS(log, "S");   // slave remount failed
    ZS_CHECK_STR_ABSENT(log, "m");     // ...so NO unmount ran
    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
}

ZS_TEST(hide_apply_never_umounts_in_the_init_namespace) {
    // The regression that motivated Round 9 (B1): simulate the exact
    // sequence the OLD code executed on the host — real unshare
    // failing, then the umount loop running anyway — and prove the
    // current code cannot produce umount2 calls without a successful
    // unshare + slave pair first.
    g_will_hide.store(1);
    g_self_so_count = 0;
    // Real unshare (fails on host) + recorders for the rest.
    zs_test_set_mount_fns(nullptr, rec_slave_ok, rec_umount_ok);
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    ZS_CHECK_STR_CONTAINS(log, "U");   // unshare failed for real
    ZS_CHECK_STR_ABSENT(log, "m");     // umount2 recorder never invoked
    ZS_CHECK_STR_ABSENT(log, "s");     // slave never invoked either
    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
}

// ----------------------------------------------------------------------
// Round 19 — the spoofed-properties bind mount: ordering, gating,
// self-check revert and success, all through the syscall seams.
// ----------------------------------------------------------------------

static int rec_bind_ok(const char* src, const char* dst) {
    (void)src; (void)dst;
    zs_test_mount_log_append('b');
    return 0;
}
// A bind mount whose self-check will FAIL (the production self-check
// opens the target and compares the magic — the test target below is
// a file with the WRONG magic).
static int rec_bind_ok_wrong_magic(const char* src, const char* dst) {
    (void)src; (void)dst;
    zs_test_mount_log_append('b');
    return 0;
}

ZS_TEST(props_bind_mount_gated_on_source_availability) {
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_set_mount_fns(rec_unshare_ok, rec_slave_ok, rec_umount_ok);
    zs_test_set_bind_mount_fn(rec_bind_ok);
    zs_test_props_source_clear();      // feature OFF: no file staged
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    ZS_CHECK_STR_CONTAINS(log, "us");  // namespace setup ran
    ZS_CHECK_STR_ABSENT(log, "b");     // ...but NO properties bind mount
    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
    zs_test_set_bind_mount_fn(nullptr);
    zs_test_props_source_clear();
}

ZS_TEST(props_bind_mount_runs_after_namespace_setup_and_unmounts) {
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_set_mount_fns(rec_unshare_ok, rec_slave_ok, rec_umount_ok);
    zs_test_set_bind_mount_fn(rec_bind_ok);

    // Stage a source file whose AREA MAGIC (offset 8 — the real
    // bionic layout: bytes_used@0, serial@4, magic@8, version@12)
    // the self-check will accept.
    char src_path[] = "/tmp/zs_props_src_XXXXXX";
    int fd = mkstemp(src_path);
    ZS_CHECK(fd >= 0);
    unsigned char hdr[16] = {};
    uint32_t magic = 0x504f5250;   // "PROP" — at offset 8
    memcpy(hdr + 8, &magic, 4);
    ZS_CHECK(write(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr);
    close(fd);
    // The TARGET the self-check opens: a file with the SAME magic
    // at offset 8.
    char tgt_path[] = "/tmp/zs_props_tgt_XXXXXX";
    fd = mkstemp(tgt_path);
    ZS_CHECK(fd >= 0);
    ZS_CHECK(write(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr);
    close(fd);

    hide_props_file_set_source(src_path, magic);
    ZS_CHECK_EQ(hide_props_file_ready(), 1);
    zs_test_set_prop_serial_target(tgt_path);
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    // Bind mount happened, AFTER the namespace setup.
    const char* b = strchr(log, 'b');
    ZS_CHECK(b != nullptr);
    ZS_CHECK((size_t)(b - log) >= 2);           // after "us"
    // Self-check SUCCEEDED (magic matched): no trailing revert.
    // The mount log's LAST entry is the 'b' itself.
    ZS_CHECK_EQ((int)strlen(log) - 1, (int)(b - log));

    unlink(src_path);
    unlink(tgt_path);
    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
    zs_test_set_bind_mount_fn(nullptr);
    zs_test_set_prop_serial_target(nullptr);
    zs_test_props_source_clear();
}

ZS_TEST(props_bind_mount_reverts_on_self_check_mismatch) {
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_set_mount_fns(rec_unshare_ok, rec_slave_ok, rec_umount_ok);
    zs_test_set_bind_mount_fn(rec_bind_ok_wrong_magic);

    char src_path[] = "/tmp/zs_props_src2_XXXXXX";
    int fd = mkstemp(src_path);
    ZS_CHECK(fd >= 0);
    unsigned char hdr[16] = {};
    uint32_t magic = 0x504f5250;
    memcpy(hdr + 8, &magic, 4);
    ZS_CHECK(write(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr);
    close(fd);
    // Target with the WRONG magic (at offset 8, where the real
    // self-check reads it): the self-check must revert.
    char tgt_path[] = "/tmp/zs_props_tgt2_XXXXXX";
    fd = mkstemp(tgt_path);
    ZS_CHECK(fd >= 0);
    uint32_t wrong = 0xdeadbeef;
    memcpy(hdr + 8, &wrong, 4);
    ZS_CHECK(write(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr);
    close(fd);

    hide_props_file_set_source(src_path, magic);
    zs_test_set_prop_serial_target(tgt_path);
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    const char* b = strchr(log, 'b');
    ZS_CHECK(b != nullptr);
    // The self-check failed -> a revert umount2 ran right after the
    // bind: the log ends with "bm".
    ZS_CHECK((size_t)(strlen(log)) >= 2);
    ZS_CHECK(log[strlen(log) - 2] == 'b');
    ZS_CHECK(log[strlen(log) - 1] == 'm');

    unlink(src_path);
    unlink(tgt_path);
    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
    zs_test_set_bind_mount_fn(nullptr);
    zs_test_set_prop_serial_target(nullptr);
    zs_test_props_source_clear();
}

ZS_TEST(props_bind_mount_missing_target_reverts) {
    // Self-check open fails (ENOENT on a path nothing mounted): the
    // mount must be reverted, never left dangling.
    g_will_hide.store(1);
    g_self_so_count = 0;
    zs_test_set_mount_fns(rec_unshare_ok, rec_slave_ok, rec_umount_ok);
    zs_test_set_bind_mount_fn(rec_bind_ok);

    char src_path[] = "/tmp/zs_props_src3_XXXXXX";
    int fd = mkstemp(src_path);
    ZS_CHECK(fd >= 0);
    unsigned char hdr[16] = {};
    uint32_t magic = 0x504f5250;
    memcpy(hdr + 8, &magic, 4);
    ZS_CHECK(write(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr);
    close(fd);
    hide_props_file_set_source(src_path, magic);
    zs_test_set_prop_serial_target("/nonexistent/zs/no_such_props_file");
    zs_test_mount_log_reset();

    hide_apply_for_target("test");

    const char* log = zs_test_mount_log();
    const char* b = strchr(log, 'b');
    ZS_CHECK(b != nullptr);
    ZS_CHECK(log[strlen(log) - 1] == 'm');   // revert umount followed

    unlink(src_path);
    zs_test_set_mount_fns(nullptr, nullptr, nullptr);
    zs_test_set_bind_mount_fn(nullptr);
    zs_test_set_prop_serial_target(nullptr);
    zs_test_props_source_clear();
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

// Round 9: regression for the wrong-hardcoded-length bug. The
// /data/system/zygisk_study/ prefix in field_is_root_path's table
// claimed length 28; the string is 26 characters. memcmp(28) read
// past the literal and NEVER matched — every mount of our own
// working directory stayed visible to denylisted apps. Direct
// behavioral assertions on every table prefix at its TRUE length.
ZS_TEST(field_is_root_path_prefix_lengths_are_correct) {
    ZS_CHECK(field_is_root_path("/data/adb/", strlen("/data/adb/")) == 1);
    ZS_CHECK(field_is_root_path("/data/adb/modules/x",
                                strlen("/data/adb/modules/x")) == 1);
    ZS_CHECK(field_is_root_path("/sbin/", strlen("/sbin/")) == 1);
    ZS_CHECK(field_is_root_path("/sbin/.magisk",
                                strlen("/sbin/.magisk")) == 1);
    ZS_CHECK(field_is_root_path("/debug_ramdisk/",
                                strlen("/debug_ramdisk/")) == 1);
    ZS_CHECK(field_is_root_path("/debug_ramdisk/anything",
                                strlen("/debug_ramdisk/anything")) == 1);
    ZS_CHECK(field_is_root_path("/data/system/zygisk_study/",
                                strlen("/data/system/zygisk_study/")) == 1);
    ZS_CHECK(field_is_root_path("/data/system/zygisk_study/sock",
                                strlen("/data/system/zygisk_study/sock")) == 1);
    // Near-miss non-matches.
    ZS_CHECK(field_is_root_path("/data/system/zygisk_studyz",
                                strlen("/data/system/zygisk_studyz")) == 0);
    ZS_CHECK(field_is_root_path("/data/app/com.x",
                                strlen("/data/app/com.x")) == 0);
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
    g_self_so_records[0] =
        so_record{0x2000, 0x1000, ZS_SO_SELF, 0, 0};
    g_self_so_records[1] =
        so_record{0x8000, 0x1000, ZS_SO_OTHER, 0, 0};
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

// ----------------------------------------------------------------------
// Round 8 tests
// ----------------------------------------------------------------------

// Round 8: the REAL denylist parser (through the new path seam — the
// pre-Round-8 tests had to mirror the parser by hand because the
// production path was hardcoded).
ZS_TEST(denylist_real_parser_via_path_seam) {
    std::string path = make_temp_denylist(
        "com.example.app1\n"
        "com.example.app2\n"
        "# a comment\n"
        "\n"
        "   \n"
        "com.third.party\n");
    hide_test_set_denylist_path(path.c_str());

    ZS_CHECK_EQ(hide_setup_for_target("com.example.app1"), 1);
    ZS_CHECK_EQ(hide_setup_for_target("com.example.app2"), 1);
    ZS_CHECK_EQ(hide_setup_for_target("com.third.party"), 1);
    ZS_CHECK_EQ(hide_setup_for_target("com.other.app"), 0);

    remove_temp(path);
    // Restore the (host-absent) production path for later tests.
    hide_test_set_denylist_path("/data/system/zygisk_study/denylist");
}

// Round 8 (mtime refresh): an edited denylist is picked up once the
// refresh gate opens.
ZS_TEST(denylist_reloads_when_mtime_changes) {
    std::string path = make_temp_denylist("com.version.one\n");
    hide_test_set_denylist_path(path.c_str());
    ZS_CHECK_EQ(hide_setup_for_target("com.version.one"), 1);
    int count_after_first = hide_test_denylist_reload_count();

    // Rewrite with different content and force a distinct mtime.
    {
        FILE* fp = fopen(path.c_str(), "w");
        ZS_CHECK(fp != nullptr);
        fputs("com.version.two\n", fp);
        fclose(fp);
        struct timespec times[2];
        times[0].tv_sec = time(nullptr) + 10;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        utimensat(AT_FDCWD, path.c_str(), times, 0);
    }

    // The throttle gate is closed (checked moments ago); force it
    // open the way a 2-second wait would.
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.version.two"), 1);
    ZS_CHECK_EQ(hide_setup_for_target("com.version.one"), 0);
    ZS_CHECK(hide_test_denylist_reload_count() > count_after_first);

    remove_temp(path);
    hide_test_set_denylist_path("/data/system/zygisk_study/denylist");
}

// Round 8 (P2): between refresh checks the denylist is NOT re-read —
// steady state costs one vDSO clock read, not a stat() per fork.
ZS_TEST(denylist_refresh_is_throttled) {
    std::string path = make_temp_denylist("com.stale.app\n");
    hide_test_set_denylist_path(path.c_str());
    ZS_CHECK_EQ(hide_setup_for_target("com.stale.app"), 1);
    int count_after_first = hide_test_denylist_reload_count();

    // Change the file AND its mtime — but do NOT open the throttle
    // gate (that is what the 2 s interval enforces in production).
    {
        FILE* fp = fopen(path.c_str(), "w");
        ZS_CHECK(fp != nullptr);
        fputs("com.fresh.app\n", fp);
        fclose(fp);
        struct timespec times[2];
        times[0].tv_sec = time(nullptr) + 20;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        utimensat(AT_FDCWD, path.c_str(), times, 0);
    }
    // The very first setup call in this test already armed the gate
    // (now + 2 s); this call runs microseconds later and must skip
    // the stat() entirely.
    ZS_CHECK_EQ(hide_setup_for_target("com.fresh.app"), 0);
    ZS_CHECK_EQ(hide_test_denylist_reload_count(),
                count_after_first);

    // Once the gate opens, the change lands.
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.fresh.app"), 1);
    ZS_CHECK(hide_test_denylist_reload_count() > count_after_first);

    remove_temp(path);
    hide_test_set_denylist_path("/data/system/zygisk_study/denylist");
}

// Round 29 (failed-open retry): the load path used to latch
// "loaded" even when fopen() was DENIED while the file existed
// (SELinux, a kernel-side path block on the zygote's exe — the
// ReZygisk #380 class, or any transient EACCES). The stored mtime
// then equaled the file's real mtime, so the refresh path never
// reloaded and the empty deny map stayed for the whole boot. The
// failure latch must retry the load. chmod(2) changes ctime but NOT
// mtime — exactly the scenario the old code froze on.
ZS_TEST(denylist_failed_open_is_retried_until_it_succeeds) {
    if (geteuid() == 0) {
        // Root bypasses permission bits; the failure injection would
        // not work. The CI/test user is unprivileged, which is the
        // environment this regression targets.
        return;
    }
    std::string path = make_temp_denylist("com.denied.app\n");
    hide_test_set_denylist_path(path.c_str());

    // Make it unreadable (exists, stat() succeeds, fopen() fails).
    ZS_CHECK_EQ(chmod(path.c_str(), 0000), 0);

    // First load: fopen denied -> the deny map stays empty. The
    // latch must be set after this failure.
    ZS_CHECK_EQ(hide_setup_for_target("com.denied.app"), 0);
    int count_after_fail = hide_test_denylist_reload_count();
    ZS_CHECK(count_after_fail >= 1);

    // Heal WITHOUT touching mtime: chmod back to readable. The old
    // code compares mtimes only — unchanged — and would never retry.
    ZS_CHECK_EQ(chmod(path.c_str(), 0644), 0);

    // Open the throttle gate and re-check: the retry must fire and
    // the deny decision must flip to hidden.
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.denied.app"), 1);
    ZS_CHECK(hide_test_denylist_reload_count() > count_after_fail);

    // Steady state: the successful load cleared the latch; a second
    // refresh window must NOT burn another reload when nothing
    // changed (mtime unchanged, latch clear).
    int count_after_heal = hide_test_denylist_reload_count();
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.denied.app"), 1);
    ZS_CHECK_EQ(hide_test_denylist_reload_count(), count_after_heal);

    remove_temp(path);
    hide_test_set_denylist_path("/data/system/zygisk_study/denylist");
}

// Round 29 (failed-open retry, packages.list side): same freeze, but
// for the uid->package map — the map the module dispatch layer and
// the data-dir derivation both depend on.
ZS_TEST(packages_list_failed_open_is_retried_until_it_succeeds) {
    if (geteuid() == 0) {
        return;  // permission-bit failure injection needs !root
    }
    std::string path;
    {
        char tmpl[] = "/tmp/zstest_pkgslist_XXXXXX";
        int fd = mkstemp(tmpl);
        ZS_CHECK(fd >= 0);
        // Modern 11-field format (verified at android-16.0.0_r1
        // Settings.java writePackageListLPrInternal) — the parser
        // only reads the first two fields.
        const char* line =
            "com.example.app 10123 0 /data/user/0/com.example.app "
            "default:targetSdk=33 0 1032,3003 0 123 0 @system\n";
        ZS_CHECK(write(fd, line, strlen(line)) == (ssize_t)strlen(line));
        close(fd);
        path = tmpl;
    }
    hide_test_set_packages_list_path(path.c_str());
    // A working denylist so the shared parse runs cleanly.
    std::string dl = make_temp_denylist("com.example.app\n");
    hide_test_set_denylist_path(dl.c_str());

    // Denied open: uid map empty.
    ZS_CHECK_EQ(chmod(path.c_str(), 0000), 0);
    char out[256] = {};
    hide_lookup_package_for_uid(10123, out, sizeof out);
    ZS_CHECK(std::string(out).empty());

    // Heal (chmod changes ctime only) and retry through an open
    // throttle gate. The refresh runs inside the fork-path entry
    // points (hide_setup_for_target), not inside the bare lookup —
    // same as production, where the gid/uid-drop hooks call setup
    // first.
    ZS_CHECK_EQ(chmod(path.c_str(), 0644), 0);
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.example.app"), 1);
    hide_lookup_package_for_uid(10123, out, sizeof out);
    ZS_CHECK(std::string(out) == "com.example.app");

    // The multi-user form of the same appId resolves too (user 999 =
    // Xiaomi dual apps, user 150 = Samsung Secure Folder — uid
    // math verified from AOSP UserHandle.getUid).
    hide_lookup_package_for_uid(999 * 100000 + 10123, out, sizeof out);
    ZS_CHECK(std::string(out) == "com.example.app");

    remove_temp(path);
    remove_temp(dl);
    hide_test_set_denylist_path("/data/system/zygisk_study/denylist");
    hide_test_set_packages_list_path("/data/system/packages.list");
}

// Round 8 (B9): the maps scanner must NEVER claim app-bundled
// libraries as ours, even when the file name collides with ours
// (an app shipping its own "libpayload.so" was enough to make the
// Round 7 scanner unmap the app's library — a guaranteed crash).
ZS_TEST(maps_scan_ignores_app_library_directories) {
    const char* synthetic =
        "00010000-00011000 r--p 00000000 00:00 1  /system/lib64/libpayload.so\n"
        "00012000-00013000 r-xp 00000000 00:00 2  /data/app/~~aX==/com.x-1/lib/arm64/libpayload.so\n"
        "00014000-00015000 r-xp 00000000 00:00 3  /data/app/com.z-2/lib/arm64/libzygisk.so\n"
        "00016000-00017000 r-xp 00000000 00:00 4  /home/dev/zygisk/tests/libpayload.so\n"
        "00018000-00019000 rw-p 00000000 00:00 5  /data/user/0/com.w/lib/libzn_loader.so\n";
    zs_scan_maps_into_records_test(synthetic, strlen(synthetic));
    ZS_CHECK_EQ(hide_unmap_record_count(), (size_t)2);

    so_record out[8] = {};
    size_t n = hide_unmap_records(out, 8);
    ZS_CHECK_EQ(n, (size_t)2);
    ZS_CHECK_EQ(out[0].base, (uintptr_t)0x00010000);   // /system copy
    ZS_CHECK_EQ(out[0].prot, (uint32_t)0);             // r--p
    ZS_CHECK_EQ(out[0].flags, (uint32_t)ZS_SO_SELF);
    ZS_CHECK_EQ(out[1].base, (uintptr_t)0x00016000);   // host-test copy
    ZS_CHECK_EQ(out[1].prot, (uint32_t)ZS_SEG_X);      // r-xp
    // The app copies at 0x12000 / 0x14000 / 0x18000 must be absent.

    hide_test_set_records(nullptr, 0);
}

// Helper: the /proc/self/maps line covering `addr`, if any.
static int maps_line_for_addr(uintptr_t addr, char* out, size_t cap) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    int found = 0;
    char line[600];
    while (fgets(line, sizeof line, f)) {
        uintptr_t lo = 0, hi = 0;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 &&
            lo <= addr && addr < hi) {
            snprintf(out, cap, "%s", line);
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// Round 8 (B6): Tier A preprocessing anonymizes read-only segments
// instead of unmapping them — content preserved byte-for-byte, the
// file path gone from maps (this is what keeps the linker's soinfo
// walks safe after we vanish).
ZS_TEST(tier_a_prepare_anonymizes_readonly_segments) {
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    ZS_CHECK(fd >= 0);
    void* p = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ZS_CHECK(p != MAP_FAILED);
    unsigned char before[4096];
    memcpy(before, p, 4096);

    char line[600];
    ZS_CHECK(maps_line_for_addr((uintptr_t)p, line, sizeof line));
    ZS_CHECK(strchr(line, '/') != nullptr);   // file-backed right now

    so_record recs[1];
    recs[0] = so_record{(uintptr_t)p, 4096, ZS_SO_OTHER, 0, 0};
    hide_test_set_records(recs, 1);

    so_record out[8];
    ZS_CHECK_EQ(hide_prepare_tier_a_records(out, 8), (size_t)0);

    // Content preserved exactly.
    ZS_CHECK(memcmp(before, p, 4096) == 0);
    // The mapping is now anonymous: no path in its maps line.
    ZS_CHECK(maps_line_for_addr((uintptr_t)p, line, sizeof line));
    ZS_CHECK(strchr(line, '/') == nullptr);

    munmap(p, 4096);
    close(fd);
    hide_test_set_records(nullptr, 0);
}

// Round 8: executable segments of OTHER records are really munmap'd.
ZS_TEST(tier_a_prepare_munmaps_other_exec_segments) {
    void* x = mmap(nullptr, 4096, PROT_READ | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ZS_CHECK(x != MAP_FAILED);

    so_record recs[1];
    recs[0] = so_record{(uintptr_t)x, 4096, ZS_SO_OTHER, ZS_SEG_X, 0};
    hide_test_set_records(recs, 1);

    so_record out[8];
    ZS_CHECK_EQ(hide_prepare_tier_a_records(out, 8), (size_t)0);

    char line[600];
    ZS_CHECK(!maps_line_for_addr((uintptr_t)x, line, sizeof line));

    hide_test_set_records(nullptr, 0);
}

// Round 8 (B7): SELF records come out FIRST and the trampoline cap
// can never cut them when many module records precede them in scan
// order.
ZS_TEST(tier_a_prepare_prioritizes_self_records) {
    // 35 OTHER records at addresses that are (a) unmapped in this
    // process and (b) below mmap_min_addr, so neither munmap nor a
    // MAP_FIXED anonymize can touch real memory.
    so_record recs[40];
    for (int i = 0; i < 35; ++i) {
        recs[i] = so_record{(uintptr_t)(0x1000 + (size_t)i * 0x400),
                            0x100, ZS_SO_OTHER, ZS_SEG_X, 0};
    }
    for (int i = 0; i < 5; ++i) {
        recs[35 + i] =
            so_record{(uintptr_t)(0x7f0000000000UL + (unsigned long)i * 0x10000UL),
                      0x1000, ZS_SO_SELF, ZS_SEG_X, 0};
    }
    hide_test_set_records(recs, 40);

    so_record out[8];
    size_t n = hide_prepare_tier_a_records(out, 8);
    ZS_CHECK_EQ(n, (size_t)5);
    for (size_t i = 0; i < n; ++i) {
        ZS_CHECK_EQ(out[i].flags, (uint32_t)ZS_SO_SELF);
        ZS_CHECK(out[i].prot & ZS_SEG_X);
    }

    hide_test_set_records(nullptr, 0);
}

// ----------------------------------------------------------------------
// Round 26 — the mount-target selection. Android 6.x maps ONE
// regular file at /dev/__properties__ (bind-cover the FILE); 7.0+
// map files inside the /dev/__properties__/ DIRECTORY (cover
// properties_serial). stat() tells the forms apart.
// ----------------------------------------------------------------------
ZS_TEST(props_mount_target_follows_the_platform_form) {
    // A regular file selects the 6.x single-file target.
    char file[] = "/tmp/zs_target_probe_file_XXXXXX";
    int fd = mkstemp(file);
    ZS_CHECK(fd >= 0);
    close(fd);
    ZS_CHECK(strcmp(zs_test_props_target_for_probe(file),
                    "/dev/__properties__") == 0);

    // A directory selects the 7.0+ serial target.
    char dir[] = "/tmp/zs_target_probe_dir_XXXXXX";
    ZS_CHECK(mkdtemp(dir) != nullptr);
    ZS_CHECK(strcmp(zs_test_props_target_for_probe(dir),
                    "/dev/__properties__/properties_serial") == 0);

    // A missing path defaults to the modern target (fail-open to the
    // 7.0+ form — the far more common one).
    ZS_CHECK(strcmp(zs_test_props_target_for_probe(
                        "/nonexistent/zs/__properties_probe"),
                    "/dev/__properties__/properties_serial") == 0);

    // A null probe (defensive) also defaults modern.
    ZS_CHECK(strcmp(zs_test_props_target_for_probe(nullptr),
                    "/dev/__properties__/properties_serial") == 0);

    unlink(file);
    rmdir(dir);
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study hide layer tests ===\n");
    return zstest::run_all();
}

// ----------------------------------------------------------------------
// Round 13
// ----------------------------------------------------------------------

// Runtime root-path prefixes: the daemon's randomized per-boot socket
// directory must be matched by the mount unmounter without being a
// compile-time constant.
ZS_TEST(runtime_root_path_prefix_matches_random_socket_dir) {
    // Nothing registered yet: the random dir is not a root path.
    ZS_CHECK(field_is_root_path("/data/system/.feedface/s",
                                strlen("/data/system/.feedface/s")) == 0);

    hide_register_root_path_prefix("/data/system/.feedface/");
    ZS_CHECK(field_is_root_path("/data/system/.feedface/s",
                                strlen("/data/system/.feedface/s")) == 1);
    ZS_CHECK(field_is_root_path("/data/system/.feedface/deep/x",
                                strlen("/data/system/.feedface/deep/x")) == 1);
    // The trailing slash in the registration prevents stem collisions:
    // a sibling sharing the stem is NOT swallowed.
    ZS_CHECK(field_is_root_path("/data/system/.feedface2/s",
                                strlen("/data/system/.feedface2/s")) == 0);
    // And the stock table still stands.
    ZS_CHECK(field_is_root_path("/data/adb/modules/x",
                                strlen("/data/adb/modules/x")) == 1);

    // Registration guards: empty/oversize are ignored without crash,
    // and the table saturates at 4 (the 5th is dropped, the first 4
    // still match).
    hide_register_root_path_prefix(nullptr);
    hide_register_root_path_prefix("");
    char big[128];
    memset(big, 'a', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    big[0] = '/';
    hide_register_root_path_prefix(big);
    hide_register_root_path_prefix("/data/system/.aaaa/");
    hide_register_root_path_prefix("/data/system/.bbbb/");
    hide_register_root_path_prefix("/data/system/.cccc/");
    hide_register_root_path_prefix("/data/system/.dddd/");  // 5th: dropped
    ZS_CHECK(field_is_root_path("/data/system/.cccc/s",
                                strlen("/data/system/.cccc/s")) == 1);
    ZS_CHECK(field_is_root_path("/data/system/.dddd/s",
                                strlen("/data/system/.dddd/s")) == 0);
    ZS_CHECK(field_is_root_path("/data/system/.feedface/s",
                                strlen("/data/system/.feedface/s")) == 1);
}

// Round 13 staleness fix: an edited packages.list reloads the
// module-args map through the SAME throttled mtime check as the
// denylist (previously only a denylist edit reloaded it, so an app
// installed after zygote start had no package_name in its specialize
// args until the next denylist edit).
ZS_TEST(packages_list_mtime_change_refreshes_module_args_map) {
    std::string pkg_path = make_temp_denylist(
        "com.first.app 10234 0 /data/data/com.first.app seinfo 0\n");
    hide_test_set_packages_list_path(pkg_path.c_str());

    char out[256] = {0};
    hide_lookup_package_for_uid(10234, out, sizeof out);
    ZS_CHECK_STR_EQ(out, "com.first.app");
    int count_after_first = hide_test_denylist_reload_count();

    // Rewrite with a second package and force a distinct mtime.
    {
        FILE* fp = fopen(pkg_path.c_str(), "w");
        ZS_CHECK(fp != nullptr);
        fputs("com.first.app 10234 0 / x 0\n"
              "com.second.app 10345 0 / x 0\n", fp);
        fclose(fp);
        struct timespec times[2];
        times[0].tv_sec = time(nullptr) + 10;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        utimensat(AT_FDCWD, pkg_path.c_str(), times, 0);
    }

    // DenyList content did NOT change — the reload must still happen
    // because packages.list did (the Round 13 fix).
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.nothing.here"), 0);
    ZS_CHECK(hide_test_denylist_reload_count() > count_after_first);
    memset(out, 0, sizeof out);
    hide_lookup_package_for_uid(10345, out, sizeof out);
    ZS_CHECK_STR_EQ(out, "com.second.app");

    remove_temp(pkg_path);
    hide_test_set_packages_list_path("/data/system/packages.list");
}

// ----------------------------------------------------------------------
// Round 14
// ----------------------------------------------------------------------

// The deny-decision key: after a setup call decided on a key, the
// uid-drop hook can skip its identical re-check; a different key
// must re-check.
ZS_TEST(deny_decision_key_tracks_the_last_setup_call) {
    ZS_CHECK(hide_deny_decided_for(10234) == 0);  // nothing decided
    ZS_CHECK_EQ(hide_setup_for_target_uid(10234), 0);
    ZS_CHECK(hide_deny_decided_for(10234) == 1);
    ZS_CHECK(hide_deny_decided_for(10235) == 0);
    // The fast path (uid < 10000) is also a decision.
    ZS_CHECK_EQ(hide_setup_for_target_uid(1000), 0);
    ZS_CHECK(hide_deny_decided_for(1000) == 1);
    ZS_CHECK(hide_deny_decided_for(10234) == 0);
    // Restore the "nothing decided" state for later tests.
    hide_setup_for_target_uid(0);
}

// The packages.map generation bumps on every reload (the dispatch
// args cache invalidates against it).
ZS_TEST(pkg_map_generation_bumps_on_reload) {
    std::string path = make_temp_denylist("com.gen.app\n");
    hide_test_set_denylist_path(path.c_str());
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.gen.app"), 1);
    uint32_t gen1 = hide_pkg_map_generation();

    // Change the denylist (mtime) and force the gate open.
    {
        FILE* fp = fopen(path.c_str(), "w");
        ZS_CHECK(fp != nullptr);
        fputs("com.gen.app\ncom.gen.two\n", fp);
        fclose(fp);
        struct timespec times[2];
        times[0].tv_sec = time(nullptr) + 10;
        times[0].tv_nsec = 0;
        times[1] = times[0];
        utimensat(AT_FDCWD, path.c_str(), times, 0);
    }
    hide_test_reset_refresh();
    ZS_CHECK_EQ(hide_setup_for_target("com.gen.two"), 1);
    ZS_CHECK(hide_pkg_map_generation() != gen1);

    remove_temp(path);
    hide_test_set_denylist_path("/data/system/zygisk_study/denylist");
}

// ----------------------------------------------------------------------
// Round 25 — hide_data_dir_for_uid (the derivation the old-kernel
// filter fallback uses to place its unlinked scratch file: the only
// directory a dropped, app-uid child is guaranteed writable).
// ----------------------------------------------------------------------
ZS_TEST(data_dir_for_uid_derives_canonical_per_user_path) {
    char tmpl[] = "/tmp/zs_pkgs_dir_XXXXXX";
    int tfd = mkstemp(tmpl);
    ZS_CHECK(tfd >= 0);
    if (tfd >= 0) close(tfd);
    std::string pkg_path(tmpl);
    FILE* fp = fopen(pkg_path.c_str(), "w");
    ZS_CHECK(fp != nullptr);
    if (fp) {
        // <package> <uid> <debugFlag> <dataDir> <seInfo> ... — the
        // parser reads the first two fields (version-tolerant).
        fputs("com.example.app 10234 0 /data/data/com.example.app default:targetSdk=28\n"
              "com.other.app 10150 0 /data/user/0/com.other.app default:targetSdk=28\n"
              "com.work.app 10577 0 /data/user/0/com.work.app default:targetSdk=28\n",
              fp);
        fclose(fp);
    }
    hide_test_set_packages_list_path(pkg_path.c_str());
    hide_test_reset_refresh();

    char out[512];
    // User 0, straightforward appId.
    ZS_CHECK_EQ(hide_data_dir_for_uid(10234, out, sizeof out), 0);
    ZS_CHECK_STR_EQ(out, "/data/user/0/com.example.app");
    // Work profile (user 10 = uid 1010234 for appId 10234): the
    // userId comes from the FULL uid, the package from the appId
    // family — exactly the module-args derivation.
    ZS_CHECK_EQ(hide_data_dir_for_uid(1010234, out, sizeof out), 0);
    ZS_CHECK_STR_EQ(out, "/data/user/10/com.example.app");
    ZS_CHECK_EQ(hide_data_dir_for_uid(10577, out, sizeof out), 0);
    ZS_CHECK_STR_EQ(out, "/data/user/0/com.work.app");
    // Unknown uid: fail, no string.
    ZS_CHECK_EQ(hide_data_dir_for_uid(10999, out, sizeof out), -1);
    ZS_CHECK(out[0] == '\0');
    // Non-app uid: fail (system_server, root, daemons).
    ZS_CHECK_EQ(hide_data_dir_for_uid(1000, out, sizeof out), -1);
    ZS_CHECK_EQ(hide_data_dir_for_uid(0, out, sizeof out), -1);
    // Truncated buffer: fail, no partial path.
    char tiny[8];
    ZS_CHECK_EQ(hide_data_dir_for_uid(10234, tiny, sizeof tiny), -1);
    ZS_CHECK(tiny[0] == '\0');

    remove_temp(pkg_path);
    hide_test_set_packages_list_path("/data/system/packages.list");
}

// ----------------------------------------------------------------------
// Round 30 — the Tier A atexit purge (bionic's __cxa_finalize
// protocol, verified from libc/bionic/atexit.cpp + crtbegin_so.c this
// round; see hide.h's design note).
// ----------------------------------------------------------------------

// A sentinel destructor: glibc/bionic __cxa_finalize CALLS the
// entries it purges, so the counter doubles as "the purge ran".
static int g_r30_sentinel_calls = 0;
static void r30_sentinel_dtor(void* arg) {
    ++g_r30_sentinel_calls;
    (void)arg;
}

ZS_TEST(dso_handle_scan_finds_self_pointing_words_and_skips_text) {
    // One page holding a fake __dso_handle at a known offset, plus
    // two decoy words (zero and a non-self pointer).
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    void* page = mmap(nullptr, (size_t)ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ZS_CHECK(page != MAP_FAILED);
    if (page == MAP_FAILED) return;
    memset(page, 0, (size_t)ps);
    uintptr_t base = (uintptr_t)page;
    // Decoy: a pointer to another address in the page (vtable-like).
    *(uintptr_t*)((char*)page + 16) = base + 32;
    // The self-pointing handle.
    uintptr_t handle_addr = base + 64;
    *(uintptr_t*)handle_addr = handle_addr;

    struct so_record recs[3];
    memset(recs, 0, sizeof recs);
    recs[0].base = base;      recs[0].size = (size_t)ps;
    recs[0].prot = ZS_SEG_W;  recs[0].flags = ZS_SO_OTHER;  // data seg
    recs[1].base = base;      recs[1].size = (size_t)ps;
    recs[1].prot = ZS_SEG_X;  recs[1].flags = ZS_SO_OTHER;  // text: skipped
    recs[2].base = handle_addr - 8; recs[2].size = 16;
    recs[2].prot = 0;         recs[2].flags = ZS_SO_SELF;   // relro: found + self
    hide_test_set_records(recs, 3);

    struct ZsDsoHandle out[8];
    size_t n = zs_collect_dso_handles(out, 8);
    // The SELF record's handle (deduped with the OTHER record's —
    // same address) is what the scan must report; text skipped.
    ZS_CHECK_EQ(n, (size_t)1);
    if (n == 1) {
        ZS_CHECK_EQ(out[0].handle, handle_addr);
        ZS_CHECK_EQ(out[0].self, 1u);   // SELF classification wins
    }

    // Cap: with room for one, the scan reports one (dedup first).
    struct ZsDsoHandle one[1];
    ZS_CHECK_EQ(zs_collect_dso_handles(one, 1), (size_t)1);

    hide_test_set_records(nullptr, 0);
    munmap(page, (size_t)ps);
}

ZS_TEST(atexit_finalize_purges_matching_entries_only) {
    // A fake dso handle (the address of a stack variable works: the
    // value only needs to be unique and non-null).
    alignas(sizeof(void*)) char fake_handle_area[sizeof(void*)];
    void* fake_handle = (void*)fake_handle_area;

    int before = g_r30_sentinel_calls;
    // Register TWO sentinels against our fake handle and one against
    // a different handle: __cxa_finalize(fake) must call exactly the
    // two, and leave the third intact.
    __cxxabiv1::__cxa_atexit(r30_sentinel_dtor, nullptr, fake_handle);
    __cxxabiv1::__cxa_atexit(r30_sentinel_dtor, nullptr, fake_handle);
    __cxxabiv1::__cxa_atexit(r30_sentinel_dtor, nullptr, (void*)&before);

    ZS_CHECK_EQ(zs_atexit_finalize((uintptr_t)fake_handle), 1);
    ZS_CHECK_EQ(g_r30_sentinel_calls, before + 2);

    // A second finalize of the SAME handle must not re-call: the
    // entries were extracted (this is the exact bionic contract the
    // Tier A purge relies on — the hidden app's later exit() walks
    // NOTHING of ours).
    ZS_CHECK_EQ(zs_atexit_finalize((uintptr_t)fake_handle), 1);
    ZS_CHECK_EQ(g_r30_sentinel_calls, before + 2);

    // Zero handle / null: refused without calling anything.
    ZS_CHECK_EQ(zs_atexit_finalize(0), 0);
    ZS_CHECK_EQ(g_r30_sentinel_calls, before + 2);

    // Purge the third sentinel too so it cannot fire at the test
    // binary's own exit (its dso would otherwise dangle into a stack
    // frame that is gone by then — the same class of bug, in
    // miniature).
    ZS_CHECK_EQ(zs_atexit_finalize((uintptr_t)&before), 1);
    ZS_CHECK_EQ(g_r30_sentinel_calls, before + 3);
}
