// SPDX-License-Identifier: Apache-2.0
// tests/test_obfstr.cpp — Round 33: unit tests for the compile-time
// string obfuscator (native/common/obfstr.h).
//
// The obfuscator is load-bearing stealth infrastructure: every
// signature string in the two /system/lib[64]-resident libraries now
// flows through it. These tests pin its three contracts:
//   1. decode correctness (expression form, varargs form, empty,
//      long, same-line pairs, '%'-bearing format strings),
//   2. the decode-once semantics of ZS_OBFS_PATH (init_array
//      initialization, stable pointer, repeated calls),
//   3. StrTable integrity (content, lengths, ptrs[] stride-8 view,
//      begin()/end() iteration, overlong-entry clamping).
//
// The no-plaintext-leak property itself is verified on the REAL
// artifacts by scripts/build_module.sh's banned-strings gate
// (verify_zip step 7) — a host test cannot see the shipped ELF.

#include "../native/common/obfstr.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "test_framework.h"

ZS_TEST(obfs_expression_form_decodes_exactly) {
    ZS_CHECK(strcmp(ZS_OBFS("/data/system/zygisk_study/denylist"),
                    "/data/system/zygisk_study/denylist") == 0);
    ZS_CHECK(strcmp(ZS_OBFS("libpayload.so"), "libpayload.so") == 0);
    ZS_CHECK(strcmp(ZS_OBFS("zygisk_module"), "zygisk_module") == 0);
}

ZS_TEST(obfs_varargs_form_is_safe_in_printf_family) {
    // The raw-pointer result must work through snprintf's varargs —
    // the exact bug class that killed the first Dec-object design
    // (an implicit conversion cannot apply to variadic arguments).
    char buf[128];
    snprintf(buf, sizeof buf, "%s%s",
             ZS_OBFS("/data/system/"), "zygisk_study");
    ZS_CHECK(strcmp(buf, "/data/system/zygisk_study") == 0);

    // Format strings themselves can be obfuscated.
    char b2[64];
    snprintf(b2, sizeof b2, ZS_OBFS("%.*s/libzygisk.so"), 3, "abc");
    ZS_CHECK(strcmp(b2, "abc/libzygisk.so") == 0);
}

ZS_TEST(obfs_edge_cases_empty_and_long) {
    // N=1 (just the NUL) must decode to an empty string.
    ZS_CHECK(ZS_OBFS("")[0] == '\0');
    // The longest signature literal in the tree.
    const char* want = "/system/lib64/libndk_translation.so";
    ZS_CHECK(strcmp(ZS_OBFS("/system/lib64/libndk_translation.so"),
                    want) == 0);
}

ZS_TEST(obfs_two_literals_on_one_line) {
    // Same line, different strings: the key derivation still yields
    // distinct-enough keystreams and both decode correctly.
    ZS_CHECK(strcmp(ZS_OBFS("libzygisk.so"), "libzygisk.so") == 0 &&
             strcmp(ZS_OBFS("libpayload.so"), "libpayload.so") == 0);
}

ZS_TEST(obfs_holder_form_survives_across_statements) {
    auto&& dir = ZS_OBFS_H("/data/adb/modules/zygisk_study/session.sock");
    std::string s(dir.c_str());
    ZS_CHECK(s == "/data/adb/modules/zygisk_study/session.sock");
    // Still valid later in the scope (lifetime extension).
    ZS_CHECK(strlen(dir.c_str()) == s.size());
}

// ROUND 33b: ZS_OBFS_PATH expands at FILE scope (an init_array
// initialized global + accessor); a file-scope test:
ZS_OBFS_PATH(obfs_test_modules_path, "/data/system/zygisk_study/modules")
ZS_OBFS_PATH(obfs_test_soname, "libpayload.so")

ZS_TEST(obfs_path_is_decode_once_and_stable) {
    // Two calls through the SAME accessor must return the SAME
    // materialized buffer (the init_array-decoded global), not two
    // decodes. (Two different sites intentionally yield two
    // different buffers — each site is its own global.)
    const char* a = obfs_test_modules_path();
    const char* b = obfs_test_modules_path();
    ZS_CHECK(a == b);
    ZS_CHECK(strcmp(a, "/data/system/zygisk_study/modules") == 0);
    ZS_CHECK(strcmp(obfs_test_soname(), "libpayload.so") == 0);
}

ZS_TEST(strtable_keeps_content_lengths_and_ptr_view) {
    static const zsst::StrTable& t = [] {
        zsst::StrTable b;
        b.add(ZS_OBFS("/data/adb/"));
        b.add(ZS_OBFS("/sbin/"));
        b.add(ZS_OBFS("/debug_ramdisk/"));
        b.add(ZS_OBFS("/data/system/zygisk_study/"));
        return b;
    }();
    ZS_CHECK(t.count == 4);
    ZS_CHECK(strcmp(t.at(0), "/data/adb/") == 0);
    ZS_CHECK(t.len(0) == 10);
    ZS_CHECK(strcmp(t.at(2), "/debug_ramdisk/") == 0);
    ZS_CHECK(t.len(2) == 15);
    // The stride-8 ptrs[] view (the accessor contract hide.cpp's
    // tests rely on — the round-33 bug this pins: &entries[0].p had
    // stride 16 and props[1] read the length field as a pointer).
    const char* const* view = t.ptrs;
    ZS_CHECK(strcmp(view[1], "/sbin/") == 0);
    ZS_CHECK(strcmp(view[3], "/data/system/zygisk_study/") == 0);
    // begin()/end() range-for over Entry{p, n}.
    size_t seen = 0;
    for (const auto& e : t) {
        ZS_CHECK(e.p != nullptr && e.n == strlen(e.p));
        ++seen;
    }
    ZS_CHECK(seen == 4);
}

ZS_TEST(strtable_clamps_overlong_entries) {
    zsst::StrTable b;
    // Longer than kMaxLen (95): clamped, never overflowed.
    char longstr[200];
    memset(longstr, 'x', sizeof longstr - 1);
    longstr[sizeof longstr - 1] = '\0';
    b.add(longstr);
    ZS_CHECK(b.count == 1);
    ZS_CHECK(strlen(b.at(0)) <= zsst::StrTable::kMaxLen);
    // Capacity clamp (49 > kMaxEntries: 48).
    zsst::StrTable c;
    for (int i = 0; i < 60; ++i) c.add("x");
    ZS_CHECK(c.count <= zsst::StrTable::kMaxEntries);
}

int main() {
    std::fprintf(stderr, "=== Zygisk Study obfstr tests (Round 33) ===\n");
    return zstest::run_all();
}
