// SPDX-License-Identifier: Apache-2.0
// tests/test_zn_loader.cpp
//
// Round 28: first dedicated host-side test coverage for
// libzn_loader (the init-oriented API bridge).
//
// Two bug classes are covered here:
//
//  1. The socket-resolution regression: libzn_loader hardcoded the
//     legacy fixed daemon socket path while the daemon (since Round
//     13) binds a randomized per-boot path published in the session
//     file. On a normal boot the connect() failed, so
//     should_inject() answered "no" for every target and
//     open_companion_fd() always returned -1. The resolver tests and
//     the live end-to-end test below fail against the old code.
//
//  2. The public-header compile contract: zygisk_study_api.h must
//     compile standalone in BOTH C and C++ translation units (the
//     fixed uid_t/gid_t include). The Makefile compiles the header
//     standalone with gcc -std=c99; this TU additionally includes it
//     from C++ to prove the C++ path.
//
// The test compiles native/libzn_loader/src/entry.cpp directly with
// -DZS_HOST_TEST, which exposes the zs_test_zn_* seams.

#include "test_framework.h"

#include "zygisk_study_api.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

// The API table lives in the libzn_loader TU we compile in.
extern "C" const struct zygisk_study_api zygisk_study_api_v1;

// Seams from entry.cpp (ZS_HOST_TEST).
extern "C" void zs_test_zn_set_session_file(const char* path);
extern "C" void zs_test_zn_set_session_file_alt(const char* path);
extern "C" int  zs_test_zn_resolve_socket(char* out, size_t outsz);

static const char* kLegacyPath =
    "/data/system/zygisk_study/sock/sock";

// ---------------------------------------------------------------------------
// Temp-session-file helper
// ---------------------------------------------------------------------------

static std::string g_zn_tmpdir;

static void make_tmpdir() {
    char tmpl[] = "/tmp/znloadXXXXXX";
    if (mkdtemp(tmpl)) g_zn_tmpdir = tmpl;
}

static std::string session_file_with(const char* content) {
    static int seq = 0;
    std::string path = g_zn_tmpdir + "/sess" + std::to_string(seq++);
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return {};
    fwrite(content, 1, strlen(content), f);
    fclose(f);
    return path;
}

static std::string session_file_gone() {
    static int seq = 0;
    return g_zn_tmpdir + "/gone" + std::to_string(seq++);
}

// ---------------------------------------------------------------------------
// Resolver unit tests
// ---------------------------------------------------------------------------

ZS_TEST(resolver_prefers_the_session_file_when_present) {
    std::string sf = session_file_with(
        "/data/system/zygisk_study/.q8fj2/sock");
    zs_test_zn_set_session_file(sf.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 1);
    ZS_CHECK_STR_EQ(out, "/data/system/zygisk_study/.q8fj2/sock");
}

ZS_TEST(resolver_trims_trailing_whitespace) {
    std::string sf = session_file_with("/tmp/dir/sock\n\r\n");
    zs_test_zn_set_session_file(sf.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 1);
    ZS_CHECK_STR_EQ(out, "/tmp/dir/sock");
}

ZS_TEST(resolver_falls_back_to_legacy_when_file_missing) {
    // The daemon starts after zygote; at early-boot calls the session
    // file does not exist yet. This must resolve to the legacy path
    // (return 0), never an empty or garbage path.
    zs_test_zn_set_session_file(session_file_gone().c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 0);
    ZS_CHECK_STR_EQ(out, kLegacyPath);
}

ZS_TEST(resolver_rejects_relative_paths) {
    std::string sf = session_file_with("relative/path\n");
    zs_test_zn_set_session_file(sf.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 0);
    ZS_CHECK_STR_EQ(out, kLegacyPath);
}

ZS_TEST(resolver_rejects_blank_and_whitespace_only_content) {
    std::string sf = session_file_with("   \n\r\n");
    zs_test_zn_set_session_file(sf.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 0);
    ZS_CHECK_STR_EQ(out, kLegacyPath);
}

ZS_TEST(resolver_rejects_overlong_paths) {
    // 120 chars: longer than the 95-byte read (and would not fit the
    // caller's 96-byte buffer either way).
    std::string long_path(120, 'a');
    long_path[0] = '/';
    std::string sf = session_file_with(long_path.c_str());
    zs_test_zn_set_session_file(sf.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 0);
    ZS_CHECK_STR_EQ(out, kLegacyPath);
}

// Round 29 — the SECOND session record (the daemon's /data/system
// workdir copy). When the module-dir record is unreadable (the
// ReZygisk #380 Samsung class: kernel path rules blocking
// app_process64's /data/adb/modules opens), the resolver must fall
// back to the workdir record instead of the legacy fixed path.
ZS_TEST(resolver_uses_the_workdir_record_when_module_dir_is_blocked) {
    std::string alt = session_file_with("/data/system/.1a2b3c4d/s\n");
    zs_test_zn_set_session_file(session_file_gone().c_str());
    zs_test_zn_set_session_file_alt(alt.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 1);
    ZS_CHECK_STR_EQ(out, "/data/system/.1a2b3c4d/s");
    zs_test_zn_set_session_file(nullptr);
    zs_test_zn_set_session_file_alt(nullptr);
}

// Round 29 — the PRIMARY record still wins when both are readable.
ZS_TEST(resolver_prefers_the_primary_record_over_the_workdir_copy) {
    std::string sf = session_file_with("/data/system/.primary99/s\n");
    std::string alt = session_file_with("/data/system/.altcopy77/s\n");
    zs_test_zn_set_session_file(sf.c_str());
    zs_test_zn_set_session_file_alt(alt.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 1);
    ZS_CHECK_STR_EQ(out, "/data/system/.primary99/s");
    zs_test_zn_set_session_file(nullptr);
    zs_test_zn_set_session_file_alt(nullptr);
}

// Round 29 — a garbage workdir record must not defeat a VALID
// primary, and a garbage primary falls through to the workdir copy
// (both records get the same parser hygiene).
ZS_TEST(resolver_rejects_overlong_content_in_the_workdir_record) {
    std::string long_path(120, 'a');
    long_path[0] = '/';
    std::string alt = session_file_with(long_path.c_str());
    zs_test_zn_set_session_file(session_file_gone().c_str());
    zs_test_zn_set_session_file_alt(alt.c_str());
    char out[96];
    int from_session = zs_test_zn_resolve_socket(out, sizeof out);
    ZS_CHECK_EQ(from_session, 0);
    ZS_CHECK_STR_EQ(out, kLegacyPath);
    zs_test_zn_set_session_file(nullptr);
    zs_test_zn_set_session_file_alt(nullptr);
}

// ---------------------------------------------------------------------------
// End-to-end: the real API table against a live unix socket
// ---------------------------------------------------------------------------

// Tiny one-shot "daemon": accepts one connection on `path`, reads an
// 'I<name>\n' request, replies `reply` (a single char), then closes.
static void run_one_shot_daemon(const std::string& path, char reply,
                                std::string* seen_name) {
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) return;
    struct sockaddr_un a{};
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path.c_str(), sizeof(a.sun_path) - 1);
    unlink(path.c_str());
    if (bind(ls, (struct sockaddr*)&a, sizeof a) != 0) { close(ls); return; }
    if (listen(ls, 1) != 0) { close(ls); return; }

    int c = accept(ls, nullptr, nullptr);
    close(ls);
    if (c < 0) return;

    // Read "I<name>\n".
    std::string got;
    char buf[64];
    while (true) {
        ssize_t n = recv(c, buf, sizeof buf, 0);
        if (n <= 0) break;
        got.append(buf, (size_t)n);
        if (got.find('\n') != std::string::npos) break;
    }
    if (seen_name) *seen_name = got;

    char r[2] = {reply, 0};
    (void)send(c, r, 1, 0);
    close(c);
    unlink(path.c_str());
}

ZS_TEST(should_inject_round_trips_the_I_protocol_via_the_session_socket) {
    // The regression test for the hardcoded-path bug: the API table
    // must connect to the SESSION-FILE socket (the randomized path),
    // not the legacy fixed path. With the old code the connect goes
    // to the legacy path, nothing listens there, and should_inject
    // returns 0 even though a daemon answered "1" on the real socket.
    std::string sock = g_zn_tmpdir + "/randsess.sock";
    std::string sf   = session_file_with(sock.c_str());
    zs_test_zn_set_session_file(sf.c_str());

    std::string seen;
    std::thread srv(run_one_shot_daemon, sock, '1', &seen);
    // Give the listener a moment to bind (the accept blocks anyway).
    usleep(150000);

    zygisk_study_process_info info{};
    info.process_name    = "com.example.target";
    info.package_name    = "com.example.target";
    info.uid             = 10234;
    info.gid             = 10234;
    info.is_system_server = 0;
    info.opaq            = nullptr;

    int rv = zygisk_study_api_v1.should_inject(&zygisk_study_api_v1, &info);
    srv.join();
    ZS_CHECK_EQ(rv, 1);
    ZS_CHECK_STR_EQ(seen, "Icom.example.target\n");
}

ZS_TEST(should_inject_answers_zero_when_daemon_says_no) {
    std::string sock = g_zn_tmpdir + "/deny.sock";
    std::string sf   = session_file_with(sock.c_str());
    zs_test_zn_set_session_file(sf.c_str());

    std::string seen;
    std::thread srv(run_one_shot_daemon, sock, '0', &seen);
    usleep(150000);

    zygisk_study_process_info info{};
    info.process_name = "com.denied.app";
    int rv = zygisk_study_api_v1.should_inject(&zygisk_study_api_v1, &info);
    srv.join();
    ZS_CHECK_EQ(rv, 0);
    ZS_CHECK_STR_EQ(seen, "Icom.denied.app\n");
}

ZS_TEST(should_inject_answers_zero_when_daemon_is_down) {
    // Session file exists, points at a socket nobody serves: the
    // connect fails and the answer is "no" (fail-closed), matching
    // the payload-side convention.
    std::string sf = session_file_with((g_zn_tmpdir + "/dead.sock").c_str());
    zs_test_zn_set_session_file(sf.c_str());

    zygisk_study_process_info info{};
    info.process_name = "com.anything";
    int rv = zygisk_study_api_v1.should_inject(&zygisk_study_api_v1, &info);
    ZS_CHECK_EQ(rv, 0);
}

ZS_TEST(should_inject_rejects_null_and_nameless_info) {
    ZS_CHECK_EQ(zygisk_study_api_v1.should_inject(
                    &zygisk_study_api_v1, nullptr), 0);
    zygisk_study_process_info info{};
    info.process_name = nullptr;
    ZS_CHECK_EQ(zygisk_study_api_v1.should_inject(
                    &zygisk_study_api_v1, &info), 0);
}

ZS_TEST(open_companion_fd_connects_via_the_session_socket) {
    // 'C' companion handshake: the daemon side reads one byte and
    // keeps the socket open. We emulate that and verify the fd we get
    // back is connected to OUR listener (the C byte arrives).
    std::string sock = g_zn_tmpdir + "/comp.sock";
    std::string sf   = session_file_with(sock.c_str());
    zs_test_zn_set_session_file(sf.c_str());

    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    ZS_CHECK(ls >= 0);
    struct sockaddr_un a{};
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, sock.c_str(), sizeof(a.sun_path) - 1);
    unlink(sock.c_str());
    ZS_CHECK_EQ(bind(ls, (struct sockaddr*)&a, sizeof a), 0);
    ZS_CHECK_EQ(listen(ls, 1), 0);

    int got_c = -1;
    std::thread srv([&ls, &got_c, &sock]() {
        int c = accept(ls, nullptr, nullptr);
        if (c >= 0) {
            char b = 0;
            if (recv(c, &b, 1, 0) == 1) got_c = b;
            close(c);
        }
        close(ls);
        unlink(sock.c_str());
    });
    usleep(150000);

    int fd = zygisk_study_api_v1.open_companion_fd(&zygisk_study_api_v1);
    srv.join();
    ZS_CHECK(fd >= 0);
    ZS_CHECK_EQ(got_c, (int)'C');
    if (fd >= 0) close(fd);
}

ZS_TEST(api_table_shape_and_caps) {
    // ABI guards: the table a module gets from dlsym must carry the
    // documented magic/version and every function pointer.
    ZS_CHECK_EQ(zygisk_study_api_v1.magic,   0x5A535354u);
    ZS_CHECK_EQ(zygisk_study_api_v1.version, 1u);
    ZS_CHECK(zygisk_study_api_v1.caps               != nullptr);
    ZS_CHECK(zygisk_study_api_v1.should_inject      != nullptr);
    ZS_CHECK(zygisk_study_api_v1.post_fork          != nullptr);
    ZS_CHECK(zygisk_study_api_v1.open_companion_fd  != nullptr);

    uint32_t caps = zygisk_study_api_v1.caps(&zygisk_study_api_v1);
    ZS_CHECK_EQ(caps, (uint32_t)(ZS_CAP_EARLY_RETURN |
                                 ZS_CAP_FD_PASSING |
                                 ZS_CAP_SERVER_SPECIALIZE));
}

ZS_TEST(api_header_compiles_with_cxx_semantics) {
    // The header is extern "C" but must be includable from C++ (it
    // was included at the top of this TU — if uid_t/gid_t were still
    // undeclared, this file would not build at all). A quick layout
    // sanity check on the fixed struct: the two id fields are present
    // and distinct.
    zygisk_study_process_info info{};
    info.uid = 1;
    info.gid = 2;
    ZS_CHECK_EQ((int)info.uid, 1);
    ZS_CHECK_EQ((int)info.gid, 2);
    ZS_CHECK(&info.uid != &info.gid);
}

// ---------------------------------------------------------------------------

int main() {
    make_tmpdir();
    if (g_zn_tmpdir.empty()) {
        std::fprintf(stderr, "cannot create tmpdir\n");
        return 1;
    }
    int rc = zstest::run_all();
    zs_test_zn_set_session_file(nullptr);  // restore default
    return rc;
}
