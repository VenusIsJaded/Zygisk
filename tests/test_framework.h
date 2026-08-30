// SPDX-License-Identifier: Apache-2.0
// tests/test_framework.h
//
// A minimal, dependency-free test framework for the host-side unit
// tests. We use this so the tests can be built with plain g++ without
// requiring GoogleTest or any other third-party library.
//
// The framework is intentionally tiny: a single ZS_TEST macro that
// registers a test function (via a static initializer) and a run_all()
// entry point that main() calls.
//
// Design goals:
//   - No external dependencies. Compiles with `g++ -std=c++17`.
//   - Clear pass/fail output, exit code 0 on success, 1 on any failure.
//   - Each test is a separate function with a name; the framework
//     runs them in registration order.

#ifndef ZYGISK_STUDY_TEST_FRAMEWORK_H
#define ZYGISK_STUDY_TEST_FRAMEWORK_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace zstest {

// A single registered test case.
struct TestCase {
    const char* name;
    void (*fn)();
};

// The global registry. We use a function-local static so the order of
// initialization across translation units is well-defined.
inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

// Counters printed at the end.
inline int& pass_count() { static int c = 0; return c; }
inline int& fail_count() { static int c = 0; return c; }

// Record a failure with a simple message and abort the current test.
// We use a longjmp-style abort via a real C++ exception so the test
// function returns to run_all() cleanly. Tests use ZS_CHECK macros
// below, not this directly.
struct CheckFailed {
    std::string msg;
};

// Run every registered test in order. Returns 0 if all passed, 1 if
// any failed.
inline int run_all() {
    int n_ok = 0, n_bad = 0;
    for (const auto& t : registry()) {
        std::fprintf(stderr, "  [run ] %s\n", t.name);
        try {
            t.fn();
            ++n_ok;
            std::fprintf(stderr, "  [pass] %s\n", t.name);
        } catch (const CheckFailed& e) {
            ++n_bad;
            std::fprintf(stderr, "  [FAIL] %s : %s\n", t.name, e.msg.c_str());
        } catch (...) {
            ++n_bad;
            std::fprintf(stderr, "  [FAIL] %s : unknown exception\n", t.name);
        }
    }
    std::fprintf(stderr, "\n%d passed, %d failed, %d total\n",
                 n_ok, n_bad, n_ok + n_bad);
    return n_bad == 0 ? 0 : 1;
}

// Registration helper used by the ZS_TEST macro.
struct Registrar {
    Registrar(const char* name, void (*fn)()) {
        registry().push_back({name, fn});
    }
};

} // namespace zstest

// Macro: declare and register a test function.
//   ZS_TEST(my_test_name) { ZS_CHECK_EQ(1, 1); }
#define ZS_TEST(name)                                                      \
    static void zstest_##name##_fn();                                       \
    static ::zstest::Registrar zstest_##name##_reg(#name,                  \
                                                    &zstest_##name##_fn);  \
    static void zstest_##name##_fn()

// Assertion macros. They throw CheckFailed on failure, which run_all
// catches so subsequent tests still run.
#define ZS_CHECK(cond)                                                     \
    do {                                                                    \
        if (!(cond)) {                                                      \
            throw ::zstest::CheckFailed{                                    \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                "  ZS_CHECK(" #cond ") failed"};                            \
        }                                                                   \
    } while (0)

#define ZS_CHECK_EQ(a, b)                                                  \
    do {                                                                    \
        auto _a = (a); auto _b = (b);                                       \
        if (!(_a == _b)) {                                                  \
            throw ::zstest::CheckFailed{                                    \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                "  ZS_CHECK_EQ(" #a ", " #b ") failed: "                    \
                + std::to_string(_a) + " != " + std::to_string(_b)};        \
        }                                                                   \
    } while (0)

#define ZS_CHECK_NE(a, b)                                                  \
    do {                                                                    \
        auto _a = (a); auto _b = (b);                                       \
        if (!(_a != _b)) {                                                  \
            throw ::zstest::CheckFailed{                                    \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                "  ZS_CHECK_NE(" #a ", " #b ") failed"                      \
            };                                                              \
        }                                                                   \
    } while (0)

#define ZS_CHECK_STR_EQ(a, b)                                              \
    do {                                                                    \
        std::string _a = (a); std::string _b = (b);                         \
        if (_a != _b) {                                                     \
            throw ::zstest::CheckFailed{                                    \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                "  ZS_CHECK_STR_EQ failed: \"" + _a +                      \
                "\" != \"" + _b + "\""};                                   \
        }                                                                   \
    } while (0)

#define ZS_CHECK_STR_CONTAINS(haystack, needle)                            \
    do {                                                                    \
        std::string _h = (haystack); std::string _n = (needle);            \
        if (_h.find(_n) == std::string::npos) {                             \
            throw ::zstest::CheckFailed{                                    \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                "  ZS_CHECK_STR_CONTAINS: substring \"" + _n +             \
                "\" not found in \"" + _h + "\""};                          \
        }                                                                   \
    } while (0)

#define ZS_CHECK_STR_ABSENT(haystack, needle)                              \
    do {                                                                    \
        std::string _h = (haystack); std::string _n = (needle);            \
        if (_h.find(_n) != std::string::npos) {                             \
            throw ::zstest::CheckFailed{                                    \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                "  ZS_CHECK_STR_ABSENT: substring \"" + _n +               \
                "\" unexpectedly found in \"" + _h + "\""};                 \
        }                                                                   \
    } while (0)

#endif // ZYGISK_STUDY_TEST_FRAMEWORK_H
