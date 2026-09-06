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
#include <sstream>
#include <type_traits>
#include <utility>
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

// Keep assertion operands outside macro-local scopes: otherwise a caller's
// `_a` or `_h` can refer to an uninitialized temporary declared by the macro.
// Reference parameters also allow comparisons of noncopyable values.
inline std::string location(const char* file, int line) {
    return std::string(file) + ":" + std::to_string(line);
}

template <typename T>
auto describe(const T& value, int)
    -> decltype(std::declval<std::ostream&>() << value, std::string()) {
    std::ostringstream out;
    if constexpr (std::is_pointer_v<std::decay_t<T>> &&
                  std::is_object_v<std::remove_pointer_t<std::decay_t<T>>>) {
        // Equality compares addresses, not pointed-to text. In particular,
        // char pointers may be null, unterminated, or point to unreadable memory.
        // Remove volatile only for formatting the address; never dereference it.
        out << const_cast<const void*>(static_cast<const volatile void*>(value));
    } else {
        out << value;
    }
    return out.str();
}

template <typename T>
std::string describe(const T&, ...) {
    return "<unprintable>";
}

template <typename A, typename B>
void check_equal(const A& a, const B& b, const char* file, int line,
                 const char* expression) {
    if (!(a == b)) {
        throw CheckFailed{location(file, line) + "  " + expression + " failed: "
                          + describe(a, 0) + " != " + describe(b, 0)};
    }
}

template <typename A, typename B>
void check_not_equal(const A& a, const B& b, const char* file, int line,
                     const char* expression) {
    if (!(a != b)) {
        throw CheckFailed{location(file, line) + "  " + expression + " failed"};
    }
}

inline std::string checked_string(const char* value, const std::string& where) {
    if (!value) throw CheckFailed{where + "  null string operand"};
    return value;
}

inline const std::string& checked_string(const std::string& value,
                                         const std::string&) {
    return value;
}

template <typename A, typename B>
void check_string_equal(const A& a, const B& b, const char* file, int line) {
    const auto where = location(file, line);
    const std::string lhs = checked_string(a, where);
    const std::string rhs = checked_string(b, where);
    if (lhs != rhs) {
        throw CheckFailed{where + "  ZS_CHECK_STR_EQ failed: \"" + lhs
                          + "\" != \"" + rhs + "\""};
    }
}

template <typename A, typename B>
void check_substring(const A& haystack, const B& needle, bool expected,
                     const char* file, int line) {
    const auto where = location(file, line);
    const std::string text = checked_string(haystack, where);
    const std::string part = checked_string(needle, where);
    if ((text.find(part) != std::string::npos) != expected) {
        throw CheckFailed{where + (expected ? "  ZS_CHECK_STR_CONTAINS: substring \""
                                           : "  ZS_CHECK_STR_ABSENT: substring \"")
                          + part + (expected ? "\" not found in \""
                                             : "\" unexpectedly found in \"")
                          + text + "\""};
    }
}

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

#define ZS_CHECK_EQ(a, b) \
    do { ::zstest::check_equal((a), (b), __FILE__, __LINE__, \
                               "ZS_CHECK_EQ(" #a ", " #b ")"); } while (0)

#define ZS_CHECK_NE(a, b) \
    do { ::zstest::check_not_equal((a), (b), __FILE__, __LINE__, \
                                   "ZS_CHECK_NE(" #a ", " #b ")"); } while (0)

#define ZS_CHECK_STR_EQ(a, b) \
    do { ::zstest::check_string_equal((a), (b), __FILE__, __LINE__); } while (0)

#define ZS_CHECK_STR_CONTAINS(haystack, needle) \
    do { ::zstest::check_substring((haystack), (needle), true, \
                                   __FILE__, __LINE__); } while (0)

#define ZS_CHECK_STR_ABSENT(haystack, needle) \
    do { ::zstest::check_substring((haystack), (needle), false, \
                                   __FILE__, __LINE__); } while (0)

#endif // ZYGISK_STUDY_TEST_FRAMEWORK_H
