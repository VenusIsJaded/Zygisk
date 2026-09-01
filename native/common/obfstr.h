// SPDX-License-Identifier: Apache-2.0
// native/common/obfstr.h
//
// ROUND 33 (STEALTH): compile-time string obfuscation.
//
// THE PROBLEM THIS SOLVES
// -----------------------
// Round 30 gave the two /system/lib[64]-resident libraries per-install
// randomized FILE names, defeating name-based detectors that scan
// /proc/<pid>/maps. But the FILES themselves are world-readable
// (0644 root:root in /system/lib[64] — any app can open() them), and
// every runtime string constant shipped verbatim inside: the fixed
// DT_SONAMEs ("libzygisk.so"), the full /data/system/zygisk_study
// path map, "zygiskd", the env-var names, the dlsym contract names.
// A one-line file scan for "zygisk" over /system/lib[64]/*.so
// fingerprinted us regardless of the randomized file name. Round 30
// closed the name vector; this header closes the CONTENT vector.
//
// THE MECHANISM
// -------------
// ZS_OBFS("literal") evaluates to a temporary object whose:
//   - compile-time part is the literal XOR'd with a position-spread
//     key — the encrypted bytes are what lands in .rodata (no string
//     table entry, no plaintext anywhere in the image);
//   - runtime part is a small decode loop into a stack buffer, with
//     the source reads declared `volatile` so the optimizer cannot
//     constant-fold the decode back into a plaintext .rodata constant
//     (the classic obfstr pitfall — without volatile, LLVM folds the
//     whole scheme and re-materializes the plain string).
//
// The result of ZS_OBFS(s) is a plain `const char*` valid until the end
// of the FULL EXPRESSION it appears in (the temporary Dec is
// materialized inside that expression):
//
//     open(ZS_OBFS("/data/..."), O_RDONLY);          // OK
//     snprintf(buf, n, "%sdenylist",
//              ZS_OBFS("/data/system/zygisk_study/")); // OK (varargs-safe)
//     dlsym(h, ZS_OBFS("zygisk_module"));            // OK
//
// Because the macro yields a raw pointer, NEVER store it in a variable
// for later use — the temporary dies at the semicolon:
//
//     const char* p = ZS_OBFS("...");  // DANGLING — FORBIDDEN
//
// To keep the decoded string alive across statements, use the holder
// form with auto&& (the Dec object's lifetime is then extended to the
// reference's scope):
//
//     auto&& dir = ZS_OBFS_H("/data/system/zygisk_study");
//     use_later(dir.c_str());
//
// HONEST SCOPE: this defeats string-signature scanning (grep for
// "zygisk", dictionary lookups over .rodata). It does NOT hide the
// strings from a determined reverse engineer with a disassembler —
// the decode loop is right there. That is the same threat model
// Round 30's randomized names chose: cheap, mass, signature-based
// detection is defeated; targeted analysis is not.
//
// Host unit tests compile the same sources, so every obfuscated path
// is still exercised end-to-end by the test suite.

#ifndef ZYGISK_STUDY_COMMON_OBFSTR_H
#define ZYGISK_STUDY_COMMON_OBFSTR_H

#include <cstddef>
#include <cstring>

namespace zsst {

// Position-spread key: a different byte per offset, derived from the
// literal's length and the source line so no two literals share a
// keystream. All arithmetic wraps in unsigned char.
inline constexpr unsigned char key_byte(unsigned key, std::size_t i) {
    return (unsigned char)(key + i * 7u + 11u);
}

// Compile-time encrypted storage. constexpr constructor => the
// encrypted array is constant-initialized into .rodata.
template <std::size_t N>
struct Obf {
    char enc[N];
    explicit constexpr Obf(const char (&s)[N], unsigned key)
        : enc{} {
        for (std::size_t i = 0; i < N; ++i) {
            enc[i] = (char)((unsigned char)s[i] ^ key_byte(key, i));
        }
    }
};

// Runtime decoder. The `volatile` on the source pointer is load-bearing:
// it prevents the optimizer from folding the decode into a plaintext
// .rodata constant (see the header comment).
template <std::size_t N>
struct Dec {
    char buf[N];

    explicit Dec(const Obf<N>& o, unsigned key) {
        const volatile char* src = o.enc;
        for (std::size_t i = 0; i < N; ++i) {
            buf[i] = (char)((unsigned char)src[i] ^ key_byte(key, i));
        }
    }

    const char* c_str() const { return buf; }
    operator const char*() const { return buf; }
};

}  // namespace zsst

// zs::StrTable — decode-once string table for the constant arrays
// that used to be `static const char* kTable[] = {"...", ...}` or
// `static const struct {const char* p; size_t n;} kPrefixes[]`.
// Build it inside a function-local static (magic static = decoded
// once, thread-safe, COW-inherited by forked children):
//
//     static const zsst::StrTable table_g = [] {
//         zsst::StrTable b;
//         b.add(ZS_OBFS("literal.one"));
//         b.add(ZS_OBFS("literal.two"));
//         return b;
//     }();                      // file-scope global: init_array, no
//                               // guard variable, no libc++abi pull
//     static const zsst::StrTable& table() { return table_g; }
//
// at(i)/len(i) preserve the compile-time-length fast path the old
// {ptr,len} tables had (the length is stored once at decode time).
namespace zsst {
class StrTable {
public:
    static constexpr std::size_t kMaxEntries = 48;
    static constexpr std::size_t kMaxLen = 95;

    struct Entry {
        const char* p;
        std::size_t n;
    };

    Entry entries[kMaxEntries] = {};
    const char* ptrs[kMaxEntries] = {};   // compact char* view (stride 8)
    std::size_t count = 0;

    void add(const char* s) {
        if (count >= kMaxEntries) return;
        std::size_t n = 0;
        while (n < kMaxLen && s[n] != '\0') ++n;
        memcpy(storage_[count], s, n);
        storage_[count][n] = '\0';
        entries[count].p = storage_[count];
        entries[count].n = n;
        ptrs[count] = storage_[count];
        ++count;
    }

    const char* at(std::size_t i) const { return entries[i].p; }
    std::size_t len(std::size_t i) const { return entries[i].n; }

    // Range-for support over Entry{p, n} — lets the converted
    // `for (const auto& e : table())` keep the old loop body shape.
    const Entry* begin() const { return entries; }
    const Entry* end() const { return entries + count; }

private:
    char storage_[kMaxEntries][kMaxLen + 1] = {};
};
}  // namespace zsst

// ZS_OBFS_PATH(name, s): FILE-SCOPE decode-once path constant.
//
//     ZS_OBFS_PATH(k_session_file, "/data/adb/modules/.../session.sock");
//     ... open(k_session_file(), O_RDONLY);
//
// Expands to an encrypted .rodata object + a trivially-destructible
// global whose constructor decodes into .bss storage during the
// library's init_array (i.e. inside its dlopen — before any function
// of the library can possibly run), plus a `name()` accessor.
//
// ROUND 33b — why init_array and NOT a function-local static: the
// first version used magic statics (`static const Path p{...}`), and
// magic statics reference __cxa_guard_acquire/release/abort, which
// pulls libc++abi's cxa_guard.cpp.o — and with it the demangling
// terminate handler and the ~180 KB itanium-demangle parser — into
// EVERY library that obfuscates a single path (measured: libzn_loader
// 9 KB -> 357 KB). init_array initialization needs no guard at all
// (globals initialize unconditionally at load), and the storage type
// is trivially destructible, so no __cxa_atexit registration exists
// either — which also keeps the Round 30 Tier A purge story exact:
// nothing registers anything with the runtime.
//
// ZS_OBFS_DEC(s): internal — expands to a prvalue Dec<N> decoded from
// the constexpr-encrypted array. The lambda makes the Obf a
// function-local constant (constant-initialized, no runtime guard).
#define ZS_OBFS_DEC(s)                                                       \
    (::zsst::Dec<sizeof(s)>(                                                \
        []() -> const ::zsst::Obf<sizeof(s)>& {                              \
            constexpr unsigned zs_k = (unsigned)(sizeof(s) * 31u + __LINE__);\
            static constexpr ::zsst::Obf<sizeof(s)> zs_enc{(s), zs_k};       \
            return zs_enc;                                                   \
        }(),                                                                 \
        (unsigned)(sizeof(s) * 31u + __LINE__)))

// ZS_OBFS(s): a `const char*` for direct use as a call argument
// (varargs-safe: the argument really is a char pointer). The Dec
// temporary is materialized inside the enclosing full expression.
#define ZS_OBFS(s) (ZS_OBFS_DEC(s).c_str())

// ZS_OBFS_H(s): the Dec object itself, for `auto&&` lifetime extension.
#define ZS_OBFS_H(s) (ZS_OBFS_DEC(s))

#define ZS_OBFS_PATH(name, s)                                              \
    static const ::zsst::Obf<sizeof(s)> name##_enc{                        \
        (s), (unsigned)(sizeof(s) * 31u + __LINE__)};                      \
    struct name##_init_t {                                                 \
        char storage[sizeof(s)];                                           \
        name##_init_t() {                                                  \
            ::zsst::Dec<sizeof(s)> d{name##_enc,                           \
                (unsigned)(sizeof(s) * 31u + __LINE__)};                   \
            for (std::size_t zs_i = 0; zs_i < sizeof(s); ++zs_i)           \
                storage[zs_i] = d.c_str()[zs_i];                           \
        }                                                                  \
    };                                                                     \
    static name##_init_t name##_g;                                         \
    static const char* name() { return name##_g.storage; }

#endif  // ZYGISK_STUDY_COMMON_OBFSTR_H
