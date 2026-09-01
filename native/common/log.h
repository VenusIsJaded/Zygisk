/* SPDX-License-Identifier: Apache-2.0
 * native/common/log.h
 *
 * Minimal logging helper for the C++ side of this project.
 *
 * On Android, the canonical logger is __android_log_print from liblog.
 * We use it so the messages come out tagged with "ZygiskStudy" in
 * logcat. If we are not on Android (e.g. host unit tests), we fall
 * back to fprintf(stderr).
 *
 * The macros are deliberately verbose (ZS_LOGI, ZS_LOGE, etc.) rather
 * than LOGI/LOGE, so that a reader of the code can grep for "ZS_" and
 * see every log site at once.
 *
 * ROUND 33 (STEALTH RELEASE): the two libraries that live in
 * /system/lib[64] (libzygisk + libpayload) are world-readable by every
 * app, and every log format string ships verbatim inside them —
 * "libzygisk: bootstrap (pid %d)", "hide: ...", the "ZygiskStudy" tag:
 * a complete plaintext fingerprint for any file-scanning detector
 * (exactly the class Round 30's randomized names defeated for FILE
 * names, but not for file CONTENTS). When ZS_STEALTH is defined (the
 * Android Release build sets it; Debug builds and host unit tests do
 * NOT), the macros compile to nothing: no format strings, no tag, no
 * snprintf, no logd socket write. Every call site was audited: the
 * arguments are local variables, strerror() or dlerror() consumed
 * nowhere else, so dropping the evaluation cannot change behavior.
 * Debug builds (cmake -DCMAKE_BUILD_TYPE=Debug) keep the full logs.
 */
#ifndef ZYGISK_STUDY_COMMON_LOG_H
#define ZYGISK_STUDY_COMMON_LOG_H

#include <cstdio>

#ifdef ZS_STEALTH
/* Release/stealth build: no log sites exist at all. The do-while keeps
 * the macro syntactically statement-shaped for `if (x) ZS_LOGE(...);`
 * call sites; the arguments are NOT evaluated (audited side-effect
 * free — see the header comment). */
#  define ZS_LOGI(fmt, ...) do { } while (0)
#  define ZS_LOGW(fmt, ...) do { } while (0)
#  define ZS_LOGE(fmt, ...) do { } while (0)
#  define ZS_LOGD(fmt, ...) do { } while (0)

#elif defined(__ANDROID__)
#  include <android/log.h>

/* __android_log_print gives us a stable per-tag buffer. */
static inline void zs_log_impl(int prio, const char* tag, const char* msg) {
    __android_log_print(prio, tag, "%s", msg);
}

#  define ZS_LOGI(fmt, ...) \
     do { char _b[512]; snprintf(_b, sizeof _b, fmt, ##__VA_ARGS__); \
          zs_log_impl(ANDROID_LOG_INFO,  "ZygiskStudy", _b); } while (0)
#  define ZS_LOGW(fmt, ...) \
     do { char _b[512]; snprintf(_b, sizeof _b, fmt, ##__VA_ARGS__); \
          zs_log_impl(ANDROID_LOG_WARN,  "ZygiskStudy", _b); } while (0)
#  define ZS_LOGE(fmt, ...) \
     do { char _b[512]; snprintf(_b, sizeof _b, fmt, ##__VA_ARGS__); \
          zs_log_impl(ANDROID_LOG_ERROR, "ZygiskStudy", _b); } while (0)
#  define ZS_LOGD(fmt, ...) \
     do { char _b[512]; snprintf(_b, sizeof _b, fmt, ##__VA_ARGS__); \
          zs_log_impl(ANDROID_LOG_DEBUG, "ZygiskStudy", _b); } while (0)

#else  /* host build for unit tests */

#  define ZS_LOGI(fmt, ...) fprintf(stderr, "[I] " fmt "\n", ##__VA_ARGS__)
#  define ZS_LOGW(fmt, ...) fprintf(stderr, "[W] " fmt "\n", ##__VA_ARGS__)
#  define ZS_LOGE(fmt, ...) fprintf(stderr, "[E] " fmt "\n", ##__VA_ARGS__)
#  define ZS_LOGD(fmt, ...) fprintf(stderr, "[D] " fmt "\n", ##__VA_ARGS__)

#endif

#endif /* ZYGISK_STUDY_COMMON_LOG_H */
