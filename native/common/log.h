/* SPDX-License-Identifier: Apache-2.0
 * native/common/log.h
 *
 * Minimal logging helper for the C++ side of this project.
 *
 * On Android, the canonical logger is __android_log_print from liblog.
 * We use __android_log_buf_write so the messages come out tagged with
 * "ZygiskStudy" in logcat. If we are not on Android (e.g. host unit
 * tests), we fall back to fprintf(stderr).
 *
 * The macros are deliberately verbose (ZS_LOGI, ZS_LOGE, etc.) rather
 * than LOGI/LOGE, so that a reader of the code can grep for "ZS_" and
 * see every log site at once.
 *
 * The intent of this header is "easy to reverse engineer": the symbols
 * you see in the resulting .so are exactly what's written here, named
 * descriptively, and the log strings are present in plain text so a
 * disassembler shows them verbatim next to the call site.
 */
#ifndef ZYGISK_STUDY_COMMON_LOG_H
#define ZYGISK_STUDY_COMMON_LOG_H

#include <cstdio>

#ifdef __ANDROID__
#  include <android/log.h>

/* __android_log_buf_write gives us a stable per-tag buffer. LOG_ID_MAIN
 * is the default; using it explicitly keeps the logs visible to anyone
 * reading logcat without a tag filter. */
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
