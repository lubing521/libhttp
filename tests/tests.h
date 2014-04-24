/*
 * Copyright (c) 2014 Nicolas Martyanoff
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HTTP_TESTS_H
#define HTTP_TESTS_H

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <utest.h>

#define HTTPT_DIE(fmt_, ...)                      \
    do {                                          \
        fprintf(stderr, fmt_"\n", ##__VA_ARGS__); \
        exit(1);                                  \
    } while (0)

#define HTTPT_REPORT_ERROR(fmt_, ...)                   \
    do {                                                \
        fprintf(stderr, "%s:%d: \e[31m" fmt_ "\e[0m\n", \
                __FILE__, __LINE__, ##__VA_ARGS__);     \
        exit(1);                                        \
    } while (0)

#define HTTPT_IS_TRUE(val_)                                                  \
    do {                                                                     \
        const char *val_str__ = #val_;                                       \
        bool val__ = val_;                                                   \
                                                                             \
        if (!val__)                                                          \
            HTTPT_REPORT_ERROR("%s is false instead of true", val_str__);    \
    } while (0)

#define HTTPT_IS_FALSE(val_)                                                 \
    do {                                                                     \
        const char *val_str__ = #val_;                                       \
        bool val__ = val_;                                                   \
                                                                             \
        if (val__)                                                           \
            HTTPT_REPORT_ERROR("%s is true instead of false", val_str__);    \
    } while (0)

#define HTTPT_IS_EQUAL_BOOL(val_, expected_)                                 \
    do {                                                                     \
        const char *val_str__ = #val_;                                       \
        bool val__ = (val_);                                                 \
        bool expected__ = (expected_);                                       \
                                                                             \
        if (val__ != expected__) {                                           \
            HTTPT_REPORT_ERROR("%s is %s instead of %s",                     \
                               val_str__, (val__ ? "true" : "false"),        \
                               (expected__ ? "true" : "false"));             \
        }                                                                    \
    } while (0)

#define HTTPT_IS_EQUAL_UINT(val_, expected_)                                  \
    do {                                                                      \
        const char *val_str__ = #val_;                                        \
        uint64_t val__ = (val_);                                              \
        uint64_t expected__ = (expected_);                                    \
                                                                              \
        if (val__ != expected__) {                                            \
            HTTPT_REPORT_ERROR("%s is equal to %"PRIu64" instead of %"PRIu64, \
                               val_str__, val__, expected__);                 \
        }                                                                     \
    } while (0)

#define HTTPT_IS_EQUAL_INT(val_, expected_)                                   \
    do {                                                                      \
        const char *val_str__ = #val_;                                        \
        int64_t val__ = (val_);                                               \
        int64_t expected__ = (expected_);                                     \
                                                                              \
        if (val__ != expected__) {                                            \
            HTTPT_REPORT_ERROR("%s is equal to %"PRIi64" instead of %"PRIi64, \
                               val_str__, val__, expected__);                 \
        }                                                                     \
    } while (0)

#define HTTPT_IS_EQUAL_PTR(val_, expected_)                                   \
    do {                                                                      \
        const char *val_str__ = #val_;                                        \
        const void * val__ = (val_);                                          \
        const void * expected__ = (expected_);                                \
                                                                              \
        if (val__ && expected__) {                                            \
            if (val__ != expected__) {                                        \
                HTTPT_REPORT_ERROR("%s is equal to %p instead of %p",         \
                                   val_str__, val__, expected__);             \
            }                                                                 \
        } else if (val__) {                                                   \
            HTTPT_REPORT_ERROR("%s is equal to %p instead of being null",     \
                               val_str__, val__);                             \
        } else if (expected__) {                                              \
            HTTPT_REPORT_ERROR("%s is null instead of being equal to %p",     \
                               val_str__, expected__);                        \
        }                                                                     \
    } while (0)

#define HTTPT_IS_EQUAL_STRING(val_, expected_)                                \
    do {                                                                      \
        const char *val_str__ = #val_;                                        \
        const char *val__ = (val_);                                           \
        const char *expected__ = (expected_);                                 \
                                                                              \
        if (!val__) {                                                         \
            HTTPT_REPORT_ERROR("%s is null instead of being equal to \"%s\"", \
                               val_str__, expected__);                        \
        }                                                                     \
                                                                              \
        if (strcmp(val__, expected__) != 0) {                                 \
            HTTPT_REPORT_ERROR("%s is equal to \"%s\" instead of \"%s\"",     \
                               val_str__, val__, expected__);                 \
        }                                                                     \
    } while (0)

#endif
