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

#include "http.h"
#include "internal.h"

#include "tests.h"

int
main(int argc, char **argv) {
    struct http_pvalue pvalue;

#define HTTPT_BEGIN(str_)                                       \
    do {                                                        \
        if (http_pvalue_parse(&pvalue, str_, NULL) == -1) {     \
            HTTPT_DIE("%s:%d: cannot parse pvalue: %s",         \
                      __FILE__, __LINE__, http_get_error());    \
        }                                                       \
    } while (0)

#define HTTPT_END(str_)            \
    do {                           \
        http_pvalue_free(&pvalue); \
    } while (0)

#define HTTPT_PVALUE_PARAMETER_IS(name_, value_)                         \
    do {                                                                 \
        HTTPT_IS_TRUE(http_pvalue_has_parameter(&pvalue, name_));        \
        HTTPT_IS_EQUAL_STRING(http_pvalue_get_parameter(&pvalue, name_), \
                              value_);                                   \
    } while (0)

    HTTPT_BEGIN("a");
    HTTPT_IS_EQUAL_STRING(pvalue.value, "a");
    HTTPT_END();

    HTTPT_BEGIN("foo");
    HTTPT_IS_EQUAL_STRING(pvalue.value, "foo");
    HTTPT_END();

    HTTPT_BEGIN("foo;a=1; b=2  ;c=3   ;  d=4");
    HTTPT_IS_EQUAL_STRING(pvalue.value, "foo");
    HTTPT_PVALUE_PARAMETER_IS("a", "1");
    HTTPT_PVALUE_PARAMETER_IS("b", "2");
    HTTPT_PVALUE_PARAMETER_IS("c", "3");
    HTTPT_PVALUE_PARAMETER_IS("d", "4");
    HTTPT_END();

    HTTPT_BEGIN("foo; a=foo; b=\"foo\"; c=\"\\\"foo\\\"\"");
    HTTPT_IS_EQUAL_STRING(pvalue.value, "foo");
    HTTPT_PVALUE_PARAMETER_IS("a", "foo");
    HTTPT_PVALUE_PARAMETER_IS("b", "foo");
    HTTPT_PVALUE_PARAMETER_IS("c", "\"foo\"");
    HTTPT_END();

#define HTTPT_INVALID_PVALUE(str_)                         \
    do {                                                   \
        if (http_pvalue_parse(&pvalue, str_, NULL) == 0) { \
            HTTPT_DIE("%s:%d: parsed invalid pvalue",      \
                      __FILE__, __LINE__);                 \
        }                                                  \
    } while (0)

    /* Invalid value */
    HTTPT_INVALID_PVALUE("");
    HTTPT_INVALID_PVALUE("?");
    HTTPT_INVALID_PVALUE("foo,");

    /* Invalid parameters */
    HTTPT_INVALID_PVALUE("foo;");
    HTTPT_INVALID_PVALUE("foo; name");
    HTTPT_INVALID_PVALUE("foo; name=");
    HTTPT_INVALID_PVALUE("foo; name;");
    HTTPT_INVALID_PVALUE("foo; @=1");
    HTTPT_INVALID_PVALUE("foo; a=1;");
    HTTPT_INVALID_PVALUE("foo; a=v@lue;");
    HTTPT_INVALID_PVALUE("foo; a=\";");
    HTTPT_INVALID_PVALUE("foo; a=\";");
    HTTPT_INVALID_PVALUE("foo; a=\"\\\"");
    HTTPT_INVALID_PVALUE("foo; a=\"\\x\"");
    HTTPT_INVALID_PVALUE("foo; a=\"foo\";");

#undef HTTPT_INVALID_PVALUE

#undef HTTPT_BEGIN
#undef HTTPT_END
#undef HTTPT_PVALUE_PARAMETER_IS

    return 0;
}

