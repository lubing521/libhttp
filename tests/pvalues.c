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

TEST(base) {
    struct http_pvalue pvalue;

#define HTTPT_BEGIN(str_)                                            \
    do {                                                             \
        if (http_pvalue_parse(&pvalue, str_, NULL) == -1)            \
            TEST_ABORT("cannot parse pvalue: %s", http_get_error()); \
    } while (0)

#define HTTPT_END(str_)            \
    do {                           \
        http_pvalue_free(&pvalue); \
    } while (0)

#define HTTPT_PVALUE_PARAMETER_IS(name_, value_)                           \
    do {                                                                   \
        TEST_TRUE(http_pvalue_has_parameter(&pvalue, name_));              \
        TEST_STRING_EQ(http_pvalue_get_parameter(&pvalue, name_), value_); \
    } while (0)

    HTTPT_BEGIN("a");
    TEST_STRING_EQ(pvalue.value, "a");
    HTTPT_END();

    HTTPT_BEGIN("foo");
    TEST_STRING_EQ(pvalue.value, "foo");
    HTTPT_END();

    HTTPT_BEGIN("foo;a=1; b=2  ;c=3   ;  d=4");
    TEST_STRING_EQ(pvalue.value, "foo");
    HTTPT_PVALUE_PARAMETER_IS("a", "1");
    HTTPT_PVALUE_PARAMETER_IS("b", "2");
    HTTPT_PVALUE_PARAMETER_IS("c", "3");
    HTTPT_PVALUE_PARAMETER_IS("d", "4");
    HTTPT_END();

    HTTPT_BEGIN("foo; a=foo; b=\"foo\"; c=\"\\\"foo\\\"\"");
    TEST_STRING_EQ(pvalue.value, "foo");
    HTTPT_PVALUE_PARAMETER_IS("a", "foo");
    HTTPT_PVALUE_PARAMETER_IS("b", "foo");
    HTTPT_PVALUE_PARAMETER_IS("c", "\"foo\"");
    HTTPT_END();
}

TEST(invalid) {
#define HTTPT_INVALID_PVALUE(str_)                       \
    do {                                                 \
        struct http_pvalue pvalue;                       \
                                                         \
        if (http_pvalue_parse(&pvalue, str_, NULL) == 0) \
            TEST_ABORT("parsed invalid pvalue");         \
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
}


int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("pvalues");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);
    TEST_RUN(suite, invalid);

    test_suite_print_results_and_exit(suite);
}
