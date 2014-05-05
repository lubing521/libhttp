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

    HTTPT_BEGIN("foo;a=1; b=2\t  ;c=3   ;  d=4");
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
    HTTPT_INVALID_PVALUE("foo?");

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

TEST(list) {
    struct http_pvalues pvalues;

#define HTTPT_BEGIN_LIST(str_)                                            \
    do {                                                                  \
        if (http_pvalues_parse(&pvalues, str_) == -1)                     \
            TEST_ABORT("cannot parse pvalue list: %s", http_get_error()); \
    } while (0)

#define HTTPT_END_LIST(str_)         \
    do {                             \
        http_pvalues_free(&pvalues); \
    } while (0)

#define HTTPT_LIST_PVALUE_PARAMETER_IS(i, name_, value_)                      \
    do {                                                                      \
        TEST_TRUE(http_pvalue_has_parameter(&pvalues.pvalues[i], name_));     \
        TEST_STRING_EQ(http_pvalue_get_parameter(&pvalues.pvalues[i], name_), \
                       value_);                                               \
    } while (0)

    HTTPT_BEGIN_LIST("a,b,c");
    TEST_STRING_EQ(pvalues.pvalues[0].value, "a");
    TEST_STRING_EQ(pvalues.pvalues[1].value, "b");
    TEST_STRING_EQ(pvalues.pvalues[2].value, "c");
    HTTPT_END_LIST();

    HTTPT_BEGIN_LIST("a ,\tb\t,  c");
    TEST_STRING_EQ(pvalues.pvalues[0].value, "a");
    TEST_STRING_EQ(pvalues.pvalues[1].value, "b");
    TEST_STRING_EQ(pvalues.pvalues[2].value, "c");
    HTTPT_END_LIST();

    HTTPT_BEGIN_LIST("a ;a=1 ,\tb ;b1=\"foo,bar\"; b2=2\t,  c; c=3");
    TEST_STRING_EQ(pvalues.pvalues[0].value, "a");
    HTTPT_LIST_PVALUE_PARAMETER_IS(0, "a", "1");
    TEST_STRING_EQ(pvalues.pvalues[1].value, "b");
    HTTPT_LIST_PVALUE_PARAMETER_IS(1, "b1", "foo,bar");
    HTTPT_LIST_PVALUE_PARAMETER_IS(1, "b2", "2");
    TEST_STRING_EQ(pvalues.pvalues[2].value, "c");
    HTTPT_LIST_PVALUE_PARAMETER_IS(2, "c", "3");
    HTTPT_END_LIST();
}

TEST(invalid_list) {
#define HTTPT_INVALID_PVALUES(str_)                   \
    do {                                              \
        struct http_pvalues pvalues;                  \
                                                      \
        if (http_pvalues_parse(&pvalues, str_) == 0)  \
            TEST_ABORT("parsed invalid pvalue list"); \
    } while (0)

    HTTPT_INVALID_PVALUES(",foo");
    HTTPT_INVALID_PVALUES(" , foo");
    HTTPT_INVALID_PVALUES("foo,");
    HTTPT_INVALID_PVALUES("foo, ");
    HTTPT_INVALID_PVALUES("foo,,bar");
    HTTPT_INVALID_PVALUES("foo, ,bar");
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("pvalues");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);
    TEST_RUN(suite, invalid);
    TEST_RUN(suite, list);
    TEST_RUN(suite, invalid_list);

    test_suite_print_results_and_exit(suite);
}
