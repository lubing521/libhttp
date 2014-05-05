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

TEST(media_types) {
    struct http_media_type *media_type;

#define HTTPT_BEGIN(str_)                                                \
    do {                                                                 \
        media_type = http_media_type_new(str_);                          \
        if (!media_type)                                                 \
            TEST_ABORT("cannot parse media type: %s", http_get_error()); \
    } while (0)

#define HTTPT_END(str_)                     \
    do {                                    \
        http_media_type_delete(media_type); \
    } while (0)

#define HTTPT_MEDIA_TYPE_PARAMETER_IS(name_, value_)                            \
    do {                                                                        \
        TEST_TRUE(http_media_type_has_parameter(media_type, name_));        \
        TEST_STRING_EQ(http_media_type_get_parameter(media_type, name_), \
                              value_);                                          \
    } while (0)

    HTTPT_BEGIN("text/plain");
    TEST_STRING_EQ(http_media_type_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                          "text/plain");
    TEST_STRING_EQ(http_media_type_get_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_get_subtype(media_type), "plain");
    HTTPT_END();

    HTTPT_BEGIN("Text/PLAIn");
    TEST_STRING_EQ(http_media_type_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                          "text/plain");
    TEST_STRING_EQ(http_media_type_get_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_get_subtype(media_type), "plain");
    HTTPT_END();

    HTTPT_BEGIN("text/plain; charset=UTF-8");
    TEST_STRING_EQ(http_media_type_string(media_type),
                          "text/plain; charset=UTF-8");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                          "text/plain");
    TEST_STRING_EQ(http_media_type_get_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("charset", "UTF-8");
    HTTPT_END();

    HTTPT_BEGIN("text/plain ;CHarsET=UTF-8");
    TEST_STRING_EQ(http_media_type_string(media_type),
                          "text/plain; charset=UTF-8");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                          "text/plain");
    TEST_STRING_EQ(http_media_type_get_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("charset", "UTF-8");
    HTTPT_END();

    HTTPT_BEGIN("text/plain;a=1; b=2  ;c=3   ;  d=4");
    TEST_STRING_EQ(http_media_type_string(media_type),
                          "text/plain; a=1; b=2; c=3; d=4");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                          "text/plain");
    TEST_STRING_EQ(http_media_type_get_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("a", "1");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("b", "2");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("c", "3");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("d", "4");
    HTTPT_END();

    HTTPT_BEGIN("text/plain; a=foo; b=\"foo\"; c=\"\\\"foo\\\"\"");
    TEST_STRING_EQ(http_media_type_string(media_type),
                          "text/plain; a=foo; b=foo; c=\"\\\"foo\\\"\"");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                          "text/plain");
    TEST_STRING_EQ(http_media_type_get_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("a", "foo");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("b", "foo");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("c", "\"foo\"");
    HTTPT_END();
}

TEST(invalid_media_types) {
#define HTTPT_INVALID_MEDIA_TYPE(str_)                    \
    do {                                                  \
        struct http_media_type *media_type;               \
                                                          \
        media_type = http_media_type_new(str_);           \
        if (media_type)                                   \
            TEST_ABORT("parsed invalid media type");      \
    } while (0)

    /* Invalid type */
    HTTPT_INVALID_MEDIA_TYPE("");
    HTTPT_INVALID_MEDIA_TYPE("/plain");
    HTTPT_INVALID_MEDIA_TYPE("tex!");

    /* Invalid subtype */
    HTTPT_INVALID_MEDIA_TYPE("text/");
    HTTPT_INVALID_MEDIA_TYPE("text/ plain");
    HTTPT_INVALID_MEDIA_TYPE("text/pl@in");

    /* Invalid parameters */
    HTTPT_INVALID_MEDIA_TYPE("text/plain;");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; name");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; name=");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; name;");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; @=1");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=1;");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=v@lue;");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=\";");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=\";");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=\"\\\"");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=\"\\x\"");
    HTTPT_INVALID_MEDIA_TYPE("text/plain; a=\"foo\";");
}

TEST(q_encoding) {
#define HTTPT_QENCODING_IS(string_, encoded_string_)            \
    do {                                                        \
        char *encoded_string;                                   \
                                                                \
        encoded_string = http_mime_q_encode(string_);           \
        TEST_STRING_EQ(encoded_string, encoded_string_); \
    } while (0)

    HTTPT_QENCODING_IS("", "=?UTF-8?Q?" "?=");
    HTTPT_QENCODING_IS("abc", "=?UTF-8?Q?" "abc" "?=");
    HTTPT_QENCODING_IS("été", "=?UTF-8?Q?" "=C3=A9t=C3=A9" "?=");
    HTTPT_QENCODING_IS("foo bar\tbaz", "=?UTF-8?Q?" "foo=20bar=09baz" "?=");
    HTTPT_QENCODING_IS("=42??", "=?UTF-8?Q?" "=3D42=3F=3F" "?=");
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("ranges");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, media_types);
    TEST_RUN(suite, invalid_media_types);
    TEST_RUN(suite, q_encoding);

    test_suite_print_results_and_exit(suite);
}
