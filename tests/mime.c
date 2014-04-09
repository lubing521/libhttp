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
    struct http_media_type *media_type;

#define HTTPT_BEGIN(str_)                                       \
    do {                                                        \
        media_type = http_media_type_new(str_);                 \
        if (!media_type) {                                      \
            HTTPT_DIE("%s:%d: cannot parse media type: %s",     \
                      __FILE__, __LINE__, http_get_error());    \
        }                                                       \
    } while (0)

#define HTTPT_END(str_)                     \
    do {                                    \
        http_media_type_delete(media_type); \
    } while (0)

#define HTTPT_MEDIA_TYPE_PARAMETER_IS(name_, value_)                            \
    do {                                                                        \
        HTTPT_IS_TRUE(http_media_type_has_parameter(media_type, name_));        \
        HTTPT_IS_EQUAL_STRING(http_media_type_get_parameter(media_type, name_), \
                              value_);                                          \
    } while (0)

    HTTPT_BEGIN("text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_string(media_type), "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_base_string(media_type),
                          "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_type(media_type), "text");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_subtype(media_type), "plain");
    HTTPT_END();

    HTTPT_BEGIN("Text/PLAIn");
    HTTPT_IS_EQUAL_STRING(http_media_type_string(media_type), "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_base_string(media_type),
                          "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_type(media_type), "text");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_subtype(media_type), "plain");
    HTTPT_END();

    HTTPT_BEGIN("text/plain; charset=UTF-8");
    HTTPT_IS_EQUAL_STRING(http_media_type_string(media_type),
                          "text/plain; charset=UTF-8");
    HTTPT_IS_EQUAL_STRING(http_media_type_base_string(media_type),
                          "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_type(media_type), "text");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("charset", "UTF-8");
    HTTPT_END();

    HTTPT_BEGIN("text/plain ;CHarsET=UTF-8");
    HTTPT_IS_EQUAL_STRING(http_media_type_string(media_type),
                          "text/plain; charset=UTF-8");
    HTTPT_IS_EQUAL_STRING(http_media_type_base_string(media_type),
                          "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_type(media_type), "text");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("charset", "UTF-8");
    HTTPT_END();

    HTTPT_BEGIN("text/plain;a=1; b=2  ;c=3   ;  d=4");
    HTTPT_IS_EQUAL_STRING(http_media_type_string(media_type),
                          "text/plain; a=1; b=2; c=3; d=4");
    HTTPT_IS_EQUAL_STRING(http_media_type_base_string(media_type),
                          "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_type(media_type), "text");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("a", "1");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("b", "2");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("c", "3");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("d", "4");
    HTTPT_END();

    HTTPT_BEGIN("text/plain; a=foo; b=\"foo\"; c=\"\\\"foo\\\"\"");
    HTTPT_IS_EQUAL_STRING(http_media_type_string(media_type),
                          "text/plain; a=foo; b=foo; c=\"\\\"foo\\\"\"");
    HTTPT_IS_EQUAL_STRING(http_media_type_base_string(media_type),
                          "text/plain");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_type(media_type), "text");
    HTTPT_IS_EQUAL_STRING(http_media_type_get_subtype(media_type), "plain");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("a", "foo");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("b", "foo");
    HTTPT_MEDIA_TYPE_PARAMETER_IS("c", "\"foo\"");
    HTTPT_END();

#define HTTPT_INVALID_MEDIA_TYPE(str_)                    \
    do {                                                  \
        media_type = http_media_type_new(str_);           \
        if (media_type) {                                 \
            HTTPT_DIE("%s:%d: parsed invalid media type", \
                      __FILE__, __LINE__);                \
        }                                                 \
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

#undef HTTPT_INVALID_MEDIA_TYPE

#undef HTTPT_BEGIN
#undef HTTPT_END
#undef HTTPT_MEDIA_TYPE_PARAMETER_IS

    return 0;
}

