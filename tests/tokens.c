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
    char token[128];
    const char *str, *end;
    int ret;

#define HTTPT_NEXT_TOKEN_IS(str_)                                              \
    do {                                                                       \
        if (end)                                                               \
            str = end;                                                         \
                                                                               \
        ret = http_token_list_get_next_token(str, token, sizeof(token), &end); \
        if (ret == -1) {                                                       \
            HTTPT_DIE("%s:%d: cannot read next token: %s",                     \
                      __FILE__, __LINE__, http_get_error());                   \
        }                                                                      \
                                                                               \
        HTTPT_IS_EQUAL_STRING(token, str_);                                    \
    } while (0)

#define HTTPT_TOKEN_LIST_IS_READ() \
    do {                                                                       \
        if (end)                                                               \
            str = end;                                                         \
                                                                               \
        ret = http_token_list_get_next_token(str, token, sizeof(token), &end); \
        if (ret != 0) {                                                        \
            HTTPT_DIE("%s:%d: token list is not entirely read",                \
                      __FILE__, __LINE__);                                     \
        }                                                                      \
    } while (0)

    str = "a";
    end = NULL;
    HTTPT_NEXT_TOKEN_IS("a");
    HTTPT_TOKEN_LIST_IS_READ();

    str = "a, bc, def";
    end = NULL;
    HTTPT_NEXT_TOKEN_IS("a");
    HTTPT_NEXT_TOKEN_IS("bc");
    HTTPT_NEXT_TOKEN_IS("def");
    HTTPT_TOKEN_LIST_IS_READ();

    str = "  a ,bc,  def   , g";
    end = NULL;
    HTTPT_NEXT_TOKEN_IS("a");
    HTTPT_NEXT_TOKEN_IS("bc");
    HTTPT_NEXT_TOKEN_IS("def");
    HTTPT_NEXT_TOKEN_IS("g");
    HTTPT_TOKEN_LIST_IS_READ();

    str = ", a,, bc ,  ,, def,";
    end = NULL;
    HTTPT_NEXT_TOKEN_IS("a");
    HTTPT_NEXT_TOKEN_IS("bc");
    HTTPT_NEXT_TOKEN_IS("def");
    HTTPT_TOKEN_LIST_IS_READ();

    str = "foo;a=1, bar ;name=value , baz; name=\"a,b,c \\\"foo\\\"\" , truc";
    end = NULL;
    HTTPT_NEXT_TOKEN_IS("foo");
    HTTPT_NEXT_TOKEN_IS("bar");
    HTTPT_NEXT_TOKEN_IS("baz");
    HTTPT_NEXT_TOKEN_IS("truc");
    HTTPT_TOKEN_LIST_IS_READ();

    str = "foo;a=1;b=2, bar ;a=1; b=2 ,baz ; a=1  ;   b=2 , truc";
    end = NULL;
    HTTPT_NEXT_TOKEN_IS("foo");
    HTTPT_NEXT_TOKEN_IS("bar");
    HTTPT_NEXT_TOKEN_IS("baz");
    HTTPT_NEXT_TOKEN_IS("truc");
    HTTPT_TOKEN_LIST_IS_READ();

#define HTTPT_TOKEN_LIST_INVALID(str_) \
    do {                                                                        \
        ret = http_token_list_get_next_token(str_, token, sizeof(token), &end); \
        if (ret == 1) {                                                         \
            HTTPT_DIE("%s:%d: token read in invalid token list",                \
                      __FILE__, __LINE__);                                      \
        } else if (ret == 0) {                                                  \
            HTTPT_DIE("%s:%d: truncated list in invalid token list",            \
                      __FILE__, __LINE__);                                      \
        }                                                                       \
    } while (0)

    /* Invalid character */
    HTTPT_TOKEN_LIST_INVALID("[foo]");

    /* Invalid separator */
    HTTPT_TOKEN_LIST_INVALID("foo bar");
#undef HTTPT_TOKEN_LIST_INVALID

#undef HTTPT_NEXT_TOKEN_IS
#undef HTTPT_TOKEN_LIST_IS_READ
}
