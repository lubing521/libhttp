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

#define HTTPT_NEXT_TOKEN()                                                     \
    do {                                                                       \
        if (end)                                                               \
            str = end;                                                         \
        ret = http_token_list_get_next_token(str, token, sizeof(token), &end); \
    } while (0)

    str = "a";
    end = NULL;
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "a");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 0);

    str = "a, bc, def";
    end = NULL;
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "a");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "bc");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "def");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 0);

    str = "  a ,bc,  def   , g";
    end = NULL;
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "a");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "bc");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "def");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "g");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 0);

    str = ", a,, bc ,  ,, def,";
    end = NULL;
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "a");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "bc");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 1);
    HTTPT_IS_EQUAL_STRING(token, "def");
    HTTPT_NEXT_TOKEN();
    HTTPT_IS_EQUAL_INT(ret, 0);

#define HTTPT_TOKEN_LIST_INVALID(str_) \
    do {                               \
        str = str_;                    \
        end = NULL;                    \
        HTTPT_NEXT_TOKEN();            \
        HTTPT_IS_EQUAL_INT(ret, -1);   \
    } while (0)

    /* Invalid character */
    HTTPT_TOKEN_LIST_INVALID("[foo]");

    /* Invalid separator */
    HTTPT_TOKEN_LIST_INVALID("foo bar");
#undef HTTPT_TOKEN_LIST_INVALID

#undef HTTPT_NEXT_TOKEN
}
