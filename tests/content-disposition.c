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
#define HTTPT_CONTENT_DISPOSITION_IS(filename_, header_)                \
    do {                                                                \
        char *header;                                                   \
                                                                        \
        header = http_format_content_disposition_attachment(filename_); \
        HTTPT_IS_EQUAL_STRING(header, header_);                         \
        http_free(header);                                              \
    } while (0)

    HTTPT_CONTENT_DISPOSITION_IS("",
                                 "attachment; filename=\"\"");
    HTTPT_CONTENT_DISPOSITION_IS("foo.png",
                                 "attachment; filename=\"foo.png\"");
    HTTPT_CONTENT_DISPOSITION_IS("\"foo.png\"",
                                 "attachment; filename=\"\\\"foo.png\\\"\"");
    HTTPT_CONTENT_DISPOSITION_IS("foo\\bar",
                                 "attachment; filename=\"foo\\\\bar\"");

#undef HTTPT_CONTENT_DISPOSITION_IS

    return 0;
}
