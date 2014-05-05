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
#define HTTPT_CONTENT_DISPOSITION_IS(filename_, header_)                \
    do {                                                                \
        char *header;                                                   \
                                                                        \
        header = http_format_content_disposition_attachment(filename_); \
        TEST_STRING_EQ(header, header_);                                \
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
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("content-disposition");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);

    test_suite_print_results_and_exit(suite);
}
