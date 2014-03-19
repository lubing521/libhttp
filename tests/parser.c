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

#include <buffer.h>

#include "http.h"
#include "internal.h"

#include "tests.h"

int
main(int argc, char **argv) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

    cfg = http_default_cfg;
    cfg.u.server.max_request_uri_length = 8;
    cfg.max_header_name_length = 8;
    cfg.max_header_value_length = 20;

#define HTTPT_BEGIN(str_)                                    \
    do {                                                     \
        int ret;                                             \
                                                             \
        buf = bf_buffer_new(0);                              \
        bf_buffer_add_string(buf, str_);                     \
                                                             \
        http_parser_init(&parser, HTTP_MSG_REQUEST, &cfg);   \
        msg = &parser.msg;                                   \
                                                             \
        ret = http_msg_parse(buf, &parser);                  \
        if (ret == -1) {                                     \
            HTTPT_DIE("%s:%d: cannot parse message: %s",     \
                      __FILE__, __LINE__, http_get_error()); \
        } else if (ret == 0) {                               \
            HTTPT_DIE("%s:%d: truncated message",            \
                      __FILE__, __LINE__);                   \
        }                                                    \
    } while (0)


#define HTTPT_END(str_)            \
    do {                           \
        http_parser_free(&parser); \
        bf_buffer_delete(buf);     \
    } while (0)

    /* --------------------------------------------------------------------
     *  Request lines
     * -------------------------------------------------------------------- */
#define HTTPT_REQUEST_LINE(str_, method_, uri_, version_)       \
    do {                                                        \
        HTTPT_BEGIN(str_);                                      \
        HTTPT_IS_EQUAL_INT(msg->u.request.method, method_);     \
        HTTPT_IS_EQUAL_STRING(msg->u.request.uri, uri_);        \
        HTTPT_IS_EQUAL_INT(msg->u.request.version, version_);   \
        HTTPT_END();                                            \
    } while (0)

#define HTTPT_INVALID_REQUEST_LINE(str_, status_code_)         \
    do {                                                       \
        HTTPT_BEGIN(str_);                                     \
        HTTPT_IS_EQUAL_INT(parser.status_code, status_code_);  \
        HTTPT_END();                                           \
    } while (0)

    HTTPT_REQUEST_LINE("GET / HTTP/1.0\r\n\r\n",
                       HTTP_GET, "/", HTTP_1_0);
    HTTPT_REQUEST_LINE("POST / HTTP/1.1\r\n\r\n",
                       HTTP_POST, "/", HTTP_1_1);
    HTTPT_REQUEST_LINE("GET   /  HTTP/1.0\r\n\r\n",
                       HTTP_GET, "/", HTTP_1_0);
    HTTPT_REQUEST_LINE("GET /foo HTTP/1.0\r\n\r\n",
                       HTTP_GET, "/foo", HTTP_1_0);

    /* Invalid method */
    HTTPT_INVALID_REQUEST_LINE("G\r / HTTP/1.0\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_REQUEST_LINE("a.b / HTTP/1.0\r\n\r\n", HTTP_NOT_IMPLEMENTED);
    HTTPT_INVALID_REQUEST_LINE("FOO / HTTP/1.0\r\n\r\n", HTTP_NOT_IMPLEMENTED);
    HTTPT_INVALID_REQUEST_LINE("FOOBARBAZ", HTTP_NOT_IMPLEMENTED);

    /* Invalid URI */
    HTTPT_INVALID_REQUEST_LINE("GET HTTP/1.0\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_REQUEST_LINE("GET /\r HTTP/1.0\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_REQUEST_LINE("GET /abcdefgh HTTP/1.0\r\n\r\n",
                               HTTP_REQUEST_URI_TOO_LONG);
    HTTPT_INVALID_REQUEST_LINE("GET /abcdefgh", HTTP_REQUEST_URI_TOO_LONG);

    /* Invalid version */
    HTTPT_INVALID_REQUEST_LINE("GET / \r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_REQUEST_LINE("GET / 42\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_REQUEST_LINE("GET / HTTP/4.2\r\n\r\n",
                               HTTP_HTTP_VERSION_NOT_SUPPORTED);
    HTTPT_INVALID_REQUEST_LINE("GET / HELLOWORD",
                               HTTP_HTTP_VERSION_NOT_SUPPORTED);

#undef HTTPT_REQUEST_LINE
#undef HTTPT_INVALID_REQUEST_LINE

    /* --------------------------------------------------------------------
     *  Headers
     * -------------------------------------------------------------------- */
#define HTTPT_BEGIN_HEADERS(str_)                  \
    do {                                           \
        HTTPT_BEGIN("GET / HTTP/1.1\r\n" str_);    \
        HTTPT_IS_EQUAL_INT(parser.status_code, 0); \
    } while (0)

#define HTTPT_INVALID_HEADER(str_, status_code_)               \
    do {                                                       \
        HTTPT_BEGIN("GET / HTTP/1.1\r\n" str_);                \
        HTTPT_IS_EQUAL_INT(parser.status_code, status_code_);  \
        HTTPT_END();                                           \
    } while (0)

#define HTTPT_IS_EQUAL_HEADER(idx_, name_, value_)               \
    do {                                                         \
        HTTPT_IS_EQUAL_STRING(msg->headers[idx_].name, name_);   \
        HTTPT_IS_EQUAL_STRING(msg->headers[idx_].value, value_); \
    } while (0)

    HTTPT_BEGIN_HEADERS("Foo: bar\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(msg->nb_headers, 1);
    HTTPT_IS_EQUAL_HEADER(0, "Foo", "bar");
    HTTPT_END();

    HTTPT_BEGIN_HEADERS("Key1: foo\r\nKey2: bar\r\nKey3: he llo\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(msg->nb_headers, 3);
    HTTPT_IS_EQUAL_HEADER(0, "Key1", "foo");
    HTTPT_IS_EQUAL_HEADER(1, "Key2", "bar");
    HTTPT_IS_EQUAL_HEADER(2, "Key3", "he llo");
    HTTPT_END();

    HTTPT_BEGIN_HEADERS("Key1:  foo  \r\nKey2:  he  llo \r\n\r\n");
    HTTPT_IS_EQUAL_UINT(msg->nb_headers, 2);
    HTTPT_IS_EQUAL_HEADER(0, "Key1", "foo");
    HTTPT_IS_EQUAL_HEADER(1, "Key2", "he  llo");
    HTTPT_END();

    HTTPT_BEGIN_HEADERS("Key1: one\r\n\the\t \r\n \tllo\r\nKey2: foo\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(msg->nb_headers, 2);
    HTTPT_IS_EQUAL_HEADER(0, "Key1", "one he llo");
    HTTPT_IS_EQUAL_HEADER(1, "Key2", "foo");
    HTTPT_END();

    /* Invalid header name */
    HTTPT_INVALID_HEADER("Key/: foo\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_HEADER("[Key]: foo\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_HEADER("Key\r\n: foo\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_HEADER("ALargeKey: foo\r\n\r\n",
                         HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
    HTTPT_INVALID_HEADER("ALargeKey", HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);

    /* Invalid separator */
    HTTPT_INVALID_HEADER("Key foo\r\n\r\n", HTTP_BAD_REQUEST);

    /* Invalid header value */
    HTTPT_INVALID_HEADER("Key: AVeryLargeValueABCDEF\r\n\r\n",
                         HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
    HTTPT_INVALID_HEADER("Key: AVeryLargeValueABCDEF",
                         HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);

#undef HTTPT_BEGIN_HEADERS
#undef HTTPT_INVALID_HEADER
#undef HTTPT_IS_EQUAL_HEADER

#undef HTTPT_BEGIN
#undef HTTPT_END

    return 0;
}
