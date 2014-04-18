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
    enum http_msg_type msg_type;
    bool skip_header_processing;

    http_cfg_init_server(&cfg);

    cfg.u.server.max_request_uri_length = 8;

    cfg.max_content_length = 48;
    cfg.max_chunk_length = 16;

    cfg.bufferize_body = true;

    msg_type = HTTP_MSG_REQUEST;
    skip_header_processing = false;

#define HTTPT_BEGIN(str_)                                       \
    do {                                                        \
        int ret;                                                \
                                                                \
        buf = bf_buffer_new(0);                                 \
        bf_buffer_add_string(buf, str_);                        \
                                                                \
        http_parser_init(&parser, msg_type, &cfg);              \
        parser.skip_header_processing = skip_header_processing; \
        msg = &parser.msg;                                      \
                                                                \
        ret = http_msg_parse(buf, &parser);                     \
        if (ret == -1) {                                        \
            HTTPT_DIE("%s:%d: cannot parse message: %s",        \
                      __FILE__, __LINE__, http_get_error());    \
        } else if (ret == 0) {                                  \
            HTTPT_DIE("%s:%d: truncated message",               \
                      __FILE__, __LINE__);                      \
        }                                                       \
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
        HTTPT_IS_EQUAL_STRING(msg->u.request.uri_string, uri_); \
        HTTPT_IS_EQUAL_INT(msg->version, version_);             \
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
    HTTPT_REQUEST_LINE("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
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
     *  Status lines
     * -------------------------------------------------------------------- */
#define HTTPT_STATUS_LINE(str_, status_code_, reason_phrase_, version_)       \
    do {                                                                      \
        HTTPT_BEGIN(str_);                                                    \
        HTTPT_IS_EQUAL_INT(msg->u.response.status_code, status_code_);        \
        HTTPT_IS_EQUAL_STRING(msg->u.response.reason_phrase, reason_phrase_); \
        HTTPT_IS_EQUAL_INT(msg->version, version_);                           \
        HTTPT_END();                                                          \
    } while (0)

#define HTTPT_INVALID_STATUS_LINE(str_)                         \
    do {                                                        \
        int ret;                                                \
                                                                \
        buf = bf_buffer_new(0);                                 \
        bf_buffer_add_string(buf, str_);                        \
                                                                \
        http_parser_init(&parser, msg_type, &cfg);              \
        parser.skip_header_processing = skip_header_processing; \
        msg = &parser.msg;                                      \
                                                                \
        ret = http_msg_parse(buf, &parser);                     \
        if (ret == 1) {                                         \
            HTTPT_DIE("%s:%d: parsed invalid message",          \
                      __FILE__, __LINE__);                      \
        } else if (ret == 0) {                                  \
            HTTPT_DIE("%s:%d: truncated message",               \
                      __FILE__, __LINE__);                      \
        }                                                       \
    } while (0)

    msg_type = HTTP_MSG_RESPONSE;

    HTTPT_STATUS_LINE("HTTP/1.0 200 OK\r\n\r\n",
                      HTTP_OK, "OK", HTTP_1_0);
    HTTPT_STATUS_LINE("HTTP/1.0 200 foo bar\tbaz\r\n\r\n",
                      HTTP_OK, "foo bar\tbaz", HTTP_1_0);
    HTTPT_STATUS_LINE("HTTP/1.0  200    foo bar\tbaz  \r\n\r\n",
                      HTTP_OK, "foo bar\tbaz  ", HTTP_1_0);

    /* Invalid version */
    HTTPT_INVALID_STATUS_LINE("HTTP 200 OK\r\n\r\n");
    HTTPT_INVALID_STATUS_LINE("HTTP/4.2 200 OK\r\n\r\n");
    HTTPT_INVALID_STATUS_LINE("HELLOWORLD 200 OK\r\n\r\n");

    /* Invalid status code */
    HTTPT_INVALID_STATUS_LINE("HTTP/1.0 200foo OK\r\n\r\n");
    HTTPT_INVALID_STATUS_LINE("HTTP/1.0 20x OK\r\n\r\n");
    HTTPT_INVALID_STATUS_LINE("HTTP/1.0 abc OK\r\n\r\n");

    /* Invalid reason phrase */
    HTTPT_INVALID_STATUS_LINE("HTTP/1.0 200\r\n\r\n");
    HTTPT_INVALID_STATUS_LINE("HTTP/1.0 200 \r\n\r\n");

#undef HTTP_STATUS_LINE
#undef HTTP_INVALID_STATUS_LINE

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

    msg_type = HTTP_MSG_REQUEST;

    cfg.max_header_name_length = 8;
    cfg.max_header_value_length = 20;

    skip_header_processing = true;

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


    cfg.max_header_name_length = 128;
    cfg.max_header_value_length = 4096;

#undef HTTPT_BEGIN_HEADERS
#undef HTTPT_INVALID_HEADER
#undef HTTPT_IS_EQUAL_HEADER

    /* --------------------------------------------------------------------
     *  Content-Disposition
     * -------------------------------------------------------------------- */
#define HTTPT_CONTENT_DISPOSITION_IS(header_, filename_)                     \
    do {                                                                     \
        char *filename;                                                      \
        int ret;                                                             \
                                                                             \
        HTTPT_BEGIN("POST / HTTP/1.0\r\n"                                    \
                    "Content-Length: 0\r\n"                                  \
                    "Content-Disposition: attachment; " header_ "\r\n"       \
                    "\r\n");                                                 \
        if (parser.status_code > 0) {                                        \
            HTTPT_DIE("%s:%d: invalid message: %s",                          \
                      __FILE__, __LINE__, parser.errmsg);                    \
        }                                                                    \
                                                                             \
        ret = http_msg_content_disposition_filename(msg, &filename);         \
        if (ret == -1) {                                                     \
            HTTPT_DIE("%s:%d: cannot read content disposition filename: %s", \
                      __FILE__, __LINE__, http_get_error());                 \
        } else if (ret == 0) {                                               \
            HTTPT_DIE("%s:%d: content disposition filename not found",       \
                      __FILE__, __LINE__);                                   \
        }                                                                    \
                                                                             \
        HTTPT_IS_EQUAL_STRING(filename, filename_);                          \
        http_free(filename);                                                 \
                                                                             \
        HTTPT_END();                                                         \
    } while (0)

    msg_type = HTTP_MSG_REQUEST;
    skip_header_processing = false;

    HTTPT_CONTENT_DISPOSITION_IS("filename=foo", "foo");

    HTTPT_CONTENT_DISPOSITION_IS("filename=\"\"", "");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"a b\"", "a b");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"a\\\"c\"", "a\"c");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"a\\\\c\"", "a\\c");

    HTTPT_CONTENT_DISPOSITION_IS("filename=\"../foo\"", "foo");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"../../foo\"", "foo");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"/home/user/foo\"", "foo");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"/home/foo/\"", "");

#undef HTTPT_CONTENT_DISPOSITION_IS

    /* --------------------------------------------------------------------
     *  Body
     * -------------------------------------------------------------------- */
#define HTTPT_BEGIN_BODY(str_)                                                \
    do {                                                                      \
        HTTPT_BEGIN("PUT / HTTP/1.0\r\nHost: localhost\r\n" str_);            \
                                                                              \
        if (parser.status_code > 0) {                                         \
            HTTPT_DIE("%s:%d: invalid message (%s): %s",                      \
                      __FILE__, __LINE__,                                     \
                      http_status_code_to_reason_phrase(parser.status_code),  \
                      parser.errmsg);                                         \
        }                                                                     \
    } while (0)

    msg_type = HTTP_MSG_REQUEST;
    skip_header_processing = false;

    HTTPT_BEGIN_BODY("Content-Length: 0\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 0);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "");
    HTTPT_END();

    HTTPT_BEGIN_BODY("Content-Length: 3\r\n\r\nfoo");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 3);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "foo");
    HTTPT_END();

    HTTPT_BEGIN_BODY("Content-Length: 8\r\n\r\nfoo\r\nbar");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 8);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "foo\r\nbar");
    HTTPT_END();

#undef HTTPT_BEGIN_BODY

    /* --------------------------------------------------------------------
     *  Chunks
     * -------------------------------------------------------------------- */
#define HTTPT_BEGIN_CHUNKS(str_)                                    \
    do {                                                            \
        HTTPT_BEGIN("PUT / HTTP/1.1\r\nHost: localhost\r\n"         \
                    "Transfer-Encoding: chunked\r\n\r\n"            \
                    str_);                                          \
                                                                    \
        if (parser.status_code > 0) {                               \
            HTTPT_DIE("%s:%d: invalid message: error %d (%s)",      \
                      __FILE__, __LINE__, parser.status_code,       \
                      parser.errmsg);                               \
        }                                                           \
    } while (0)

    HTTPT_BEGIN_CHUNKS("0\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 0);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("3\r\nfoo\r\n6\r\nfoobar\r\n0\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 9);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "foofoobar");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("a\r\nfoobar baz\r\n0\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 10);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "foobar baz");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("1;a=1\r\na\r\n1 ; a=1\r\nb\r\n0\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 2);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "ab");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("1;a=\"foo\"\r\na\r\n1 ; a=\"\"\r\nb\r\n0\r\n\r\n");
    HTTPT_IS_EQUAL_UINT(http_msg_body_length(msg), 2);
    HTTPT_IS_EQUAL_STRING(http_msg_body(msg), "ab");
    HTTPT_END();

#undef HTTPT_BEGIN_CHUNKS

#define HTTPT_INVALID_CHUNKS(str_, status_code_)                       \
    do {                                                               \
        HTTPT_BEGIN("PUT / HTTP/1.1\r\nHost: localhost\r\n"            \
                    "Transfer-Encoding: chunked\r\n\r\n"               \
                    str_);                                             \
                                                                       \
        if (parser.status_code != status_code_) {                      \
            HTTPT_DIE("%s:%d: wrong http error %d (%s) instead of %d", \
                      __FILE__, __LINE__, parser.status_code,          \
                      parser.errmsg, status_code_);                    \
        }                                                              \
                                                                       \
        HTTPT_END();                                                   \
    } while (0)

    /* Invalid length */
    HTTPT_INVALID_CHUNKS("\r\nfoo\r\n0\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_CHUNKS("g3\r\nfoo\r\n0\r\n\r\n", HTTP_BAD_REQUEST);

    /* Chunk too large */
    HTTPT_INVALID_CHUNKS("11\r\nabcdefghijklmnopq\r\n0\r\n\r\n",
                         HTTP_REQUEST_ENTITY_TOO_LARGE);

#undef HTTPT_INVALID_CHUNKS

#undef HTTPT_BEGIN
#undef HTTPT_END

    http_cfg_free(&cfg);
    return 0;
}
