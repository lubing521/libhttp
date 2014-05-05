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

#define HTTPT_BEGIN(str_, msg_type_, skip_header_processing_)         \
    do {                                                              \
        int ret;                                                      \
                                                                      \
        buf = bf_buffer_new(0);                                       \
        bf_buffer_add_string(buf, str_);                              \
                                                                      \
        http_parser_init(&parser, msg_type_, &cfg);                   \
        parser.skip_header_processing = skip_header_processing_;      \
        msg = &parser.msg;                                            \
                                                                      \
        ret = http_msg_parse(buf, &parser);                           \
        if (ret == -1) {                                              \
            TEST_ABORT("cannot parse message: %s", http_get_error()); \
        } else if (ret == 0) {                                        \
            TEST_ABORT("truncated message");                          \
        }                                                             \
    } while (0)

#define HTTPT_END(str_)            \
    do {                           \
        http_parser_free(&parser); \
        bf_buffer_delete(buf);     \
    } while (0)

TEST(request_lines) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_REQUEST_LINE(str_, method_, uri_, version_) \
    do {                                                  \
        HTTPT_BEGIN(str_, HTTP_MSG_REQUEST, false);       \
        TEST_INT_EQ(msg->u.request.method, method_);      \
        TEST_STRING_EQ(msg->u.request.uri_string, uri_);  \
        TEST_INT_EQ(msg->version, version_);              \
        HTTPT_END();                                      \
    } while (0)

#define HTTPT_INVALID_REQUEST_LINE(str_, status_code_)         \
    do {                                                       \
        HTTPT_BEGIN(str_, HTTP_MSG_REQUEST, false);            \
        TEST_INT_EQ(parser.status_code, status_code_);         \
        HTTPT_END();                                           \
    } while (0)

    http_cfg_init_server(&cfg);

    cfg.u.server.max_request_uri_length = 8;

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

    http_cfg_free(&cfg);
}

TEST(status_lines) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_STATUS_LINE(str_, status_code_, reason_phrase_, version_) \
    do {                                                                \
        HTTPT_BEGIN(str_, HTTP_MSG_RESPONSE, false);                    \
        TEST_INT_EQ(msg->u.response.status_code, status_code_);         \
        TEST_STRING_EQ(msg->u.response.reason_phrase, reason_phrase_);  \
        TEST_INT_EQ(msg->version, version_);                            \
        HTTPT_END();                                                    \
    } while (0)

#define HTTPT_INVALID_STATUS_LINE(str_)                         \
    do {                                                        \
        int ret;                                                \
                                                                \
        buf = bf_buffer_new(0);                                 \
        bf_buffer_add_string(buf, str_);                        \
                                                                \
        http_parser_init(&parser, HTTP_MSG_RESPONSE, &cfg);     \
        msg = &parser.msg;                                      \
                                                                \
        ret = http_msg_parse(buf, &parser);                     \
        if (ret == 1) {                                         \
            TEST_ABORT("parsed invalid message");               \
        } else if (ret == 0) {                                  \
            TEST_ABORT("truncated message");                    \
        }                                                       \
                                                                \
        http_parser_free(&parser);                              \
        bf_buffer_delete(buf);                                  \
    } while (0)

    http_cfg_init_client(&cfg);

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

    http_cfg_free(&cfg);
}

TEST(headers) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_BEGIN_HEADERS(str_)                                       \
    do {                                                                \
        HTTPT_BEGIN("GET / HTTP/1.1\r\n" str_, HTTP_MSG_REQUEST, true); \
        TEST_INT_EQ(parser.status_code, 0);                             \
    } while (0)

#define HTTPT_INVALID_HEADER(str_, status_code_)                        \
    do {                                                                \
        HTTPT_BEGIN("GET / HTTP/1.1\r\n" str_, HTTP_MSG_REQUEST, true); \
        TEST_INT_EQ(parser.status_code, status_code_);                  \
        HTTPT_END();                                                    \
    } while (0)

#define HTTPT_IS_EQUAL_HEADER(idx_, name_, value_)        \
    do {                                                  \
        TEST_STRING_EQ(msg->headers[idx_].name, name_);   \
        TEST_STRING_EQ(msg->headers[idx_].value, value_); \
    } while (0)

    http_cfg_init_server(&cfg);

    cfg.max_header_name_length = 8;
    cfg.max_header_value_length = 20;

    HTTPT_BEGIN_HEADERS("Foo: bar\r\n\r\n");
    TEST_UINT_EQ(msg->nb_headers, 1);
    HTTPT_IS_EQUAL_HEADER(0, "Foo", "bar");
    HTTPT_END();

    HTTPT_BEGIN_HEADERS("Key1: foo\r\nKey2: bar\r\nKey3: he llo\r\n\r\n");
    TEST_UINT_EQ(msg->nb_headers, 3);
    HTTPT_IS_EQUAL_HEADER(0, "Key1", "foo");
    HTTPT_IS_EQUAL_HEADER(1, "Key2", "bar");
    HTTPT_IS_EQUAL_HEADER(2, "Key3", "he llo");
    HTTPT_END();

    HTTPT_BEGIN_HEADERS("Key1:  foo  \r\nKey2:  he  llo \r\n\r\n");
    TEST_UINT_EQ(msg->nb_headers, 2);
    HTTPT_IS_EQUAL_HEADER(0, "Key1", "foo");
    HTTPT_IS_EQUAL_HEADER(1, "Key2", "he  llo");
    HTTPT_END();

    HTTPT_BEGIN_HEADERS("Key1: one\r\n\the\t \r\n \tllo\r\nKey2: foo\r\n\r\n");
    TEST_UINT_EQ(msg->nb_headers, 2);
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

    http_cfg_free(&cfg);
}

TEST(content_disposition) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_CONTENT_DISPOSITION_IS(header_, filename_)               \
    do {                                                               \
        char *filename;                                                \
        int ret;                                                       \
                                                                       \
        HTTPT_BEGIN("POST / HTTP/1.0\r\n"                              \
                    "Content-Length: 0\r\n"                            \
                    "Content-Disposition: attachment; " header_ "\r\n" \
                    "\r\n",                                            \
                    HTTP_MSG_REQUEST, false);                          \
        if (parser.status_code > 0)                                    \
            TEST_ABORT("invalid message: %s", parser.errmsg);          \
                                                                       \
        ret = http_msg_content_disposition_filename(msg, &filename);   \
        if (ret == -1) {                                               \
            TEST_ABORT("cannot read content disposition filename: %s", \
                       http_get_error());                              \
        } else if (ret == 0) {                                         \
            TEST_ABORT("content disposition filename not found");      \
        }                                                              \
                                                                       \
        TEST_STRING_EQ(filename, filename_);                           \
        http_free(filename);                                           \
                                                                       \
        HTTPT_END();                                                   \
    } while (0)

    http_cfg_init_server(&cfg);

    HTTPT_CONTENT_DISPOSITION_IS("filename=foo", "foo");

    HTTPT_CONTENT_DISPOSITION_IS("filename=\"\"", "");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"a b\"", "a b");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"a\\\"c\"", "a\"c");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"a\\\\c\"", "a\\c");

    HTTPT_CONTENT_DISPOSITION_IS("filename=\"../foo\"", "foo");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"../../foo\"", "foo");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"/home/user/foo\"", "foo");
    HTTPT_CONTENT_DISPOSITION_IS("filename=\"/home/foo/\"", "");

    http_cfg_free(&cfg);
}

TEST(body) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_BEGIN_BODY(str_)                                                \
    do {                                                                      \
        HTTPT_BEGIN("PUT / HTTP/1.0\r\nHost: localhost\r\n" str_,             \
                    HTTP_MSG_REQUEST, false);                                 \
                                                                              \
        if (parser.status_code > 0) {                                         \
            TEST_ABORT("invalid message (%s): %s",                            \
                      http_status_code_to_reason_phrase(parser.status_code),  \
                      parser.errmsg);                                         \
        }                                                                     \
    } while (0)

    http_cfg_init_server(&cfg);

    HTTPT_BEGIN_BODY("Content-Length: 0\r\n\r\n");
    TEST_UINT_EQ(http_msg_body_length(msg), 0);
    TEST_STRING_EQ(http_msg_body(msg), "");
    HTTPT_END();

    HTTPT_BEGIN_BODY("Content-Length: 3\r\n\r\nfoo");
    TEST_UINT_EQ(http_msg_body_length(msg), 3);
    TEST_STRING_EQ(http_msg_body(msg), "foo");
    HTTPT_END();

    HTTPT_BEGIN_BODY("Content-Length: 8\r\n\r\nfoo\r\nbar");
    TEST_UINT_EQ(http_msg_body_length(msg), 8);
    TEST_STRING_EQ(http_msg_body(msg), "foo\r\nbar");
    HTTPT_END();

    http_cfg_free(&cfg);
}

TEST(chunks) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_BEGIN_CHUNKS(str_)                               \
    do {                                                       \
        HTTPT_BEGIN("PUT / HTTP/1.1\r\nHost: localhost\r\n"    \
                    "Transfer-Encoding: chunked\r\n\r\n" str_, \
                    HTTP_MSG_REQUEST, false);                  \
                                                               \
        if (parser.status_code > 0) {                          \
            TEST_ABORT("invalid message: error %d (%s)",       \
                      parser.status_code, parser.errmsg);      \
        }                                                      \
    } while (0)

    http_cfg_init_server(&cfg);

    HTTPT_BEGIN_CHUNKS("0\r\n\r\n");
    TEST_UINT_EQ(http_msg_body_length(msg), 0);
    TEST_STRING_EQ(http_msg_body(msg), "");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("3\r\nfoo\r\n6\r\nfoobar\r\n0\r\n\r\n");
    TEST_UINT_EQ(http_msg_body_length(msg), 9);
    TEST_STRING_EQ(http_msg_body(msg), "foofoobar");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("a\r\nfoobar baz\r\n0\r\n\r\n");
    TEST_UINT_EQ(http_msg_body_length(msg), 10);
    TEST_STRING_EQ(http_msg_body(msg), "foobar baz");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("1;a=1\r\na\r\n1 ; a=1\r\nb\r\n0\r\n\r\n");
    TEST_UINT_EQ(http_msg_body_length(msg), 2);
    TEST_STRING_EQ(http_msg_body(msg), "ab");
    HTTPT_END();

    HTTPT_BEGIN_CHUNKS("1;a=\"foo\"\r\na\r\n1 ; a=\"\"\r\nb\r\n0\r\n\r\n");
    TEST_UINT_EQ(http_msg_body_length(msg), 2);
    TEST_STRING_EQ(http_msg_body(msg), "ab");
    HTTPT_END();

    http_cfg_free(&cfg);
}

TEST(invalid_chunks) {
    struct bf_buffer *buf;
    struct http_cfg cfg;
    struct http_parser parser;
    struct http_msg *msg;

#define HTTPT_INVALID_CHUNKS(str_, status_code_)                        \
    do {                                                                \
        HTTPT_BEGIN("PUT / HTTP/1.1\r\nHost: localhost\r\n"             \
                    "Transfer-Encoding: chunked\r\n\r\n" str_,          \
                    HTTP_MSG_REQUEST, false);                           \
                                                                        \
        if (parser.status_code != status_code_) {                       \
            TEST_ABORT("wrong http error %d (%s) instead of %d",        \
                      parser.status_code, parser.errmsg, status_code_); \
        }                                                               \
                                                                        \
        HTTPT_END();                                                    \
    } while (0)

    http_cfg_init_server(&cfg);

    cfg.max_chunk_length = 16;

    /* Invalid length */
    HTTPT_INVALID_CHUNKS("\r\nfoo\r\n0\r\n\r\n", HTTP_BAD_REQUEST);
    HTTPT_INVALID_CHUNKS("g3\r\nfoo\r\n0\r\n\r\n", HTTP_BAD_REQUEST);

    /* Chunk too large */
    HTTPT_INVALID_CHUNKS("11\r\nabcdefghijklmnopq\r\n0\r\n\r\n",
                         HTTP_REQUEST_ENTITY_TOO_LARGE);

    http_cfg_free(&cfg);
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("messages");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, request_lines);
    TEST_RUN(suite, status_lines);
    TEST_RUN(suite, headers);
    TEST_RUN(suite, content_disposition);
    TEST_RUN(suite, body);
    TEST_RUN(suite, chunks);
    TEST_RUN(suite, invalid_chunks);

    test_suite_print_results_and_exit(suite);
}
