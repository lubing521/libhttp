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
    struct http_uri *uri;

#define HTTPT_BEGIN(str_)                                         \
    do {                                                          \
        uri = http_uri_new(str_);                                 \
        if (!uri)                                                 \
            TEST_ABORT("cannot parse uri: %s", http_get_error()); \
    } while (0)

#define HTTPT_END() \
    http_uri_delete(uri);

    HTTPT_BEGIN("/");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("/foo/bar");
    TEST_STRING_EQ(uri->path, "/foo/bar");
    HTTPT_END();

    HTTPT_BEGIN("/foo/bar?a=1&b=2");
    TEST_STRING_EQ(uri->path, "/foo/bar");
    TEST_TRUE(http_uri_has_query_parameter(uri, "a"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "a"), "1");
    TEST_TRUE(http_uri_has_query_parameter(uri, "b"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "b"), "2");
    HTTPT_END();

    HTTPT_BEGIN("http://127.0.0.1");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "127.0.0.1");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://127.0.0.1:443");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "127.0.0.1");
    TEST_STRING_EQ(uri->port, "443");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://[::1]");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "::1");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://[::1]:443");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "::1");
    TEST_STRING_EQ(uri->path, "/");
    TEST_STRING_EQ(uri->port, "443");
    HTTPT_END();

    HTTPT_BEGIN("http://[fe80::1e6f:65ff:EA21:A373]:443");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "fe80::1e6f:65ff:EA21:A373");
    TEST_STRING_EQ(uri->path, "/");
    TEST_STRING_EQ(uri->port, "443");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com:8080");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->port, "8080");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/#foo");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/");
    TEST_STRING_EQ(uri->fragment, "foo");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com#foo");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/");
    TEST_STRING_EQ(uri->fragment, "foo");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com:8080/");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->port, "8080");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://foo@example.com");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->user, "foo");
    TEST_STRING_EQ(uri->host, "example.com");
    HTTPT_END();

    HTTPT_BEGIN("http://foo:bar@example.com");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->user, "foo");
    TEST_STRING_EQ(uri->password, "bar");
    TEST_STRING_EQ(uri->host, "example.com");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/a/b/c");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/a/b/c");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/?a=1&b=2");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/");
    TEST_TRUE(http_uri_has_query_parameter(uri, "a"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "a"), "1");
    TEST_TRUE(http_uri_has_query_parameter(uri, "b"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "b"), "2");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/a/b/c?a=1&b=2");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/a/b/c");
    TEST_TRUE(http_uri_has_query_parameter(uri, "a"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "a"), "1");
    TEST_TRUE(http_uri_has_query_parameter(uri, "b"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "b"), "2");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/a/b/c?a=1&b=2#foo");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/a/b/c");
    TEST_TRUE(http_uri_has_query_parameter(uri, "a"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "a"), "1");
    TEST_TRUE(http_uri_has_query_parameter(uri, "b"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "b"), "2");
    TEST_STRING_EQ(uri->fragment, "foo");
    HTTPT_END();

    HTTPT_BEGIN("http://foo:bar@example.com:8080/path?a=1&b=2");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->user, "foo");
    TEST_STRING_EQ(uri->password, "bar");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->port, "8080");
    TEST_STRING_EQ(uri->path, "/path");
    TEST_TRUE(http_uri_has_query_parameter(uri, "a"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "a"), "1");
    TEST_TRUE(http_uri_has_query_parameter(uri, "b"));
    TEST_STRING_EQ(http_uri_query_parameter(uri, "b"), "2");
    HTTPT_END();

    HTTPT_BEGIN("%68%74%74%70://%65%78%61%6d%70%6c%65.%63%6f%6D");
    TEST_STRING_EQ(uri->scheme, "http");
    TEST_STRING_EQ(uri->host, "example.com");
    TEST_STRING_EQ(uri->path, "/");
    HTTPT_END();
}

TEST(invalid) {
#define HTTPT_INVALID_URI(str_)                                         \
    do {                                                                \
        struct http_uri *uri;                                           \
                                                                        \
        uri = http_uri_new(str_);                                       \
        if (uri)                                                        \
            TEST_ABORT("parsed invalid uri");                           \
    } while (0)

    /* Invalid string */
    HTTPT_INVALID_URI("");
    HTTPT_INVALID_URI("http");

    /* Invalid scheme */
    HTTPT_INVALID_URI("42foo://example.com");
    HTTPT_INVALID_URI("foo#bar://example.com");
    HTTPT_INVALID_URI("://example.com");
    HTTPT_INVALID_URI("http:/example.com");
    HTTPT_INVALID_URI("http//example.com");

    /* Invalid user */
    HTTPT_INVALID_URI("http://@bar:example.com");

    /* Invalid password */
    HTTPT_INVALID_URI("http://foo:@example.com");

    /* Invalid host */
    HTTPT_INVALID_URI("http:///");
    HTTPT_INVALID_URI("http://foo@/");

    /* Invalid numeric address */
    HTTPT_INVALID_URI("http://2foo.com");
    HTTPT_INVALID_URI("http://[foo.com]");

    /* Invalid port */
    HTTPT_INVALID_URI("http://example.com:");
    HTTPT_INVALID_URI("http://example.com:/");
    HTTPT_INVALID_URI("http://example.com:?a=1&b=2");

    /* Invalid escape sequence */
    HTTPT_INVALID_URI("%6ttp://example.com");
    HTTPT_INVALID_URI("http://example.co%");
    HTTPT_INVALID_URI("http://example.co%6");
    HTTPT_INVALID_URI("http://example.co%g");
}

TEST(query) {
    struct http_query_parameter *parameters;
    size_t nb_parameters;

#define HTTPT_BEGIN_QUERY(str_)                                               \
    do {                                                                      \
        if (http_query_parameters_parse(str_,                                 \
                                        &parameters, &nb_parameters) == -1) { \
            TEST_ABORT("cannot parse query: %s", http_get_error());           \
        }                                                                     \
    } while (0)

#define HTTPT_END_QUERY()                              \
    do {                                               \
        for (size_t i = 0; i < nb_parameters; i++)     \
            http_query_parameter_free(parameters + i); \
        http_free(parameters);                         \
    } while (0)

    HTTPT_BEGIN_QUERY("");
    TEST_UINT_EQ(nb_parameters, 0);
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("a");
    TEST_UINT_EQ(nb_parameters, 1);
    TEST_STRING_EQ(parameters[0].name, "a");
    TEST_PTR_NULL(parameters[0].value);
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("foo");
    TEST_UINT_EQ(nb_parameters, 1);
    TEST_STRING_EQ(parameters[0].name, "foo");
    TEST_PTR_NULL(parameters[0].value);
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("foo=bar");
    TEST_UINT_EQ(nb_parameters, 1);
    TEST_STRING_EQ(parameters[0].name, "foo");
    TEST_STRING_EQ(parameters[0].value, "bar");
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("a=1&b=2");
    TEST_UINT_EQ(nb_parameters, 2);
    TEST_STRING_EQ(parameters[0].name, "a");
    TEST_STRING_EQ(parameters[0].value, "1");
    TEST_STRING_EQ(parameters[1].name, "b");
    TEST_STRING_EQ(parameters[1].value, "2");
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("a&b=2;c&d=3");
    TEST_UINT_EQ(nb_parameters, 4);
    TEST_STRING_EQ(parameters[0].name, "a");
    TEST_PTR_NULL(parameters[0].value);
    TEST_STRING_EQ(parameters[1].name, "b");
    TEST_STRING_EQ(parameters[1].value, "2");
    TEST_STRING_EQ(parameters[2].name, "c");
    TEST_PTR_NULL(parameters[2].value);
    TEST_STRING_EQ(parameters[3].name, "d");
    TEST_STRING_EQ(parameters[3].value, "3");
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("a+b+=%20%c3%a9tat");
    TEST_UINT_EQ(nb_parameters, 1);
    TEST_STRING_EQ(parameters[0].name, "a b ");
    TEST_STRING_EQ(parameters[0].value, " état");
    HTTPT_END_QUERY();

    HTTPT_BEGIN_QUERY("%3d=%20%26&%3b=++");
    TEST_UINT_EQ(nb_parameters, 2);
    TEST_STRING_EQ(parameters[0].name, "=");
    TEST_STRING_EQ(parameters[0].value, " &");
    TEST_STRING_EQ(parameters[1].name, ";");
    TEST_STRING_EQ(parameters[1].value, "  ");
    HTTPT_END_QUERY();
}

TEST(invalid_query) {
#define HTTPT_INVALID_QUERY(str_)                                             \
    do {                                                                      \
        struct http_query_parameter *parameters;                              \
        size_t nb_parameters;                                                 \
                                                                              \
        if (http_query_parameters_parse(str_,                                 \
                                        &parameters, &nb_parameters) == 0) {  \
            TEST_ABORT("parsed invalid query");                               \
        }                                                                     \
    } while (0)

    HTTPT_INVALID_QUERY("&");
    HTTPT_INVALID_QUERY("a=1&");
    HTTPT_INVALID_QUERY("a=");
    HTTPT_INVALID_QUERY("=1");
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("uris");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);
    TEST_RUN(suite, invalid);
    TEST_RUN(suite, query);
    TEST_RUN(suite, invalid_query);

    test_suite_print_results_and_exit(suite);
}
