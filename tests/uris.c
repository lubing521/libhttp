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
    struct http_uri *uri;
    struct http_query_parameter *parameters;
    size_t nb_parameters;

    /* --------------------------------------------------------------------
     *  URI
     * -------------------------------------------------------------------- */
#define HTTPT_BEGIN(str_)                                    \
    do {                                                     \
        uri = http_uri_new(str_);                            \
        if (!uri) {                                          \
            HTTPT_DIE("%s:%d: cannot parse uri: %s",         \
                      __FILE__, __LINE__, http_get_error()); \
        }                                                    \
    } while (0)

#define HTTPT_END() \
    http_uri_delete(uri);

    HTTPT_BEGIN("/");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("/foo/bar");
    HTTPT_IS_EQUAL_STRING(uri->path, "/foo/bar");
    HTTPT_END();

    HTTPT_BEGIN("/foo/bar?a=1&b=2");
    HTTPT_IS_EQUAL_STRING(uri->path, "/foo/bar");
    HTTPT_IS_EQUAL_STRING(uri->query, "a=1&b=2");
    HTTPT_END();

    HTTPT_BEGIN("http://127.0.0.1");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "127.0.0.1");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://127.0.0.1:443");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "127.0.0.1");
    HTTPT_IS_EQUAL_STRING(uri->port, "443");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://[::1]");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "::1");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://[::1]:443");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "::1");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_IS_EQUAL_STRING(uri->port, "443");
    HTTPT_END();

    HTTPT_BEGIN("http://[fe80::1e6f:65ff:EA21:A373]:443");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "fe80::1e6f:65ff:EA21:A373");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_IS_EQUAL_STRING(uri->port, "443");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com:8080");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->port, "8080");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com:8080/");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->port, "8080");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

    HTTPT_BEGIN("http://foo@example.com");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->user, "foo");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_END();

    HTTPT_BEGIN("http://foo:bar@example.com");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->user, "foo");
    HTTPT_IS_EQUAL_STRING(uri->password, "bar");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/a/b/c");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->path, "/a/b/c");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/?a=1&b=2");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_IS_EQUAL_STRING(uri->query, "a=1&b=2");
    HTTPT_END();

    HTTPT_BEGIN("http://example.com/a/b/c?a=1&b=2");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->path, "/a/b/c");
    HTTPT_IS_EQUAL_STRING(uri->query, "a=1&b=2");
    HTTPT_END();

    HTTPT_BEGIN("http://foo:bar@example.com:8080/path?a=1&b=2");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->user, "foo");
    HTTPT_IS_EQUAL_STRING(uri->password, "bar");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->port, "8080");
    HTTPT_IS_EQUAL_STRING(uri->path, "/path");
    HTTPT_IS_EQUAL_STRING(uri->query, "a=1&b=2");
    HTTPT_END();

    HTTPT_BEGIN("%68%74%74%70://%65%78%61%6d%70%6c%65.%63%6f%6D");
    HTTPT_IS_EQUAL_STRING(uri->scheme, "http");
    HTTPT_IS_EQUAL_STRING(uri->host, "example.com");
    HTTPT_IS_EQUAL_STRING(uri->path, "/");
    HTTPT_END();

#define HTTPT_INVALID_URI(str_)                                         \
    do {                                                                \
        uri = http_uri_new(str_);                                       \
        if (uri)                                                        \
            HTTPT_DIE("%s:%d: parsed invalid uri", __FILE__, __LINE__); \
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

#undef HTTPT_INVALID_URI

#undef HTTPT_BEGIN
#undef HTTPT_END

    /* --------------------------------------------------------------------
     *  Query string
     * -------------------------------------------------------------------- */
#define HTTPT_BEGIN(str_)                                                     \
    do {                                                                      \
        if (http_query_parameters_parse(str_,                                 \
                                        &parameters, &nb_parameters) == -1) { \
            HTTPT_DIE("%s:%d: cannot parse query: %s",                        \
                      __FILE__, __LINE__, http_get_error());                  \
        }                                                                     \
    } while (0)

#define HTTPT_END()                                    \
    do {                                               \
        for (size_t i = 0; i < nb_parameters; i++)     \
            http_query_parameter_free(parameters + i); \
        http_free(parameters);                         \
    } while (0)

    HTTPT_BEGIN("");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 0);
    HTTPT_END();

    HTTPT_BEGIN("a");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 1);
    HTTPT_IS_EQUAL_STRING(parameters[0].name, "a");
    HTTPT_IS_EQUAL_PTR(parameters[0].value, NULL);
    HTTPT_END();

    HTTPT_BEGIN("foo");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 1);
    HTTPT_IS_EQUAL_STRING(parameters[0].name, "foo");
    HTTPT_IS_EQUAL_PTR(parameters[0].value, NULL);
    HTTPT_END();

    HTTPT_BEGIN("foo=bar");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 1);
    HTTPT_IS_EQUAL_STRING(parameters[0].name, "foo");
    HTTPT_IS_EQUAL_STRING(parameters[0].value, "bar");
    HTTPT_END();

    HTTPT_BEGIN("a=1&b=2");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 2);
    HTTPT_IS_EQUAL_STRING(parameters[0].name, "a");
    HTTPT_IS_EQUAL_STRING(parameters[0].value, "1");
    HTTPT_IS_EQUAL_STRING(parameters[1].name, "b");
    HTTPT_IS_EQUAL_STRING(parameters[1].value, "2");
    HTTPT_END();

    HTTPT_BEGIN("a&b=2;c&d=3");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 4);
    HTTPT_IS_EQUAL_STRING(parameters[0].name, "a");
    HTTPT_IS_EQUAL_PTR(parameters[0].value, NULL);
    HTTPT_IS_EQUAL_STRING(parameters[1].name, "b");
    HTTPT_IS_EQUAL_STRING(parameters[1].value, "2");
    HTTPT_IS_EQUAL_STRING(parameters[2].name, "c");
    HTTPT_IS_EQUAL_PTR(parameters[2].value, NULL);
    HTTPT_IS_EQUAL_STRING(parameters[3].name, "d");
    HTTPT_IS_EQUAL_STRING(parameters[3].value, "3");
    HTTPT_END();

    HTTPT_BEGIN("a+b+=%20%c3%a9tat");
    HTTPT_IS_EQUAL_UINT(nb_parameters, 1);
    HTTPT_IS_EQUAL_STRING(parameters[0].name, "a b ");
    HTTPT_IS_EQUAL_STRING(parameters[0].value, " état");
    HTTPT_END();

#define HTTPT_INVALID_QUERY(str_)                                             \
    do {                                                                      \
        if (http_query_parameters_parse(str_,                                 \
                                        &parameters, &nb_parameters) == 0) {  \
            HTTPT_DIE("%s:%d: parsed invalid query",                          \
                      __FILE__, __LINE__);                                    \
        }                                                                     \
    } while (0)

    HTTPT_INVALID_QUERY("&");
    HTTPT_INVALID_QUERY("a=1&");
    HTTPT_INVALID_QUERY("a=");
    HTTPT_INVALID_QUERY("=1");

#undef HTTPT_INVALID_QUERY

#undef HTTPT_BEGIN
#undef HTTPT_END

    return 0;
}
