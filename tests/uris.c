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

#define HTTPT_INVALID_URI(str_)                                         \
    do {                                                                \
        uri = http_uri_new(str_);                                       \
        if (uri)                                                        \
            HTTPT_DIE("%s:%d: parsed invalid uri", __FILE__, __LINE__); \
    } while (0)

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

#undef HTTPT_INVALID_URI

#undef HTTPT_BEGIN
#undef HTTPT_END

    return 0;
}
