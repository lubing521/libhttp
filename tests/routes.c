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
    struct http_route_component *components;
    size_t nb_components;

    struct http_route_base *route_base;

    /* Route components parsing */

#define HTTPT_BEGIN(str_)                                                 \
    if (http_route_components_parse(str_,                                 \
                                    &components, &nb_components) == -1) { \
        HTTPT_DIE("%s:%d: cannot parse route path: %s",                   \
                  __FILE__, __LINE__, http_get_error());                  \
    }

#define HTTPT_END() \
    http_route_components_free(components, nb_components)

    HTTPT_BEGIN("/foo");
    HTTPT_IS_EQUAL_UINT(nb_components, 1);
    HTTPT_IS_EQUAL_INT(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[0].value, "foo");
    HTTPT_END();

    HTTPT_BEGIN("/foo/bar/baz");
    HTTPT_IS_EQUAL_UINT(nb_components, 3);
    HTTPT_IS_EQUAL_INT(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[0].value, "foo");
    HTTPT_IS_EQUAL_INT(components[1].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[1].value, "bar");
    HTTPT_IS_EQUAL_INT(components[2].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[2].value, "baz");
    HTTPT_END();

    HTTPT_BEGIN("/foo/*/bar/*");
    HTTPT_IS_EQUAL_UINT(nb_components, 4);
    HTTPT_IS_EQUAL_INT(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[0].value, "foo");
    HTTPT_IS_EQUAL_INT(components[1].type, HTTP_ROUTE_COMPONENT_WILDCARD);
    HTTPT_IS_EQUAL_PTR(components[1].value, NULL);
    HTTPT_IS_EQUAL_INT(components[2].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[2].value, "bar");
    HTTPT_IS_EQUAL_INT(components[3].type, HTTP_ROUTE_COMPONENT_WILDCARD);
    HTTPT_IS_EQUAL_PTR(components[3].value, NULL);
    HTTPT_END();

    HTTPT_BEGIN("/foo/:a/bar/:end");
    HTTPT_IS_EQUAL_UINT(nb_components, 4);
    HTTPT_IS_EQUAL_INT(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[0].value, "foo");
    HTTPT_IS_EQUAL_INT(components[1].type, HTTP_ROUTE_COMPONENT_NAMED);
    HTTPT_IS_EQUAL_STRING(components[1].value, "a");
    HTTPT_IS_EQUAL_INT(components[2].type, HTTP_ROUTE_COMPONENT_STRING);
    HTTPT_IS_EQUAL_STRING(components[2].value, "bar");
    HTTPT_IS_EQUAL_INT(components[3].type, HTTP_ROUTE_COMPONENT_NAMED);
    HTTPT_IS_EQUAL_STRING(components[3].value, "end");
    HTTPT_END();

#define HTTPT_INVALID_ROUTE_PATH(str_)                                         \
    if (http_route_components_parse(str_, &components, &nb_components) == 0) { \
        HTTPT_DIE("%s:%d: parsed invalid route path", __FILE__, __LINE__);     \
    }

    HTTPT_INVALID_ROUTE_PATH("");
    HTTPT_INVALID_ROUTE_PATH("//");
    HTTPT_INVALID_ROUTE_PATH("/foo/");
    HTTPT_INVALID_ROUTE_PATH("/foo//bar");
    HTTPT_INVALID_ROUTE_PATH("/:");
    HTTPT_INVALID_ROUTE_PATH("/:/");

#undef HTTPT_INVALID_ROUTE_PATH

#undef HTTPT_BEGIN
#undef HTTPT_END

    /* Route matching */

#define HTTPT_BEGIN()                       \
    do {                                    \
        route_base = http_route_base_new(); \
    } while (0)

#define HTTPT_END() \
    http_route_base_delete(route_base)

#define HTTPT_ADD_ROUTE(method_, path_, handler_)                 \
    do {                                                          \
        struct http_route *route;                                 \
                                                                  \
        route = http_route_new(method_, path_,                    \
                               (http_msg_handler)handler_);       \
        if (!route) {                                             \
            HTTPT_DIE("%s:%d: cannot create route: %s",           \
                      __FILE__, __LINE__, http_get_error());      \
        }                                                         \
                                                                  \
        if (http_route_base_add_route(route_base, route) == -1) { \
            HTTPT_DIE("%s:%d: cannot add route: %s",              \
                      __FILE__, __LINE__, http_get_error());      \
        }                                                         \
    } while (0)

#define HTTPT_ROUTE_HANDLER_IS_FOUND(method_, path_, handler_) \
    do {                                                                \
        const struct http_route *route;                                 \
        http_msg_handler handler;                                       \
        enum http_route_match_result match_result;                      \
                                                                        \
        route = http_route_base_find_route(route_base, method_, path_,  \
                                           &match_result);              \
        handler = route->msg_handler;                                   \
                                                                        \
        HTTPT_IS_EQUAL_PTR(handler, (http_msg_handler)handler_);        \
        HTTPT_IS_EQUAL_INT(match_result, HTTP_ROUTE_MATCH_OK);          \
    } while (0)

#define HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(method_, path_, match_result_) \
    do {                                                                \
        const struct http_route *route;                                 \
        enum http_route_match_result match_result;                      \
                                                                        \
        route = http_route_base_find_route(route_base, method_, path_,  \
                                                   &match_result);      \
        HTTPT_IS_EQUAL_PTR(route, NULL);                                \
        HTTPT_IS_EQUAL_INT(match_result, match_result_);                \
    } while (0)

    HTTPT_BEGIN();
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_END();

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/a", 0x1);
    HTTPT_ADD_ROUTE(HTTP_POST, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_POST, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_PUT, "/a",
                                     HTTP_ROUTE_MATCH_WRONG_METHOD);
    HTTPT_END();

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/a", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b", 0x2);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b/c", 0x3);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b/d", 0x4);
    HTTPT_ADD_ROUTE(HTTP_GET, "/e", 0x5);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b/c", 0x3);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b/d", 0x4);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/e", 0x5);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/b/f",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/b/d/f",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/g",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/h",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_END();

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/b",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_END();

    /* Wildcards */
    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/*", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/*", 0x2);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b", 0x3);
    HTTPT_ADD_ROUTE(HTTP_GET, "/*/c", 0x4);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/1", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/1/2",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b", 0x3);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/c", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/d/c", 0x4);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/d/c/e",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_END();

    /* Named components */
    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/:n", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/:n", 0x2);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b", 0x3);
    HTTPT_ADD_ROUTE(HTTP_GET, "/:n/c", 0x4);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/1", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/1/2",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b", 0x3);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/c", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/d/c", 0x4);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/d/c/e",
                                     HTTP_ROUTE_MATCH_WRONG_PATH);
    HTTPT_END();

#undef HTTPT_ADD_ROUTE

#undef HTTPT_BEGIN
#undef HTTPT_END
#undef HTTPT_ROUTE_HANDLER_IS_FOUND
#undef HTTPT_ROUTE_HANDLER_IS_NOT_FOUND

    return 0;
}
