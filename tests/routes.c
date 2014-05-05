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

TEST(parsing) {
    struct http_route_component *components;
    size_t nb_components;

#define HTTPT_BEGIN(str_)                                                 \
    if (http_route_components_parse(str_,                                 \
                                    &components, &nb_components) == -1) { \
        TEST_ABORT("cannot parse route path: %s", http_get_error());      \
    }

#define HTTPT_END() \
    http_route_components_free(components, nb_components)

    HTTPT_BEGIN("/foo");
    TEST_UINT_EQ(nb_components, 1);
    TEST_INT_EQ(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[0].value, "foo");
    HTTPT_END();

    HTTPT_BEGIN("/foo/bar/baz");
    TEST_UINT_EQ(nb_components, 3);
    TEST_INT_EQ(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[0].value, "foo");
    TEST_INT_EQ(components[1].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[1].value, "bar");
    TEST_INT_EQ(components[2].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[2].value, "baz");
    HTTPT_END();

    HTTPT_BEGIN("/foo/*/bar/*");
    TEST_UINT_EQ(nb_components, 4);
    TEST_INT_EQ(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[0].value, "foo");
    TEST_INT_EQ(components[1].type, HTTP_ROUTE_COMPONENT_WILDCARD);
    HTTPT_IS_EQUAL_PTR(components[1].value, NULL);
    TEST_INT_EQ(components[2].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[2].value, "bar");
    TEST_INT_EQ(components[3].type, HTTP_ROUTE_COMPONENT_WILDCARD);
    HTTPT_IS_EQUAL_PTR(components[3].value, NULL);
    HTTPT_END();

    HTTPT_BEGIN("/foo/:a/bar/:end");
    TEST_UINT_EQ(nb_components, 4);
    TEST_INT_EQ(components[0].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[0].value, "foo");
    TEST_INT_EQ(components[1].type, HTTP_ROUTE_COMPONENT_NAMED);
    TEST_STRING_EQ(components[1].value, "a");
    TEST_INT_EQ(components[2].type, HTTP_ROUTE_COMPONENT_STRING);
    TEST_STRING_EQ(components[2].value, "bar");
    TEST_INT_EQ(components[3].type, HTTP_ROUTE_COMPONENT_NAMED);
    TEST_STRING_EQ(components[3].value, "end");
    HTTPT_END();

#undef HTTPT_BEGIN
#undef HTTPT_END
}

TEST(invalid) {
    struct http_route_component *components;
    size_t nb_components;

#define HTTPT_INVALID_ROUTE_PATH(str_)                                         \
    if (http_route_components_parse(str_, &components, &nb_components) == 0) { \
        TEST_ABORT("parsed invalid route path");                               \
    }

    HTTPT_INVALID_ROUTE_PATH("");
    HTTPT_INVALID_ROUTE_PATH("//");
    HTTPT_INVALID_ROUTE_PATH("/foo/");
    HTTPT_INVALID_ROUTE_PATH("/foo//bar");
    HTTPT_INVALID_ROUTE_PATH("/:");
    HTTPT_INVALID_ROUTE_PATH("/:/");
}

TEST(matching) {
    struct http_named_parameter *named_parameters;
    size_t nb_named_parameters;

    struct http_route_base *route_base;

#define HTTPT_BEGIN()                       \
    do {                                    \
        route_base = http_route_base_new(); \
                                            \
        named_parameters = NULL;            \
        nb_named_parameters = 0;            \
    } while (0)

#define HTTPT_END()                                               \
    do {                                                          \
        http_route_base_delete(route_base);                       \
    } while (0)

#define HTTPT_ADD_ROUTE(method_, path_, handler_)                 \
    do {                                                          \
        struct http_route *route;                                 \
                                                                  \
        route = http_route_new(method_, path_,                    \
                               (http_msg_handler)handler_);       \
        http_route_base_add_route(route_base, route);             \
    } while (0)

#define HTTPT_ROUTE_HANDLER_IS_FOUND(method_, path_, handler_)             \
    do {                                                                   \
        const struct http_route *route;                                    \
        http_msg_handler handler;                                          \
        enum http_route_match_result match_result;                         \
                                                                           \
        if (http_route_base_find_route(route_base, method_, path_,         \
                                       &route, &match_result,              \
                                       &named_parameters,                  \
                                       &nb_named_parameters) == -1) {      \
            TEST_ABORT("cannot find route: %s", http_get_error());         \
        }                                                                  \
        handler = route ? route->msg_handler : NULL;                       \
                                                                           \
        TEST_PTR_EQ(handler, (http_msg_handler)handler_);                  \
        TEST_INT_EQ(match_result, HTTP_ROUTE_MATCH_OK);                    \
    } while (0)

#define HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(method_, path_, match_result_)    \
    do {                                                                   \
        const struct http_route *route;                                    \
        enum http_route_match_result match_result;                         \
                                                                           \
        if (http_route_base_find_route(route_base, method_, path_,         \
                                       &route, &match_result,              \
                                       &named_parameters,                  \
                                       &nb_named_parameters) == -1) {      \
            TEST_ABORT("cannot find route: %s", http_get_error());         \
        }                                                                  \
                                                                           \
        TEST_PTR_NULL(route);                                              \
        TEST_INT_EQ(match_result, match_result_);                          \
    } while (0)

    HTTPT_BEGIN();
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_END();

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/a", 0x1);
    HTTPT_ADD_ROUTE(HTTP_POST, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_POST, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_PUT, "/a",
                                     HTTP_ROUTE_MATCH_METHOD_NOT_FOUND);
    HTTPT_END();

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/a", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b", 0x2);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b/c", 0x3);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b/d", 0x4);
    HTTPT_ADD_ROUTE(HTTP_GET, "/e", 0x5);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b/c", 0x3);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b/d", 0x4);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/e", 0x5);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/b/f",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/b/d/f",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/g",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/h",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_END();

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/b",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_END();

    /* Wildcards */
    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/*", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/*", 0x2);
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/b", 0x3);
    HTTPT_ADD_ROUTE(HTTP_GET, "/*/c", 0x4);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a", 0x1);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/1", 0x2);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/a/1/2",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/b", 0x3);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/c", 0x2);
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/d/c", 0x4);
    HTTPT_ROUTE_HANDLER_IS_NOT_FOUND(HTTP_GET, "/d/c/e",
                                     HTTP_ROUTE_MATCH_PATH_NOT_FOUND);
    HTTPT_END();

#undef HTTP_BEGIN
#undef HTTP_END
}

TEST(named_components) {
    struct http_named_parameter *named_parameters;
    size_t nb_named_parameters;

    struct http_route_base *route_base;

#define HTTPT_NAMED_PARAMETER_EQ(name_, value_)               \
    do {                                                      \
        char *value;                                          \
                                                              \
        value = NULL;                                         \
        for (size_t i = 0; i < nb_named_parameters; i++) {    \
            if (strcmp(named_parameters[i].name, name_) == 0) \
                value = named_parameters[i].value;            \
        }                                                     \
                                                              \
        if (value_) {                                         \
            TEST_STRING_EQ(value, value_);             \
        } else {                                              \
            HTTPT_IS_EQUAL_PTR(value, NULL);                  \
        }                                                     \
    } while (0)

#define HTTPT_FREE_NAMED_PARAMETERS()                         \
    do {                                                      \
        for (size_t i = 0; i < nb_named_parameters; i++)      \
            http_named_parameter_free(named_parameters + i);  \
        http_free(named_parameters);                          \
    } while (0)

    HTTPT_BEGIN();
    HTTPT_ADD_ROUTE(HTTP_GET, "/a/:1", 0x1);
    HTTPT_ADD_ROUTE(HTTP_GET, "/b/:1/:2", 0x2);
    HTTPT_ADD_ROUTE(HTTP_GET, "/c/:1/d/:2/e", 0x3);

    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/a/foo", 0x1);
    TEST_UINT_EQ(nb_named_parameters, 1);
    HTTPT_NAMED_PARAMETER_EQ("1", "foo");

    HTTPT_FREE_NAMED_PARAMETERS();
    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/b/foo/bar", 0x2);
    TEST_UINT_EQ(nb_named_parameters, 2);
    HTTPT_NAMED_PARAMETER_EQ("1", "foo");
    HTTPT_NAMED_PARAMETER_EQ("2", "bar");
    HTTPT_FREE_NAMED_PARAMETERS();

    HTTPT_ROUTE_HANDLER_IS_FOUND(HTTP_GET, "/c/hello/d/world/e", 0x3);
    TEST_UINT_EQ(nb_named_parameters, 2);
    HTTPT_NAMED_PARAMETER_EQ("1", "hello");
    HTTPT_NAMED_PARAMETER_EQ("2", "world");
    HTTPT_FREE_NAMED_PARAMETERS();

    HTTPT_END();
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("routes");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, parsing);
    TEST_RUN(suite, invalid);
    TEST_RUN(suite, matching);
    TEST_RUN(suite, named_components);

    test_suite_print_results_and_exit(suite);
}
