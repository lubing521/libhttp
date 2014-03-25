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

#include <assert.h>
#include <string.h>

#include "http.h"
#include "internal.h"

static bool http_route_matches_request(const struct http_route *,
                                       enum http_method, const char *,
                                       enum http_route_match_result *);
static int http_route_cmp(const void *, const void *);

static void http_route_base_sort_routes(struct http_route_base *);

int
http_route_components_parse(const char *path,
                            struct http_route_component **pcomponents,
                            size_t *p_nb_components) {
    struct http_route_component *components;
    size_t nb_components;
    size_t components_sz;
    const char *ptr, *start;
    size_t toklen;

    components = NULL;
    nb_components = 0;
    components_sz = 0;

    ptr = path;
    if (*ptr != '/') {
        http_set_error("path is not absolute");
        goto error;
    }

    ptr++; /* skip '/' */
    start = ptr;

    if (*ptr == '\0') {
        /* Root path */
        *pcomponents = NULL;
        *p_nb_components = 0;

        return 0;
    }

    for (;;) {
        if (*ptr == '/' || *ptr == '\0') {
            struct http_route_component component;

            toklen = (size_t)(ptr - start);
            if (toklen == 0) {
                http_set_error("empty component in path");
                goto error;
            }

            if (memcmp(start, "*", toklen) == 0) {
                component.type = HTTP_ROUTE_COMPONENT_WILDCARD;
            } else if (*start == ':') {
                component.type = HTTP_ROUTE_COMPONENT_NAMED;

                start++;
                toklen--;
                if (toklen == 0) {
                    http_set_error("empty named variable in path");
                    goto error;
                }
            } else {
                component.type = HTTP_ROUTE_COMPONENT_STRING;
            }

            if (component.type == HTTP_ROUTE_COMPONENT_WILDCARD) {
                component.value = NULL;
            } else {
                component.value = http_strndup(start, toklen);
                if (!component.value)
                    goto error;
            }

            if (nb_components == 0) {
                components_sz = 1;
                components = http_malloc(sizeof(struct http_route_component));
                if (!components)
                    goto error;
            } else if (nb_components + 1 > components_sz) {
                struct http_route_component *ncomponents;
                size_t nsz;

                components_sz *= 2;
                nsz = components_sz * sizeof(struct http_route_component);
                ncomponents = http_realloc(components, nsz);
                if (!ncomponents)
                    goto error;
                components = ncomponents;
            }

            components[nb_components++] = component;

            if (*ptr == '\0')
                break;

            ptr++;
            start = ptr;
        } else {
            ptr++;
        }
    }

    *pcomponents = components;
    *p_nb_components = nb_components;
    return 0;

error:
    http_route_components_free(components, nb_components);
    return -1;
}

void
http_route_components_free(struct http_route_component *components,
                           size_t nb_components) {
    if (!components)
        return;

    for (size_t i = 0; i < nb_components; i++) {
        struct http_route_component *component;

        component = components + i;

        if (component->type == HTTP_ROUTE_COMPONENT_STRING
         || component->type == HTTP_ROUTE_COMPONENT_NAMED) {
            http_free(component->value);
        }
    }

    http_free(components);
}

struct http_route *
http_route_new(enum http_method method, const char *path,
               http_msg_handler msg_handler) {
    struct http_route *route;

    route = http_malloc(sizeof(struct http_route));
    if (!route)
        return NULL;
    memset(route, 0, sizeof(struct http_route));

    route->method = method;
    route->path = http_strdup(path);
    route->msg_handler = msg_handler;

    if (http_route_components_parse(path, &route->components,
                                    &route->nb_components) == -1) {
        http_route_delete(route);
        return NULL;
    }

    return route;
}

void
http_route_delete(struct http_route *route) {
    if (!route)
        return;

    http_free(route->path);

    http_route_components_free(route->components, route->nb_components);

    memset(route, 0, sizeof(struct http_route));
    http_free(route);
}

struct http_route_base *
http_route_base_new(void) {
    struct http_route_base *base;

    base = http_malloc(sizeof(struct http_route_base));
    if (!base)
        return NULL;
    memset(base, 0, sizeof(struct http_route_base));

    base->sorted = true;

    return base;
}

void
http_route_base_delete(struct http_route_base *base) {
    if (!base)
        return;

    for (size_t i = 0; i < base->nb_routes; i++)
        http_route_delete(base->routes[i]);
    http_free(base->routes);

    memset(base, 0, sizeof(struct http_route_base));
    http_free(base);
}

int
http_route_base_add_route(struct http_route_base *base,
                          struct http_route *route) {
    struct http_route **routes;
    size_t routes_sz;

    if (*route->path != '/') {
        http_set_error("path is not absolute");
        return -1;
    }

    if (base->nb_routes == 0) {
        routes_sz = 1;
        routes = http_malloc(sizeof(struct http_route *));
    } else {
        routes_sz = base->routes_sz * 2;
        routes = http_realloc(base->routes,
                              routes_sz * sizeof(struct http_route *));
    }

    if (!routes)
        return -1;

    base->routes = routes;
    base->routes_sz = routes_sz;

    base->routes[base->nb_routes++] = route;

    base->sorted = false;
    return 0;
}

const struct http_route *
http_route_base_find_route(struct http_route_base *base,
                           enum http_method method, const char *path,
                           enum http_route_match_result *p_match_result) {
    enum http_route_match_result match_result;

    if (!base->sorted)
        http_route_base_sort_routes(base);

    match_result = HTTP_ROUTE_MATCH_WRONG_PATH;

    for (size_t i = 0; i < base->nb_routes; i++) {
        enum http_route_match_result result;
        if (http_route_matches_request(base->routes[i], method, path,
                                       &result)) {
            *p_match_result = HTTP_ROUTE_MATCH_OK;
            return base->routes[i];
        }

        if (result == HTTP_ROUTE_MATCH_WRONG_METHOD) {
            match_result = HTTP_ROUTE_MATCH_WRONG_METHOD;
        } else if (result == HTTP_ROUTE_MATCH_WRONG_PATH
                && match_result != HTTP_ROUTE_MATCH_WRONG_METHOD) {
            match_result = HTTP_ROUTE_MATCH_WRONG_PATH;
        }
    }

    *p_match_result = match_result;
    return NULL;
}

static bool
http_route_matches_request(const struct http_route *route,
                           enum http_method method, const char *path,
                           enum http_route_match_result *match_result) {
    const char *ptr, *start;
    size_t idx;

    assert(*path == '/');

    ptr = path;
    idx = 0;

    ptr++; /* skip the initial '/' */
    start = ptr;

    if (route->nb_components == 0 && *ptr == '\0') {
        *match_result = HTTP_ROUTE_MATCH_OK;
        goto end;
    } else if (route->nb_components == 0 || *ptr == '\0') {
        *match_result = HTTP_ROUTE_MATCH_WRONG_PATH;
        return false;
    }

    for (;;) {
        if (*ptr == '/' || *ptr == '\0') {
            struct http_route_component *component;
            size_t toklen;

            toklen = (size_t)(ptr - start);

            component = route->components + idx;
            switch (component->type) {
            case HTTP_ROUTE_COMPONENT_STRING:
                if (strlen(component->value) != toklen
                 || memcmp(component->value, start, toklen) != 0) {
                    *match_result = HTTP_ROUTE_MATCH_WRONG_PATH;
                    return false;
                }
                break;

            case HTTP_ROUTE_COMPONENT_WILDCARD:
            case HTTP_ROUTE_COMPONENT_NAMED:
                break;
            }

            if (*ptr == '\0') {
                if (idx < route->nb_components - 1) {
                    *match_result = HTTP_ROUTE_MATCH_WRONG_PATH;
                    return false;
                }

                break;
            } else if (*ptr == '/') {
                while (*ptr == '/')
                    ptr++;
                start = ptr;

                idx++;
                if (idx >= route->nb_components) {
                    *match_result = HTTP_ROUTE_MATCH_WRONG_PATH;
                    return false;
                }
            }
        } else {
            ptr++;
        }
    }

end:
    if (route->method == method) {
        *match_result = HTTP_ROUTE_MATCH_OK;
        return true;
    } else {
        *match_result = HTTP_ROUTE_MATCH_WRONG_METHOD;
        return false;
    }
}

static int
http_route_cmp(const void *arg1, const void *arg2) {
    const struct http_route *r1, *r2;

    r1 = *(const struct http_route **)arg1;
    r2 = *(const struct http_route **)arg2;

    if (r1->nb_components > r2->nb_components) {
        return -1;
    } else if (r1->nb_components < r2->nb_components) {
        return 1;
    } else {
        for (size_t i = 0 ; i < r1->nb_components; i++) {
            struct http_route_component *component_1, *component_2;

            component_1 = &r1->components[i];
            component_2 = &r2->components[i];

            if (component_1->type == HTTP_ROUTE_COMPONENT_WILDCARD) {
                return 1;
            } else if (component_2->type == HTTP_ROUTE_COMPONENT_WILDCARD) {
                return -1;
            } else if (component_1->type == HTTP_ROUTE_COMPONENT_NAMED) {
                return 1;
            } else if (component_2->type == HTTP_ROUTE_COMPONENT_NAMED) {
                return -1;
            }
        }

        return -1;
    }
}

static void
http_route_base_sort_routes(struct http_route_base *base) {
    qsort(base->routes, base->nb_routes, sizeof(struct http_route *),
          http_route_cmp);

    base->sorted = true;
}
