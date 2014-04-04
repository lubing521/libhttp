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

static bool http_route_matches_path(const struct http_route *, char **, size_t);
static bool http_route_matches_request(const struct http_route *,
                                       enum http_method, char **, size_t,
                                       enum http_route_match_result *);
static int http_route_cmp(const void *, const void *);

static void http_route_base_sort_routes(struct http_route_base *);

static int http_path_parse(const char *, char ***, size_t *);
static void http_path_free(char **, size_t);

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
            } else if (nb_components + 1 > components_sz) {
                size_t nsz;

                components_sz *= 2;
                nsz = components_sz * sizeof(struct http_route_component);
                components = http_realloc(components, nsz);
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

void
http_route_apply_options(struct http_route *route,
                         const struct http_route_options *options,
                         const struct http_cfg *cfg) {
    if (options) {
        route->options = *options;
    } else {
        http_route_options_init(&route->options, cfg);
    }
}

struct http_route_base *
http_route_base_new(void) {
    struct http_route_base *base;

    base = http_malloc(sizeof(struct http_route_base));
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

void
http_route_base_add_route(struct http_route_base *base,
                          struct http_route *route) {
    assert(*route->path == '/');

    if (base->nb_routes == 0) {
        base->routes_sz = 1;
        base->routes = http_malloc(sizeof(struct http_route *));
    } else {
        size_t nsz;

        base->routes_sz *= 2;

        nsz = base->routes_sz * sizeof(struct http_route *);
        base->routes = http_realloc(base->routes, nsz);
    }

    base->routes[base->nb_routes++] = route;

    base->sorted = false;
}

int
http_route_base_find_route(struct http_route_base *base,
                           enum http_method method, const char *path,
                           const struct http_route **proute,
                           enum http_route_match_result *p_match_result,
                           struct http_named_parameter **p_named_parameters,
                           size_t *p_nb_named_parameters) {
    struct http_route *route;
    struct http_named_parameter *named_parameters;
    size_t nb_named_parameters;
    enum http_route_match_result match_result;
    char **path_components;
    size_t nb_path_components, idx;

    if (!base->sorted)
        http_route_base_sort_routes(base);

    if (*path != '/') {
        *proute = NULL;
        *p_match_result = HTTP_ROUTE_MATCH_WRONG_PATH;
        return 0;
    }

    if (http_path_parse(path, &path_components, &nb_path_components) == -1)
        return -1;

    route = NULL;
    match_result = HTTP_ROUTE_MATCH_PATH_NOT_FOUND;

    for (size_t i = 0; i < base->nb_routes; i++) {
        enum http_route_match_result result;

        if (http_route_matches_request(base->routes[i], method,
                                       path_components, nb_path_components,
                                       &result)) {
            route = base->routes[i];
            match_result = HTTP_ROUTE_MATCH_OK;
            break;
        }

        if (result == HTTP_ROUTE_MATCH_METHOD_NOT_FOUND) {
            match_result = HTTP_ROUTE_MATCH_METHOD_NOT_FOUND;
        } else if (result == HTTP_ROUTE_MATCH_PATH_NOT_FOUND
                && match_result != HTTP_ROUTE_MATCH_METHOD_NOT_FOUND) {
            match_result = HTTP_ROUTE_MATCH_PATH_NOT_FOUND;
        }
    }

    if (!route) {
        *proute = NULL;
        *p_match_result = match_result;

        http_path_free(path_components, nb_path_components);
        return 0;
    }

    if (route->nb_components != nb_path_components) {
        /* We made a mistake somewhere, it should not happen */
        http_set_error("route/path size mismatch");
        return -1;
    }

    /* Copy named parameters */
    nb_named_parameters = 0;
    for (size_t i = 0; i < route->nb_components; i++) {
        if (route->components[i].type == HTTP_ROUTE_COMPONENT_NAMED)
            nb_named_parameters++;
    }

    if (p_named_parameters && nb_named_parameters > 0) {
        named_parameters = http_calloc(nb_named_parameters,
                                       sizeof(struct http_named_parameter));

        idx = 0;
        for (size_t i = 0; i < route->nb_components; i++) {
            struct http_route_component *component;

            component = route->components + i;

            if (component->type != HTTP_ROUTE_COMPONENT_NAMED)
                continue;

            named_parameters[idx].name = http_strdup(component->value);
            named_parameters[idx].value = http_strdup(path_components[i]);
            idx++;
        }
    } else {
        named_parameters = NULL;
    }

    http_path_free(path_components, nb_path_components);

    *proute = route;
    *p_match_result = match_result;

    if (p_named_parameters)
        *p_named_parameters = named_parameters;
    if (p_nb_named_parameters)
        *p_nb_named_parameters = nb_named_parameters;
    return 0;
}

int
http_route_base_find_path_methods(struct http_route_base *base,
                                  const char *path,
                                  enum http_method methods[static HTTP_METHOD_MAX],
                                  size_t *p_nb_methods) {
    char **path_components;
    size_t nb_path_components;
    size_t nb_methods;

    if (http_path_parse(path, &path_components, &nb_path_components) == -1)
        return -1;

    nb_methods = 0;
    for (size_t i = 0; i < base->nb_routes; i++) {
        if (http_route_matches_path(base->routes[i], path_components,
                                    nb_path_components)) {
            methods[nb_methods++] = base->routes[i]->method;
        }
    }

    http_path_free(path_components, nb_path_components);

    *p_nb_methods = nb_methods;
    return 0;
}

static bool
http_route_matches_path(const struct http_route *route,
                        char **path_components, size_t nb_path_components) {
    if (route->nb_components == 0 && nb_path_components == 0)
        return true;

    if (nb_path_components != route->nb_components)
        return false;

    for (size_t i = 0; i < nb_path_components; i++) {
        struct http_route_component *route_component;
        const char *path_component;

        route_component = route->components + i;
        path_component = path_components[i];

        switch (route_component->type) {
        case HTTP_ROUTE_COMPONENT_STRING:
            if (strcmp(route_component->value, path_component) != 0)
                return false;
            break;

        case HTTP_ROUTE_COMPONENT_WILDCARD:
        case HTTP_ROUTE_COMPONENT_NAMED:
            break;
        }
    }

    return true;
}

static bool
http_route_matches_request(const struct http_route *route,
                           enum http_method method,
                           char **path_components, size_t nb_path_components,
                           enum http_route_match_result *match_result) {
    if (!http_route_matches_path(route,
                                 path_components, nb_path_components)) {
        *match_result = HTTP_ROUTE_MATCH_PATH_NOT_FOUND;
        return false;
    }

    if (route->method == method) {
        *match_result = HTTP_ROUTE_MATCH_OK;
        return true;
    } else {
        *match_result = HTTP_ROUTE_MATCH_METHOD_NOT_FOUND;
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

static int
http_path_parse(const char *path, char ***pcomponents, size_t *p_nb_components) {
    char **components;
    size_t nb_components, idx;
    const char *ptr, *start;

    /* Count the number of components */
    ptr = path;
    while (*ptr == '/')
        ptr++;
    if (*ptr == '\0') {
        *p_nb_components = 0;
        *pcomponents = NULL;
        return 0;
    }

    nb_components = 0;
    for (;;) {
        if (*ptr == '/' || *ptr == '\0') {
            while (*ptr == '/')
                ptr++;

            nb_components++;

            if (*ptr == '\0')
                break;
        } else {
            ptr++;
        }
    }

    components = http_calloc(nb_components, sizeof(char *));

    /* Copy the components */
    ptr = path;
    while (*ptr == '/')
        ptr++;
    start = ptr;

    idx = 0;
    for (;;) {
        if (*ptr == '/' || *ptr == '\0') {
            size_t toklen;

            toklen = (size_t)(ptr - start);
            components[idx] = http_strndup(start, toklen);
            if (!components[idx])
                goto error;

            idx++;
            if (idx > nb_components) {
                /* We did not count correctly */
                http_set_error("error while parsing path");
                goto error;
            }

            while (*ptr == '/')
                ptr++;
            start = ptr;

            if (*ptr == '\0')
                break;
        } else {
            ptr++;
        }
    }

    *pcomponents = components;
    *p_nb_components = nb_components;
    return 0;

error:
    http_path_free(components, nb_components);
    return -1;
}

static void
http_path_free(char **components, size_t nb_components) {
    for (size_t i = 0; i < nb_components; i++)
        http_free(components[i]);
    http_free(components);
}
