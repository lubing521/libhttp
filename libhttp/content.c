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

#include <string.h>

#include "http.h"
#include "internal.h"

struct http_form_data {
    struct http_query_parameter *parameters;
    size_t nb_parameters;
};

static struct http_form_data *http_form_data_new(const char *);
static void http_form_data_delete(struct http_form_data *);

void *
http_content_form_data_decode(const struct http_msg *msg,
                              const struct http_cfg *cfg) {
    return http_form_data_new(msg->body);
}

void
http_content_form_data_delete(void *content) {
    http_form_data_delete(content);
}

static struct http_form_data *
http_form_data_new(const char *string) {
    struct http_form_data *data;

    data = http_malloc(sizeof(struct http_form_data));
    if (!data)
        return NULL;

    memset(data, 0, sizeof(struct http_form_data));

    if (http_query_parameters_parse(string, &data->parameters,
                                    &data->nb_parameters) == -1) {
        http_free(data);
        return NULL;
    }

    return data;
}

static void
http_form_data_delete(struct http_form_data *data) {
    if (!data)
        return;

    for (size_t i = 0; i < data->nb_parameters; i++)
        http_query_parameter_free(data->parameters + i);
    http_free(data->parameters);

    memset(data, 0, sizeof(struct http_form_data));
    http_free(data);
}

const char *
http_form_data_get_parameter(const struct http_form_data *data,
                             const char *name) {
    for (size_t i = 0; i < data->nb_parameters; i++) {
        const struct http_query_parameter *parameter;

        parameter = data->parameters + i;

        if (strcmp(parameter->name, name) == 0)
            return parameter->value;
    }

    return NULL;
}
