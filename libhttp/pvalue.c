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

#include <ctype.h>
#include <string.h>

#include "http.h"
#include "internal.h"

static bool http_is_pvalue_char(unsigned char);

void
http_pvalue_parameter_init(struct http_pvalue_parameter *parameter) {
    memset(parameter, 0, sizeof(struct http_pvalue_parameter));
}

void
http_pvalue_parameter_free(struct http_pvalue_parameter *parameter) {
    if (!parameter)
        return;

    http_free(parameter->name);
    http_free(parameter->value);

    memset(parameter, 0, sizeof(struct http_pvalue_parameter));
}

int
http_pvalue_parse(struct http_pvalue *pvalue, const char *string,
                  const char **pend) {
    const char *ptr, *start;
    size_t toklen;

    memset(pvalue, 0, sizeof(struct http_pvalue));

    ptr = string;

    /* Value */
    start = ptr;
    for (;;) {
        if (*ptr == ' ' || *ptr == '\t' || *ptr == ';' || *ptr == '\0') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0) {
                http_set_error("empty value");
                goto error;
            }

            pvalue->value = http_strndup(start, toklen);
            break;
        } else if (!http_is_pvalue_char((unsigned char)*ptr)) {
            http_set_error("invalid character \\%hhu in value",
                           (unsigned char)*ptr);
            goto error;
        } else {
            ptr++;
        }
    }

    while (*ptr == ' ' || *ptr == '\t')
        ptr++;

    if (*ptr != ';') {
        /* No parameters */
        if (pend)
            *pend = ptr;
        return 0;
    }

    ptr++; /* skip ';' */

    /* Parameters (optional) */
    for (;;) {
        struct http_pvalue_parameter parameter;

        http_pvalue_parameter_init(&parameter);

        while (*ptr == ' ' || *ptr == '\t')
            ptr++;

        /* Name */
        start = ptr;
        for (;;) {
            if (*ptr == '=' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty parameter name");
                    http_pvalue_parameter_free(&parameter);
                    goto error;
                }

                parameter.name = http_strndup(start, toklen);
                for (size_t i = 0; i < toklen; i++)
                    parameter.name[i] = tolower(parameter.name[i]);

                break;
            } else if (!http_is_pvalue_char((unsigned char)*ptr)) {
                http_set_error("invalid character \\%hhu in parameter name",
                               (unsigned char)*ptr);
                http_pvalue_parameter_free(&parameter);
                goto error;
            } else {
                ptr++;
            }
        }

        if (*ptr != '=') {
            http_set_error("missing separator after parameter name");
            http_pvalue_parameter_free(&parameter);
            goto error;
        }

        ptr++; /* skip '=' */

        /* Value */
        if (*ptr == '"') {
            /* Quoted value */
            ptr++; /* skip '"' */

            start = ptr;
            for (;;) {
                if (*ptr == '"' || *ptr == '\0') {
                    char *optr;
                    toklen = (size_t)(ptr - start);
                    if (toklen == 0) {
                        http_set_error("empty parameter value");
                        http_pvalue_parameter_free(&parameter);
                        goto error;
                    }

                    parameter.value = http_malloc(toklen + 1);

                    optr = parameter.value;
                    for (size_t i = 0; i < toklen; i++) {
                        if (start[i] == '\\') {
                            continue;
                        } else {
                            *optr++ = start[i];
                        }
                    }

                    *optr = '\0';
                    break;
                } else if (*ptr == '\\') {
                    ptr++;
                    if (*ptr == '"' || *ptr == '\\') {
                        ptr++;
                    } else if (*ptr == '\0') {
                        http_set_error("truncated escape sequence "
                                       "in parameter value");
                        http_pvalue_parameter_free(&parameter);
                        goto error;
                    } else {
                        http_set_error("invalid escaped character \\%hhu "
                                       "in parameter value",
                                       (unsigned char)*ptr);
                        http_pvalue_parameter_free(&parameter);
                        goto error;
                    }
                } else {
                    ptr++;
                }
            }

            if (*ptr != '"') {
                http_set_error("truncated quoted parameter value");
                http_pvalue_parameter_free(&parameter);
                goto error;
            }

            ptr++; /* skip '"' */
        } else {
            /* Token */
            start = ptr;
            for (;;) {
                if (*ptr == ';' || *ptr == ' ' || *ptr == '\0') {
                    toklen = (size_t)(ptr - start);
                    if (toklen == 0) {
                        http_set_error("empty parameter value");
                        http_pvalue_parameter_free(&parameter);
                        goto error;
                    }

                    parameter.value = http_strndup(start, toklen);
                    break;
                } else if (!http_is_pvalue_char((unsigned char)*ptr)) {
                    http_set_error("invalid character \\%hhu in parameter name",
                                   (unsigned char)*ptr);
                    http_pvalue_parameter_free(&parameter);
                    goto error;
                } else {
                    ptr++;
                }
            }
        }

        http_pvalue_add_parameter(pvalue, &parameter);

        while (*ptr == ' ' || *ptr == '\t')
            ptr++;

        if (*ptr == '\0') {
            break;
        } else if (*ptr != ';') {
            http_set_error("invalid character \\%hhu after parameter value",
                           (unsigned char)*ptr);
            goto error;
        }

        ptr++; /* skip ';' */
    }

    if (pend)
        *pend = ptr;
    return 0;

error:
    http_pvalue_free(pvalue);
    return -1;
}

void
http_pvalue_free(struct http_pvalue *pvalue) {
    if (!pvalue)
        return;

    http_free(pvalue->value);
    for (size_t i = 0; i < pvalue->nb_parameters; i++)
        http_pvalue_parameter_free(pvalue->parameters + i);
    http_free(pvalue->parameters);

    memset(pvalue, 0, sizeof(struct http_pvalue));
}

void
http_pvalue_add_parameter(struct http_pvalue *pvalue,
                          const struct http_pvalue_parameter *param) {
    size_t param_sz;

    param_sz = sizeof(struct http_pvalue_parameter);

    if (pvalue->nb_parameters == 0) {
        pvalue->parameters = http_malloc(param_sz);
    } else {
        size_t nsz;

        nsz = (pvalue->nb_parameters + 1) * param_sz;
        pvalue->parameters = http_realloc(pvalue->parameters, nsz);
    }

    pvalue->parameters[pvalue->nb_parameters++] = *param;
}

bool
http_pvalue_has_parameter(const struct http_pvalue *pvalue, const char *name) {
    return http_pvalue_get_parameter(pvalue, name) != NULL;
}

const char *
http_pvalue_get_parameter(const struct http_pvalue *pvalue, const char *name) {
    for (size_t i = 0; i < pvalue->nb_parameters; i++) {
        struct http_pvalue_parameter *parameter;

        parameter = pvalue->parameters + i;

        if (strcmp(parameter->name, name) == 0)
            return parameter->value;
    }

    return NULL;
}

static bool
http_is_pvalue_char(unsigned char c) {
    static uint32_t table[8] = {
        0x00000000, /*   0- 31                                          */

        0x03ff6cfa, /*  32- 63  ?>=< ;:98 7654 3210 /.-, +*)( `&%$ #"!  */
                    /*          0000 0011 1111 1111 0110 1100 1111 1010 */

        0xc7fffffe, /*  64- 95  _^]\ [ZYX WVUT SRQP ONML KJIH GFED CBA@ */
                    /*          1100 0111 1111 1111 1111 1111 1111 1110 */

        0x67ffffff, /*  96-127   ~}| {zyx wvut srqp onml kjih gfed cba` */
                    /*          0101 0111 1111 1111 1111 1111 1111 1111 */

        0x00000000, /* 128-159                                          */
        0x00000000, /* 160-191                                          */
        0x00000000, /* 192-223                                          */
        0x00000000, /* 224-255                                          */
    };

    return table[c / 32] & (uint32_t)(1 << (c % 32));
}
