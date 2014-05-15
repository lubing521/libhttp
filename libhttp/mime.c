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

static bool http_is_media_type_char(unsigned char);

struct http_media_type_parameter {
    char *name;  /* case insensitive */
    char *value; /* potentially case sensitive */
};

static void
http_media_type_parameter_init(struct http_media_type_parameter *);
static void
http_media_type_parameter_free(struct http_media_type_parameter *);

struct http_media_type {
    char *string;
    char *base_string;

    char *type;     /* case insensitive */
    char *subtype;  /* case insensitive */

    struct http_media_type_parameter *parameters;
    size_t nb_parameters;
};

static int http_media_type_parse(struct http_media_type *, const char *);
static void http_media_type_format_strings(struct http_media_type *);

static void
http_media_type_add_parameter(struct http_media_type *,
                              const struct http_media_type_parameter *);

struct http_media_type *
http_media_type_new(const char *string) {
    struct http_media_type *media_type;

    media_type = http_malloc0(sizeof(struct http_media_type));

    if (http_media_type_parse(media_type, string) == -1) {
        http_media_type_delete(media_type);
        return NULL;
    }

    http_media_type_format_strings(media_type);
    return media_type;
}

void
http_media_type_delete(struct http_media_type *media_type) {
    if (!media_type)
        return;

    http_free(media_type->string);
    http_free(media_type->base_string);
    http_free(media_type->type);
    http_free(media_type->subtype);

    for (size_t i = 0; i < media_type->nb_parameters; i++)
        http_media_type_parameter_free(media_type->parameters + i);

    memset(media_type, 0, sizeof(struct http_media_type));
    http_free(media_type);
}

const char *
http_media_type_string(const struct http_media_type *media_type) {
    return media_type->string;
}

const char *
http_media_type_base_string(const struct http_media_type *media_type) {
    return media_type->base_string;
}

const char *
http_media_type_get_type(const struct http_media_type *media_type) {
    return media_type->type;
}

const char *
http_media_type_get_subtype(const struct http_media_type *media_type) {
    return media_type->subtype;
}

bool
http_media_type_has_parameter(const struct http_media_type *media_type,
                              const char *name) {
    return http_media_type_get_parameter(media_type, name) != NULL;
}

const char *
http_media_type_get_parameter(const struct http_media_type *media_type,
                              const char *name) {
    for (size_t i = 0; i < media_type->nb_parameters; i++) {
        struct http_media_type_parameter *parameter;

        parameter = media_type->parameters + i;

        if (strcmp(parameter->name, name) == 0)
            return parameter->value;
    }

    return NULL;
}

char *
http_mime_q_encode(const char *string) {
    /* RFC 2047 4.2: Upper case should be used for hexadecimal digits "A"
     * through "F". */
    static const char *hex_digits = "0123456789ABCDEF";

    const char *prefix, *suffix;
    size_t prefix_len, suffix_len;
    const char *iptr;
    char *optr;

    char *encoded_string;
    size_t len;

    prefix = "=?UTF-8?Q?";
    prefix_len = strlen(prefix);

    suffix = "?=";
    suffix_len = strlen(prefix);

    /* Compute the size of the encoded string */
    len = prefix_len;

    iptr = string;
    while (*iptr != '\0') {
        if ((*iptr >= 'a' && *iptr <= 'z')
         || (*iptr >= 'A' && *iptr <= 'Z')
         || (*iptr >= '0' && *iptr <= '9')) {
            len++;
        } else {
            len += 3;
        }

        iptr++;
    }

    len += suffix_len;

    /* Encode the string */
    encoded_string = http_malloc(len + 1);

    optr = encoded_string;
    memcpy(optr, prefix, prefix_len);
    optr += prefix_len;

    iptr = string;
    while (*iptr != '\0') {
        if ((*iptr >= 'a' && *iptr <= 'z')
         || (*iptr >= 'A' && *iptr <= 'Z')
         || (*iptr >= '0' && *iptr <= '9')) {
            *optr++ = *iptr;
        } else {
            unsigned char c;

            c = (unsigned char)*iptr;

            *optr++ = '=';
            *optr++ = hex_digits[c >> 4];
            *optr++ = hex_digits[c & 0xf];
        }

        iptr++;
    }

    memcpy(optr, suffix, suffix_len);
    optr += suffix_len;

    *optr = '\0';
    return encoded_string;
}

void
http_mime_generate_boundary(char boundary[static HTTP_MIME_BOUNDARY_SZ],
                            size_t sz) {
    static char *characters = "abcdefghijklmnopqrstuvwxyz0123456789";

    size_t nb_characters;

    /* TODO Use a real random number generator to generate random bytes and
     * base64 the result. */

    nb_characters = strlen(characters);

    for (size_t i = 0; i < sz - 1; i++)
        boundary[i] = characters[(size_t)rand() % nb_characters];
    boundary[sz - 1] = '\0';
}

static bool
http_is_media_type_char(unsigned char c) {
    static uint32_t table[8] = {
        0x00000000, /*   0- 31                                          */

        0x03ff6800, /*  32- 63  ?>=< ;:98 7654 3210 /.-, +*)( `&%$ #"!  */
                    /*          0000 0011 1111 1111 0110 1000 0000 0000 */

        0x87fffffe, /*  64- 95  _^]\ [ZYX WVUT SRQP ONML KJIH GFED CBA@ */
                    /*          1000 0111 1111 1111 1111 1111 1111 1110 */

        0x07fffffe, /*  96-127   ~}| {zyx wvut srqp onml kjih gfed cba` */
                    /*          0000 0111 1111 1111 1111 1111 1111 1110 */

        0x00000000, /* 128-159                                          */
        0x00000000, /* 160-191                                          */
        0x00000000, /* 192-223                                          */
        0x00000000, /* 224-255                                          */
    };

    return table[c / 32] & (uint32_t)(1 << (c % 32));
}

static void
http_media_type_parameter_init(struct http_media_type_parameter *parameter) {
    memset(parameter, 0, sizeof(struct http_media_type_parameter));
}

static void
http_media_type_parameter_free(struct http_media_type_parameter *parameter) {
    if (!parameter)
        return;

    http_free(parameter->name);
    http_free(parameter->value);

    memset(parameter, 0, sizeof(struct http_media_type_parameter));
}

static int
http_media_type_parse(struct http_media_type *media_type, const char *string) {
    const char *ptr, *start;
    size_t toklen;

    ptr = string;

    /* Type */
    start = ptr;
    for (;;) {
        if (*ptr == '/') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0) {
                http_set_error("empty type");
                return -1;
            }

            media_type->type = http_strndup(start, toklen);
            for (size_t i = 0; i < toklen; i++)
                media_type->type[i] = tolower(media_type->type[i]);

            break;
        } else if (*ptr == '\0') {
            http_set_error("missing subtype");
            return -1;
        } else if (!http_is_media_type_char((unsigned char)*ptr)) {
            http_set_error("invalid character \\%hhu in type",
                           (unsigned char)*ptr);
            return -1;
        } else {
            ptr++;
        }
    }

    ptr++; /* skip '/' */

    /* Subtype */
    start = ptr;
    for (;;) {
        if (*ptr == ';' || *ptr == ' ' || *ptr == '\0') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0) {
                http_set_error("empty subtype");
                return -1;
            }

            media_type->subtype = http_strndup(start, toklen);
            for (size_t i = 0; i < toklen; i++)
                media_type->subtype[i] = tolower(media_type->subtype[i]);

            break;
        } else if (!http_is_media_type_char((unsigned char)*ptr)) {
            http_set_error("invalid character \\%hhu in subtype",
                           (unsigned char)*ptr);
            return -1;
        } else {
            ptr++;
        }
    }

    while (*ptr == ' ')
        ptr++;

    if (*ptr != ';') {
        /* No parameters */
        return 0;
    }

    ptr++; /* skip ';' */

    /* Parameters (optional) */
    for (;;) {
        struct http_media_type_parameter parameter;

        http_media_type_parameter_init(&parameter);

        while (*ptr == ' ')
            ptr++;

        /* Name */
        start = ptr;
        for (;;) {
            if (*ptr == '=' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty parameter name");
                    http_media_type_parameter_free(&parameter);
                    return -1;
                }

                parameter.name = http_strndup(start, toklen);
                for (size_t i = 0; i < toklen; i++)
                    parameter.name[i] = tolower(parameter.name[i]);

                break;
            } else if (!http_is_media_type_char((unsigned char)*ptr)) {
                http_set_error("invalid character \\%hhu in parameter name",
                               (unsigned char)*ptr);
                http_media_type_parameter_free(&parameter);
                return -1;
            } else {
                ptr++;
            }
        }

        if (*ptr != '=') {
            http_set_error("missing separator after parameter name");
            http_media_type_parameter_free(&parameter);
            return -1;
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
                        http_media_type_parameter_free(&parameter);
                        return -1;
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
                        http_media_type_parameter_free(&parameter);
                        return -1;
                    } else {
                        http_set_error("invalid escaped character \\%hhu "
                                       "in parameter value",
                                       (unsigned char)*ptr);
                        http_media_type_parameter_free(&parameter);
                        return -1;
                    }
                } else {
                    ptr++;
                }
            }

            if (*ptr != '"') {
                http_set_error("truncated quoted parameter value");
                http_media_type_parameter_free(&parameter);
                return -1;
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
                        http_media_type_parameter_free(&parameter);
                        return -1;
                    }

                    parameter.value = http_strndup(start, toklen);
                    break;
                } else if (!http_is_media_type_char((unsigned char)*ptr)) {
                    http_set_error("invalid character \\%hhu in parameter name",
                                   (unsigned char)*ptr);
                    http_media_type_parameter_free(&parameter);
                    return -1;
                } else {
                    ptr++;
                }
            }
        }

        http_media_type_add_parameter(media_type, &parameter);

        while (*ptr == ' ')
            ptr++;

        if (*ptr == '\0') {
            break;
        } else if (*ptr != ';') {
            http_set_error("invalid character \\%hhu after parameter value",
                           (unsigned char)*ptr);
            return -1;
        }

        ptr++; /* skip ';' */
    }

    return 0;
}

static void
http_media_type_format_strings(struct http_media_type *media_type) {
    struct bf_buffer *buf;

    buf = bf_buffer_new(0);

    bf_buffer_add_string(buf, media_type->type);
    bf_buffer_add_string(buf, "/");
    bf_buffer_add_string(buf, media_type->subtype);

    media_type->base_string = bf_buffer_dup_string(buf);

    for (size_t i = 0; i < media_type->nb_parameters; i++) {
        struct http_media_type_parameter *parameter;
        const char *value;
        bool need_escaping;

        parameter = media_type->parameters + i;

        bf_buffer_add_string(buf, "; ");
        bf_buffer_add_string(buf, parameter->name);
        bf_buffer_add_string(buf, "=");

        value = parameter->value;
        need_escaping = false;
        for (const char *ptr = value; *ptr != '\0'; ptr++) {
            if (!http_is_media_type_char((unsigned char)*ptr)) {
                need_escaping = true;
                break;
            }
        }

        if (need_escaping) {
            const char *iptr;
            size_t len;
            char *tmp;
            char *optr;

            len = strlen(value);
            tmp = http_malloc(len * 2 + 1);
            optr = tmp;

            iptr = value;
            while (*iptr != '\0') {
                if (*iptr == '"' || *iptr == '\\') {
                    *optr++ = '\\';
                    *optr++ = *iptr++;
                } else {
                    *optr++ = *iptr++;
                }
            }

            *optr = '\0';

            bf_buffer_add_string(buf, "\"");
            bf_buffer_add_string(buf, tmp);
            bf_buffer_add_string(buf, "\"");

            http_free(tmp);
        } else {
            bf_buffer_add_string(buf, parameter->value);
        }
    }

    media_type->string = bf_buffer_dup_string(buf);
    bf_buffer_delete(buf);
}

static void
http_media_type_add_parameter(struct http_media_type *media_type,
                              const struct http_media_type_parameter *param) {
    size_t param_sz;

    param_sz = sizeof(struct http_media_type_parameter);

    if (media_type->nb_parameters == 0) {
        media_type->parameters = http_malloc(param_sz);
    } else {
        size_t nsz;

        nsz = (media_type->nb_parameters + 1) * param_sz;
        media_type->parameters = http_realloc(media_type->parameters, nsz);
    }

    media_type->parameters[media_type->nb_parameters++] = *param;
}
