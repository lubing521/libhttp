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

static int http_uri_parse(const char *, struct http_uri *);
static char *http_uri_decode_component(const char *, size_t);

static int http_read_hex_digit(unsigned char, int *);

static bool http_uri_is_scheme_char(unsigned char);
static bool http_uri_is_ipv4_addr_char(unsigned char);
static bool http_uri_is_ipv6_addr_char(unsigned char);
static bool http_uri_is_port_char(unsigned char);

struct http_uri *
http_uri_new(const char *str) {
    struct http_uri *uri;

    uri = http_malloc(sizeof(struct http_uri));
    if (!uri)
        return NULL;

    if (http_uri_parse(str, uri) == -1) {
        http_uri_delete(uri);
        return NULL;
    }

    return uri;
}

void
http_uri_delete(struct http_uri *uri) {
    if (!uri)
        return;

    http_free(uri->scheme);
    http_free(uri->user);
    http_free(uri->password);
    http_free(uri->host);
    http_free(uri->port);
    http_free(uri->path);
    http_free(uri->query);

    memset(uri, 0, sizeof(struct http_uri));
    http_free(uri);
}

static int
http_uri_parse(const char *str, struct http_uri *uri) {
    const char *ptr, *start, *colon;
    size_t toklen;

    memset(uri, 0, sizeof(struct http_uri));

    ptr = str;

    if (*ptr == '\0') {
        http_set_error("empty string");
        goto error;
    }

    /* Scheme */
    start = ptr;

    if (*ptr == '/') {
        goto path;
    } else if (!(*ptr >= 'a' && *ptr <= 'z')
            && !(*ptr >= 'A' && *ptr <= 'Z')
            && *ptr != '%') {
        http_set_error("invalid first character \\%hhu in scheme",
                       (unsigned char)*ptr);
        goto error;
    }

    for (;;) {
        if (*ptr == ':' || *ptr == '\0') {
            toklen = (size_t)(ptr - start);
            uri->scheme = http_uri_decode_component(start, toklen);
            if (!uri->scheme)
                goto error;

            break;
        } else if (!http_uri_is_scheme_char((unsigned char)*ptr)
                && *ptr != '%') {
            http_set_error("invalid character \\%hhu in scheme",
                           (unsigned char)*ptr);
            goto error;
        }

        ptr++;
    }

    /* Skip '://' */
    if (ptr[0] != ':' || ptr[1] != '/' || ptr[2] != '/') {
        http_set_error("invalid characters after scheme");
        goto error;
    }

    ptr += 3;

    /* User (optional) */
    start = ptr;
    colon = NULL;
    while (*ptr != '\0') {
        if (*ptr == ':') {
            colon = ptr;
        } else if (*ptr == '@') {
            if (colon) {
                toklen = (size_t)(colon - start);
            } else {
                toklen = (size_t)(ptr - start);
            }

            uri->user = http_uri_decode_component(start, toklen);
            if (!uri->user)
                goto error;

            if (colon)
                ptr = colon;
            break;
        } else if (*ptr == '/') {
            /* End of authority, no user found */
            break;
        }

        ptr++;
    }

    if (!uri->user) {
        /* Since we did not find a username, we backtrack to read the host. */
        ptr = start;
    }

    /* Password (optional) */
    if (uri->user && *ptr == ':') {
        start = ptr;

        for (;;) {
            if (*ptr == '@' || *ptr == '\0') {
                toklen = (size_t)(ptr - start - 1);
                if (toklen == 0) {
                    http_set_error("empty password");
                    goto error;
                }

                uri->password = http_uri_decode_component(start + 1, toklen);
                if (!uri->password)
                    goto error;

                break;
            } else if (*ptr == '/') {
                /* End of authority, no password found */
                break;
            }

            ptr++;
        }

        if (!uri->password) {
            http_set_error("empty password");
            goto error;
        }
    }

    if (uri->user) {
        /* Skip '@' */
        ptr++;
    }

    /* Host */
    start = ptr;
    if (*start >= '0' && *start <= '9') {
        /* IPv4 address */
        for (;;) {
            if (*ptr == '/' || *ptr == ':' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty host");
                    goto error;
                }

                uri->host = http_uri_decode_component(start, toklen);
                if (!uri->host)
                    goto error;

                break;
            } else if (!http_uri_is_ipv4_addr_char((unsigned char)*ptr)) {
                http_set_error("invalid character \\%hhu in ipv4 address",
                               (unsigned char)*ptr);
                goto error;
            }

            ptr++;
        }
    } else if (*start == '[') {
        ptr++; /* '[' */
        start = ptr;

        /* IPv6 address */
        for (;;) {
            if (*ptr == ']') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty host");
                    goto error;
                }

                uri->host = http_uri_decode_component(start, toklen);
                if (!uri->host)
                    goto error;

                ptr++; /* ']' */

                break;
            } else if (*ptr == '\0') {
                http_set_error("truncated ipv6 address");
                goto error;
            } else if (!http_uri_is_ipv6_addr_char((unsigned char)*ptr)) {
                http_set_error("invalid character \\%hhu in ipv6 address",
                               (unsigned char)*ptr);
                goto error;
            }

            ptr++;
        }
    } else {
        /* Hostname */
        for (;;) {
            if (*ptr == '/' || *ptr == ':' || *ptr == '#' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty host");
                    goto error;
                }

                uri->host = http_uri_decode_component(start, toklen);
                if (!uri->host)
                    goto error;

                break;
            }

            ptr++;
        }
    }

    /* Port (optional) */
    if (*ptr == ':') {
        ptr++;

        start = ptr;

        for (;;) {
            if (*ptr == '/' || *ptr == '#' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty port");
                    goto error;
                }

                uri->port = http_uri_decode_component(start, toklen);
                if (!uri->port)
                    goto error;

                break;
            } else if (!http_uri_is_port_char((unsigned char)*ptr)) {
                http_set_error("invalid character \\%hhu in port",
                               (unsigned char)*ptr);
                goto error;
            }

            ptr++;
        }
    }

    /* Path (optional, default '/') */
path:
    if (*ptr == '/') {
        start = ptr;

        for (;;) {
            if (*ptr == '?' || *ptr == '#' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                uri->path = http_uri_decode_component(start, toklen);
                if (!uri->path)
                    goto error;

                break;
            }

            ptr++;
        }
    } else {
        uri->path = http_strdup("/");
        if (!uri->path)
            goto error;
    }

    /* Query (optional) */
    if (*ptr == '?') {
        ptr++;

        start = ptr;

        while (*ptr != '#' && *ptr != '\0')
            ptr++;

        toklen = (size_t)(ptr - start);
        uri->query = http_uri_decode_component(start, toklen);
        if (!uri->query)
            goto error;
    }

    return 1;

error:
    return -1;
}

char *
http_uri_decode_query_component(const char *str, size_t sz) {
    const char *iptr;
    char *component, *optr;
    size_t str_length, ilen;

    str_length = strlen(str);
    component = http_malloc(str_length + 1);
    if (!component)
        return NULL;

    iptr = str;
    ilen = sz;

    optr = component;

    while (ilen > 0) {
        if (*iptr == '%') {
            int d1, d2;

            if (ilen < 3) {
                http_set_error("truncated escape sequence");
                goto error;
            }

            if (http_read_hex_digit((unsigned char)iptr[1], &d1) == -1
             || http_read_hex_digit((unsigned char)iptr[2], &d2) == -1) {
                http_set_error("invalid escape sequence");
                goto error;
            }

            *optr++ = (d1 << 4) | d2;
            iptr += 3;
            ilen -= 3;
        } else if (*iptr == '+') {
            *optr++ = ' ';
            iptr++;
            ilen--;
        } else {
            *optr++ = *iptr++;
            ilen--;
        }
    }

    *optr = '\0';
    return component;

error:
    http_free(component);
    return NULL;
}

static char *
http_uri_decode_component(const char *str, size_t sz) {
    const char *iptr;
    char *component, *optr;
    size_t str_length, ilen;

    str_length = strlen(str);
    component = http_malloc(str_length + 1);
    if (!component)
        return NULL;

    iptr = str;
    ilen = sz;

    optr = component;

    while (ilen > 0) {
        if (*iptr == '%') {
            int d1, d2;

            if (ilen < 3) {
                http_set_error("truncated escape sequence");
                goto error;
            }

            if (http_read_hex_digit((unsigned char)iptr[1], &d1) == -1
             || http_read_hex_digit((unsigned char)iptr[2], &d2) == -1) {
                http_set_error("invalid escape sequence");
                goto error;
            }

            *optr++ = (d1 << 4) | d2;
            iptr += 3;
            ilen -= 3;
        } else {
            *optr++ = *iptr++;
            ilen--;
        }
    }

    *optr = '\0';
    return component;

error:
    http_free(component);
    return NULL;
}

static int
http_read_hex_digit(unsigned char c, int *val) {
    if (c >= '0' && c <= '9') {
        *val = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        *val = 10 + c - 'a';
    } else if (c >= 'A' && c <= 'F') {
        *val = 10 + c - 'A';
    } else {
        return -1;
    }

    return 0;
}

static bool
http_uri_is_scheme_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '+' || c == '-' || c == '.';
}

static bool
http_uri_is_ipv4_addr_char(unsigned char c) {
    return (c >= '0' && c <= '9') || c == '.';
}

static bool
http_uri_is_ipv6_addr_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == ':';
}

static bool
http_uri_is_port_char(unsigned char c) {
    return c >= '0' && c <= '9';
}
