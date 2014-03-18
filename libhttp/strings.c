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

char *
http_strdup(const char *str) {
    return http_strndup(str, strlen(str));
}

char *
http_strndup(const char *str, size_t len) {
    char *nstr;

    nstr = http_malloc(len + 1);
    memcpy(nstr, str, len);
    nstr[len] = '\0';

    return nstr;
}

size_t
http_memspn(const char *buf, size_t sz, const char *accept) {
    uint64_t table[4];
    size_t n;

    if (*accept == '\0')
        return sz;

    table[0] = 0;
    table[1] = 0;
    table[2] = 0;
    table[3] = 0;

    do {
        uint8_t c;

        c = (uint8_t)*accept;
        table[c >> 6] |= (1 << (c & 63));

        accept++;
    } while (*accept != '\0');

    n = 0;
    for (size_t i = 0; i < sz; i++) {
        uint8_t c;

        c = (uint8_t)buf[i];
        if (!(table[c >> 6] & (1 << (c & 63))))
            return n;
    }

    return sz;
}

size_t
http_memcspn(const char *buf, size_t sz, const char *reject) {
    size_t reject_sz, n;
    uint64_t table[4];

    if (*reject == '\0')
        return sz;

    reject_sz = strlen(reject);
    if (reject_sz == 1) {
        const char *ptr;

        ptr = memchr(buf, reject[0], sz);
        if (!ptr)
            return sz;

        return (size_t)(ptr - buf);
    }

    table[0] = 0;
    table[1] = 0;
    table[2] = 0;
    table[3] = 0;

    do {
        uint8_t c;

        c = (uint8_t)*reject;
        table[c >> 6] |= (1 << (c & 63));

        reject++;
    } while (*reject != '\0');

    n = 0;
    for (size_t i = 0; i < sz; i++) {
        uint8_t c;

        c = (uint8_t)buf[i];
        if (table[c >> 6] & (1 << (c & 63)))
            return n;
    }

    return sz;
}

#ifndef NDEBUG
const char *
http_fmt_data(const char *buf, size_t sz) {
    static __thread char tmp[1024];
    const char *iptr;
    char *optr;
    size_t ilen, olen;

    iptr = buf;
    ilen = sz;

    optr = tmp;
    olen = sizeof(tmp) - 1;

    while (ilen > 0 && olen > 0) {
        if (isprint((unsigned char)*iptr)) {
            *optr++ = *iptr;
            olen--;
        } else {
            int ret;

            ret = snprintf(optr, olen, "\\%hhu", (unsigned char)*iptr);
            if (ret == -1 || (size_t)ret >= olen)
                break;

            optr += ret;
            olen -= (size_t)ret;
        }

        iptr++;
        ilen--;
    }

    *optr = '\0';
    return tmp;
}
#endif
