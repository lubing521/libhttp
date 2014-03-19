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
#include <errno.h>
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

int
http_parse_size(const char *str, size_t *pval) {
    unsigned long long int ull;

    errno = 0;
    ull = strtoull(str, NULL, 10);
    if (errno) {
        http_set_error("%s", strerror(errno));
        return -1;
    }

    if (ull > SIZE_MAX) {
        http_set_error("size too large");
        return -1;
    }

    *pval = (size_t)ull;
    return 0;
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
