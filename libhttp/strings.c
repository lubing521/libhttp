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

char *
http_iconv(const char *str, const char *from, const char *to) {
    const char *input;
    char *output;
    size_t ilen, olen, str_length;
    iconv_t conv;

    conv = iconv_open(to, from);
    if (conv == (iconv_t)-1) {
        http_set_error("cannot create iconv conversion descriptor "
                       "from %s to %s: %s",
                       from, to, strerror(errno));
        return NULL;
    }

    str_length = strlen(str);

    olen = str_length;
    output = http_malloc(olen + 1);
    if (!output) {
        iconv_close(conv);
        return NULL;
    }

    for (;;) {
        size_t ret;

        char *tmp;
        size_t tmp_len;

        input = str;
        ilen = str_length;

        tmp = output;
        tmp_len = olen;

#ifdef HTTP_PLATFORM_FREEBSD
        ret = iconv(conv, (const char **)&input, &ilen, &tmp, &tmp_len);
#else
        ret = iconv(conv, (char **)&input, &ilen, &tmp, &tmp_len);
#endif

        if (ret == (size_t)-1) {
            if (errno == E2BIG) {
                char *noutput;

                olen *= 2;
                noutput = http_realloc(output, olen + 1);
                if (!noutput) {
                    http_free(output);
                    iconv_close(conv);
                    return NULL;
                }

                output = noutput;
                continue;
            } else {
                http_set_error("cannot convert string from %s to %s: %s",
                               from, to, strerror(errno));
                printf("%s\n", http_get_error());
                http_free(output);
                iconv_close(conv);
                return NULL;
            }
        }

        *tmp = '\0';
        break;
    }

    iconv_close(conv);
    return output;
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
