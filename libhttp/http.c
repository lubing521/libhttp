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

const char *
http_method_to_string(enum http_method method) {
    static const char *strings[] = {
        [HTTP_OPTIONS] = "OPTIONS",
        [HTTP_GET]     = "GET",
        [HTTP_HEAD]    = "HEAD",
        [HTTP_POST]    = "POST",
        [HTTP_PUT]     = "PUT",
        [HTTP_DELETE]  = "DELETE",
        [HTTP_TRACE]   = "TRACE",
        [HTTP_CONNECT] = "CONNECT",
    };
    static size_t nb_strings;

    nb_strings = HTTP_ARRAY_NB_ELEMENTS(strings);
    if (method >= nb_strings)
        return NULL;

    return strings[method];
}
