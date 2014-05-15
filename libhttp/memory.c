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

#include <errno.h>
#include <string.h>

#include "http.h"
#include "internal.h"

#define HTTP_DEFAULT_ALLOCATOR \
    {                        \
        .malloc = malloc,    \
        .free = free,        \
        .calloc = calloc,    \
        .realloc = realloc   \
    }


static const struct http_memory_allocator http_default_allocator =
    HTTP_DEFAULT_ALLOCATOR;

static struct http_memory_allocator http_allocator = HTTP_DEFAULT_ALLOCATOR;

const struct http_memory_allocator *http_default_memory_allocator =
    &http_default_allocator;

void
http_set_memory_allocator(const struct http_memory_allocator *allocator) {
    if (allocator) {
        http_allocator = *allocator;
    } else {
        http_allocator = http_default_allocator;
    }
}

void *
http_malloc(size_t sz) {
    void *ptr;

    ptr = malloc(sz);
    if (!ptr) {
        fprintf(stderr, "cannot allocate %zu bytes: %s\n",
                sz, strerror(errno));
        abort();
    }

    return ptr;
}

void *
http_malloc0(size_t sz) {
    void *ptr;

    ptr = http_malloc(sz);
    memset(ptr, 0, sz);

    return ptr;
}

void *
http_calloc(size_t nb, size_t sz) {
    void *ptr;

    ptr = calloc(nb, sz);
    if (!ptr) {
        fprintf(stderr, "cannot allocate %zu elements of %zu bytes each: %s\n",
                nb, sz, strerror(errno));
        abort();
    }

    return ptr;
}

void *
http_realloc(void *ptr, size_t sz) {
    void *nptr;

    nptr = realloc(ptr, sz);
    if (!nptr) {
        fprintf(stderr, "cannot reallocate %zu bytes: %s\n",
                sz, strerror(errno));
        abort();
    }

    return nptr;
}

void
http_free(void *ptr) {
    free(ptr);
}

