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

static int http_range_cmp(const void *, const void *);

void
http_ranges_init(struct http_ranges *set) {
    memset(set, 0, sizeof(struct http_ranges));
}

void
http_ranges_free(struct http_ranges *set) {
    if (!set)
        return;

    http_free(set->ranges);

    memset(set, 0, sizeof(struct http_ranges));
}

int
http_ranges_parse(struct http_ranges *set, const char *str) {
    const char *ptr, *start;
    size_t toklen;

    http_ranges_init(set);

    ptr = str;

    /* Unit */
    while (*ptr == ' ' || *ptr == '\t')
        ptr++;

    if (*ptr == '\0') {
        http_set_error("missing unit");
        goto error;
    }

    start = ptr;
    for (;;) {
        if (*ptr == '\0') {
            http_set_error("truncated unit");
            goto error;
        } else if (*ptr == '=' || *ptr == ' ' || *ptr == '\t') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0) {
                http_set_error("empty unit");
                goto error;
            }

            if (toklen == strlen("bytes")
             && memcmp(start, "bytes", toklen) == 0) {
                set->unit = HTTP_RANGE_UNIT_BYTES;
            } else {
                http_set_error("unknown unit");
                goto error;
            }

            break;
        }

        ptr++;
    }

    while (*ptr == ' ' || *ptr == '\t')
        ptr++;

    if (*ptr == '\0') {
        http_set_error("truncated range set");
        goto error;
    }

    ptr++; /* skip '=' */

    /* Ranges */
    for (;;) {
        struct http_range range;

        memset(&range, 0, sizeof(struct http_range));

        while (*ptr == ' ' || *ptr == '\t')
            ptr++;

        if (*ptr == '\0') {
            http_set_error("truncated range set");
            goto error;
        }

        if (!((*ptr >= '0' && *ptr <= '9') || *ptr == '-')) {
            http_set_error_invalid_character((unsigned char)*ptr, " in range");
            goto error;
        }

        /* First byte */
        if (*ptr >= '0' && *ptr <= '9') {
            char tmp[21];

            start = ptr;
            while (*ptr >= '0' && *ptr <= '9')
                ptr++;

            toklen = (size_t)(ptr - start);
            if (toklen >= sizeof(tmp)) {
                http_set_error("offset too large");
                goto error;
            }

            memcpy(tmp, start, toklen);
            tmp[toklen] = '\0';

            if (http_parse_size(tmp, &range.first) == -1) {
                http_set_error("invalid offset: %s", http_get_error());
                goto error;
            }

            range.has_first = true;

            while (*ptr == ' ' || *ptr == '\t')
                ptr++;

            if (*ptr == '\0') {
                http_set_error("truncated range");
                goto error;
            }
        }

        /* Separator */
        if (*ptr != '-') {
            http_set_error_invalid_character((unsigned char)*ptr,
                                             " after range start");
            goto error;
        }

        ptr++; /* skip '-' */

        while (*ptr == ' ' || *ptr == '\t')
            ptr++;

        if (*ptr == ',' || *ptr == '\0') {
            /* No last byte */
            if (!range.has_first) {
                http_set_error("missing both start and end in range");
                goto error;
            }

            http_ranges_add_range(set, &range);

            if (*ptr == ',') {
                ptr++; /* skip ',' */
                continue;
            } else if (*ptr == '\0') {
                break;
            }
        }

        /* Last byte */
        if (*ptr >= '0' && *ptr <= '9') {
            char tmp[21];

            start = ptr;
            while (*ptr >= '0' && *ptr <= '9')
                ptr++;

            toklen = (size_t)(ptr - start);
            if (toklen >= sizeof(tmp)) {
                http_set_error("offset too large");
                goto error;
            }

            memcpy(tmp, start, toklen);
            tmp[toklen] = '\0';

            if (http_parse_size(tmp, &range.last) == -1) {
                http_set_error("invalid offset: %s", http_get_error());
                goto error;
            }

            /* RFC 2616: 14.35.1: If the last-byte-pos value is present, it
             * MUST be greater than or equal to the first-byte-pos in that
             * byte-range-spec, or the byte-range-spec is syntactically
             * invalid. The recipient of a byte-range-set that includes one or
             * more syntactically invalid byte-range-spec values MUST ignore
             * the header field that includes that byte-range-set. */
            if (range.has_first && range.last < range.first) {
                http_set_error("range end before range start");
                goto error;
            }

            range.has_last = true;
        } else {
            http_set_error_invalid_character((unsigned char)*ptr,
                                             " in range end");
            goto error;
        }

        http_ranges_add_range(set, &range);

        while (*ptr == ' ' || *ptr == '\t')
            ptr++;

        if (*ptr == ',') {
            ptr++; /* skip ',' */
        } else if (*ptr == '\0') {
            break;
        }
    }

    return 0;

error:
    http_ranges_free(set);
    return -1;
}

void
http_ranges_simplify(const struct http_ranges *set, size_t entity_sz,
                     struct http_ranges *dest) {
    memset(dest, 0, sizeof(struct http_ranges));

    dest->unit = set->unit;

    dest->ranges = http_malloc(set->nb_ranges * sizeof(struct http_range));
    memcpy(dest->ranges, set->ranges, set->nb_ranges * sizeof(struct http_range));
    dest->nb_ranges = set->nb_ranges;

    /* Replace partial ranges with complete ones and clamp offsets */
    for (size_t i = 0; i < dest->nb_ranges; i++) {
        struct http_range *range;

        range = dest->ranges + i;

        if (!range->has_first) {
            range->has_first = true;

            if (range->last > entity_sz) {
                range->first = 0;
            } else {
                range->first = entity_sz - range->last;
            }

            range->last = entity_sz - 1;
        }

        if (!range->has_last) {
            range->has_last = true;
            range->last = entity_sz - 1;
        }

        if (range->first < entity_sz && range->last >= entity_sz)
            range->last = entity_sz - 1;
    }

    /* Join ranges which overlap */
    if (dest->nb_ranges >= 2) {
        qsort(dest->ranges, dest->nb_ranges, sizeof(struct http_range),
              http_range_cmp);

        for (size_t i = 0; i < dest->nb_ranges - 1; i++) {
            struct http_range *range;
            size_t nb_merged;

            range = dest->ranges + i;

            /* Count how many ranges can be merged with the current one */
            nb_merged = 0;
            for (size_t j = i + 1; j < dest->nb_ranges; j++) {
                struct http_range *other_range;

                other_range = dest->ranges + j;

                if (range->last >= other_range->first) {
                    if (other_range->last > range->last)
                        range->last = other_range->last;
                    nb_merged++;
                } else {
                    break;
                }
            }

            /* Merge */
            if (nb_merged > 0) {
                size_t nb_moved;

                nb_moved = dest->nb_ranges - i - 1 - nb_merged;
                if (nb_moved > 0) {
                    memmove(range + 1, range + 1 + nb_merged,
                            nb_moved * sizeof(struct http_range));
                }

                dest->nb_ranges -= nb_merged;
            }
        }

        dest->ranges = http_realloc(dest->ranges,
                                    dest->nb_ranges * sizeof(struct http_range));
    }
}

bool
http_ranges_is_satisfiable(const struct http_ranges *set,
                           size_t entity_sz) {
    for (size_t i = 0; i < set->nb_ranges; i++) {
        struct http_range *range;

        range = set->ranges + i;

        if (range->first < entity_sz)
            return true;
    }

    return false;
}

size_t
http_ranges_length(const struct http_ranges *set) {
    size_t length;

    /* XXX Result is only correct if the range has been simplified */

    length = 0;
    for (size_t i = 0; i < set->nb_ranges; i++) {
        struct http_range *range;

        range = set->ranges + i;

        length += range->last - range->first + 1;
    }

    return length;
}

void
http_ranges_add_range(struct http_ranges *set,
                      const struct http_range *range) {
    if (set->nb_ranges == 0) {
        set->ranges = http_malloc(sizeof(struct http_range));
    } else {
        size_t nsz;

        nsz = (set->nb_ranges + 1) * sizeof(struct http_range);
        set->ranges = http_realloc(set->ranges, nsz);
    }

    set->ranges[set->nb_ranges++] = *range;
}

static int
http_range_cmp(const void *arg1, const void *arg2) {
    struct http_range *r1, *r2;

    r1 = (struct http_range *)arg1;
    r2 = (struct http_range *)arg2;

    if (r1->first != r2->first) {
        return r1->first - r2->first;
    } else {
        return r1->last - r2->last;
    }
    return 0;
}
