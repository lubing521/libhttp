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

#include <unistd.h>

#include "http.h"
#include "internal.h"

struct http_stream_entry {
    intptr_t arg;

    struct http_stream_functions functions;

    struct http_stream_entry *prev;
    struct http_stream_entry *next;
};

static struct http_stream_entry *http_stream_entry_new(intptr_t);
static void http_stream_entry_delete(struct http_stream_entry *);

struct http_stream {
    struct http_stream_entry *first_entry;
    struct http_stream_entry *last_entry;
};

static void http_stream_remove_first_entry(struct http_stream *);


static int http_stream_buffer_write(intptr_t, int, size_t *);
static void http_stream_buffer_delete(intptr_t);

struct http_stream_functions http_stream_buffer_functions = {
    .delete_func = http_stream_buffer_delete,
    .write_func  = http_stream_buffer_write,
};


struct http_stream_file {
    int fd;
    size_t file_sz;
    char *path;
    struct bf_buffer *buf;

    struct http_ranges ranges;
    size_t range_idx;        /* current range */
    size_t range_read_sz;    /* number of bytes read in the current range */

    bool done_reading;
};

static struct http_stream_file *http_stream_file_new(int, size_t, const char *);

static int http_stream_file_write(intptr_t, int, size_t *);
static void http_stream_file_delete(intptr_t);

struct http_stream_functions http_stream_file_functions = {
    .delete_func = http_stream_file_delete,
    .write_func  = http_stream_file_write,
};


struct http_stream *
http_stream_new(void) {
    struct http_stream *stream;

    stream = http_malloc(sizeof(struct http_stream));
    memset(stream, 0, sizeof(struct http_stream));

    return stream;
}

void
http_stream_delete(struct http_stream *stream) {
    struct http_stream_entry *entry;

    if (!stream)
        return;

    entry = stream->first_entry;
    while (entry) {
        struct http_stream_entry *next;

        next = entry->next;
        http_stream_entry_delete(entry);
        entry = next;
    }

    memset(stream, 0, sizeof(struct http_stream));
    http_free(stream);
}

void
http_stream_add_entry(struct http_stream *stream, intptr_t arg,
                       const struct http_stream_functions *functions) {
    struct http_stream_entry *entry;

    entry = http_stream_entry_new(arg);
    entry->functions = *functions;

    entry->prev = stream->last_entry;
    entry->next = NULL;

    if (stream->last_entry)
        stream->last_entry->next = entry;

    if (!stream->first_entry)
        stream->first_entry = entry;

    stream->last_entry = entry;
}

void
http_stream_add_data(struct http_stream *stream, const void *data, size_t sz) {
    struct http_stream_entry *entry;
    struct bf_buffer *buf;

    entry = stream->last_entry;
    if (entry && entry->functions.write_func == http_stream_buffer_write) {
        buf = (struct bf_buffer *)entry->arg;
    } else {
        buf = bf_buffer_new(0);
        http_stream_add_entry(stream, (intptr_t)buf,
                              &http_stream_buffer_functions);
        entry = stream->last_entry;
    }

    bf_buffer_add(buf, data, sz);
}

void
http_stream_add_vprintf(struct http_stream *stream,
                        const char *fmt, va_list ap) {
    struct http_stream_entry *entry;
    struct bf_buffer *buf;

    entry = stream->last_entry;
    if (entry && entry->functions.write_func == http_stream_buffer_write) {
        buf = (struct bf_buffer *)entry->arg;
    } else {
        buf = bf_buffer_new(0);
        http_stream_add_entry(stream, (intptr_t)buf,
                              &http_stream_buffer_functions);
        entry = stream->last_entry;
    }

    bf_buffer_add_vprintf(buf, fmt, ap);
}

void
http_stream_add_printf(struct http_stream *stream, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    http_stream_add_vprintf(stream, fmt, ap);
    va_end(ap);
}

void
http_stream_add_file(struct http_stream *stream, int fd, size_t file_sz,
                     const char *path) {
    struct http_stream_file *file;
    struct http_range range;

    memset(&range, 0, sizeof(struct http_range));
    range.has_first = true;
    range.first = 0;
    range.has_last = true;
    range.last = file_sz - 1;

    file = http_stream_file_new(fd, file_sz, path);

    http_ranges_init(&file->ranges);
    http_ranges_add_range(&file->ranges, &range);

    http_stream_add_entry(stream, (intptr_t)file, &http_stream_file_functions);
}

void
http_stream_add_partial_file(struct http_stream *stream,
                             int fd, size_t file_sz, const char *path,
                             const struct http_ranges *ranges) {
    struct http_stream_file *file;

    file = http_stream_file_new(fd, file_sz, path);
    file->ranges = *ranges;

    http_stream_add_entry(stream, (intptr_t)file, &http_stream_file_functions);
}

int
http_stream_write(struct http_stream *stream, int fd, size_t *psz) {
    struct http_stream_entry *entry;
    int ret;

    entry = stream->first_entry;
    if (!entry)
        return 0;

    ret = entry->functions.write_func(entry->arg, fd, psz);
    if (ret <= 0) {
        /* Either something went wrong or the stream entry was entirely
         * consumed. */
        http_stream_remove_first_entry(stream);
        http_stream_entry_delete(entry);

        if (ret == -1) {
            return -1;
        } else {
            return stream->first_entry ? 1 : 0;
        }
    }

    return 1;
}

static struct http_stream_entry *
http_stream_entry_new(intptr_t arg) {
    struct http_stream_entry *entry;

    entry = http_malloc(sizeof(struct http_stream_entry));
    memset(entry, 0, sizeof(struct http_stream_entry));

    entry->arg = arg;

    return entry;
}

static void
http_stream_entry_delete(struct http_stream_entry *entry) {
    if (!entry)
        return;

    if (entry->functions.delete_func)
        entry->functions.delete_func(entry->arg);

    memset(entry, 0, sizeof(struct http_stream_entry));
    http_free(entry);
}

static void
http_stream_remove_first_entry(struct http_stream *stream) {
    if (!stream->first_entry)
        return;

    if (stream->first_entry->next)
        stream->first_entry->next->prev = NULL;

    if (stream->first_entry == stream->last_entry) {
        stream->first_entry = NULL;
        stream->last_entry = NULL;
    } else {
        stream->first_entry = stream->first_entry->next;
    }
}

static int
http_stream_buffer_write(intptr_t arg, int fd, size_t *psz) {
    struct bf_buffer *buf;
    ssize_t ret;

    buf = (struct bf_buffer *)arg;

    ret = bf_buffer_write(buf, fd);
    if (ret == -1) {
        http_set_error("%s", bf_get_error());
        return -1;
    }

    *psz = (size_t)ret;

    if (bf_buffer_length(buf) == 0)
        return 0;

    return 1;
}

static void
http_stream_buffer_delete(intptr_t arg) {
    bf_buffer_delete((struct bf_buffer *)arg);
}

static struct http_stream_file *
http_stream_file_new(int fd, size_t file_sz, const char *path) {
    struct http_stream_file *file;

    file = http_malloc(sizeof(struct http_stream_file));
    memset(file, 0, sizeof(struct http_stream_file));

    file->fd = fd;
    file->file_sz = file_sz;
    file->path = http_strdup(path);
    file->buf = bf_buffer_new(0);

    return file;
}

static int
http_stream_file_write(intptr_t arg, int fd, size_t *psz) {
    struct http_stream_file *file;
    ssize_t ret;

    file = (struct http_stream_file *)arg;

    /* If we have no data ready to write, we need to read the file */
    if (bf_buffer_length(file->buf) == 0) {
        struct http_range *range;
        size_t range_sz, read_sz;

        range = file->ranges.ranges + file->range_idx;
        range_sz = range->last - range->first + 1;
        //read_sz = MIN(range_sz - file->range_read_sz, (size_t)BUFSIZ);
        read_sz = MIN(range_sz - file->range_read_sz, (size_t)50);

        /* If we are just starting to read the current range, we need to move
         * to the right offset */
        if (file->range_read_sz == 0) {
            if (lseek(file->fd, (off_t)range->first, SEEK_SET) == -1) {
                http_set_error("cannot seek %s: %s",
                               file->path, strerror(errno));
                return -1;
            }
        }

        ret = bf_buffer_read(file->buf, file->fd, read_sz);
        if (ret == -1) {
            http_set_error("cannot read %s: %s", file->path, strerror(errno));
            return -1;
        }

        file->range_read_sz += (size_t)ret;

        if (ret == 0 && file->range_read_sz < range_sz) {
            if (file->range_read_sz > 0) {
                /* Invalid range */
                http_set_error("range ends after the end of the file");
                return -1;
            }
        }

        if (file->range_read_sz == range_sz) {
            /* We entirely read the current range */
            if (file->range_idx == file->ranges.nb_ranges - 1) {
                /* We read all ranges */
                file->done_reading = true;
                close(file->fd);
                file->fd = -1;
            } else {
                /* Next range */
                file->range_idx++;
                file->range_read_sz = 0;
            }
        }
    }

    /* Write as much as possible */
    ret = bf_buffer_write(file->buf, fd);
    if (ret == -1) {
        http_set_error("%s", strerror(errno));
        return -1;
    }

    if (bf_buffer_length(file->buf) == 0 && file->done_reading) {
        /* We read and wrote all ranges */
        return 0;
    }

    *psz = (size_t)ret;
    return 1;
}

static void
http_stream_file_delete(intptr_t arg) {
    struct http_stream_file *file;

    file = (struct http_stream_file *)arg;
    if (!file)
        return;

    http_free(file->path);
    if (file->fd >= 0)
        close(file->fd);
    bf_buffer_delete(file->buf);

    http_ranges_free(&file->ranges);

    memset(file, 0, sizeof(struct http_stream_file));
    http_free(file);
}
