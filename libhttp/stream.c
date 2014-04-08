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
    char *path;
    struct bf_buffer *buf;
};

static struct http_stream_file *http_stream_file_new(int, const char *);

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
http_stream_add_file(struct http_stream *stream, int fd, const char *path) {
    struct http_stream_file *file;

    file = http_stream_file_new(fd, path);
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

        return stream->first_entry ? 1 : 0;
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
http_stream_file_new(int fd, const char *path) {
    struct http_stream_file *file;

    file = http_malloc(sizeof(struct http_stream_file));
    memset(file, 0, sizeof(struct http_stream_file));

    file->fd = fd;
    file->path = http_strdup(path);
    file->buf = bf_buffer_new(0);

    return file;
}

static int
http_stream_file_write(intptr_t arg, int fd, size_t *psz) {
    struct http_stream_file *file;
    ssize_t ret;

    file = (struct http_stream_file *)arg;

    if (bf_buffer_length(file->buf) == 0) {
        ret = bf_buffer_read(file->buf, file->fd, BUFSIZ);
        if (ret == -1) {
            http_set_error("cannot read %s: %s", file->path, strerror(errno));
            return -1;
        }

        if (ret == 0) {
            close(file->fd);
            file->fd = -1;
        }
    }

    if (bf_buffer_length(file->buf) > 0) {
        ret = bf_buffer_write(file->buf, fd);
        if (ret == -1) {
            http_set_error("%s", strerror(errno));
            return -1;
        }

        *psz = (size_t)ret;
    } else {
        *psz = 0;
    }

    if (file->fd == -1 && bf_buffer_length(file->buf) == 0)
        return 0;

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

    memset(file, 0, sizeof(struct http_stream_file));
    http_free(file);
}
