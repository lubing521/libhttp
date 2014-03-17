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

#ifndef HTTP_INTERNAL_H
#define HTTP_INTERNAL_H

#include <stdlib.h>

/* Misc */
#define HTTP_ARRAY_NB_ELEMENTS(array_) (sizeof(array_) / sizeof(array_[0]))

/* Error handling */
#define HTTP_ERROR_BUFSZ 1024

void http_set_error(const char *, ...)
    __attribute__((format(printf, 1, 2)));

/* Memory */
void *http_malloc(size_t);
void *http_calloc(size_t, size_t);
void *http_realloc(void *, size_t);
void http_free(void *);

/* Strings */
char *http_strdup(const char *);
char *http_strndup(const char *, size_t);

/* Protocol */
enum http_parsing_state {
    HTTP_PARSING_BEFORE_START_LINE,
    HTTP_PARSING_BEFORE_HEADER,
    HTTP_PARSING_BEFORE_BODY,

    HTTP_PARSING_DONE,
};

struct http_msg {
    enum http_msg_type type;

    union {
        struct {
            enum http_version version;
            enum http_method method;
            char *uri;
        } request;

        struct {
            enum http_version version;
            enum http_status_code status_code;
            char *reason_phrase;
        } response;
    } u;

    /* TODO Headers */
    /* TODO Body */

    enum http_parsing_state parsing_state;
};

void http_msg_free(struct http_msg *);

int http_msg_parse(struct http_msg *, struct bf_buffer *,
                   const struct http_cfg *,
                   enum http_status_code *);
int http_msg_parse_request_line(struct http_msg *, struct bf_buffer *,
                                const struct http_cfg *,
                                enum http_status_code *);
int http_msg_parse_status_line(struct http_msg *, struct bf_buffer *,
                               const struct http_cfg *,
                               enum http_status_code *);
int http_msg_parse_headers(struct http_msg *, struct bf_buffer *,
                           const struct http_cfg *,
                           enum http_status_code *);
int http_msg_parse_body(struct http_msg *, struct bf_buffer *,
                        const struct http_cfg *,
                        enum http_status_code *);

#endif
