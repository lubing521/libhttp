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

size_t http_memspn(const char *, size_t, const char *);
size_t http_memcspn(const char *, size_t, const char *);

#ifndef NDEBUG
const char *http_fmt_data(const char *, size_t);
#endif

/* Protocol */
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
};

void http_msg_free(struct http_msg *);

enum http_parser_state {
    HTTP_PARSER_START,
    HTTP_PARSER_HEADER,
    HTTP_PARSER_BODY,

    HTTP_PARSER_ERROR,
    HTTP_PARSER_DONE,
};

struct http_parser {
    enum http_parser_state state;

    struct http_msg msg;
    enum http_status_code status_code;
    char errmsg[HTTP_ERROR_BUFSZ];

    const struct http_cfg *cfg;
};

int http_parser_init(struct http_parser *);
void http_parser_free(struct http_parser *);

void http_parser_fail(struct http_parser *, enum http_status_code,
                      const char *, ...)
    __attribute__((format(printf, 3, 4)));

int http_msg_parse(struct bf_buffer *, struct http_parser *);
int http_msg_parse_request_line(struct bf_buffer *, struct http_parser *);
int http_msg_parse_status_line(struct bf_buffer *, struct http_parser *);
int http_msg_parse_headers(struct bf_buffer *, struct http_parser *);
int http_msg_parse_body(struct bf_buffer *, struct http_parser *);

#endif
