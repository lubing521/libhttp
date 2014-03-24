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

#include <buffer.h>
#include <hashtable.h>

/* Misc */
#define HTTP_ARRAY_NB_ELEMENTS(array_) (sizeof(array_) / sizeof(array_[0]))

int http_now_ms(uint64_t *);

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

int http_parse_size(const char *, size_t *);

#ifndef NDEBUG
const char *http_fmt_data(const char *, size_t);
#endif

/* Protocol */
char *http_decode_header_value(const char *, size_t);

struct http_header {
    char *name;
    char *value;
};

void http_header_init(struct http_header *);
void http_header_free(struct http_header *);

struct http_msg {
    enum http_msg_type type;
    enum http_version version;

    union {
        struct {
            enum http_method method;
            char *uri;
        } request;

        struct {
            enum http_status_code status_code;
            char *reason_phrase;
        } response;
    } u;

    struct http_uri *request_uri;

    struct http_header *headers;
    size_t nb_headers;
    size_t headers_sz;

    char *body;
    size_t body_sz;

    bool has_content_length;
    size_t content_length;

    int connection_options;
};

void http_msg_init(struct http_msg *);
void http_msg_free(struct http_msg *);

int http_msg_add_header(struct http_msg *, const struct http_header *);

bool http_msg_can_have_body(const struct http_msg *);

/* Misc */
int http_token_list_get_next_token(const char *, char *, size_t, const char **);

/* Parser */
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

int http_parser_init(struct http_parser *, enum http_msg_type,
                     const struct http_cfg *);
void http_parser_free(struct http_parser *);
int http_parser_reset(struct http_parser *, enum http_msg_type,
                      const struct http_cfg *);

void http_parser_fail(struct http_parser *, enum http_status_code,
                      const char *, ...)
    __attribute__((format(printf, 3, 4)));

int http_msg_parse(struct bf_buffer *, struct http_parser *);
int http_msg_parse_request_line(struct bf_buffer *, struct http_parser *);
int http_msg_parse_status_line(struct bf_buffer *, struct http_parser *);
int http_msg_parse_headers(struct bf_buffer *, struct http_parser *);
int http_msg_parse_body(struct bf_buffer *, struct http_parser *);

/* Connections */
struct http_connection {
    struct http_server *server;

    int sock;

    struct event *ev_read;
    struct event *ev_write;

    struct bf_buffer *rbuf;
    struct bf_buffer *wbuf;

    char host[NI_MAXHOST];
    char port[NI_MAXSERV];

    bool shutting_down;

    struct http_parser parser;

    enum http_version http_version;

    uint64_t last_activity;
};

struct http_connection *http_connection_setup(struct http_server *, int);

void http_connection_check_for_timeout(struct http_connection *, uint64_t);

int http_connection_write(struct http_connection *, const void *, size_t);
int http_connection_printf(struct http_connection *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

void http_connection_on_read_event(evutil_socket_t, short, void *);
void http_connection_on_write_event(evutil_socket_t, short, void *);

void http_connection_error(struct http_connection *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void http_connection_trace(struct http_connection *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

/* Routes */
enum http_route_match_result {
    HTTP_ROUTE_MATCH_OK,
    HTTP_ROUTE_MATCH_WRONG_METHOD,
    HTTP_ROUTE_MATCH_WRONG_PATH,
};

enum http_route_component_type {
    HTTP_ROUTE_COMPONENT_STRING,
    HTTP_ROUTE_COMPONENT_WILDCARD,
    HTTP_ROUTE_COMPONENT_NAMED,
};

struct http_route_component {
    enum http_route_component_type type;
    char *value;
};

int http_route_components_parse(const char *,
                                struct http_route_component **, size_t *);
void http_route_components_free(struct http_route_component *, size_t);

struct http_route {
    enum http_method method;

    char *path;
    struct http_route_component *components;
    size_t nb_components;

    http_msg_handler msg_handler;
};

struct http_route *http_route_new(enum http_method, const char *,
                                  http_msg_handler);
void http_route_delete(struct http_route *);

struct http_route_base {
    struct http_route **routes;
    size_t nb_routes;
    size_t routes_sz;

    void *msg_handler_arg;

    bool sorted;
};

struct http_route_base *http_route_base_new(void);
void http_route_base_delete(struct http_route_base *);

int http_route_base_add_route(struct http_route_base *, struct http_route *);
http_msg_handler http_route_base_find_msg_handler(struct http_route_base *,
                                                  enum http_method, const char *,
                                                  enum http_route_match_result *);

/* Servers */
struct http_server {
    struct http_cfg cfg;

    struct event_base *ev_base;
    struct event *timeout_timer;

    struct ht_table *listeners;
    struct ht_table *connections;

    struct http_route_base *route_base;
};

void http_server_error(struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void http_server_trace(struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

/* URIs */
struct http_uri {
    char *scheme;
    char *user;
    char *password;
    char *host;
    char *port;
    char *path;
    char *query;
};

#endif
