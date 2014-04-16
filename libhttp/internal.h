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

#include <iconv.h>

#include <buffer.h>
#include <hashtable.h>

/* Misc */
#define HTTP_ARRAY_NB_ELEMENTS(array_) (sizeof(array_) / sizeof(array_[0]))

int http_now_ms(uint64_t *);

/* Error handling */
#define HTTP_ERROR_BUFSZ 1024

/* Strings */
char *http_strdup(const char *);
char *http_strndup(const char *, size_t);

int http_vasprintf(char **, const char *, va_list);
int http_asprintf(char **, const char *, ...)
    __attribute__((format(printf, 2, 3)));

int http_parse_size(const char *, size_t *);

char *http_iconv(const char *, const char *, const char *);

#ifndef NDEBUG
const char *http_fmt_data(const char *, size_t);
#endif

/* Streams */
struct http_stream_functions {
    void (*delete_func)(intptr_t);
    int (*write_func)(intptr_t, int, size_t *);
};

struct http_stream *http_stream_new(void);
void http_stream_delete(struct http_stream *);

void http_stream_add_entry(struct http_stream *, intptr_t,
                           const struct http_stream_functions *);
void http_stream_add_data(struct http_stream *, const void *, size_t);
void http_stream_add_vprintf(struct http_stream *, const char *, va_list);
void http_stream_add_printf(struct http_stream *, const char *, ...);
void http_stream_add_file(struct http_stream *, int, const char *);

int http_stream_write(struct http_stream *, int, size_t *);

extern struct http_stream_functions http_stream_buffer_functions;
extern struct http_stream_functions http_stream_file_functions;

/* Protocol */
char *http_decode_header_value(const char *, size_t);

struct http_header {
    char *name;
    char *value;
};

void http_header_init(struct http_header *);
void http_header_free(struct http_header *);

struct http_named_parameter {
    char *name;
    char *value;
};

void http_named_parameter_free(struct http_named_parameter *);

struct http_request {
    enum http_method method;
    char *uri_string;

    struct http_uri *uri;

    struct http_named_parameter *named_parameters;
    size_t nb_named_parameters;

    bool expects_100_continue;
};

void http_request_free(struct http_request *);

struct http_response {
    enum http_status_code status_code;
    char *reason_phrase;
};

void http_response_free(struct http_response *);

struct http_msg {
    enum http_msg_type type;
    enum http_version version;

    union {
        struct http_request request;
        struct http_response response;
    } u;

    struct http_header *headers;
    size_t nb_headers;
    size_t headers_sz;

    bool is_bufferized;
    bool is_complete;
    bool aborted;

    char *body;
    size_t body_length;
    size_t total_body_length;
    bool is_body_chunked;

    void *content;
    const struct http_content_decoder *content_decoder;

    bool has_content_length;
    size_t content_length;

    uint32_t connection_options;

    struct http_media_type *content_type;
};

void http_msg_init(struct http_msg *, enum http_msg_type);
void http_msg_free(struct http_msg *);

void http_msg_add_header(struct http_msg *, const struct http_header *);

bool http_msg_can_have_body(const struct http_msg *);

/* Content decoders */
void *http_content_form_data_decode(const struct http_msg *,
                                    const struct http_cfg *);
void http_content_form_data_delete(void *);

/* Misc */
int http_token_list_get_next_token(const char *, char *, size_t, const char **);

/* Parser */
enum http_parser_state {
    HTTP_PARSER_START,
    HTTP_PARSER_HEADER,
    HTTP_PARSER_BODY,
    HTTP_PARSER_TRAILER,

    HTTP_PARSER_ERROR,
    HTTP_PARSER_DONE,
};

struct http_parser {
    enum http_parser_state state;

    struct http_msg msg;
    enum http_status_code status_code;
    char errmsg[HTTP_ERROR_BUFSZ];

    struct http_connection *connection;
    const struct http_cfg *cfg;

    bool skip_header_processing;

    bool headers_processed;
    bool msg_preprocessed;
};

int http_parser_init(struct http_parser *, enum http_msg_type,
                     const struct http_cfg *);
void http_parser_free(struct http_parser *);
int http_parser_reset(struct http_parser *, enum http_msg_type,
                      const struct http_cfg *);

bool http_parser_are_headers_read(struct http_parser *);

void http_parser_fail(struct http_parser *, enum http_status_code,
                      const char *, ...)
    __attribute__((format(printf, 3, 4)));

int http_msg_parse(struct bf_buffer *, struct http_parser *);
int http_msg_parse_request_line(struct bf_buffer *, struct http_parser *);
int http_msg_parse_status_line(struct bf_buffer *, struct http_parser *);
int http_msg_parse_headers(struct bf_buffer *, struct http_parser *);
int http_msg_parse_body(struct bf_buffer *, struct http_parser *);
int http_msg_parse_chunk(struct bf_buffer *, struct http_parser *);

/* Connections */

/* host + port + ipv6 brackets + colon */
#define HTTP_HOST_PORT_BUFSZ (NI_MAXHOST + NI_MAXSERV + 2 + 1)

enum http_connection_type {
    HTTP_CONNECTION_CLIENT,
    HTTP_CONNECTION_SERVER,
};

struct http_connection {
    enum http_connection_type type;

    struct http_server *server; /* if type == HTTP_CONNECTION_SERVER */
    struct http_client *client; /* if type == HTTP_CONNECTION_CLIENT */

    int sock;

    struct event *ev_read;
    struct event *ev_write;
    bool is_ev_write_enabled;

    struct bf_buffer *rbuf;
    struct http_stream *wstream;

    char address[HTTP_HOST_PORT_BUFSZ];

    bool shutting_down;

    struct http_parser parser;

    enum http_version http_version;

    uint64_t last_activity;

    struct http_msg *current_msg;
    const struct http_route *current_route;
};

struct http_connection *http_connection_new(enum http_connection_type,
                                            void *, int);

const struct http_cfg *http_connection_get_cfg(const struct http_connection *);

void http_connection_check_for_timeout(struct http_connection *, uint64_t);

void http_connection_write(struct http_connection *, const void *, size_t);
void http_connection_printf(struct http_connection *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

void http_connection_on_read_event(evutil_socket_t, short, void *);
void http_connection_on_write_event(evutil_socket_t, short, void *);

void http_connection_abort(struct http_connection *);

/* Routes */
enum http_route_match_result {
    HTTP_ROUTE_MATCH_OK,
    HTTP_ROUTE_MATCH_WRONG_PATH,
    HTTP_ROUTE_MATCH_METHOD_NOT_FOUND,
    HTTP_ROUTE_MATCH_PATH_NOT_FOUND,
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

    struct http_route_options options;
};

struct http_route *http_route_new(enum http_method, const char *,
                                  http_msg_handler);
void http_route_delete(struct http_route *);

void http_route_apply_options(struct http_route *,
                              const struct http_route_options *,
                              const struct http_cfg *);

struct http_route_base {
    struct http_route **routes;
    size_t nb_routes;
    size_t routes_sz;

    void *msg_handler_arg;

    bool sorted;
};

struct http_route_base *http_route_base_new(void);
void http_route_base_delete(struct http_route_base *);

void http_route_base_add_route(struct http_route_base *, struct http_route *);
int http_route_base_find_route(struct http_route_base *,
                               enum http_method, const char *,
                               const struct http_route **proute,
                               enum http_route_match_result *,
                               struct http_named_parameter **,
                               size_t *);
int http_route_base_find_path_methods(struct http_route_base *,
                                      const char *,
                                      enum http_method [static HTTP_METHOD_MAX],
                                      size_t *);

/* Servers */
struct http_server {
    struct http_cfg *cfg;

    struct event_base *ev_base;
    struct event *timeout_timer;

    struct ht_table *listeners;
    struct ht_table *connections;

    struct http_route_base *route_base;
};

void http_server_error(const struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void http_server_trace(const struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

bool http_server_does_listen_on(const struct http_server *,
                                const char *, const char *);
bool http_server_does_listen_on_host_string(const struct http_server *,
                                            const char *);

/* Clients */

struct http_client {
    struct http_cfg *cfg;

    struct event_base *ev_base;

    int sock;
    struct event *ev_sock;

    char host[NI_MAXHOST];
    char numeric_host[NI_MAXHOST];
    char port[NI_MAXSERV];
    char host_port[HTTP_HOST_PORT_BUFSZ];
    char numeric_host_port[HTTP_HOST_PORT_BUFSZ];

    struct http_connection *connection;
};

void http_client_error(const struct http_client *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
void http_client_trace(const struct http_client *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

/* URIs */
struct http_query_parameter {
    char *name;
    char *value;
};

void http_query_parameter_free(struct http_query_parameter *);

int http_query_parameters_parse(const char *, struct http_query_parameter **,
                                size_t *);

struct http_uri {
    char *scheme;
    char *user;
    char *password;
    char *host;
    char *port;
    char *path;
    char *fragment;

    struct http_query_parameter *query_parameters;
    size_t nb_query_parameters;
};

char *http_uri_decode_query_component(const char *, size_t);
void http_uri_encode_query_component(const char *, struct bf_buffer *);

#endif
