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

#ifndef HTTP_HTTP_H
#define HTTP_HTTP_H

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <event.h>

#include <buffer.h>
#include <hashtable.h>

/* Error handling */
const char *http_get_error(void);

/* Memory */
struct http_memory_allocator {
   void *(*malloc)(size_t);
   void (*free)(void *);
   void *(*calloc)(size_t, size_t);
   void *(*realloc)(void *, size_t);
};

extern const struct http_memory_allocator *http_default_memory_allocator;

void http_set_memory_allocator(const struct http_memory_allocator *allocator);

/* Time */
#define HTTP_RFC1123_DATE_BUFSZ 64

void http_format_date(char [static HTTP_RFC1123_DATE_BUFSZ], size_t,
                      const struct tm *);
int http_format_timestamp(char [static HTTP_RFC1123_DATE_BUFSZ], size_t,
                          time_t);

/* Protocol */
enum http_version {
    HTTP_1_0 = 0,
    HTTP_1_1,
};

const char *http_version_to_string(enum http_version);

enum http_method {
    HTTP_GET = 0,
    HTTP_POST,
    HTTP_HEAD,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_OPTIONS,

    HTTP_METHOD_MAX
};

const char *http_method_to_string(enum http_method);

enum http_status_code {
    HTTP_CONTINUE                        = 100,
    HTTP_SWITCHING_PROTOCOLS             = 101,

    HTTP_OK                              = 200,
    HTTP_CREATED                         = 201,
    HTTP_ACCEPTED                        = 202,
    HTTP_NON_AUTHORITATIVE_INFORMATION   = 203,
    HTTP_NO_CONTENT                      = 204,
    HTTP_RESET_CONTENT                   = 205,
    HTTP_PARTIAL_CONTENT                 = 206,

    HTTP_MULTIPLE_CHOICES                = 300,
    HTTP_MOVED_PERMANENTLY               = 301,
    HTTP_FOUND                           = 302,
    HTTP_SEE_OTHERS                      = 303,
    HTTP_NOT_MODIFIED                    = 304,
    HTTP_USE_PROXY                       = 305,
    HTTP_TEMPORARY_REDIRECT              = 307,

    HTTP_BAD_REQUEST                     = 400,
    HTTP_UNAUTHORIZED                    = 401,
    HTTP_PAYMENT_REQUIRED                = 402,
    HTTP_FORBIDDEN                       = 403,
    HTTP_NOT_FOUND                       = 404,
    HTTP_METHOD_NOT_ALLOWED              = 405,
    HTTP_NOT_ACCEPTABLE                  = 406,
    HTTP_PROXY_AUTHENTICATION_REQUIRED   = 407,
    HTTP_REQUEST_TIMEOUT                 = 408,
    HTTP_CONFLICT                        = 409,
    HTTP_GONE                            = 410,
    HTTP_LENGTH_REQUIRED                 = 411,
    HTTP_PRECONDITION_FAILED             = 412,
    HTTP_REQUEST_ENTITY_TOO_LARGE        = 413,
    HTTP_REQUEST_URI_TOO_LONG            = 414,
    HTTP_UNSUPPORTED_MEDIA_TYPE          = 415,
    HTTP_REQUEST_RANGE_NOT_SATISFIABLE   = 416,
    HTTP_EXPECTATION_FAILED              = 417,
    HTTP_PRECONDITION_REQUIRED           = 428, /* RFC 6585 */
    HTTP_TOO_MANY_REQUESTS               = 429, /* RFC 6585 */
    HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431, /* RFC 6585 */

    HTTP_INTERNAL_SERVER_ERROR           = 500,
    HTTP_NOT_IMPLEMENTED                 = 501,
    HTTP_BAD_GATEWAY                     = 502,
    HTTP_SERVICE_UNAVAILABLE             = 503,
    HTTP_GATEWAY_TIMEOUT                 = 504,
    HTTP_HTTP_VERSION_NOT_SUPPORTED      = 505,
    HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511, /* RFC 6585 */
};

const char *http_status_code_to_reason_phrase(enum http_status_code);

enum http_msg_type {
    HTTP_MSG_REQUEST,
    HTTP_MSG_RESPONSE,
};

enum http_connection_option {
    HTTP_CONNECTION_KEEP_ALIVE = 0x01, /* HTTP/1.0 only */
    HTTP_CONNECTION_CLOSE      = 0x02,
};

enum http_bufferization {
    HTTP_BUFFERIZE_AUTO,
    HTTP_BUFFERIZE_ALWAYS,
    HTTP_BUFFERIZE_NEVER,
};

struct http_msg;
struct http_header;
struct http_connection;

enum http_version http_msg_version(const struct http_msg *);

enum http_method http_request_method(const struct http_msg *);
const char *http_request_uri(const struct http_msg *);

enum http_status_code http_response_status_code(const struct http_msg *);
const char *http_response_reason_phrase(const struct http_msg *);

size_t http_msg_nb_headers(const struct http_msg *);
const struct http_header *http_msg_header(const struct http_msg *, size_t);
const char *http_msg_get_header(const struct http_msg *, const char *);

bool http_msg_is_complete(const struct http_msg *);

const char *http_msg_body(const struct http_msg *);
size_t http_msg_body_length(const struct http_msg *);

const char *http_msg_get_named_parameter(const struct http_msg *, const char *);
const char *http_msg_get_query_parameter(const struct http_msg *, const char *);

const char *http_header_name(const struct http_header *);
const char *http_header_value(const struct http_header *);

const void *http_msg_content(const struct http_msg *);

struct http_form_data;

bool http_msg_has_form_data(const struct http_msg *);
bool http_form_data_has_parameter(const struct http_form_data *,
                                  const char *);
const char *http_form_data_get_parameter(const struct http_form_data *,
                                         const char *);

/* Configuration */
struct http_client;
struct http_cfg;

typedef void (*http_error_hook)(const char *, void *);
typedef void (*http_trace_hook)(const char *, void *);

typedef int (*http_error_body_writer)(struct http_connection *,
                                      enum http_status_code, const char *);

typedef void (*http_request_hook)(struct http_connection *,
                                  const struct http_msg *, void *);

typedef void (*http_response_handler)(struct http_client *,
                                      const struct http_msg *,
                                      void *);

typedef void *(*http_content_decode_func)(const struct http_msg *,
                                          const struct http_cfg *);
typedef void (*http_content_delete_func)(void *);

struct http_content_decoder {
    const char *content_type;

    http_content_decode_func decode;
    http_content_delete_func delete;
};

struct http_cfg {
    const char *host;
    const char *port;

    http_error_hook error_hook;
    http_trace_hook trace_hook;
    http_request_hook request_hook;
    void *hook_arg;

    union {
        struct {
            int connection_backlog;

            size_t max_request_uri_length;

            http_error_body_writer error_body_writer;
        } server;

        struct {
            size_t max_reason_phrase_length;

            http_response_handler response_handler;
            void *response_handler_arg;
        } client;
    } u;

    size_t max_header_name_length;
    size_t max_header_value_length;

    size_t max_content_length;
    size_t max_chunk_length;

    enum http_bufferization bufferization;

    uint64_t connection_timeout; /* milliseconds */

    struct http_content_decoder *content_decoders;
    size_t nb_content_decoders;
};

void http_cfg_init(struct http_cfg *cfg);
void http_cfg_free(struct http_cfg *cfg);

void http_cfg_content_decoder_add(struct http_cfg *, const char *,
                                  http_content_decode_func,
                                  http_content_delete_func);
const struct http_content_decoder *
http_cfg_content_decoder_get(const struct http_cfg *, const char *);

/* URIs */
struct http_uri *http_uri_new(const char *);
void http_uri_delete(struct http_uri *);

const char *http_uri_host(const struct http_uri *);
const char *http_uri_port(const struct http_uri *);

char *http_uri_encode(const struct http_uri *);
char *http_uri_encode_path_and_query(const struct http_uri *);

/* Server */
struct http_route_options {
    enum http_bufferization bufferization;
};

void http_route_options_init(struct http_route_options *,
                             const struct http_cfg *);

typedef void (*http_msg_handler)(struct http_connection *,
                                 const struct http_msg *, void *);

struct http_server *http_server_new(struct http_cfg *, struct event_base *);
void http_server_delete(struct http_server *server);

void http_server_set_msg_handler_arg(struct http_server *, void *);
int http_server_add_route(struct http_server *,
                          enum http_method, const char *, http_msg_handler,
                          const struct http_route_options *);

int http_default_error_body_writer(struct http_connection *,
                                   enum http_status_code, const char *);

/* Client */
struct http_client *http_client_new(struct http_cfg *, struct event_base *);
void http_client_delete(struct http_client *client);

int http_client_send_request(struct http_client *, enum http_method,
                             const struct http_uri *);

/* Connections */
void http_connection_delete(struct http_connection *);
int http_connection_shutdown(struct http_connection *);

int http_connection_write_error(struct http_connection *,
                                enum http_status_code,
                                const char *, ...);

int http_connection_write_request(struct http_connection *,
                                  enum http_method, const struct http_uri *);
int http_connection_write_response(struct http_connection *,
                                   enum http_status_code, const char *);
int http_connection_write_header(struct http_connection *,
                                 const char *, const char *);
int http_connection_write_header_size(struct http_connection *,
                                      const char *, size_t);
int http_connection_write_body(struct http_connection *,
                               const char *, size_t);
int http_connection_write_empty_body(struct http_connection *);

#endif
