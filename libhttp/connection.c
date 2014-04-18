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

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "http.h"
#include "internal.h"

static int http_connection_find_route(struct http_connection *,
                                      struct http_msg *);
static int http_connection_preprocess_msg(struct http_connection *,
                                          struct http_msg *);
static int http_connection_preprocess_request(struct http_connection *,
                                              struct http_msg *);
static int http_connection_preprocess_response(struct http_connection *,
                                               struct http_msg *);
static void http_connection_call_request_handler(struct http_connection *,
                                                 struct http_msg *);
static void http_connection_call_response_handler(struct http_connection *,
                                                  struct http_msg *);
static void http_connection_on_msg_processed(struct http_connection *);

static int http_connection_write_request_headers(struct http_connection *);
static int http_connection_write_response_headers(struct http_connection *);
static int http_connection_write_error_body(struct http_connection *,
                                            enum http_status_code,
                                            const char *);
static int http_connection_write_options_response(struct http_connection *,
                                                  struct http_msg *);
static int http_connection_write_405_error(struct http_connection *,
                                           struct http_msg *);

struct http_connection *
http_connection_new(enum http_connection_type type, void *client_or_server,
                    int sock) {
    struct http_connection *connection;
    struct event_base *ev_base;
    struct http_cfg *cfg;
    enum http_msg_type msg_type;

    connection = http_malloc(sizeof(struct http_connection));
    memset(connection, 0, sizeof(struct http_connection));

    connection->type = type;

    if (type == HTTP_CONNECTION_CLIENT) {
        connection->client = client_or_server;

        ev_base = connection->client->ev_base;
        cfg = connection->client->cfg;
    } else if (type == HTTP_CONNECTION_SERVER) {
        connection->server = client_or_server;

        ev_base = connection->server->ev_base;
        cfg = connection->server->cfg;
    } else {
        http_set_error("unknown connection type %d", type);
        goto error;
    }

    connection->sock = sock;

    connection->ev_read = event_new(ev_base, connection->sock,
                                    EV_READ | EV_PERSIST,
                                    http_connection_on_read_event,
                                    connection);
    if (!connection->ev_read) {
        http_set_error("cannot create read event handler: %s",
                       strerror(errno));
        goto error;
    }

    if (event_add(connection->ev_read, NULL) == -1) {
        http_set_error("cannot add read event handler: %s", strerror(errno));
        goto error;
    }

    connection->ev_write = event_new(ev_base, connection->sock,
                                     EV_WRITE | EV_PERSIST,
                                     http_connection_on_write_event,
                                     connection);
    if (!connection->ev_write) {
        http_set_error("cannot create write event handler: %s",
                       strerror(errno));
    }

    connection->rbuf = bf_buffer_new(0);
    connection->wstream = http_stream_new();

    if (type == HTTP_CONNECTION_SERVER) {
        msg_type = HTTP_MSG_REQUEST;
    } else {
        msg_type = HTTP_MSG_RESPONSE;
    }

    if (http_parser_init(&connection->parser, msg_type, cfg) == -1)
        goto error;

    connection->parser.connection = connection;

    connection->http_version = HTTP_1_1;

    if (http_now_ms(&connection->last_activity) == -1)
        goto error;

    return connection;

error:
    http_connection_delete(connection);
    return NULL;
}

const struct http_cfg *
http_connection_get_cfg(const struct http_connection *connection) {
    if (connection->type == HTTP_CONNECTION_SERVER) {
        return connection->server->cfg;
    } else {
        return connection->client->cfg;
    }
}

void
http_connection_check_for_timeout(struct http_connection *connection,
                                  uint64_t now) {
    const struct http_cfg *cfg;
    uint64_t diff;

    assert(connection->type == HTTP_CONNECTION_SERVER);

    cfg = http_connection_get_cfg(connection);

    diff = now - connection->last_activity;
    if (diff > cfg->connection_timeout) {
        if (!connection->msg_handler_called
         && (connection->parser.state == HTTP_PARSER_HEADER
          || connection->parser.state == HTTP_PARSER_BODY
          || connection->parser.state == HTTP_PARSER_TRAILER)) {
            http_connection_write_error(connection, HTTP_REQUEST_TIMEOUT, NULL);
        }

        http_connection_shutdown(connection);
    }
}

void
http_connection_write(struct http_connection *connection,
                      const void *data, size_t sz) {
    http_stream_add_data(connection->wstream, data, sz);

    if (!connection->is_ev_write_enabled) {
        if (event_add(connection->ev_write, NULL) == -1) {
            http_connection_error(connection,
                                  "cannot add write event handler: %s",
                                  strerror(errno));
            return;
        }

        connection->is_ev_write_enabled = true;
    }
}

void
http_connection_printf(struct http_connection *connection,
                       const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    http_stream_add_vprintf(connection->wstream, fmt, ap);
    va_end(ap);

    if (!connection->is_ev_write_enabled) {
        if (event_add(connection->ev_write, NULL) == -1) {
            http_connection_error(connection,
                                  "cannot add write event handler: %s",
                                  strerror(errno));
            return;
        }

        connection->is_ev_write_enabled = true;
    }
}

int
http_connection_write_error(struct http_connection *connection,
                            enum http_status_code status_code,
                            const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    const char *errmsg;
    va_list ap;

    if (fmt) {
        va_start(ap, fmt);
        vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
        va_end(ap);
    }

    if (http_connection_write_response(connection, status_code, NULL) == -1)
        return -1;

    errmsg = fmt ? buf : NULL;
    if (http_connection_write_error_body(connection, status_code, errmsg) == -1)
        return -1;

    return 0;
}

void
http_connection_delete(struct http_connection *connection) {
    if (!connection)
        return;

    if (connection->sock >= 0) {
        if (connection->type == HTTP_CONNECTION_SERVER) {
            ht_table_remove(connection->server->connections,
                            HT_INT32_TO_POINTER(connection->sock));
        }

        close(connection->sock);
        connection->sock = -1;
    }

    if (connection->ev_read)
        event_free(connection->ev_read);
    if (connection->ev_write)
        event_free(connection->ev_write);

    bf_buffer_delete(connection->rbuf);
    http_stream_delete(connection->wstream);

    http_parser_free(&connection->parser);

    memset(connection, 0, sizeof(struct http_connection));
    http_free(connection);
}

int
http_connection_shutdown(struct http_connection *connection) {
    if (event_del(connection->ev_read) == -1) {
        http_set_error("cannot remove read event handler: %s",
                       strerror(errno));
        http_connection_delete(connection);
        return -1;
    }

    if (shutdown(connection->sock, SHUT_RD) == -1) {
        http_set_error("cannot shutdown socket: %s", strerror(errno));
        http_connection_delete(connection);
        return -1;
    }

    connection->shutting_down = true;
    return 0;
}

const char *
http_connection_address(const struct http_connection *connection) {
    return connection->address;
}

void
http_connection_trace(struct http_connection *connection,
                      const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    if (connection->type == HTTP_CONNECTION_SERVER) {
        http_server_trace(connection->server, "%s: %s",
                          connection->address, buf);
    } else {
        http_client_trace(connection->client, "%s: %s",
                          connection->address, buf);
    }
}

void
http_connection_error(struct http_connection *connection,
                      const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    if (connection->type == HTTP_CONNECTION_SERVER) {
        http_server_error(connection->server, "%s: %s",
                          connection->address, buf);
    } else {
        http_client_error(connection->client, "%s: %s",
                          connection->address, buf);
    }
}

void
http_connection_on_read_event(evutil_socket_t sock, short events, void *arg) {
    struct http_connection *connection;
    const struct http_cfg *cfg;
    ssize_t ret;

    connection = arg;

    cfg = http_connection_get_cfg(connection);

    ret = bf_buffer_read(connection->rbuf, connection->sock, BUFSIZ);
    if (ret == -1) {
        if (errno != ECONNRESET) {
            http_connection_abort(connection);
            http_connection_error(connection, "cannot read socket: %s",
                                  strerror(errno));
        }

        http_connection_delete(connection);
        return;
    }

    if (ret == 0) {
        http_connection_delete(connection);
        return;
    }

    for (;;) {
        struct http_parser *parser;
        struct http_msg *msg;
        int ret;

        parser = &connection->parser;
        msg = &parser->msg;

        ret = http_msg_parse(connection->rbuf, parser);
        if (ret == -1) {
            http_connection_error(connection, "cannot parse message: %s",
                                  http_get_error());
            http_connection_write_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                        "%s", http_get_error());
            goto error;
        }

        if (http_parser_are_headers_read(parser) && !parser->msg_preprocessed) {
            int ret;

            ret = http_connection_preprocess_msg(connection, msg);
            if (ret == -1) {
                http_connection_error(connection, "%s", http_get_error());
                http_connection_write_error(connection,
                                            HTTP_INTERNAL_SERVER_ERROR, NULL);
                goto error;
            }

            if (ret == 1) {
                /* We already responded to the message */
                http_connection_on_msg_processed(connection);
                break;
            }

            parser->msg_preprocessed = true;
        }

        if (ret == 0) {
            /* The message was not entirely read */

            /* If we are not bufferizing the whole message, we can call the
             * message handler right now.
             *
             * Of course we do not call the handler if nothing was read since
             * the last time (it can happen with chunked coding when a chunk
             * was not entirely read). */

            if (connection->current_msg
             && http_parser_are_headers_read(parser)
             && !msg->is_bufferized && msg->body_length > 0) {
                if (connection->type == HTTP_CONNECTION_SERVER) {
                    http_connection_call_request_handler(connection, msg);
                } else {
                    http_connection_call_response_handler(connection, msg);
                }

                http_free(msg->body);
                msg->body = NULL;
                msg->body_length = 0;
            }

            break;
        }

        if (parser->state == HTTP_PARSER_ERROR) {
            http_connection_error(connection, "cannot parse message: %s",
                                  parser->errmsg);
            http_connection_write_error(connection, parser->status_code,
                                        "cannot parse message: %s",
                                        parser->errmsg);
            goto error;
        } else if (parser->state == HTTP_PARSER_DONE) {
            msg->is_complete = true;

            if (connection->type == HTTP_CONNECTION_SERVER) {
                http_connection_call_request_handler(connection, msg);
            } else {
                http_connection_call_response_handler(connection, msg);
            }

            if (cfg->request_hook)
                cfg->request_hook(connection, msg, cfg->hook_arg);

            if (!connection->current_msg) {
                /* The request was fully processed */
                break;
            }

            http_connection_on_msg_processed(connection);
        }
    }

    if (http_now_ms(&connection->last_activity) == -1) {
        http_connection_error(connection, "%s", http_get_error());
        goto error;
    }

    return;

error:
    /* At this point we do not know whether we started responsing to the
     * message or not; since we do not want to let the connection in an
     * unknown state, we close it. */
    http_connection_abort(connection);
    http_connection_shutdown(connection);
}

void
http_connection_on_write_event(evutil_socket_t sock, short events, void *arg) {
    struct http_connection *connection;
    int ret;
    size_t sz;

    connection = arg;

    ret = http_stream_write(connection->wstream, connection->sock, &sz);
    if (ret == -1) {
        http_connection_abort(connection);
        http_connection_error(connection, "cannot write to socket: %s",
                              strerror(errno));
        http_connection_delete(connection);
        return;
    }

    if (ret == 0) {
        /* Stream consumed */
        event_del(connection->ev_write);
        connection->is_ev_write_enabled = false;

        if (connection->shutting_down) {
            http_connection_delete(connection);
            return;
        }
    }
}

void
http_connection_abort(struct http_connection *connection) {
    struct http_msg *msg;
    bool headers_read;

    msg = connection->current_msg;
    headers_read = http_parser_are_headers_read(&connection->parser);

    if (msg && headers_read && !msg->is_bufferized && !msg->aborted) {
        msg->aborted = true;

        if (connection->type == HTTP_CONNECTION_SERVER) {
            http_connection_call_request_handler(connection, msg);
        } else {
            http_connection_call_response_handler(connection, msg);
        }
    }
}

int
http_connection_write_request(struct http_connection *connection,
                              enum http_method method,
                              const struct http_uri *uri) {
    const char *version_str, *method_str;
    char *path;

    version_str = http_version_to_string(HTTP_1_1);

    method_str = http_method_to_string(method);
    if (!method_str) {
        http_set_error("unknown http method %d", method);
        return -1;
    }

    path = http_uri_encode_path_and_query(uri);
    if (!path)
        return -1;

    http_connection_printf(connection, "%s %s %s\r\n",
                           method_str, path, version_str);

    http_free(path);
    return 0;
}

int
http_connection_write_response(struct http_connection *connection,
                               enum http_status_code status_code,
                               const char *reason_phrase) {
    const char *version_str;

    version_str = http_version_to_string(connection->http_version);
    if (!version_str) {
        http_set_error("unknown http version %d", connection->http_version);
        return -1;
    }

    if (!reason_phrase) {
        reason_phrase = http_status_code_to_reason_phrase(status_code);
        if (!reason_phrase) {
            http_set_error("unknown status code %d", status_code);
            return -1;
        }
    }

    http_connection_printf(connection, "%s %d %s\r\n",
                           version_str, status_code,
                           reason_phrase);
    return 0;
}

void
http_connection_write_header(struct http_connection *connection,
                             const char *name, const char *value) {
    char *encoded_value;

    encoded_value = http_iconv(value, "UTF-8", "ISO-8859-1");
    if (!encoded_value)
        encoded_value = http_mime_q_encode(value);

    http_connection_printf(connection, "%s: %s\r\n",
                           name, encoded_value);

    http_free(encoded_value);
}

void
http_connection_write_header_size(struct http_connection *connection,
                                  const char *name, size_t value) {
    http_connection_printf(connection, "%s: %zu\r\n", name, value);
}

int
http_connection_write_body(struct http_connection *connection,
                           const char *buf, size_t sz) {
    if (connection->type == HTTP_CONNECTION_SERVER) {
        if (http_connection_write_response_headers(connection) == -1)
            return -1;
    } else {
        if (http_connection_write_request_headers(connection) == -1)
            return -1;
    }

    http_connection_write_header_size(connection, "Content-Length", sz);
    http_connection_write(connection, "\r\n", 2);
    http_connection_write(connection, buf, sz);

    return 0;
}

void
http_connection_write_empty_body(struct http_connection *connection) {
    http_connection_write_header(connection, "Content-Length", "0");
    http_connection_write(connection, "\r\n", 2);
}

int
http_connection_write_file(struct http_connection *connection, int fd,
                           const char *path) {
    struct stat st;
    size_t sz;

    if (fstat(fd, &st) == -1) {
        http_set_error("cannot stat file %s: %s", path, strerror(errno));
        return -1;
    }

    sz = (size_t)st.st_size;

    http_connection_write_header_size(connection, "Content-Length", sz);
    http_connection_write(connection, "\r\n", 2);
    http_stream_add_file(connection->wstream, fd, path);

    return 0;
}

static int
http_connection_find_route(struct http_connection *connection,
                           struct http_msg *msg) {
    struct http_route_base *route_base;
    const struct http_route *route;
    struct http_request *request;
    enum http_route_match_result match_result;
    enum http_method method;
    struct http_uri *uri;

    assert(msg->type == HTTP_MSG_REQUEST);

    route_base = connection->server->route_base;
    request = &msg->u.request;
    method = msg->u.request.method;
    uri = msg->u.request.uri;

    if (http_route_base_find_route(route_base,
                                   method, uri->path,
                                   &route, &match_result,
                                   &request->named_parameters,
                                   &request->nb_named_parameters) == -1) {
        http_connection_write_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                    "cannot find route: %s", http_get_error());
        return 1;
    }

    if (!route) {
        int ret;

        switch (match_result) {
        case HTTP_ROUTE_MATCH_METHOD_NOT_FOUND:
            ret = http_connection_write_405_error(connection, msg);
            break;

        case HTTP_ROUTE_MATCH_PATH_NOT_FOUND:
            ret = http_connection_write_error(connection, HTTP_NOT_FOUND,
                                              NULL);
            break;

        case HTTP_ROUTE_MATCH_WRONG_PATH:
        default:
            ret = http_connection_write_error(connection, HTTP_BAD_REQUEST,
                                              "cannot parse path");
            break;
        }

        if (ret == -1)
            return -1;

        return 1;
    }

    connection->current_route = route;
    return 0;
}

static int
http_connection_preprocess_msg(struct http_connection *connection,
                               struct http_msg *msg) {
    assert(!connection->current_msg);

    connection->current_msg = msg;
    connection->http_version = msg->version;

    if (connection->type == HTTP_CONNECTION_SERVER) {
        return http_connection_preprocess_request(connection, msg);
    } else {
        return http_connection_preprocess_response(connection, msg);
    }
}

static int
http_connection_preprocess_request(struct http_connection *connection,
                                   struct http_msg *msg) {
    const struct http_cfg *cfg;
    const struct http_route *route;
    const char *uri_string;
    struct http_uri *uri;
    enum http_method method;
    int ret;

    cfg = http_connection_get_cfg(connection);

    method = msg->u.request.method;
    uri_string = msg->u.request.uri_string;

    /* URI */
    if (strcmp(uri_string, "*") == 0) {
        if (method != HTTP_OPTIONS) {
            if (http_connection_write_error(connection, HTTP_BAD_REQUEST,
                                            "invalid uri: '*'") == -1)
                return -1;

            return 1;
        }

        uri = NULL;
    } else {
        /* Absolute URI or absolute path */
        uri = msg->u.request.uri;

        /* We have to accept absolute URIs (RFC 2616 5.1.2) but since we do
         * not act as a proxy, we only accept them when the host and port of
         * URI is an address we are listening on. */
        if (uri->host) {
            if (!http_server_does_listen_on(connection->server,
                                            uri->host, uri->port)) {
                http_connection_write_error(connection, HTTP_BAD_REQUEST,
                                            "absolute uri is not associated "
                                            "with an address we are "
                                            "listening on");
                return 1;
            }
        }
    }

    /* We handle OPTIONS requests ourselves */
    if (method == HTTP_OPTIONS) {
        if (http_connection_write_options_response(connection, msg) == -1)
            return -1;

        return 1;
    }

    /* Find a route to handle the request */
    ret = http_connection_find_route(connection, msg);
    if (ret != 0)
        return ret;

    route = connection->current_route;

    /* Check the content length */
    if (msg->has_content_length) {
        size_t max_content_length;

        if (route) {
            max_content_length = route->options.max_content_length;
        } else {
            max_content_length = cfg->max_content_length;
        }

        if (max_content_length > 0
         && msg->content_length > max_content_length) {
            if (http_connection_write_error(connection,
                                            HTTP_REQUEST_ENTITY_TOO_LARGE,
                                            "content length too large") == -1) {
                return -1;
            }

            return 1;
        }
    }

    /* Is the body of the request bufferized ? */
    msg->is_bufferized = route->options.bufferize_body;

    return 0;
}

static int
http_connection_preprocess_response(struct http_connection *connection,
                                    struct http_msg *msg) {
    const struct http_cfg *cfg;

    cfg = http_connection_get_cfg(connection);

    /* Is the body of the response bufferized ? */
    msg->is_bufferized = cfg->bufferize_body;

    return 0;
}

static void
http_connection_call_request_handler(struct http_connection *connection,
                                     struct http_msg *msg) {
    void *arg;

    assert(msg->type == HTTP_MSG_REQUEST);
    assert(connection->current_msg);
    assert(connection->current_route);

    arg = connection->server->route_base->msg_handler_arg;
    connection->current_route->msg_handler(connection, msg, arg);

    connection->msg_handler_called = true;
}

static void
http_connection_call_response_handler(struct http_connection *connection,
                                      struct http_msg *msg) {
    struct http_cfg *cfg;
    void *arg;

    assert(msg->type == HTTP_MSG_RESPONSE);
    assert(connection->current_msg);

    cfg = connection->client->cfg;

    if (!cfg->u.client.response_handler)
        return;

    arg = cfg->u.client.response_handler_arg;
    cfg->u.client.response_handler(connection->client, msg, arg);

    connection->msg_handler_called = true;
}

static void
http_connection_on_msg_processed(struct http_connection *connection) {
    const struct http_cfg *cfg;
    struct http_msg *msg;
    enum http_msg_type msg_type;
    bool do_shutdown;

    assert(connection->current_msg);

    cfg = http_connection_get_cfg(connection);
    msg = connection->current_msg;

    if (msg->version == HTTP_1_0) {
        do_shutdown = !(msg->connection_options & HTTP_CONNECTION_KEEP_ALIVE);
    } else if (msg->version == HTTP_1_1) {
        do_shutdown = msg->connection_options & HTTP_CONNECTION_CLOSE;
    } else {
        do_shutdown = true;
    }

    if (do_shutdown) {
        if (http_connection_shutdown(connection) == -1) {
            http_connection_abort(connection);
            http_connection_error(connection,
                                  "cannot shutdown connection: %s",
                                  http_get_error());
            http_connection_delete(connection);
            return;
        }
    }

    if (connection->type == HTTP_CONNECTION_SERVER) {
        msg_type = HTTP_MSG_REQUEST;
    } else {
        msg_type = HTTP_MSG_RESPONSE;
    }

    if (http_parser_reset(&connection->parser, msg_type, cfg) == -1) {
        http_connection_abort(connection);
        http_connection_error(connection, "cannot reset parser: %s",
                              http_get_error());
        http_connection_delete(connection);
        return;
    }

    connection->parser.connection = connection;

    connection->current_msg = NULL;
    connection->current_route = NULL;
    connection->msg_handler_called = false;
}

static int
http_connection_write_request_headers(struct http_connection *connection) {
    const struct http_cfg *cfg;

    cfg = connection->client->cfg;

    /* TODO */

    return 0;
}

static int
http_connection_write_response_headers(struct http_connection *connection) {
    const struct http_cfg *cfg;
    char date[HTTP_RFC1123_DATE_BUFSZ];

    cfg = connection->server->cfg;

    if (http_format_timestamp(date, HTTP_RFC1123_DATE_BUFSZ,
                              time(NULL)) == -1) {
        return -1;
    }

    http_connection_write_header(connection, "Date", date);
    return 0;
}

static int
http_connection_write_error_body(struct http_connection *connection,
                                 enum http_status_code status_code,
                                 const char *errmsg) {
    const struct http_cfg *cfg;

    cfg = http_connection_get_cfg(connection);

    if (cfg->u.server.error_body_writer(connection, status_code, errmsg) == -1)
        return -1;

    return 0;
}

static int
http_connection_write_options_response(struct http_connection *connection,
                                       struct http_msg *msg) {
    if (strcmp(msg->u.request.uri_string, "*") == 0) {
        const char *methods;

        methods = "GET, POST, HEAD, PUT, DELETE, OPTIONS";

        if (http_connection_write_response(connection, HTTP_OK, NULL) == -1)
            return -1;
        http_connection_write_header(connection, "Allow", methods);
    } else {
        enum http_method methods[HTTP_METHOD_MAX];
        struct http_route_base *route_base;
        struct http_uri *uri;
        size_t nb_methods;

        route_base = connection->server->route_base;
        uri = msg->u.request.uri;

        if (http_route_base_find_path_methods(route_base, uri->path,
                                              methods, &nb_methods) == -1) {
            return -1;
        }

        if (nb_methods == 0) {
            http_connection_write_error(connection, HTTP_NOT_FOUND, NULL);
            return 1;
        }

        if (http_connection_write_response(connection, HTTP_OK, NULL) == -1)
            return -1;

        for (size_t i = 0; i < nb_methods; i++) {
            enum http_method method;
            const char *method_string;

            method = methods[i];
            method_string = http_method_to_string(method);

            http_connection_write_header(connection, "Allow", method_string);
        }
    }

    return 0;
}

static int
http_connection_write_405_error(struct http_connection *connection,
                                struct http_msg *msg) {
    enum http_method methods[HTTP_METHOD_MAX];
    struct http_route_base *route_base;
    struct http_uri *uri;
    size_t nb_methods;

    assert(msg->type == HTTP_MSG_REQUEST);

    route_base = connection->server->route_base;
    uri = msg->u.request.uri;

    if (http_route_base_find_path_methods(route_base, uri->path,
                                          methods, &nb_methods) == -1) {
        http_connection_error(connection, "%s", http_get_error());
        goto error;
    }

    if (nb_methods == 0) {
        if (http_connection_write_error(connection, HTTP_NOT_FOUND,
                                        NULL) == -1) {
            http_connection_error(connection, "%s", http_get_error());
            goto error;
        }
        return 0;
    }

    if (http_connection_write_response(connection, HTTP_METHOD_NOT_ALLOWED,
                                       NULL) == -1) {
        http_connection_error(connection, "%s", http_get_error());
        goto error;
    }

    for (size_t i = 0; i < nb_methods; i++) {
        enum http_method method;
        const char *method_string;

        method = methods[i];
        method_string = http_method_to_string(method);

        http_connection_write_header(connection, "Allow", method_string);
    }

    if (http_connection_write_error_body(connection, HTTP_METHOD_NOT_ALLOWED,
                                         NULL) == -1) {
        goto error;
    }

    return 0;

error:
    http_connection_abort(connection);
    http_connection_delete(connection);
    return -1;
}
