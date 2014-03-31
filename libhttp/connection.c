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

#include <unistd.h>

#include "http.h"
#include "internal.h"

static void http_connection_preprocess_request(struct http_connection *,
                                               struct http_msg *);
static void http_connection_call_msg_handler(struct http_connection *,
                                             struct http_msg *);
static void http_connection_on_msg_processed(struct http_connection *);

static int http_connection_write_auto_headers(struct http_connection *);
static int http_connection_write_options_response(struct http_connection *,
                                                  struct http_msg *);

struct http_connection *
http_connection_setup(struct http_server *server, int sock) {
    struct http_connection *connection;

    connection = http_malloc(sizeof(struct http_connection));
    memset(connection, 0, sizeof(struct http_connection));

    connection->server = server;
    connection->sock = sock;

    connection->ev_read = event_new(server->ev_base, connection->sock,
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

    connection->ev_write = event_new(server->ev_base, connection->sock,
                                     EV_WRITE | EV_PERSIST,
                                     http_connection_on_write_event,
                                     connection);
    if (!connection->ev_write) {
        http_set_error("cannot create write event handler: %s",
                       strerror(errno));
    }

    connection->rbuf = bf_buffer_new(0);
    if (!connection->rbuf) {
        http_set_error("%s", bf_get_error());
        goto error;
    }

    connection->wbuf = bf_buffer_new(0);
    if (!connection->wbuf) {
        http_set_error("%s", bf_get_error());
        goto error;
    }

    if (http_parser_init(&connection->parser, HTTP_MSG_REQUEST,
                         &server->cfg) == -1) {
        goto error;
    }

    connection->parser.server = server;
    connection->parser.connection = connection;

    connection->http_version = HTTP_1_1;

    if (http_now_ms(&connection->last_activity) == -1)
        goto error;

    return connection;

error:
    http_connection_close(connection);
    return NULL;
}

void
http_connection_check_for_timeout(struct http_connection *connection,
                                  uint64_t now) {
    uint64_t diff;

    diff = now - connection->last_activity;
    if (diff > connection->server->cfg.connection_timeout) {
        http_connection_http_error(connection, HTTP_REQUEST_TIMEOUT);
        http_connection_shutdown(connection);
    }
}

int
http_connection_write(struct http_connection *connection,
                      const void *data, size_t sz) {
    size_t previous_length;

    previous_length = bf_buffer_length(connection->wbuf);

    if (bf_buffer_add(connection->wbuf, data, sz) == -1) {
        http_set_error("%s", bf_get_error());
        return -1;
    }

    if (previous_length == 0) {
        if (event_add(connection->ev_write, NULL) == -1) {
            http_set_error("cannot add write event handler: %s",
                           strerror(errno));
            bf_buffer_truncate(connection->wbuf, previous_length);
            return -1;
        }
    }

    return 0;
}

int
http_connection_printf(struct http_connection *connection,
                                   const char *fmt, ...) {
    size_t previous_length;
    va_list ap;

    previous_length = bf_buffer_length(connection->wbuf);

    va_start(ap, fmt);
    if (bf_buffer_add_vprintf(connection->wbuf, fmt, ap) == -1) {
        http_set_error("%s", bf_get_error());
        return -1;
    }
    va_end(ap);

    if (previous_length == 0) {
        if (event_add(connection->ev_write, NULL) == -1) {
            http_set_error("cannot add write event handler: %s",
                           strerror(errno));
            bf_buffer_truncate(connection->wbuf, previous_length);
            return -1;
        }
    }

    return 0;
}

int
http_connection_http_error(struct http_connection *connection,
                           enum http_status_code status_code) {
    const char *reason_phrase;
    char body[1024];
    size_t body_len;

    reason_phrase = http_status_code_to_reason_phrase(status_code);
    snprintf(body, sizeof(body), "<h1>%d %s</h1>\n",
             status_code, reason_phrase);
    body_len = strlen(body);

    if (http_connection_write_response(connection,
                                       status_code, reason_phrase) == -1) {
        goto error;
    }

    if (http_connection_write_header(connection,
                                     "Content-Type", "text/html") == -1) {
        goto error;
    }

    if (http_connection_write_header_size(connection,
                                          "Content-Length", body_len) == -1) {
        goto error;
    }

    if (http_connection_write_body(connection, body, body_len) == -1)
        goto error;

    return 0;

error:
    http_connection_error(connection, "%s", http_get_error());
    http_connection_close(connection);
    return -1;
}

void
http_connection_close(struct http_connection *connection) {
    if (!connection)
        return;

    if (connection->sock >= 0) {
        ht_table_remove(connection->server->connections,
                        HT_INT32_TO_POINTER(connection->sock));

        close(connection->sock);
        connection->sock = -1;
    }

    if (connection->ev_read)
        event_free(connection->ev_read);
    if (connection->ev_write)
        event_free(connection->ev_write);

    bf_buffer_delete(connection->rbuf);
    bf_buffer_delete(connection->wbuf);

    http_parser_free(&connection->parser);

    memset(connection, 0, sizeof(struct http_connection));
    http_free(connection);
}

int
http_connection_shutdown(struct http_connection *connection) {
    if (event_del(connection->ev_read) == -1) {
        http_set_error("cannot remove read event handler: %s",
                       strerror(errno));
        http_connection_close(connection);
        return -1;
    }

    if (shutdown(connection->sock, SHUT_RD) == -1) {
        http_set_error("cannot shutdown socket: %s", strerror(errno));
        http_connection_close(connection);
        return -1;
    }

    connection->shutting_down = true;
    return 0;
}

void
http_connection_on_read_event(evutil_socket_t sock, short events, void *arg) {
    struct http_connection *connection;
    const struct http_cfg *cfg;
    ssize_t ret;

    connection = arg;
    cfg = &connection->server->cfg;

    ret = bf_buffer_read(connection->rbuf, connection->sock, BUFSIZ);
    if (ret == -1) {
        http_connection_error(connection, "cannot read socket: %s",
                              strerror(errno));
        http_connection_close(connection);
        return;
    }

    if (ret == 0) {
        http_connection_close(connection);
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
            http_connection_error(connection, "cannot parse request: %s",
                                  http_get_error());
            http_connection_http_error(connection,
                                       HTTP_INTERNAL_SERVER_ERROR);
            http_connection_shutdown(connection);
            return;
        }

        if (http_parser_are_headers_read(parser) && !parser->msg_preprocessed) {
            http_connection_preprocess_request(connection, msg);
            parser->msg_preprocessed = true;

            if (!connection->current_msg) {
                /* The request was fully processed */
                break;
            }
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
             && !http_parser_is_msg_bufferized(parser, msg)
             && msg->body_length > 0) {
                http_connection_call_msg_handler(connection, msg);

                http_free(msg->body);
                msg->body = NULL;
                msg->body_length = 0;
            }

            break;
        }

        if (parser->state == HTTP_PARSER_ERROR) {
            http_connection_error(connection, "cannot parse request: %s",
                                   parser->errmsg);
            http_connection_http_error(connection, parser->status_code);
            http_connection_shutdown(connection);
            return;
        } else if (parser->state == HTTP_PARSER_DONE) {
            msg->is_complete = true;

            if (cfg->request_hook)
                cfg->request_hook(connection, msg, cfg->hook_arg);

            http_connection_call_msg_handler(connection, msg);
            if (!connection->current_msg) {
                /* The request was fully processed */
                break;
            }

            http_connection_on_msg_processed(connection);
        }
    }

    if (http_now_ms(&connection->last_activity) == -1)
        http_connection_error(connection, "%s", http_get_error());
}

void
http_connection_on_write_event(evutil_socket_t sock, short events, void *arg) {
    struct http_connection *connection;
    ssize_t ret;

    connection = arg;

    ret = bf_buffer_write(connection->wbuf, connection->sock);
    if (ret == -1) {
        http_connection_error(connection, "cannot write to socket: %s",
                              strerror(errno));
        http_connection_close(connection);
        return;
    }

    bf_buffer_skip(connection->wbuf, (size_t)ret);
    if (bf_buffer_length(connection->wbuf) == 0) {
        event_del(connection->ev_write);

        if (connection->shutting_down) {
            http_connection_close(connection);
            return;
        }
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

    http_server_error(connection->server, "%s:%s: %s",
                      connection->host, connection->port, buf);
}

void
http_connection_trace(struct http_connection *connection,
                      const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_server_trace(connection->server, "%s:%s: %s",
                      connection->host, connection->port, buf);
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

    if (http_connection_printf(connection, "%s %d %s\r\n",
                               version_str, status_code,
                               reason_phrase) == -1) {
        return -1;
    }

    return 0;
}

int
http_connection_write_header(struct http_connection *connection,
                             const char *name, const char *value) {
    char *encoded_value;

    encoded_value = http_iconv(value, "UTF-8", "ISO-8859-1");
    if (!encoded_value) {
        /* TODO MIME encoding required */
        return -1;
    }

    if (http_connection_printf(connection, "%s: %s\r\n",
                               name, encoded_value) == -1) {
        http_free(encoded_value);
        return -1;
    }

    http_free(encoded_value);
    return 0;
}

int
http_connection_write_header_size(struct http_connection *connection,
                                  const char *name, size_t value) {
    if (http_connection_printf(connection, "%s: %zu\r\n",
                               name, value) == -1) {
        return -1;
    }

    return 0;
}

int
http_connection_write_body(struct http_connection *connection,
                           const char *buf, size_t sz) {
    if (http_connection_write_auto_headers(connection) == -1)
        return -1;

    if (http_connection_write(connection, "\r\n", 2) == -1)
        return -1;

    if (http_connection_write(connection, buf, sz) == -1)
        return -1;

    return 0;
}

int
http_connection_write_empty_body(struct http_connection *connection) {
    if (http_connection_write(connection, "\r\n", 2) == -1)
        return -1;

    return 0;
}

static void
http_connection_preprocess_request(struct http_connection *connection,
                                   struct http_msg *msg) {
    const char *uri_string;
    struct http_uri *uri;
    enum http_method method;

    assert(msg->type == HTTP_MSG_REQUEST);
    assert(!connection->current_msg);

    connection->current_msg = msg;

    method = msg->u.request.method;
    uri_string = msg->u.request.uri_string;

    /* Version */
    connection->http_version = msg->version;

    /* URI */
    if (strcmp(uri_string, "*") == 0) {
        if (method != HTTP_OPTIONS) {
            http_connection_trace(connection, "invalid uri: '*'");
            http_connection_http_error(connection, HTTP_BAD_REQUEST);
            goto msg_processed;
        }

        uri = NULL;
    } else {
        /* Absolute URI or absolute path */
        uri = http_uri_new(uri_string);
        if (!uri) {
            http_connection_trace(connection, "cannot parse uri: %s",
                                  http_get_error());
            http_connection_http_error(connection, HTTP_BAD_REQUEST);
            goto msg_processed;
        }

        msg->u.request.uri = uri;

        /* We have to accept absolute URIs (RFC 2616 5.1.2) but since we do
         * not act as a proxy, we only accept them when the host and port of
         * URI is an address we are listening on. */
        if (uri->host) {
            if (!http_server_does_listen_on(connection->server,
                                            uri->host, uri->port)) {
                http_connection_trace(connection,
                                      "absolute uri is not associated with an "
                                      "address we are listening on");
                http_connection_http_error(connection, HTTP_BAD_REQUEST);
                goto msg_processed;
            }
        }
    }

    /* Query parameters */
    if (uri && uri->query) {
        struct http_query_parameter **p_query_parameters;
        size_t *p_nb_query_parameters;

        p_query_parameters = &msg->u.request.query_parameters;
        p_nb_query_parameters = &msg->u.request.nb_query_parameters;

        if (http_query_parameters_parse(uri->query,
                                        p_query_parameters,
                                        p_nb_query_parameters) == -1) {
            http_connection_trace(connection, "cannot parse query: %s",
                                  http_get_error());
            http_connection_http_error(connection, HTTP_BAD_REQUEST);
            goto msg_processed;
        }
    }

    /* We handle OPTIONS requests ourselves */
    if (method == HTTP_OPTIONS) {
        if (http_connection_write_options_response(connection, msg) == -1)
            goto msg_processed;

        goto msg_processed;
    }

    return;

msg_processed:
    http_connection_on_msg_processed(connection);
}

static void
http_connection_call_msg_handler(struct http_connection *connection,
                                 struct http_msg *msg) {
    struct http_route_base *route_base;
    const struct http_route *route;
    enum http_route_match_result match_result;
    enum http_method method;

    assert(msg->type == HTTP_MSG_REQUEST);
    assert(connection->current_msg);

    if (!connection->current_msg_handler) {
        struct http_named_parameter **p_named_parameters;
        size_t *p_nb_named_parameters;

        route_base = connection->server->route_base;
        method = connection->current_msg->u.request.method;

        p_named_parameters = &msg->u.request.named_parameters;
        p_nb_named_parameters = &msg->u.request.nb_named_parameters;

        if (http_route_base_find_route(route_base,
                                       method, msg->u.request.uri->path,
                                       &route, &match_result,
                                       p_named_parameters,
                                       p_nb_named_parameters) == -1) {
            http_connection_error(connection,
                                  "cannot find route for request '%s %s': %s",
                                  http_method_to_string(method),
                                  msg->u.request.uri->path, http_get_error());
            http_connection_http_error(connection, HTTP_INTERNAL_SERVER_ERROR);
            http_connection_on_msg_processed(connection);
            return;
        }

        if (!route) {
            switch (match_result) {
            case HTTP_ROUTE_MATCH_METHOD_NOT_FOUND:
                http_connection_http_error(connection, HTTP_METHOD_NOT_ALLOWED);
                break;

            case HTTP_ROUTE_MATCH_PATH_NOT_FOUND:
                http_connection_http_error(connection, HTTP_NOT_FOUND);
                break;

            case HTTP_ROUTE_MATCH_WRONG_PATH:
            default:
                http_connection_http_error(connection, HTTP_BAD_REQUEST);
                break;
            }

            http_connection_on_msg_processed(connection);
            return;
        }

        connection->current_msg_handler = route->msg_handler;
        connection->current_msg_handler_arg = route_base->msg_handler_arg;
    }

    connection->current_msg_handler(connection, msg,
                                    connection->current_msg_handler_arg);
}

static void
http_connection_on_msg_processed(struct http_connection *connection) {
    const struct http_cfg *cfg;
    struct http_msg *msg;
    bool do_shutdown;

    assert(connection->current_msg);

    cfg = &connection->server->cfg;
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
            http_connection_error(connection,
                                  "cannot shutdown connection: %s",
                                  http_get_error());
        }
    }

    if (http_parser_reset(&connection->parser, HTTP_MSG_REQUEST, cfg) == -1) {
        http_connection_error(connection, "cannot reset parser: %s",
                              http_get_error());
        http_connection_close(connection);
        return;
    }

    connection->parser.server = connection->server;
    connection->parser.connection = connection;

    connection->current_msg = NULL;
    connection->current_msg_handler = NULL;
    connection->current_msg_handler_arg = NULL;
}

static int
http_connection_write_auto_headers(struct http_connection *connection) {
    const struct http_cfg *cfg;
    char date[HTTP_RFC1123_DATE_BUFSZ];

    cfg = &connection->server->cfg;


    if (http_format_timestamp(date, HTTP_RFC1123_DATE_BUFSZ,
                              time(NULL)) == -1) {
        return -1;
    }

    if (http_connection_write_header(connection, "Date", date) == -1)
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
            goto error;
        if (http_connection_write_header(connection, "Allow", methods) == -1)
            goto error;
    } else {
        enum http_method methods[HTTP_METHOD_MAX];
        struct http_route_base *route_base;
        struct http_uri *uri;
        size_t nb_methods;

        route_base = connection->server->route_base;
        uri = msg->u.request.uri;

        if (http_route_base_find_path_methods(route_base, uri->path,
                                              methods, &nb_methods) == -1) {
            goto error;
        }

        if (nb_methods == 0) {
            http_connection_http_error(connection, HTTP_NOT_FOUND);
            return 0;
        }

        if (http_connection_write_response(connection, HTTP_OK, NULL) == -1)
            goto error;

        for (size_t i = 0; i < nb_methods; i++) {
            enum http_method method;
            const char *method_string;

            method = methods[i];
            method_string = http_method_to_string(method);

            if (http_connection_write_header(connection, "Allow",
                                             method_string) == -1) {
                goto error;
            }
        }
    }

    return 0;

error:
    http_connection_error(connection, "%s", http_get_error());
    http_connection_close(connection);
    return -1;
}
