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

#include <fcntl.h>
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
static void http_connection_on_response_sent(struct http_connection *,
                                             enum http_status_code);
static void http_connection_call_request_handler(struct http_connection *,
                                                 struct http_msg *);
static void http_connection_call_response_handler(struct http_connection *,
                                                  struct http_msg *);
static void http_connection_on_msg_processed(struct http_connection *);

static int http_connection_init_response_headers(struct http_connection *,
                                                 struct http_headers *);
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

    connection = http_malloc0(sizeof(struct http_connection));

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

    if (type == HTTP_CONNECTION_SERVER) {
        if (cfg->use_ssl) {
            connection->ssl = http_ssl_new(connection->server->ssl_ctx, sock);
            if (!connection->ssl)
                goto error;
        }
    }

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
    connection->wstream = http_stream_new(connection);

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
    http_connection_discard(connection);
    return NULL;
}

void
http_connection_delete(struct http_connection *connection) {
    struct http_request_info *info;

    if (!connection)
        return;

    if (connection->ev_read)
        event_free(connection->ev_read);
    if (connection->ev_write)
        event_free(connection->ev_write);

    if (connection->sock >= 0) {
        close(connection->sock);
        connection->sock = -1;
    }

    bf_buffer_delete(connection->rbuf);
    http_stream_delete(connection->wstream);

    http_parser_free(&connection->parser);

    if (connection->ssl)
        SSL_free(connection->ssl);

    info = connection->requests_first;
    while (info) {
        struct http_request_info *next;

        next = info->next;
        http_request_info_delete(info);

        info = next;
    }

    memset(connection, 0, sizeof(struct http_connection));
    http_free(connection);
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
        http_connection_trace(connection, "timeout");

        if (!connection->msg_handler_called
         && (connection->parser.state == HTTP_PARSER_HEADER
          || connection->parser.state == HTTP_PARSER_BODY
          || connection->parser.state == HTTP_PARSER_TRAILER)) {
            http_connection_send_error(connection, HTTP_REQUEST_TIMEOUT, NULL);
        }

        if (http_connection_shutdown(connection) == -1) {
            http_connection_error(connection,
                                  "cannot shutdown connection: %s",
                                  http_get_error());
            return;
        }
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

void
http_connection_discard(struct http_connection *connection) {
    if (connection->sock >= 0) {
        if (connection->type == HTTP_CONNECTION_SERVER)
            http_server_unregister_connection(connection->server, connection);
    }

    http_connection_delete(connection);
}

int
http_connection_shutdown(struct http_connection *connection) {
    http_connection_abort(connection);

    if (event_del(connection->ev_read) == -1) {
        http_set_error("cannot remove read event handler: %s",
                       strerror(errno));
        http_connection_discard(connection);
        return -1;
    }

    if (shutdown(connection->sock, SHUT_RD) == -1) {
        http_set_error("cannot shutdown socket: %s", strerror(errno));
        http_connection_discard(connection);
        return -1;
    }

    connection->shutting_down = true;

    /* If the output stream is empty, we can discard the connection right now.
     * If there are still data to send, wait until this is done. */
    if (http_stream_is_empty(connection->wstream))
        http_connection_discard(connection);
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

int
http_connection_send_response(struct http_connection *connection,
                              enum http_status_code status_code,
                              struct http_headers *headers) {
    if (headers == NULL)
        headers = http_headers_new();

    if (http_connection_init_response_headers(connection, headers) == -1)
        goto error;

    if (http_connection_write_response(connection, status_code, NULL) == -1)
        goto error;

    http_connection_write_headers_and_body(connection, headers, NULL, 0);

    if (status_code != HTTP_CONTINUE)
        http_connection_on_response_sent(connection, status_code);

    http_headers_delete(headers);
    return 0;

error:
    http_headers_delete(headers);
    return -1;
}

int
http_connection_send_response_with_body(struct http_connection *connection,
                                        enum http_status_code status_code,
                                        struct http_headers *headers,
                                        const char *body, size_t bodysz) {
    if (headers == NULL)
        headers = http_headers_new();

    if (http_connection_init_response_headers(connection, headers) == -1)
        goto error;

    if (http_connection_write_response(connection, status_code, NULL) == -1)
        goto error;

    http_connection_write_headers_and_body(connection, headers, body, bodysz);

    http_connection_on_response_sent(connection, status_code);

    http_headers_delete(headers);
    return 0;

error:
    http_headers_delete(headers);
    return -1;
}

int
http_connection_send_response_with_file(struct http_connection *connection,
                                        enum http_status_code status_code,
                                        struct http_headers *headers,
                                        const char *path, int fd,
                                        size_t file_sz,
                                        const struct http_ranges *ranges) {
    struct http_ranges simplified_ranges;

    /* Check the ranges if there are any */
    if (ranges) {
        http_ranges_simplify(ranges, file_sz, &simplified_ranges);

        if (!http_ranges_is_satisfiable(&simplified_ranges, file_sz)) {
            /* TODO HTTP_REQUEST_RANGE_NOT_SATISFIABLE */
            http_set_error("range not satisfiable");
            goto error;
        }

        ranges = &simplified_ranges;
    }

    /* Send the response */
    if (headers == NULL)
        headers = http_headers_new();

    if (http_connection_init_response_headers(connection, headers) == -1)
        goto error;

    if (http_connection_write_response(connection, status_code, NULL) == -1)
        goto error;

    http_connection_write_headers_and_file(connection, headers,
                                           path, fd, file_sz, ranges);

    http_connection_on_response_sent(connection, status_code);

    http_headers_delete(headers);
    return 0;

error:
    close(fd);
    http_headers_delete(headers);
    return -1;
}

int
http_connection_send_error(struct http_connection *connection,
                           enum http_status_code status_code,
                           const char *fmt, ...) {
    const struct http_cfg *cfg;
    struct http_headers *headers;
    char errmsg[HTTP_ERROR_BUFSZ];
    va_list ap;
    int ret;

    assert(connection->type == HTTP_CONNECTION_SERVER);

    cfg = http_connection_get_cfg(connection);

    if (fmt) {
        va_start(ap, fmt);
        vsnprintf(errmsg, HTTP_ERROR_BUFSZ, fmt, ap);
        va_end(ap);
    }

    headers = http_headers_new();
    ret = cfg->u.server.error_sender(connection, status_code, headers,
                                     fmt ? errmsg : NULL);

    return ret;
}

void
http_connection_on_read_event(evutil_socket_t sock, short events, void *arg) {
    struct http_connection *connection;
    const struct http_cfg *cfg;
    ssize_t ret;

    connection = arg;

    cfg = http_connection_get_cfg(connection);

    if (cfg->use_ssl) {
        int errcode;

        ret = http_buf_ssl_read(connection->rbuf, connection->sock, BUFSIZ,
                                connection->ssl, &errcode);
        if (ret == -1) {
            switch (errcode) {
            case SSL_ERROR_WANT_READ:
                /* The read event handler is always enabled, so we just
                 * return: we will call SSL_read() again the next time we get
                 * a read event. */
                 break;

            case SSL_ERROR_WANT_WRITE:
                if (event_add(connection->ev_write, NULL) == -1) {
                    http_connection_error(connection,
                                          "cannot add write event handler: %s",
                                          strerror(errno));
                    http_connection_discard(connection);
                    break;
                }

                connection->is_ev_write_enabled = true;
                break;

            default:
                http_connection_error(connection, "cannot read ssl socket: %s",
                                      http_ssl_get_error());
                http_connection_abort(connection);
                http_connection_discard(connection);
                break;
            }
        }
    } else {
        ret = bf_buffer_read(connection->rbuf, connection->sock, BUFSIZ);
        if (ret == -1) {
            if (errno != ECONNRESET) {
                http_connection_error(connection, "cannot read socket: %s",
                                      strerror(errno));
            }

            http_connection_abort(connection);
            http_connection_discard(connection);
            return;
        }
    }

    if (ret == 0) {
        /* Connection closed */
        http_connection_discard(connection);
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
            http_connection_send_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                       "%s", http_get_error());
            goto error;
        }

        if (http_parser_are_headers_read(parser) && !parser->msg_preprocessed) {
            int ret;

            if (connection->type == HTTP_CONNECTION_SERVER) {
                http_connection_track_request_received(connection, msg);
            } else if (connection->type == HTTP_CONNECTION_CLIENT) {
                http_connection_track_response_received(connection, msg);
            }

            ret = http_connection_preprocess_msg(connection, msg);
            if (ret == -1) {
                http_connection_error(connection, "%s", http_get_error());
                http_connection_send_error(connection,
                                           HTTP_INTERNAL_SERVER_ERROR,
                                           "%s", http_get_error());
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
             && parser->msg_preprocessed
             && !msg->is_bufferized && msg->body_length > 0) {
                if (connection->type == HTTP_CONNECTION_SERVER) {
                    http_connection_call_request_handler(connection, msg);
                } else {
                    http_connection_call_response_handler(connection, msg);
                }

                /* For bufferized messages, msg->body only contains data
                 * received since the last call to the handler, so we delete
                 * them to be ready for the next time we receive some. */
                http_free(msg->body);
                msg->body = NULL;
                msg->body_length = 0;
            }

            break;
        }

        if (parser->state == HTTP_PARSER_ERROR) {
            http_connection_error(connection, "cannot parse message: %s",
                                  parser->errmsg);
            if (connection->type == HTTP_CONNECTION_SERVER) {
                http_connection_send_error(connection, parser->status_code,
                                           "%s", parser->errmsg);
            }
            goto error;
        } else if (parser->state == HTTP_PARSER_DONE) {
            msg->is_complete = true;

            if (connection->type == HTTP_CONNECTION_SERVER) {
                http_connection_call_request_handler(connection, msg);
            } else {
                http_connection_call_response_handler(connection, msg);
            }

            if (cfg->request_received_hook)
                cfg->request_received_hook(connection, msg, cfg->hook_arg);

            if (!connection->msg_handler_called) {
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
    if (http_connection_shutdown(connection) == -1) {
        http_connection_error(connection,
                              "cannot shutdown connection: %s",
                              http_get_error());
        return;
    }
}

void
http_connection_on_write_event(evutil_socket_t sock, short events, void *arg) {
    struct http_connection *connection;
    int ret;
    size_t sz;

    connection = arg;

    ret = http_stream_write(connection->wstream, connection->sock, &sz);
    if (ret == -1) {
        if (!connection->closed_by_peer) {
            http_connection_abort(connection);
            http_connection_error(connection, "cannot write to socket: %s",
                                  strerror(errno));
        }

        http_connection_discard(connection);
        return;
    }

    if (ret == 0) {
        /* Stream consumed */
        event_del(connection->ev_write);
        connection->is_ev_write_enabled = false;

        if (connection->shutting_down) {
            http_connection_discard(connection);
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

    /* If there is a current message that is not bufferized, we need to call
     * the handler one last time. */

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
                              const char *path) {
    const char *version_str, *method_str;

    version_str = http_version_to_string(HTTP_1_1);

    method_str = http_method_to_string(method);
    if (!method_str) {
        http_set_error("unknown http method %d", method);
        return -1;
    }

    http_connection_printf(connection, "%s %s %s\r\n",
                           method_str, path, version_str);
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
    http_connection_printf(connection, "%s: %s\r\n", name, value);
}

void
http_connection_write_header_size(struct http_connection *connection,
                                  const char *name, size_t value) {
    http_connection_printf(connection, "%s: %zu\r\n", name, value);
}

void
http_connection_write_headers(struct http_connection *connection,
                              struct http_headers *headers) {
    for (size_t i = 0; i < headers->nb_headers; i++) {
        struct http_header *header;

        header = headers->headers + i;
        http_connection_write_header(connection, header->name, header->value);
    }
}

void
http_connection_write_headers_and_body(struct http_connection *connection,
                                       struct http_headers *headers,
                                       const char *body, size_t bodysz) {

    if (body) {
        http_headers_format_header(headers, "Content-Length", "%zu", bodysz);
    } else {
        http_headers_set_header(headers, "Content-Length", "0");
    }

    http_connection_write_headers(connection, headers);
    http_connection_write(connection, "\r\n", 2);

    if (body) {
        http_connection_write(connection, body, bodysz);
    }
}

void
http_connection_write_headers_and_file(struct http_connection *connection,
                                       struct http_headers *headers,
                                       const char *path, int fd, size_t file_sz,
                                       const struct http_ranges *ranges) {
    char **mime_part_headers;
    size_t nb_mime_parts;
    char *mime_footer;
    size_t content_length;

    if (ranges) {
        content_length = http_ranges_length(ranges);
    } else {
        content_length = file_sz;
    }

    nb_mime_parts = 0;
    mime_part_headers = NULL;
    mime_footer = NULL;

    if (ranges && ranges->nb_ranges > 1) {
        char boundary[HTTP_MIME_BOUNDARY_SZ];
        const char *content_type;
        int ret;

        /* Generate a MIME document of type multipart/byteranges. */

        /* Extract the content type to include it in MIME headers */
        content_type = http_headers_get_header(headers, "Content-Type");
        if (!content_type)
            content_type = "application/octet-stream";

        /* Generate MIME headers and footer using a random boundary */
        http_mime_generate_boundary(boundary, HTTP_MIME_BOUNDARY_SZ);

        nb_mime_parts = ranges->nb_ranges;
        mime_part_headers = http_calloc(nb_mime_parts, sizeof(char *));

        for (size_t i = 0; i < nb_mime_parts; i++) {
            struct http_range *range;

            range = ranges->ranges + i;

            ret = http_asprintf(&mime_part_headers[i],
                                "\r\n--%s\r\n"
                                "Content-Type: %s\r\n"
                                "Content-Range: bytes %zu-%zu/%zu\r\n\r\n",
                                boundary, content_type,
                                range->first, range->last, file_sz);

            content_length += (size_t)ret;
        }

        ret = http_asprintf(&mime_footer, "\r\n--%s--\r\n", boundary);
        content_length += (size_t)ret;

        /* We do not need to quote/escape boundary because we use base64 to
         * make sure we only have token characters */
        http_headers_format_header(headers, "Content-Type",
                                   "multipart/byteranges; boundary=%s",
                                   boundary);
    } else if (ranges && ranges->nb_ranges == 1) {
        struct http_range *range;

        range = ranges->ranges;

        http_headers_format_header(headers, "Content-Range",
                                   "bytes %zu-%zu/%zu",
                                   range->first, range->last, file_sz);
    }

    http_headers_format_header(headers, "Content-Length",
                               "%zu", content_length);

    http_connection_write_headers(connection, headers);
    http_connection_write(connection, "\r\n", 2);

    if (ranges) {
        http_stream_add_partial_file(connection->wstream, fd, file_sz, path,
                                     ranges, mime_part_headers, nb_mime_parts,
                                     mime_footer);
    } else {
        http_stream_add_file(connection->wstream, fd, file_sz, path);
    }
}

void
http_connection_register_request_info(struct http_connection *connection,
                                      struct http_request_info *info) {
    /*
     * requests_first --> request_1 --> request_2 --> NULL
     *                                    ^
     *                                    |
     * requests_last ---------------------+
     */

    info->next = NULL;
    info->prev = connection->requests_last;

    if (connection->requests_last)
        connection->requests_last->next = info;

    if (!connection->requests_first)
        connection->requests_first = info;

    connection->requests_last = info;
}

void
http_connection_unregister_request_info(struct http_connection *connection,
                                        struct http_request_info *info) {
    if (info->prev)
        info->prev->next = info->next;
    if (info->next)
        info->next->prev = info->prev;

    if (connection->requests_first == info)
        connection->requests_first = info->next;
    if (connection->requests_last == info)
        connection->requests_last = info->prev;
}

void
http_connection_track_request_send(struct http_connection *connection,
                                   enum http_method method,
                                   const char *uri_string) {
    struct http_request_info *info;

    assert(connection->type == HTTP_CONNECTION_CLIENT);

    info = http_request_info_new();

    info->version = HTTP_1_1;
    info->method = method,
    info->uri_string = http_strdup(uri_string);
    info->date = time(NULL);

    http_connection_register_request_info(connection, info);
}

void
http_connection_track_request_received(struct http_connection *connection,
                                       const struct http_msg *msg) {
    struct http_request_info *info;
    const struct http_request *request;

    assert(connection->type == HTTP_CONNECTION_SERVER);
    assert(msg->type == HTTP_MSG_REQUEST);

    request = &msg->u.request;

    info = http_request_info_new();

    info->version = msg->version;
    info->method = request->method;
    info->uri_string = http_strdup(request->uri_string);
    info->date = time(NULL);

    http_connection_register_request_info(connection, info);
}

void
http_connection_track_response_sent(struct http_connection *connection,
                                    enum http_status_code status_code) {
    struct http_request_info *info;
    const struct http_cfg *cfg;

    assert(connection->type == HTTP_CONNECTION_SERVER);

    cfg = http_connection_get_cfg(connection);

    if (!connection->current_msg) {
        /* If there is no current message, it means we could not parse the
         * request. We cannot track it */
        return;
    }

    /* In HTTP, response are sent in the order requests were received. For
     * example, when receiving requests A, B and C, the server *must* respond
     * to A first, then to B and C. */

    if (!connection->requests_first) {
        http_connection_error(connection,
                              "sending response without pending request");
        return;
    }

    info = connection->requests_first;

    info->status_code = status_code;

    if (cfg->request_hook)
        cfg->request_hook(connection, info, cfg->hook_arg);

    http_connection_unregister_request_info(connection, info);
    http_request_info_delete(info);
}

void
http_connection_track_response_received(struct http_connection *connection,
                                        const struct http_msg *msg) {
    struct http_request_info *info;
    const struct http_response *response;
    const struct http_cfg *cfg;

    assert(connection->type == HTTP_CONNECTION_CLIENT);
    assert(msg->type == HTTP_MSG_RESPONSE);

    cfg = http_connection_get_cfg(connection);

    response = &msg->u.response;

    if (response->status_code == HTTP_CONTINUE)
        return;

    if (!connection->requests_first) {
        http_connection_error(connection,
                              "response received without pending request");
        return;
    }

    info = connection->requests_first;

    info->status_code = response->status_code;

    if (cfg->request_hook)
        cfg->request_hook(connection, info, cfg->hook_arg);

    http_connection_unregister_request_info(connection, info);
    http_request_info_delete(info);
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
        if (http_connection_send_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                       "cannot find route: %s",
                                       http_get_error()) == -1) {
            return -1;
        }

        return 1;
    }

    if (!route) {
        int ret;

        switch (match_result) {
        case HTTP_ROUTE_MATCH_METHOD_NOT_FOUND:
            ret = http_connection_write_405_error(connection, msg);
            break;

        case HTTP_ROUTE_MATCH_PATH_NOT_FOUND:
            ret = http_connection_send_error(connection, HTTP_NOT_FOUND, NULL);
            break;

        case HTTP_ROUTE_MATCH_WRONG_PATH:
        default:
            ret = http_connection_send_error(connection, HTTP_BAD_REQUEST,
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
            if (http_connection_send_error(connection, HTTP_BAD_REQUEST,
                                           "invalid uri: '*'") == -1) {
                return -1;
            }

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
                if (http_connection_send_error(connection, HTTP_BAD_REQUEST,
                                               "absolute uri is not "
                                               "associated with an address "
                                               "we are listening on") == -1) {
                    return -1;
                }

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
            if (http_connection_send_error(connection,
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
http_connection_on_response_sent(struct http_connection *connection,
                                 enum http_status_code status_code) {
    if (connection->current_msg) {
        struct http_msg *msg;

        msg = connection->current_msg;
        assert(msg->type == HTTP_MSG_REQUEST);

        msg->u.request.response_sent = true;

        http_connection_track_response_sent(connection, status_code);
    }
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

    if (msg->is_complete && !msg->u.request.response_sent) {
        http_connection_error(connection,
                              "message handler did not send a response");
        http_connection_send_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                   "no available response");
    }

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
            http_connection_error(connection,
                                  "cannot shutdown connection: %s",
                                  http_get_error());
            return;
        }
    }

    if (connection->type == HTTP_CONNECTION_SERVER) {
        msg_type = HTTP_MSG_REQUEST;
    } else {
        msg_type = HTTP_MSG_RESPONSE;
    }

    if (http_parser_reset(&connection->parser, msg_type, cfg) == -1) {
        http_connection_error(connection, "cannot reset parser: %s",
                              http_get_error());
        http_connection_abort(connection);
        http_connection_discard(connection);
        return;
    }

    connection->parser.connection = connection;

    connection->current_msg = NULL;
    connection->current_route = NULL;
    connection->msg_handler_called = false;
}

static int
http_connection_init_response_headers(struct http_connection *connection,
                                      struct http_headers *headers) {
    char date[HTTP_RFC1123_DATE_BUFSZ];
    const struct http_cfg *cfg;
    const struct http_route *route;

    route = connection->current_route;

    cfg = http_connection_get_cfg(connection);

    if (http_format_timestamp(date, HTTP_RFC1123_DATE_BUFSZ,
                              time(NULL)) == -1) {
        return -1;
    }

    http_headers_set_header(headers, "Date", date);
    http_headers_add_headers(headers, cfg->default_headers);

    /* There is no current route if we are sending a response before finding a
     * route (for example for errors, responses to OPTIONS requests, 100
     * Continue, etc. */
    if (route)
        http_headers_add_headers(headers, route->options.default_headers);

    return 0;
}

static int
http_connection_write_options_response(struct http_connection *connection,
                                       struct http_msg *msg) {
    struct http_headers *headers;

    headers = http_headers_new();

    if (strcmp(msg->u.request.uri_string, "*") == 0) {
        http_headers_add_header(headers, "Allow",
                                "GET, POST, HEAD, PUT, DELETE, OPTIONS");

        return http_connection_send_response(connection, HTTP_OK, headers);
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
            http_headers_delete(headers);
            return http_connection_send_error(connection, HTTP_NOT_FOUND, NULL);
        }

        for (size_t i = 0; i < nb_methods; i++) {
            enum http_method method;
            const char *method_string;

            method = methods[i];
            method_string = http_method_to_string(method);

            http_headers_add_header(headers, "Allow", method_string);
        }

        return http_connection_send_response(connection, HTTP_OK, headers);
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
        if (http_connection_send_error(connection, HTTP_NOT_FOUND, NULL) == -1) {
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

    if (http_connection_send_error(connection, HTTP_METHOD_NOT_ALLOWED,
                                   NULL) == -1) {
        goto error;
    }

    return 0;

error:
    http_connection_abort(connection);
    http_connection_discard(connection);
    return -1;
}
