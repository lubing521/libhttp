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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <buffer.h>
#include <hashtable.h>

#include "http.h"
#include "internal.h"

struct http_cfg http_server_default_cfg = {
    .host = "localhost",
    .port = "80",

    .error_hook = NULL,
    .trace_hook = NULL,
    .hook_arg = NULL,

    .u = {
        .server = {
            .connection_backlog = 5,

            .max_request_uri_length = 2048,
        }
    }
};

static void http_server_error(struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
static void http_server_trace(struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

struct http_sconnection {
    struct http_server *server;

    int sock;

    struct event *ev_read;
    struct event *ev_write;

    struct bf_buffer *rbuf;
    struct bf_buffer *wbuf;

    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
};

static struct http_sconnection * http_sconnection_setup(struct http_server *, int);
static void http_sconnection_close(struct http_sconnection *);

static int http_sconnection_write(struct http_sconnection *, const void *, size_t);

static void http_sconnection_on_read_event(evutil_socket_t, short, void *);
static void http_sconnection_on_write_event(evutil_socket_t, short, void *);

static void http_sconnection_error(struct http_sconnection *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
static void http_sconnection_trace(struct http_sconnection *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

struct http_listener {
    struct http_server *server;

    int sock;
    struct event *ev_sock;

    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
};

static struct http_listener *http_listener_setup(struct http_server *,
                                                 const struct addrinfo *);
static void http_listener_close(struct http_listener *);

static void http_listener_on_sock_event(evutil_socket_t, short, void *);

struct http_server {
    struct http_cfg cfg;

    struct event_base *ev_base;

    struct ht_table *listeners;
    struct ht_table *connections;
};

struct http_server *
http_server_listen(const struct http_cfg *cfg,
                         struct event_base *ev_base) {
    struct http_server *server;
    struct addrinfo hints, *res;
    int ret;

    server = http_malloc(sizeof(struct http_server));
    memset(server, 0, sizeof(struct http_server));

    server->cfg = *cfg;

    server->ev_base = ev_base;

    server->listeners = ht_table_new(ht_hash_int32, ht_equal_int32);
    if (!server->listeners) {
        http_set_error("%s", ht_get_error());
        goto error;
    }

    server->connections = ht_table_new(ht_hash_int32, ht_equal_int32);
    if (!server->connections) {
        http_set_error("%s", ht_get_error());
        goto error;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = 0;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_addrlen = 0;

    ret = getaddrinfo(server->cfg.host, server->cfg.port, &hints, &res);
    if (ret != 0) {
        http_set_error("cannot resolve address %s:%s: %s",
                       server->cfg.host, server->cfg.port, gai_strerror(ret));
        goto error;
    }

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        struct http_listener *listener;

        listener = http_listener_setup(server, ai);
        if (!listener) {
            http_server_error(server, "%s", http_get_error());
            continue;
        }

        if (ht_table_insert(server->listeners,
                            HT_INT32_TO_POINTER(listener->sock),
                            listener) == -1) {
            http_server_error(server, "%s", ht_get_error());
            http_listener_close(listener);
            continue;
        }
    }

    freeaddrinfo(res);

    if (ht_table_get_nb_entries(server->listeners) == 0) {
        http_set_error("cannot listen on any address");
        goto error;
    }

    return server;

error:
    http_server_shutdown(server);
    return NULL;
}

void
http_server_shutdown(struct http_server *server) {
    struct ht_table_iterator *it;

    if (!server)
        return;

    it = ht_table_iterate(server->connections);
    if (it) {
        struct http_sconnection *connection;

        while (ht_table_iterator_get_next(it, NULL, (void **)&connection) == 1)
            http_sconnection_close(connection);
        ht_table_delete(server->connections);

        ht_table_iterator_delete(it);
    }

    it = ht_table_iterate(server->listeners);
    if (it) {
        struct http_listener *listener;

        while (ht_table_iterator_get_next(it, NULL, (void **)&listener) == 1)
            http_listener_close(listener);
        ht_table_delete(server->listeners);

        ht_table_iterator_delete(it);
    }

    memset(server, 0, sizeof(struct http_server));
    http_free(server);
}

static void
http_server_error(struct http_server *server, const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    if (!server->cfg.error_hook)
        return;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    server->cfg.error_hook(buf, server->cfg.hook_arg);
}

static void
http_server_trace(struct http_server *server, const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    if (!server->cfg.trace_hook)
        return;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    server->cfg.trace_hook(buf, server->cfg.hook_arg);
}

static struct http_sconnection *
http_sconnection_setup(struct http_server *server, int sock) {
    struct http_sconnection *connection;

    connection = http_malloc(sizeof(struct http_sconnection));
    memset(connection, 0, sizeof(struct http_sconnection));

    connection->server = server;
    connection->sock = sock;

    connection->ev_read = event_new(server->ev_base, connection->sock,
                                    EV_READ | EV_PERSIST,
                                    http_sconnection_on_read_event,
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
                                     http_sconnection_on_write_event,
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

    return connection;

error:
    http_sconnection_close(connection);
    return NULL;
}

static int
http_sconnection_write(struct http_sconnection *connection,
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

static void
http_sconnection_close(struct http_sconnection *connection) {
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

    memset(connection, 0, sizeof(struct http_sconnection));
    http_free(connection);
}

static void
http_sconnection_on_read_event(evutil_socket_t sock, short events, void *arg) {
    struct http_sconnection *connection;
    ssize_t ret;

    connection = arg;

    ret = bf_buffer_read(connection->rbuf, connection->sock, BUFSIZ);
    if (ret == -1) {
        http_sconnection_error(connection, "cannot read socket: %s",
                               strerror(errno));
        http_sconnection_close(connection);
        return;
    }

    if (ret == 0) {
        http_sconnection_trace(connection, "connection closed");
        http_sconnection_close(connection);
        return;
    }

    http_sconnection_trace(connection, "%zi bytes read", ret);

    for (;;) {
        struct http_msg msg;
        int ret;

        memset(&msg, 0, sizeof(struct http_msg));

        msg.type = HTTP_MSG_REQUEST;
        msg.parsing_state = HTTP_PARSING_BEFORE_START_LINE;

        ret = http_msg_parse(&msg, connection->rbuf, &connection->server->cfg);
        if (ret == -1) {
            http_sconnection_error(connection, "cannot parse request: %s",
                                   http_get_error());
            http_sconnection_close(connection);
            return;
        }

        if (ret == 0)
            break;

        http_sconnection_trace(connection, "%s %s %s",
                               http_method_to_string(msg.u.request.method),
                               msg.u.request.uri,
                               http_version_to_string(msg.u.request.version));

        http_msg_free(&msg);
    }
}

static void
http_sconnection_on_write_event(evutil_socket_t sock, short events, void *arg) {
    struct http_sconnection *connection;
    ssize_t ret;

    connection = arg;

    ret = bf_buffer_write(connection->wbuf, connection->sock);
    if (ret == -1) {
        http_sconnection_error(connection, "cannot write to socket: %s",
                               strerror(errno));
        http_sconnection_close(connection);
        return;
    }

    bf_buffer_skip(connection->wbuf, (size_t)ret);
    if (bf_buffer_length(connection->wbuf) == 0)
        event_del(connection->ev_write);

    http_sconnection_trace(connection, "%zi bytes written", ret);
}

static void
http_sconnection_error(struct http_sconnection *connection,
                       const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_server_error(connection->server, "%s:%s: %s",
                      connection->host, connection->port, buf);
}

static void
http_sconnection_trace(struct http_sconnection *connection,
                       const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_server_trace(connection->server, "%s:%s: %s",
                      connection->host, connection->port, buf);
}

static struct http_listener *
http_listener_setup(struct http_server *server, const struct addrinfo *ai) {
    struct http_listener *listener;
    struct http_cfg *cfg;
    int ret;

    listener = http_malloc(sizeof(struct http_listener));
    if (!listener)
        return NULL;

    memset(listener, 0, sizeof(struct http_listener));

    listener->server = server;

    cfg = &server->cfg;

    listener->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener->sock == -1) {
        http_set_error("cannot create socket: %s", strerror(errno));
        goto error;
    }

    if (bind(listener->sock, ai->ai_addr, ai->ai_addrlen) == -1) {
        http_set_error("cannot bind socket: %s", strerror(errno));
        goto error;
    }

    if (listen(listener->sock, cfg->u.server.connection_backlog) == -1) {
        http_set_error("cannot listen on socket: %s", strerror(errno));
        goto error;
    }

    ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                      listener->host, NI_MAXHOST,
                      listener->port, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        http_set_error("cannot resolve address: %s", gai_strerror(ret));
        goto error;
    }

    listener->ev_sock = event_new(server->ev_base, listener->sock,
                                  EV_READ | EV_PERSIST,
                                  http_listener_on_sock_event,
                                  listener);
    if (!listener->ev_sock) {
        http_set_error("cannot create read event: %s", strerror(errno));
        goto error;
    }

    if (event_add(listener->ev_sock, NULL) == -1) {
        http_set_error("cannot add read event: %s", strerror(errno));
        goto error;
    }

    http_server_trace(listener->server, "listening on %s:%s",
                      listener->host, listener->port);
    return listener;

error:
    http_listener_close(listener);
    return NULL;
}

static void
http_listener_close(struct http_listener *listener) {
    if (!listener)
        return;

    if (listener->ev_sock)
        event_free(listener->ev_sock);

    if (listener->sock >= 0)
        close(listener->sock);
    listener->sock = -1;

    memset(listener, 0, sizeof(struct http_listener));
    http_free(listener);
}

static void
http_listener_on_sock_event(evutil_socket_t sock, short events, void *arg) {
    struct http_server *server;
    struct http_listener *listener;
    struct http_sconnection *connection;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int client_sock;
    int ret;

    listener = arg;
    server = listener->server;

    addrlen = sizeof(struct sockaddr_storage);
    client_sock = accept(listener->sock, (struct sockaddr *)&addr, &addrlen);
    if (client_sock == -1) {
        http_server_error(server, "cannot accept connection: %s",
                          strerror(errno));
        return;
    }

    connection = http_sconnection_setup(server, client_sock);
    if (!connection) {
        http_server_error(server, "cannot setup connection: %s",
                          http_get_error());
        close(sock);
        return;
    }

    if (ht_table_insert(server->connections,
                        HT_INT32_TO_POINTER(connection->sock),
                        connection) == -1) {
        http_server_error(server, "%s", ht_get_error());
        http_sconnection_close(connection);
        return;
    }

    ret = getnameinfo((struct sockaddr *)&addr, addrlen,
                      connection->host, NI_MAXHOST,
                      connection->port, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        http_server_error(server, "cannot resolve address: %s",
                          gai_strerror(ret));
        http_sconnection_close(connection);
        return;
    }

    http_sconnection_trace(connection, "connection accepted");

#if 0
    {
        const char *response;

        response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";

        if (http_sconnection_write(connection,
                                   response, strlen(response)) == -1) {
            http_sconnection_error(connection, "cannot send response: %s",
                                   http_get_error());
            http_sconnection_close(connection);
            return;
        }
    }
#endif
}
