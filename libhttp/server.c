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

struct http_server_cfg http_server_default_cfg = {
    .host = "localhost",
    .port = "80",

    .connection_backlog = 5,

    .error_hook = NULL,
    .trace_hook = NULL,
    .hook_arg = NULL,
};

static void http_server_error(struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));
static void http_server_trace(struct http_server *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

struct http_server_connection {
    int sock;

    struct bf_buffer *rbuf;
    struct bf_buffer *wbuf;
};

static struct http_server_connection *http_server_connection_setup(int);
static void http_server_connection_close(struct http_server_connection *);

struct http_listener {
    struct http_server *server;

    int sock;
    struct event *ev;

    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
};

static struct http_listener *http_listener_setup(struct http_server *,
                                                 const struct addrinfo *);
static void http_listener_close(struct http_listener *);

struct http_server {
    struct http_server_cfg cfg;

    struct event_base *ev_base;

    struct ht_table *listeners;
    struct ht_table *connections;
};

struct http_server *
http_server_listen(const struct http_server_cfg *cfg,
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
        struct http_server_connection *connection;

        while (ht_table_iterator_get_next(it, NULL, (void **)&connection) == 1)
            http_server_connection_close(connection);
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

static struct http_server_connection *
http_server_connection_setup(int sock) {
    struct http_server_connection *connection;

    connection = http_malloc(sizeof(struct http_server_connection));
    memset(connection, 0, sizeof(struct http_server_connection));

    connection->sock = sock;

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
    http_server_connection_close(connection);
    return NULL;
}

static void
http_server_connection_close(struct http_server_connection *connection) {
    if (!connection)
        return;

    close(connection->sock);
    connection->sock = -1;

    bf_buffer_delete(connection->rbuf);
    bf_buffer_delete(connection->wbuf);

    memset(connection, 0, sizeof(struct http_server_connection));
    http_free(connection);
}

static struct http_listener *
http_listener_setup(struct http_server *server, const struct addrinfo *ai) {
    struct http_listener *listener;
    struct http_server_cfg *cfg;
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

    if (listen(listener->sock, cfg->connection_backlog) == -1) {
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

    if (listener->sock >= 0)
        close(listener->sock);
    listener->sock = -1;

    memset(listener, 0, sizeof(struct http_listener));
    http_free(listener);
}
