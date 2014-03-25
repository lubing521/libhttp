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

#include "http.h"
#include "internal.h"

static void http_server_on_timeout_timer(evutil_socket_t, short, void *);

struct http_listener {
    struct http_server *server;

    int sock;
    struct event *ev_sock;

    char host[NI_MAXHOST];
    char numeric_host[NI_MAXHOST];
    char port[NI_MAXSERV];
};

static struct http_listener *http_listener_setup(struct http_server *,
                                                 const struct addrinfo *);
static void http_listener_close(struct http_listener *);

static void http_listener_on_sock_event(evutil_socket_t, short, void *);

struct http_server *
http_server_listen(const struct http_cfg *cfg,
                   struct event_base *ev_base) {
    struct timeval tv;
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

    server->route_base = http_route_base_new();
    if (!server->route_base)
        goto error;

    server->timeout_timer = evtimer_new(ev_base, http_server_on_timeout_timer,
                                        server);
    if (!server->timeout_timer) {
        http_set_error("cannot create timer: %s", strerror(errno));
        goto error;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 100 * 1000;
    if (evtimer_add(server->timeout_timer, &tv) == -1) {
        http_set_error("cannot start timer: %s", strerror(errno));
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

    if (server->timeout_timer)
        event_free(server->timeout_timer);

    http_route_base_delete(server->route_base);

    it = ht_table_iterate(server->connections);
    if (it) {
        struct http_connection *connection;

        while (ht_table_iterator_get_next(it, NULL, (void **)&connection) == 1)
            http_connection_close(connection);
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

void
http_server_set_msg_handler_arg(struct http_server *server, void *arg) {
    server->route_base->msg_handler_arg = arg;
}

int
http_server_add_route(struct http_server *server,
                      enum http_method method, const char *path,
                      http_msg_handler msg_handler) {
    struct http_route *route;

    route = http_route_new(method, path, msg_handler);
    if (!route)
        return -1;

    if (http_route_base_add_route(server->route_base, route) == -1) {
        http_route_delete(route);
        return -1;
    }

    return 0;
}

void
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

void
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

bool
http_server_does_listen_on(const struct http_server *server,
                           const char *host, const char *port) {
    struct ht_table_iterator *it;

    it = ht_table_iterate(server->listeners);
    if (it) {
        struct http_listener *listener;

        while (ht_table_iterator_get_next(it, NULL, (void **)&listener) == 1) {
            if ((strcmp(host, listener->host) == 0
                 || strcmp(host, listener->numeric_host) == 0)
                && (!port || (strcmp(port, listener->port) == 0))) {
                return true;
            }
        }

        ht_table_iterator_delete(it);
    }

    return false;
}

static void
http_server_on_timeout_timer(evutil_socket_t fd, short events, void *arg) {
    struct ht_table_iterator *it;
    struct http_server *server;
    struct timeval tv;
    uint64_t now;

    server = arg;

    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000;
    if (evtimer_add(server->timeout_timer, &tv) == -1)
        http_server_error(server, "cannot start timer: %s", strerror(errno));

    if (http_now_ms(&now) == -1) {
        http_server_error(server, "%s", http_get_error());
        return;
    }

    it = ht_table_iterate(server->connections);
    if (it) {
        struct http_connection *connection;

        while (ht_table_iterator_get_next(it, NULL, (void **)&connection) == 1)
            http_connection_check_for_timeout(connection, now);

        ht_table_iterator_delete(it);
    }
}

static struct http_listener *
http_listener_setup(struct http_server *server, const struct addrinfo *ai) {
    struct http_listener *listener;
    struct http_cfg *cfg;
    int ret, opt;

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

    opt = 1;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(opt)) == -1) {
        http_set_error("cannot set SO_REUSEADDR socket option: %s",
                       strerror(errno));
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
                      listener->numeric_host, NI_MAXHOST,
                      listener->port, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        http_set_error("cannot resolve address: %s", gai_strerror(ret));
        goto error;
    }

    ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                      listener->host, NI_MAXHOST,
                      NULL, 0,
                      0);
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

    http_server_trace(listener->server, "listening on %s:%s (%s)",
                      listener->numeric_host, listener->port, listener->host);
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
    struct http_connection *connection;
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

    connection = http_connection_setup(server, client_sock);
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
        http_connection_close(connection);
        return;
    }

    ret = getnameinfo((struct sockaddr *)&addr, addrlen,
                      connection->host, NI_MAXHOST,
                      connection->port, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        http_server_error(server, "cannot resolve address: %s",
                          gai_strerror(ret));
        http_connection_close(connection);
        return;
    }
}
