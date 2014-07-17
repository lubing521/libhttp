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
    char host_port[HTTP_HOST_PORT_BUFSZ];
    char numeric_host_port[HTTP_HOST_PORT_BUFSZ];
};

static struct http_listener *http_listener_new(struct http_server *,
                                               const struct addrinfo *);
static void http_listener_delete(struct http_listener *);

static void http_listener_on_sock_event(evutil_socket_t, short, void *);

void
http_route_options_init(struct http_route_options *options,
                        const struct http_cfg *cfg) {
    memset(options, 0, sizeof(struct http_route_options));

    options->bufferize_body = cfg->bufferize_body;
    options->max_content_length = cfg->max_content_length;
}

struct http_server *
http_server_new(struct http_cfg *cfg, struct event_base *ev_base) {
    struct timeval tv;
    struct http_server *server;
    struct addrinfo hints, *res;
    int ret;

    server = http_malloc0(sizeof(struct http_server));

    server->cfg = cfg;

    server->ev_base = ev_base;

    server->listeners = ht_table_new(ht_hash_int32, ht_equal_int32);
    server->connections = ht_table_new(ht_hash_int32, ht_equal_int32);

    if (cfg->use_ssl) {
        const char *crt_path, *key_path;

        crt_path = cfg->u.server.ssl_certificate;
        if (!crt_path) {
            http_set_error("no ssl certificate set in configuration");
            goto error;
        }

        key_path = cfg->u.server.ssl_key;
        if (!key_path) {
            http_set_error("no ssl private key set in configuration");
            goto error;
        }

        server->ssl_ctx = http_ssl_server_ctx_new(cfg);
        if (!server->ssl_ctx)
            goto error;

        if (SSL_CTX_use_certificate_file(server->ssl_ctx,
                                         crt_path, SSL_FILETYPE_PEM) != 1) {
            http_set_error("cannot use ssl certificate from %s: %s",
                           crt_path, http_ssl_get_error());
            goto error;
        }

        if (SSL_CTX_use_PrivateKey_file(server->ssl_ctx,
                                        key_path, SSL_FILETYPE_PEM) != 1) {
            http_set_error("cannot use ssl private key from %s: %s",
                           key_path, http_ssl_get_error());
            goto error;
        }
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = 0;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_addrlen = 0;

    ret = getaddrinfo(cfg->host, cfg->port, &hints, &res);
    if (ret != 0) {
        http_set_error("cannot resolve address %s:%s: %s",
                       cfg->host, cfg->port, gai_strerror(ret));
        goto error;
    }

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        struct http_listener *listener;

        listener = http_listener_new(server, ai);
        if (!listener) {
            http_server_error(server, "%s", http_get_error());
            continue;
        }

        if (ht_table_insert(server->listeners,
                            HT_INT32_TO_POINTER(listener->sock),
                            listener) == -1) {
            http_server_error(server, "%s", ht_get_error());
            http_listener_delete(listener);
            continue;
        }
    }

    freeaddrinfo(res);

    if (ht_table_nb_entries(server->listeners) == 0) {
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
    http_server_delete(server);
    return NULL;
}

void
http_server_delete(struct http_server *server) {
    struct ht_table_iterator *it;

    if (!server)
        return;

    if (server->timeout_timer)
        event_free(server->timeout_timer);

    http_route_base_delete(server->route_base);

    it = ht_table_iterate(server->connections);
    if (it) {
        struct http_connection *connection;

        while (ht_table_iterator_next(it, NULL, (void **)&connection) == 1)
            http_connection_delete(connection);
        ht_table_iterator_delete(it);

        ht_table_delete(server->connections);

    }

    it = ht_table_iterate(server->listeners);
    if (it) {
        struct http_listener *listener;

        while (ht_table_iterator_next(it, NULL, (void **)&listener) == 1)
            http_listener_delete(listener);
        ht_table_iterator_delete(it);

        ht_table_delete(server->listeners);
    }

    if (server->ssl_ctx)
        SSL_CTX_free(server->ssl_ctx);

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
                      http_msg_handler msg_handler,
                      const struct http_route_options *options) {
    struct http_route *route;

    route = http_route_new(method, path, msg_handler);
    if (!route)
        return -1;

    http_route_apply_options(route, options, server->cfg);
    http_route_base_add_route(server->route_base, route);
    return 0;
}

int http_default_error_sender(struct http_connection *connection,
                              enum http_status_code status_code,
                              struct http_headers *headers,
                              const char *errmsg) {
    const char *reason_phrase;
    char *body;
    size_t bodysz;
    int ret;

    reason_phrase = http_status_code_to_reason_phrase(status_code);
    if (!reason_phrase)
        reason_phrase = "";

    if (errmsg) {
        ret = http_asprintf(&body, "<h1>%d %s</h1>\n<p>%s</p>\n",
                            status_code, reason_phrase, errmsg);
    } else {
        ret = http_asprintf(&body, "<h1>%d %s</h1>\n",
                            status_code, reason_phrase);
    }

    bodysz = (size_t)ret;

    http_headers_set_header(headers, "Content-Type", "text/html");

    if (http_connection_send_response_with_body(connection, status_code,
                                                headers,
                                                body, bodysz) == -1) {
        http_free(body);
        return -1;
    }

    http_free(body);
    return 0;
}

void
http_server_error(const struct http_server *server, const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    if (!server->cfg->error_hook)
        return;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    server->cfg->error_hook(buf, server->cfg->hook_arg);
}

void
http_server_trace(const struct http_server *server, const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    if (!server->cfg->trace_hook)
        return;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    server->cfg->trace_hook(buf, server->cfg->hook_arg);
}

bool
http_server_does_listen_on(const struct http_server *server,
                           const char *host, const char *port) {
    struct http_listener *listener;
    struct ht_table_iterator *it;
    bool found;

    it = ht_table_iterate(server->listeners);
    if (!it) {
        http_server_error(server, "cannot iterate on listeners: %s",
                          ht_get_error());
        return false;
    }

    found = false;
    while (ht_table_iterator_next(it, NULL, (void **)&listener) == 1) {
        if ((strcmp(host, listener->host) == 0
             || strcmp(host, listener->numeric_host) == 0)
            && (!port || (strcmp(port, listener->port) == 0))) {
            found = true;
            break;
        }
    }

    ht_table_iterator_delete(it);
    return found;
}

bool
http_server_does_listen_on_host_string(const struct http_server *server,
                                       const char *host_string) {
    struct http_listener *listener;
    struct ht_table_iterator *it;
    bool found;

    it = ht_table_iterate(server->listeners);
    if (!it) {
        http_server_error(server, "cannot iterate on listeners: %s",
                          ht_get_error());
        return false;
    }

    found = false;
    while (ht_table_iterator_next(it, NULL, (void **)&listener) == 1) {
        if (strcmp(host_string, listener->host) == 0
         || strcmp(host_string, listener->numeric_host) == 0
         || strcmp(host_string, listener->host_port) == 0
         || strcmp(host_string, listener->numeric_host_port) == 0) {
            found = true;
            break;
        }
    }

    ht_table_iterator_delete(it);
    return found;
}

void
http_server_register_connection(struct http_server *server,
                                struct http_connection *connection) {
    assert(connection->sock >= 0);

    ht_table_insert(server->connections, HT_INT32_TO_POINTER(connection->sock),
                    connection);
}

void
http_server_unregister_connection(struct http_server *server,
                                  struct http_connection *connection) {
    assert(connection->sock >= 0);

    ht_table_remove(server->connections,
                    HT_INT32_TO_POINTER(connection->sock));
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

        while (ht_table_iterator_next(it, NULL, (void **)&connection) == 1)
            http_connection_check_for_timeout(connection, now);

        ht_table_iterator_delete(it);
    }
}

static struct http_listener *
http_listener_new(struct http_server *server, const struct addrinfo *ai) {
    struct http_listener *listener;
    struct http_cfg *cfg;
    int ret, opt;

    listener = http_malloc(sizeof(struct http_listener));
    memset(listener, 0, sizeof(struct http_listener));

    listener->server = server;

    cfg = server->cfg;

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

    snprintf(listener->host_port, HTTP_HOST_PORT_BUFSZ,
             "%s:%s", listener->host, listener->port);

    if (ai->ai_family == AF_INET) {
        snprintf(listener->numeric_host_port, HTTP_HOST_PORT_BUFSZ,
                 "%s:%s", listener->numeric_host, listener->port);
    } else if (ai->ai_family == AF_INET6) {
        snprintf(listener->numeric_host_port, HTTP_HOST_PORT_BUFSZ,
                 "[%s]:%s", listener->numeric_host, listener->port);
    } else {
        http_set_error("unknown address family %d", ai->ai_family);
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

    http_server_trace(listener->server, "listening on %s (%s)",
                      listener->numeric_host_port, listener->host_port);
    return listener;

error:
    http_listener_delete(listener);
    return NULL;
}

static void
http_listener_delete(struct http_listener *listener) {
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
    struct http_cfg *cfg;
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int client_sock;
    int ret;

    listener = arg;
    server = listener->server;

    cfg = server->cfg;

    addrlen = sizeof(struct sockaddr_storage);
    client_sock = accept(listener->sock, (struct sockaddr *)&addr, &addrlen);
    if (client_sock == -1) {
        http_server_error(server, "cannot accept connection: %s",
                          strerror(errno));
        return;
    }

    connection = http_connection_new(HTTP_CONNECTION_SERVER, server,
                                     client_sock);
    if (!connection) {
        http_server_error(server, "cannot create connection: %s",
                          http_get_error());
        close(sock);
        return;
    }

    ret = getnameinfo((struct sockaddr *)&addr, addrlen,
                      host, NI_MAXHOST,
                      port, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        http_server_error(server, "cannot resolve address: %s",
                          gai_strerror(ret));
        http_connection_discard(connection);
        return;
    }

    if (addr.ss_family == AF_INET) {
        snprintf(connection->address, HTTP_HOST_PORT_BUFSZ,
                 "%s:%s", host, port);
    } else if (addr.ss_family == AF_INET6) {
        snprintf(connection->address, HTTP_HOST_PORT_BUFSZ,
                 "[%s]:%s", host, port);
    } else {
        http_server_error(server, "unknown address family %d",
                          addr.ss_family);
        http_connection_discard(connection);
        return;
    }

    if (cfg->use_ssl) {
        if (SSL_accept(connection->ssl) != 1) {
            http_server_error(server, "cannot accept ssl connection: %s",
                              http_ssl_get_error());
            http_connection_discard(connection);
            return;
        }
    }

    http_server_register_connection(server, connection);
}
