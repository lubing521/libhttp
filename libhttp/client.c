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

#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "http.h"
#include "internal.h"

static void http_client_disconnect(struct http_client *);

static void  http_client_init_request_headers(struct http_client *,
                                              const struct http_uri *,
                                              struct http_headers *);

struct http_client *
http_client_new(struct http_cfg *cfg, struct event_base *ev_base) {
    struct http_client *client;
    struct addrinfo hints, *res;
    int ret;

    client = http_malloc0(sizeof(struct http_client));

    client->cfg = cfg;
    client->ev_base = ev_base;

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

    client->sock = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        client->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (client->sock == -1) {
            http_client_error(client, "cannot create socket: %s",
                              strerror(errno));
            continue;
        }

        ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                          client->numeric_host, NI_MAXHOST,
                          client->port, NI_MAXSERV,
                          NI_NUMERICHOST | NI_NUMERICSERV);
        if (ret != 0) {
            http_set_error("cannot resolve address: %s", gai_strerror(ret));
            freeaddrinfo(res);
            goto error;
        }

        ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                          client->host, NI_MAXHOST,
                          NULL, 0,
                          0);
        if (ret != 0) {
            http_set_error("cannot resolve address: %s", gai_strerror(ret));
            freeaddrinfo(res);
            goto error;
        }

        snprintf(client->host_port, HTTP_HOST_PORT_BUFSZ,
                 "%s:%s", client->host, client->port);

        if (ai->ai_family == AF_INET) {
            snprintf(client->numeric_host_port, HTTP_HOST_PORT_BUFSZ,
                     "%s:%s", client->numeric_host, client->port);
        } else if (ai->ai_family == AF_INET6) {
            snprintf(client->numeric_host_port, HTTP_HOST_PORT_BUFSZ,
                     "[%s]:%s", client->numeric_host, client->port);
        } else {
            http_set_error("unknown address family %d", ai->ai_family);
            freeaddrinfo(res);
            goto error;
        }

        if (connect(client->sock, ai->ai_addr, ai->ai_addrlen) == -1) {
            http_client_error(client, "cannot connect to %s",
                              client->numeric_host_port);
            close(client->sock);
            client->sock = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (client->sock == -1) {
        http_set_error("cannot connect to %s:%s", cfg->host, cfg->port);
        goto error;
    }

    client->connection = http_connection_new(HTTP_CONNECTION_CLIENT, client,
                                             client->sock);
    if (!client->connection)
        goto error;

    http_client_trace(client, "connected to %s", client->numeric_host_port);

    return client;

error:
    http_client_delete(client);
    return NULL;
}

void
http_client_delete(struct http_client *client) {
    if (!client)
        return;

    if (client->sock >= 0)
        close(client->sock);

    if (client->ev_sock)
        event_free(client->ev_sock);

    http_connection_delete(client->connection);

    memset(client, 0, sizeof(struct http_client));
    http_free(client);
}

struct http_connection *
http_client_connection(const struct http_client *client) {
    return client->connection;
}

int
http_client_send_request(struct http_client *client, enum http_method method,
                         const struct http_uri *uri,
                         struct http_headers *headers) {
    char *path;

    path = http_uri_encode_path_and_query(uri);
    if (!path)
        return -1;

    if (headers == NULL)
        headers = http_headers_new();

    http_client_init_request_headers(client, uri, headers);

    if (http_connection_write_request(client->connection, method, path) == -1)
        goto error;

    http_connection_write_headers(client->connection, headers);
    http_connection_write(client->connection, "\r\n", 2);

    http_connection_track_request_send(client->connection, method, path);

    http_free(path);
    http_headers_delete(headers);
    return 0;

error:
    http_free(path);
    http_headers_delete(headers);
    http_client_disconnect(client);
    return -1;
}

int
http_client_send_request_with_body(struct http_client *client,
                                   enum http_method method,
                                   const struct http_uri *uri,
                                   struct http_headers *headers,
                                   const char *body, size_t bodysz) {
    char *path;

    path = http_uri_encode_path_and_query(uri);
    if (!path)
        return -1;

    if (headers == NULL)
        headers = http_headers_new();

    http_client_init_request_headers(client, uri, headers);

    http_headers_format_header(headers, "Content-Length", "%zu", bodysz);

    if (http_connection_write_request(client->connection, method, path) == -1)
        goto error;

    http_connection_write_headers(client->connection, headers);
    http_connection_write(client->connection, "\r\n", 2);
    http_connection_write(client->connection, body, bodysz);

    http_connection_track_request_send(client->connection, method, path);

    http_free(path);
    http_headers_delete(headers);
    return 0;

error:
    http_free(path);
    http_headers_delete(headers);
    http_client_disconnect(client);
    return -1;
}

int
http_client_send_request_with_file(struct http_client *client,
                                   enum http_method method,
                                   const struct http_uri *uri,
                                   struct http_headers *headers,
                                   const char *file_path, int fd,
                                   size_t file_sz) {
    char *path;

    path = http_uri_encode_path_and_query(uri);
    if (!path)
        return -1;

    if (headers == NULL)
        headers = http_headers_new();

    http_client_init_request_headers(client, uri, headers);

    http_headers_format_header(headers, "Content-Length", "%zu", file_sz);

    if (http_connection_write_request(client->connection, method, path) == -1)
        goto error;

    http_connection_write_headers(client->connection, headers);
    http_connection_write(client->connection, "\r\n", 2);
    http_stream_add_file(client->connection->wstream, fd, file_sz, file_path);

    http_connection_track_request_send(client->connection, method, path);

    http_free(path);
    http_headers_delete(headers);
    return 0;

error:
    close(fd);
    http_free(path);
    http_headers_delete(headers);
    return -1;
}

void
http_client_error(const struct http_client *client, const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    if (!client->cfg->error_hook)
        return;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    client->cfg->error_hook(buf, client->cfg->hook_arg);
}

void
http_client_trace(const struct http_client *client, const char *fmt, ...) {
    char buf[HTTP_ERROR_BUFSZ];
    va_list ap;

    if (!client->cfg->trace_hook)
        return;

    va_start(ap, fmt);
    vsnprintf(buf, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    client->cfg->trace_hook(buf, client->cfg->hook_arg);
}

static void
http_client_disconnect(struct http_client *client) {
    http_connection_discard(client->connection);
    client->connection = NULL;
}

static void
http_client_init_request_headers(struct http_client *client,
                                 const struct http_uri *uri,
                                 struct http_headers *headers) {
    http_headers_set_header(headers, "Host", uri->host);
}
