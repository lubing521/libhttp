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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <event.h>

#include "http.h"

struct https {
    struct event_base *ev_base;
    struct event *ev_sigint;
    struct event *ev_sigterm;

    struct http_server *server;

    bool do_exit;
};

static struct https https;

static void https_die(const char *, ...);
static void https_usage(const char *, int);

static void https_initialize(struct http_cfg *);
static void https_shutdown(void);

static void https_on_signal(evutil_socket_t, short, void *);
static void https_on_error(const char *, void *);
static void https_on_trace(const char *, void *);
static void https_on_request_received(struct http_connection *,
                                      const struct http_msg *, void *);
static void https_on_request(struct http_connection *,
                             const struct http_request_info *, void *);

static void https_foo_get(struct http_connection *, const struct http_msg *,
                          void *);
static void https_foo_post(struct http_connection *, const struct http_msg *,
                           void *);
static void https_foo_bar_get(struct http_connection *,
                              const struct http_msg *, void *);
static void https_license_get(struct http_connection *,
                              const struct http_msg *, void *);
static void https_upload_buffered_post(struct http_connection *,
                                       const struct http_msg *, void *);
static void https_upload_unbuffered_post(struct http_connection *,
                                         const struct http_msg *, void *);

int
main(int argc, char **argv) {
    const char *ssl_crt, *ssl_key;
    bool bufferize_body, use_ssl;
    struct http_cfg cfg;
    int opt;

    ssl_crt = NULL;
    ssl_key = NULL;

    bufferize_body = true;
    use_ssl = false;

    opterr = 0;
    while ((opt = getopt(argc, argv, "bc:hk:us")) != -1) {
        switch (opt) {
        case 'c':
            ssl_crt = optarg;
            break;

        case 'b':
            bufferize_body = true;
            break;

        case 'h':
            https_usage(argv[0], 0);
            break;

        case 'k':
            ssl_key = optarg;
            break;

        case 'u':
            bufferize_body = false;
            break;

        case 's':
            use_ssl = true;
            break;

        case '?':
            https_usage(argv[0], 1);
        }
    }

    if (use_ssl)
        http_ssl_initialize();

    http_cfg_init_server(&cfg);

    cfg.port = "8080";

    cfg.use_ssl = use_ssl;
    cfg.u.server.ssl_certificate = ssl_crt;
    cfg.u.server.ssl_key = ssl_key;

    cfg.error_hook = https_on_error;
    cfg.trace_hook = https_on_trace;
    cfg.request_received_hook = https_on_request_received;
    cfg.request_hook = https_on_request;

    cfg.bufferize_body = bufferize_body;

    https_initialize(&cfg);

    while (!https.do_exit) {
        if (event_base_loop(https.ev_base, EVLOOP_ONCE) == -1)
            https_die("cannot read events: %s", strerror(errno));
    }

    https_shutdown();

    http_cfg_free(&cfg);

    if (use_ssl)
        http_ssl_shutdown();
    return 0;
}

static void
https_usage(const char *argv0, int exit_code) {
    printf("Usage: %s [-bhu]\n"
            "\n"
            "Options:\n"
            "  -b         bufferize requests\n"
            "  -c <path>  set the ssl certificate\n"
            "  -h         display help\n"
            "  -k <path>  set the ssl private key\n"
            "  -u         do not bufferize requests\n"
            "  -s         use ssl\n",
            argv0);
    exit(exit_code);
}

void
https_die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}

static void
https_initialize(struct http_cfg *cfg) {
    struct http_route_options options;

    https.ev_base = event_base_new();
    if (!https.ev_base)
        https_die("cannot create event base: %s", strerror(errno));

    /* Signals */
#define HTTPS_SETUP_SIGNAL_HANDLER(handle_, signo_)                           \
    do {                                                                      \
        handle_ = evsignal_new(https.ev_base, signo_, https_on_signal, NULL); \
        if (!handle_)                                                         \
            https_die("cannot create signal handler: %s", strerror(errno));   \
                                                                              \
        if (evsignal_add(handle_, NULL) == -1)                                \
            https_die("cannot add signal handler: %s", strerror(errno));      \
    } while (0);

HTTPS_SETUP_SIGNAL_HANDLER(https.ev_sigint, SIGINT);
HTTPS_SETUP_SIGNAL_HANDLER(https.ev_sigterm, SIGTERM);

#undef HTTPS_SETUP_SIGNAL_HANDLER

    signal(SIGPIPE, SIG_IGN);

    /* Server */
    https.server = http_server_new(cfg, https.ev_base);
    if (!https.server)
        https_die("%s", http_get_error());

    http_server_add_route(https.server, HTTP_GET, "/foo",
                          https_foo_get, NULL);
    http_server_add_route(https.server, HTTP_POST, "/foo",
                          https_foo_post, NULL);
    http_server_add_route(https.server, HTTP_GET, "/foo/bar",
                          https_foo_bar_get, NULL);

    http_server_add_route(https.server, HTTP_GET, "/license",
                          https_license_get, NULL);

    http_route_options_init(&options, cfg);
    options.bufferize_body = true;
    http_server_add_route(https.server, HTTP_POST, "/upload/buffered",
                          https_upload_buffered_post, &options);
    http_route_options_free(&options);

    http_route_options_init(&options, cfg);
    options.bufferize_body = false;
    options.max_content_length = 0;
    http_server_add_route(https.server, HTTP_POST, "/upload/unbuffered",
                          https_upload_unbuffered_post, &options);
    http_route_options_free(&options);
}

static void
https_shutdown(void) {
    http_server_delete(https.server);

    event_free(https.ev_sigint);
    event_free(https.ev_sigterm);
    event_base_free(https.ev_base);
}

static void
https_on_signal(evutil_socket_t signo, short events, void *arg) {
    printf("signal %d received\n", signo);

    if (signo == SIGINT || signo == SIGTERM) {
        https.do_exit = true;
    }
}

static void
https_on_error(const char *msg, void *arg) {
    fprintf(stderr, "error: %s\n", msg);
}

static void
https_on_trace(const char *msg, void *arg) {
    printf("%s\n", msg);
}

static void
https_on_request_received(struct http_connection *connection,
                          const struct http_msg *msg, void *arg) {
    size_t nb_headers;

    printf("request   %s %s %s\n",
           http_method_to_string(http_request_method(msg)),
           http_request_uri(msg),
           http_version_to_string(http_msg_version(msg)));

    nb_headers = http_msg_nb_headers(msg);
    for (size_t i = 0; i < nb_headers; i++) {
        const struct http_header *header;

        header = http_msg_header(msg, i);
        printf("  header  %s: %s\n",
               http_header_name(header), http_header_value(header));
    }

    if (http_msg_body_length(msg) > 0)
        printf("  body    %zu bytes\n\n", http_msg_body_length(msg));
}

static void
https_on_request(struct http_connection *connection,
                 const struct http_request_info *info, void *arg) {
    char date_string[64];
    struct tm tm;
    time_t date;

    date = http_request_info_date(info);

    if (localtime_r(&date, &tm) == NULL) {
        fprintf(stderr, "cannot transform date: %s\n", strerror(errno));
        return;
    }

    strftime(date_string, sizeof(date_string), "%Y-%m-%dT%H:%M:%S%z", &tm);

    printf("%s %s %s %d\n",
           date_string,
           http_method_to_string(http_request_info_method(info)),
           http_request_info_uri_string(info),
           http_request_info_status_code(info));
}

static void
https_foo_get(struct http_connection *connection, const struct http_msg *msg,
              void *arg) {
    struct http_headers *headers;
    const char *body;
    size_t bodysz;

    body = "GET /foo\n";
    bodysz = strlen(body);

    headers = http_headers_new();
    http_headers_set_header(headers, "Content-Type", "text/plain");

    http_connection_send_response_with_body(connection, HTTP_OK, headers,
                                            body, bodysz);
}

static void
https_foo_post(struct http_connection *connection, const struct http_msg *msg,
               void *arg) {
    static size_t content_len = 0;

    struct http_headers *headers;
    char body[128];
    size_t bodysz;

    content_len += http_msg_body_length(msg);

    printf("%zu bytes received (total: %zu)\n",
           http_msg_body_length(msg), content_len);

    if (!http_msg_is_complete(msg))
        return;

    snprintf(body, sizeof(body), "%zu bytes received\n", content_len);
    bodysz = strlen(body);

    headers = http_headers_new();
    http_headers_set_header(headers, "Content-Type", "text/plain");

    http_connection_send_response_with_body(connection, HTTP_OK, headers,
                                            body, bodysz);

    content_len = 0;
}

static void
https_foo_bar_get(struct http_connection *connection,
                  const struct http_msg *msg, void *arg) {
    struct http_headers *headers;
    const char *body;
    size_t bodysz;

    body = "GET /foo/bar\n";
    bodysz = strlen(body);

    headers = http_headers_new();
    http_headers_set_header(headers, "Content-Type", "text/plain");

    http_connection_send_response_with_body(connection, HTTP_OK, headers,
                                            body, bodysz);
}

static void
https_license_get(struct http_connection *connection,
                  const struct http_msg *msg, void *arg) {
    struct http_headers *headers;
    enum http_status_code status_code;
    const char *path;
    struct stat st;
    size_t file_sz;
    int fd;

    path = "./LICENSE";

    fd = open(path, O_RDONLY, path);
    if (fd == -1) {
        if (errno == ENOENT) {
            http_connection_send_error(connection, HTTP_NOT_FOUND, NULL);
        } else {
            http_connection_send_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                       "cannot open file %s: %s",
                                       path, strerror(errno));
        }

        return;
    }

    if (fstat(fd, &st) == -1) {
        http_connection_send_error(connection, HTTP_INTERNAL_SERVER_ERROR,
                                   "cannot stat file %s: %s",
                                   path, strerror(errno));
        return;
    }

    file_sz = (size_t)st.st_size;

    if (http_request_has_ranges(msg)) {
        status_code = HTTP_PARTIAL_CONTENT;
    } else {
        status_code = HTTP_OK;
    }

    headers = http_headers_new();
    http_headers_set_header(headers, "Content-Type", "text/plain");

    http_connection_send_response_with_file(connection, status_code, headers,
                                            path, fd, file_sz,
                                            http_request_ranges(msg));
}

static void
https_upload_buffered_post(struct http_connection *connection,
                           const struct http_msg *msg, void *arg) {
    struct http_headers *headers;
    char body[128];
    size_t bodysz;

    http_connection_trace(connection, "%zu bytes received",
                          http_msg_body_length(msg));

    snprintf(body, sizeof(body), "%zu bytes received\n",
             http_msg_body_length(msg));
    bodysz = strlen(body);

    headers = http_headers_new();
    http_headers_set_header(headers, "Content-Type", "text/plain");

    http_connection_send_response_with_body(connection, HTTP_OK, headers,
                                            body, bodysz);
}

static void
https_upload_unbuffered_post(struct http_connection *connection,
                             const struct http_msg *msg, void *arg) {
    static size_t content_len = 0;

    struct http_headers *headers;
    char body[128];
    size_t bodysz;

    if (http_msg_aborted(msg)) {
        http_connection_error(connection, "request processing aborted");
        content_len = 0;
        return;
    }

    content_len += http_msg_body_length(msg);

    http_connection_trace(connection, "%zu/%zu bytes received",
                          http_msg_body_length(msg), content_len);

    if (!http_msg_is_complete(msg))
        return;

    /* Send response */
    snprintf(body, sizeof(body), "%zu bytes received\n", content_len);
    bodysz = strlen(body);

    headers = http_headers_new();
    http_headers_set_header(headers, "Content-Type", "text/plain");

    http_connection_send_response_with_body(connection, HTTP_OK, headers,
                                            body, bodysz);

    content_len = 0;
}
