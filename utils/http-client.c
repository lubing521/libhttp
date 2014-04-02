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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <event.h>

#include "http.h"

struct httpc {
    struct event_base *ev_base;

    bool do_exit;
};

static struct httpc httpc;

static void httpc_die(const char *, ...);
static void httpc_usage(const char *, int);

static void httpc_initialize(void);
static void httpc_shutdown(void);

static void httpc_on_error(const char *, void *);
static void httpc_on_trace(const char *, void *);

static void httpc_process_uri(struct http_uri *);
static void httpc_on_response(struct http_client *, const struct http_msg *,
                              void *);

int
main(int argc, char **argv) {
    int opt, nb_args;

    opterr = 0;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
            httpc_usage(argv[0], 0);
            break;

        case '?':
            httpc_usage(argv[0], 1);
        }
    }

    nb_args = argc - optind;
    if (nb_args < 1)
        httpc_usage(argv[0], 1);

    httpc_initialize();

    for (int i = 0; i < nb_args; i++) {
        struct http_uri *uri;
        const char *uri_str;

        uri_str = argv[optind + i];
        uri = http_uri_new(uri_str);
        if (!uri)
            httpc_die("invalid uri '%s': %s", uri_str, http_get_error());

        httpc_process_uri(uri);

        http_uri_delete(uri);
    }

    httpc_shutdown();
    return 0;
}

static void
httpc_usage(const char *argv0, int exit_code) {
    printf("Usage: %s [-h]\n"
            "\n"
            "Options:\n"
            "  -h display help\n",
            argv0);
    exit(exit_code);
}

void
httpc_die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}

static void
httpc_initialize(void) {
    httpc.ev_base = event_base_new();
    if (!httpc.ev_base)
        httpc_die("cannot create event base: %s", strerror(errno));
}

static void
httpc_shutdown(void) {
    event_base_free(httpc.ev_base);
}

static void
httpc_on_error(const char *msg, void *arg) {
    fprintf(stderr, "error: %s\n", msg);
}

static void
httpc_on_trace(const char *msg, void *arg) {
    printf("%s\n", msg);
}

static void
httpc_process_uri(struct http_uri *uri) {
    struct http_client *client;
    struct http_cfg cfg;

    if (http_cfg_init(&cfg) == -1)
        httpc_die("cannot initialize configuration: %s", http_get_error());

    cfg.host = http_uri_host(uri);
    if (!cfg.host)
        httpc_die("missing host in uri");

    cfg.port = http_uri_port(uri);

    cfg.error_hook = httpc_on_error;
    cfg.trace_hook = httpc_on_trace;

    cfg.u.client.response_handler = httpc_on_response;

    client = http_client_new(&cfg, httpc.ev_base);
    if (!client)
        httpc_die("%s", http_get_error());

    if (http_client_send_request(client, HTTP_GET, uri) == -1)
        httpc_die("cannot send request: %s", http_get_error());

    httpc.do_exit = false;
    while (!httpc.do_exit) {
        if (event_base_loop(httpc.ev_base, EVLOOP_ONCE) == -1)
            httpc_die("cannot read events: %s", strerror(errno));
    }

    http_client_delete(client);
    http_cfg_free(&cfg);
}

static void
httpc_on_response(struct http_client *client, const struct http_msg *msg,
                  void *arg) {
    size_t nb_headers;

    printf("\nresponse  %s %d %s\n",
           http_version_to_string(http_msg_version(msg)),
           http_response_status_code(msg),
           http_response_reason_phrase(msg));

    nb_headers = http_msg_nb_headers(msg);
    for (size_t i = 0; i < nb_headers; i++) {
        const struct http_header *header;

        header = http_msg_header(msg, i);
        printf("header    %s: %s\n",
               http_header_name(header), http_header_value(header));
    }

    if (http_msg_body_length(msg) > 0)
        printf("body      %zu bytes\n\n", http_msg_body_length(msg));

    httpc.do_exit = true;
}
