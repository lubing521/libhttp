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

    struct http_client *client;

    bool do_exit;
};

static struct httpc httpc;

static void httpc_die(const char *, ...);
static void httpc_usage(const char *, int);

static void httpc_initialize(struct http_cfg *);
static void httpc_shutdown(void);

static void httpc_on_error(const char *, void *);
static void httpc_on_trace(const char *, void *);

int
main(int argc, char **argv) {
    struct http_cfg cfg;
    int opt;

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

    if (http_cfg_init(&cfg) == -1)
        httpc_die("cannot initialize configuration: %s", http_get_error());

    cfg.port = "8080";
    cfg.error_hook = httpc_on_error;
    cfg.trace_hook = httpc_on_trace;

    httpc_initialize(&cfg);

    while (!httpc.do_exit) {
        if (event_base_loop(httpc.ev_base, EVLOOP_ONCE) == -1)
            httpc_die("cannot read events: %s", strerror(errno));
    }

    httpc_shutdown();

    http_cfg_free(&cfg);
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
httpc_initialize(struct http_cfg *cfg) {
    httpc.ev_base = event_base_new();
    if (!httpc.ev_base)
        httpc_die("cannot create event base: %s", strerror(errno));

    /* Client */
    httpc.client = http_client_new(cfg, httpc.ev_base);
    if (!httpc.client)
        httpc_die("%s", http_get_error());
}

static void
httpc_shutdown(void) {
    http_client_delete(httpc.client);

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
