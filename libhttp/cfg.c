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

#include <string.h>

#include "http.h"
#include "internal.h"

int
http_cfg_init(struct http_cfg *cfg) {
    memset(cfg, 0, sizeof(struct http_cfg));

    cfg->body_decoders = ht_table_new(ht_hash_string, ht_equal_string);
    if (!cfg->body_decoders) {
        http_set_error("%s", ht_get_error());
        return -1;
    }

    cfg->host = "localhost";
    cfg->port = "80";

    cfg->u.server.connection_backlog = 5;
    cfg->u.server.max_request_uri_length = 2048;

    cfg->max_header_name_length = 128;
    cfg->max_header_value_length = 4096;

    cfg->max_content_length = 16 * 1000 * 1000;
    cfg->max_chunk_length = 1000 * 1000;

    cfg->bufferization = HTTP_BUFFERIZE_AUTO;

    cfg->connection_timeout = 10000;

    return 0;
}

void
http_cfg_free(struct http_cfg *cfg) {
    ht_table_delete(cfg->body_decoders);

    memset(cfg, 0, sizeof(struct http_cfg));
}
