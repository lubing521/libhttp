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

void
http_cfg_init(struct http_cfg *cfg) {
    memset(cfg, 0, sizeof(struct http_cfg));

    http_cfg_content_decoder_add(cfg, "application/x-www-form-urlencoded",
                                     http_content_form_data_decode,
                                     http_content_form_data_delete);

    cfg->host = "localhost";
    cfg->port = "80";

    cfg->u.server.connection_backlog = 5;
    cfg->u.server.max_request_uri_length = 2048;
    cfg->u.server.error_body_writer = http_default_error_body_writer;

    cfg->u.client.max_reason_phrase_length = 128;

    cfg->max_header_name_length = 128;
    cfg->max_header_value_length = 4096;

    cfg->max_content_length = 16 * 1000 * 1000;
    cfg->max_chunk_length = 1000 * 1000;

    cfg->bufferization = HTTP_BUFFERIZE_AUTO;

    cfg->connection_timeout = 10000;
}

void
http_cfg_free(struct http_cfg *cfg) {
    http_free(cfg->content_decoders);

    memset(cfg, 0, sizeof(struct http_cfg));
}

void
http_cfg_content_decoder_add(struct http_cfg *cfg, const char *content_type,
                             http_content_decode_func decode,
                             http_content_delete_func delete) {
    struct http_content_decoder *decoder;

    if (cfg->nb_content_decoders == 0) {
        cfg->content_decoders = http_malloc(sizeof(struct http_content_decoder));
    } else {
        size_t nsz;

        nsz = (cfg->nb_content_decoders + 1)
            * sizeof(struct http_content_decoder);
        cfg->content_decoders = http_realloc(cfg->content_decoders, nsz);
    }

    decoder = cfg->content_decoders + cfg->nb_content_decoders;

    decoder->content_type = content_type;
    decoder->decode = decode;
    decoder->delete = delete;

    cfg->nb_content_decoders++;
}

const struct http_content_decoder *
http_cfg_content_decoder_get(const struct http_cfg *cfg,
                             const char *content_type) {
    for (size_t i = 0; i < cfg->nb_content_decoders; i++) {
        const struct http_content_decoder *decoder;

        decoder = cfg->content_decoders + i;
        if (strcmp(decoder->content_type, content_type) == 0)
            return decoder;
    }

    return NULL;
}
