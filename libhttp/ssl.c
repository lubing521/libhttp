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
#include <string.h>

#include "http.h"
#include "internal.h"

static __thread char http_ssl_error_buf[HTTP_ERROR_BUFSZ];

void
http_ssl_initialize(void) {
    SSL_library_init();
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();
}

void
http_ssl_shutdown(void) {
    EVP_cleanup();
    ERR_free_strings();
}

const char *
http_ssl_get_error(void) {
    char *ptr;
    size_t len;
    bool first;

    ptr = http_ssl_error_buf;
    len = HTTP_ERROR_BUFSZ;

    first = true;

    for (;;) {
        unsigned long errcode;
        const char *errstr;
        size_t errlen;

        errcode = ERR_get_error();
        if (errcode == 0)
            break;

        if (!first) {
            strncpy(ptr, ", ", len);
            ptr[len - 1] = '\0';

            ptr += 2;
            len -= 2;
            if (len <= 0)
                break;
        }

        errstr = ERR_error_string(errcode, NULL);
        strncpy(ptr, errstr, len);
        ptr[len - 1] = '\0';

        errlen = strlen(errstr);
        ptr += errlen;
        len -= errlen;
        if (len <= 0)
            break;

        first = false;
    }

    if (ptr == http_ssl_error_buf) {
        strncpy(ptr, "empty ssl error queue", len);
        ptr[len - 1] = '\0';
    }

    return http_ssl_error_buf;
}

SSL_CTX *
http_ssl_server_ctx_new(const struct http_cfg *cfg) {
    SSL_CTX *ctx;
    long options;

    ctx = SSL_CTX_new(TLSv1_server_method());
    if (!ctx) {
        http_set_error("cannot create ssl context: %s", http_ssl_get_error());
        return NULL;
    }

    options = SSL_OP_ALL | SSL_OP_NO_SSLv2;
    SSL_CTX_set_options(ctx, options);

    options  = SSL_MODE_ENABLE_PARTIAL_WRITE;
    options |= SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
    SSL_CTX_set_mode(ctx, options);

    if (cfg->ssl_ciphers) {
        if (SSL_CTX_set_cipher_list(ctx, cfg->ssl_ciphers) == 0) {
            http_set_error("cannot set cipher list: %s", http_ssl_get_error());
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

SSL *
http_ssl_new(SSL_CTX *ctx, int fd) {
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (!ssl) {
        http_set_error("cannot create ssl connection: %s",
                       http_ssl_get_error());
        return NULL;
    }

    if (SSL_set_fd(ssl, fd) == 0) {
        http_set_error("cannot set ssl connection file descriptor: %s",
                       http_ssl_get_error());
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

ssize_t
http_buf_ssl_read(struct bf_buffer *buf, int fd, size_t sz,
                  SSL *ssl, int *ssl_errcode) {
    char tmp[sz];
    int ret;

    ret = SSL_read(ssl, tmp, sz);
    if (ret <= 0) {
        int errcode;

        errcode = SSL_get_error(ssl, ret);
        *ssl_errcode = errcode;

        if (errcode == SSL_ERROR_ZERO_RETURN) {
            return 0;
        } else {
            http_set_error("cannot read ssl socket: %s",
                           http_ssl_get_error());
            return -1;
        }
    }

    bf_buffer_add(buf, tmp, (size_t)ret);
    return ret;
}

ssize_t
http_buf_ssl_write(struct bf_buffer *buf, int fd, size_t len,
                   SSL *ssl, int *ssl_errcode) {
    const void *ptr;
    int ret;

    ptr = bf_buffer_data(buf);

    ret = SSL_write(ssl, ptr, len);
    if (ret <= 0) {
        int errcode;

        errcode = SSL_get_error(ssl, ret);
        *ssl_errcode = errcode;

        if (errcode == SSL_ERROR_SYSCALL) {
            http_set_error("cannot write to ssl socket: %s",
                           strerror(errno));
        } else {
            http_set_error("cannot write to ssl socket: %s",
                           http_ssl_get_error());
        }

        return -1;
    }

    bf_buffer_skip(buf, (size_t)ret);
    return ret;
}

ssize_t
http_connection_ssl_write(struct http_connection *connection,
                          struct bf_buffer *buf) {
    ssize_t ret;
    size_t len;
    int errcode;

    if (connection->ssl_last_write_length > 0) {
        len = (size_t)connection->ssl_last_write_length;

        /* If len is smaller than the size of the write buffer, then the write
         * buffer has been tampered with, i.e. with a manual operation
         * (bf_buffer_skip()) or by writing it with bf_buffer_write().
         *
         * In both cases, this should never be the case, and it is the sign
         * that something is really wrong with libhttp. */
        assert(len >= bf_buffer_length(buf));
    } else {
        len = bf_buffer_length(buf);
    }

    ret = http_buf_ssl_write(buf, connection->sock, len,
                             connection->ssl, &errcode);
    if (ret == -1) {
        switch (errcode) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            /* From SSL_write(3):
             *
             * When an SSL_write() operation has to be repeated because of
             * SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE, it must be
             * repeated with the same arguments.
             *
             * So we save the length we used to re-use it next time.
             */
            connection->ssl_last_write_length = len;
            return 0;

        default:
            if (errcode == SSL_ERROR_SYSCALL && errno == ECONNRESET)
                connection->closed_by_peer = true;
            return -1;
        }
    }

    connection->ssl_last_write_length = 0;
    return ret;
}
