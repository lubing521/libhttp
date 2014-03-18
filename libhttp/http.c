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

const char *
http_version_to_string(enum http_version version) {
    static const char *strings[] = {
        [HTTP_1_0] = "HTTP/1.0",
        [HTTP_1_1] = "HTTP/1.1",
    };
    static size_t nb_strings;

    nb_strings = HTTP_ARRAY_NB_ELEMENTS(strings);
    if (version >= nb_strings)
        return NULL;

    return strings[version];
}

const char *
http_method_to_string(enum http_method method) {
    static const char *strings[] = {
        [HTTP_GET]     = "GET",
        [HTTP_POST]    = "POST",
        [HTTP_HEAD]    = "HEAD",
        [HTTP_PUT]     = "PUT",
        [HTTP_DELETE]  = "DELETE",
    };
    static size_t nb_strings;

    nb_strings = HTTP_ARRAY_NB_ELEMENTS(strings);
    if (method >= nb_strings)
        return NULL;

    return strings[method];
}

const char *
http_status_code_to_reason_phrase(enum http_status_code status_code) {
    static const char *strings[] = {
        [HTTP_CONTINUE]                      = "Continue",
        [HTTP_SWITCHING_PROTOCOLS]           = "Switching Protocols",

        [HTTP_OK]                            = "OK",
        [HTTP_CREATED]                       = "Created",
        [HTTP_ACCEPTED]                      = "Accepted",
        [HTTP_NON_AUTHORITATIVE_INFORMATION] = "Non-Authoritative Information",
        [HTTP_NO_CONTENT]                    = "No Content",
        [HTTP_RESET_CONTENT]                 = "Reset Content",
        [HTTP_PARTIAL_CONTENT]               = "Partial Content",

        [HTTP_MULTIPLE_CHOICES]              = "Multiple Choices",
        [HTTP_MOVED_PERMANENTLY]             = "Moved Permanently",
        [HTTP_FOUND]                         = "Found",
        [HTTP_SEE_OTHERS]                    = "See Other",
        [HTTP_NOT_MODIFIED]                  = "Not Modified",
        [HTTP_USE_PROXY]                     = "Use Proxy",
        [HTTP_TEMPORARY_REDIRECT]            = "Temporary Redirect",

        [HTTP_BAD_REQUEST]                   = "Bad Request",
        [HTTP_UNAUTHORIZED]                  = "Unauthorized",
        [HTTP_PAYMENT_REQUIRED]              = "Payment Required",
        [HTTP_FORBIDDEN]                     = "Forbidden",
        [HTTP_NOT_FOUND]                     = "Not Found",
        [HTTP_METHOD_NOT_ALLOWED]            = "Method Not Allowed",
        [HTTP_NOT_ACCEPTABLE]                = "Not Acceptable",
        [HTTP_PROXY_AUTHENTICATION_REQUIRED] = "Proxy Authentication Required",
        [HTTP_REQUEST_TIMEOUT]               = "Request Time-out",
        [HTTP_CONFLICT]                      = "Conflict",
        [HTTP_GONE]                          = "Gone",
        [HTTP_LENGTH_REQUIRED]               = "Length Required",
        [HTTP_PRECONDITION_FAILED]           = "Precondition Failed",
        [HTTP_REQUEST_ENTITY_TOO_LARGE]      = "Request Entity Too Large",
        [HTTP_REQUEST_URI_TOO_LONG]          = "Request-URI Too Large",
        [HTTP_UNSUPPORTED_MEDIA_TYPE]        = "Unsupported Media Type",
        [HTTP_REQUEST_RANGE_NOT_SATISFIABLE] = "Requested range not satisfiable",
        [HTTP_EXPECTATION_FAILED]            = "Expectation Failed",

        [HTTP_INTERNAL_SERVER_ERROR]         = "Internal Server Error",
        [HTTP_NOT_IMPLEMENTED]               = "Not Implemented",
        [HTTP_BAD_GATEWAY]                   = "Bad Gateway",
        [HTTP_SERVICE_UNAVAILABLE]           = "Service Unavailable",
        [HTTP_GATEWAY_TIMEOUT]               = "Gateway Time-out",
        [HTTP_HTTP_VERSION_NOT_SUPPORTED]    = "HTTP Version not supported",
    };
    static size_t nb_strings;

    nb_strings = HTTP_ARRAY_NB_ELEMENTS(strings);
    if (status_code >= nb_strings)
        return NULL;

    return strings[status_code];
}

void
http_msg_free(struct http_msg *msg) {
    if (!msg)
        return;

    switch (msg->type) {
    case HTTP_MSG_REQUEST:
        http_free(msg->u.request.uri);
        break;

    case HTTP_MSG_RESPONSE:
        break;
    }

    memset(msg, 0, sizeof(struct http_msg));
}

int
http_parser_init(struct http_parser *parser) {
    memset(parser, 0, sizeof(struct http_parser));

    parser->state = HTTP_PARSER_START;

    return 0;
}

void
http_parser_free(struct http_parser *parser) {
    if (!parser)
        return;

    http_msg_free(&parser->msg);

    memset(parser, 0, sizeof(struct http_parser));
}

void
http_parser_fail(struct http_parser *parser, enum http_status_code status_code,
                 const char *fmt, ...) {
    va_list ap;

    parser->state = HTTP_PARSER_ERROR;
    parser->status_code = status_code;

    va_start(ap, fmt);
    vsnprintf(parser->errmsg, HTTP_ERROR_BUFSZ, fmt, ap);
    va_end(ap);
}

int
http_msg_parse(struct bf_buffer *buf, struct http_parser *parser) {
    switch (parser->state) {
    case HTTP_PARSER_START:
        if (parser->msg.type == HTTP_MSG_REQUEST) {
            return http_msg_parse_request_line(buf, parser);
        } else if (parser->msg.type == HTTP_MSG_RESPONSE) {
            return http_msg_parse_status_line(buf, parser);
        } else {
            http_set_error("unknown message type %d", parser->msg.type);
            return -1;
        }

    case HTTP_PARSER_HEADER:
        return http_msg_parse_headers(buf, parser);

    case HTTP_PARSER_BODY:
        return http_msg_parse_body(buf, parser);

    case HTTP_PARSER_ERROR:
        return -1;

    case HTTP_PARSER_DONE:
        return 1;
    }
}

int
http_msg_parse_request_line(struct bf_buffer *buf, struct http_parser *parser) {
    struct http_msg *msg;
    const char *ptr, *start;
    size_t len, toklen;
    bool found;

    msg = &parser->msg;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

#define HTTP_ERROR(status_code_, fmt_, ...)                           \
    do {                                                             \
        http_parser_fail(parser, status_code_, fmt_, ##__VA_ARGS__); \
        return 1;                                                    \
    } while (0)

#define HTTP_SKIP_SP()               \
    while (len > 0 && *ptr == ' ') { \
        ptr++;                       \
        len--;                       \
    }

#define HTTP_SKIP_CRLF()                                   \
    while (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') { \
        ptr += 2;                                          \
        len -= 2;                                          \
    }

    /* RFC 2616 4.1: In the interest of robustness, servers SHOULD ignore any
     * empty line(s) received where a Request-Line is expected. */
    HTTP_SKIP_CRLF();

    /* Method */
    start = ptr;
    found = false;
    while (len > 0) {
        /* RFC 2616 5.1.1: The method is case-sensitive. */
        if (*ptr == ' ') {
            toklen = (size_t)(ptr - start);

            if (memcmp(start, "GET", toklen) == 0) {
                msg->u.request.method = HTTP_GET;
            } else if (memcmp(start, "POST", toklen) == 0) {
                msg->u.request.method = HTTP_POST;
            } else if (memcmp(start, "HEAD", toklen) == 0) {
                msg->u.request.method = HTTP_HEAD;
            } else if (memcmp(start, "PUT", toklen) == 0) {
                msg->u.request.method = HTTP_PUT;
            } else if (memcmp(start, "DELETE", toklen) == 0) {
                msg->u.request.method = HTTP_DELETE;
            } else {
                HTTP_ERROR(HTTP_NOT_IMPLEMENTED, "unsupported method");
            }

            found = true;
            break;
        } else if (*ptr == '\r' || *ptr == '\n') {
            HTTP_ERROR(HTTP_BAD_REQUEST, "invalid character in request line");
        } else if (*ptr < 'A' || *ptr > 'Z') {
            HTTP_ERROR(HTTP_NOT_IMPLEMENTED, "unsupported method");
        }

        ptr++;
        len--;
    }

    if (!found)
        return 0;

    /* Request URI */
    HTTP_SKIP_SP();

    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == ' ') {
            toklen = (size_t)(ptr - start);

            msg->u.request.uri = http_strndup(start, toklen);
            if (!msg->u.request.uri)
                return -1;

            found = true;
            break;
        } else if (*ptr == '\r' || *ptr == '\n') {
            HTTP_ERROR(HTTP_NOT_IMPLEMENTED, "invalid character in request uri");
        }

        ptr++;
        len--;
    }

    if (!found)
        return 0;

    /* HTTP version */
    HTTP_SKIP_SP();

    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == '\r' || *ptr == '\n') {
            const char *prefix;
            size_t prefix_sz;

            toklen = (size_t)(ptr - start);

            prefix = "HTTP/";
            prefix_sz = strlen(prefix);

            if (toklen < prefix_sz || memcmp(start, prefix, prefix_sz) != 0)
                HTTP_ERROR(HTTP_BAD_REQUEST, "invalid http version format");

            start += prefix_sz;
            toklen -= prefix_sz;

            if (toklen < 3)
                HTTP_ERROR(HTTP_BAD_REQUEST, "invalid http version format");

            if (memcmp(start, "1.0", toklen) == 0) {
                msg->u.request.version = HTTP_1_0;
            } else if (memcmp(start, "1.1", toklen) == 0) {
                msg->u.request.version = HTTP_1_1;
            } else {
                HTTP_ERROR(HTTP_HTTP_VERSION_NOT_SUPPORTED,
                           "unsupported http version");
            }

            found = true;
            break;
        }

        ptr++;
        len--;
    }

    if (!found)
        return 0;

    HTTP_SKIP_CRLF();

#undef HTTP_ERROR
#undef HTTP_SKIP_SP
#undef HTTP_SKIP_CRLF

    bf_buffer_skip(buf, bf_buffer_length(buf) - len);

    parser->state = HTTP_PARSER_HEADER;
    return 1;
}

int
http_msg_parse_status_line(struct bf_buffer *buf, struct http_parser *parser) {
    return 0;
}

int
http_msg_parse_headers(struct bf_buffer *buf, struct http_parser *parser) {
    return 0;
}

int
http_msg_parse_body(struct bf_buffer *buf, struct http_parser *parser) {
    return 0;
}
