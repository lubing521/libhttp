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

static int http_method_parse(const char *, size_t, enum http_method *);
static int http_version_parse(const char *, size_t, enum http_version *);

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
        [HTTP_OPTIONS] = "OPTIONS",
        [HTTP_GET]     = "GET",
        [HTTP_HEAD]    = "HEAD",
        [HTTP_POST]    = "POST",
        [HTTP_PUT]     = "PUT",
        [HTTP_DELETE]  = "DELETE",
        [HTTP_TRACE]   = "TRACE",
        [HTTP_CONNECT] = "CONNECT",
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
http_msg_parse(struct http_msg *msg, struct bf_buffer *buf,
               const struct http_cfg *cfg,
               enum http_status_code *http_error) {
    int ret;

    switch (msg->parsing_state) {
    case HTTP_PARSING_BEFORE_START_LINE:
        if (msg->type == HTTP_MSG_REQUEST) {
            ret = http_msg_parse_request_line(msg, buf, cfg, http_error);
        } else if (msg->type == HTTP_MSG_RESPONSE) {
            ret = http_msg_parse_status_line(msg, buf, cfg, http_error);
        } else {
            http_set_error("unknown message type %d", msg->type);
            return -1;
        }

        return ret;

    case HTTP_PARSING_BEFORE_HEADER:
        return http_msg_parse_headers(msg, buf, cfg, http_error);

    case HTTP_PARSING_BEFORE_BODY:
        return http_msg_parse_body(msg, buf, cfg, http_error);

    case HTTP_PARSING_DONE:
        return 1;
    }
}

int
http_msg_parse_request_line(struct http_msg *msg, struct bf_buffer *buf,
                            const struct http_cfg *cfg,
                            enum http_status_code *http_error) {
    const char *ptr;
    size_t len;

    const char *space, *cr;
    size_t toklen;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    *http_error = 0;

    /* Method */
    space = memchr(ptr, ' ', len);
    if (!space) {
        if (len > 7) { /* HTTP_OPTIONS */
            http_set_error("method too long");
            *http_error = HTTP_NOT_IMPLEMENTED;
            return -1;
        } else {
            return 0;
        }
    }

    toklen = (size_t)(space - ptr);
    if (toklen == 0) {
        http_set_error("empty method");
        *http_error = HTTP_BAD_REQUEST;
        return -1;
    }

    if (http_method_parse(ptr, toklen, &msg->u.request.method) == -1) {
        *http_error = HTTP_NOT_IMPLEMENTED;
        return -1;
    }

    ptr += toklen + 1;
    len -= toklen - 1;

    /* URI */
    space = memchr(ptr, ' ', len);
    if (!space) {
        if (len > cfg->u.server.max_request_uri_length) {
            http_set_error("request uri too long");
            *http_error = HTTP_REQUEST_URI_TOO_LONG;
            return -1;
        } else {
            return 0;
        }
    }

    toklen = (size_t)(space - ptr);
    if (toklen == 0) {
        http_set_error("empty request uri");
        *http_error = HTTP_BAD_REQUEST;
        return -1;
    }

    msg->u.request.uri = http_strndup(ptr, toklen);

    ptr += toklen + 1;
    len -= toklen - 1;

    /* HTTP version */
    cr = memchr(ptr, '\r', len);
    if (!cr) {
        if (len > 8) {
            http_set_error("http version too long");
            *http_error = HTTP_HTTP_VERSION_NOT_SUPPORTED;
            return -1;
        } else {
            return 0;
        }
    }

    toklen = (size_t)(cr - ptr);
    if (cr == 0) {
        http_set_error("empty version");
        return -1;
    }

    if (http_version_parse(ptr, toklen, &msg->u.request.version) == -1) {
        *http_error = HTTP_HTTP_VERSION_NOT_SUPPORTED;
        return -1;
    }

    ptr += toklen + 1;
    len -= toklen - 1;

    bf_buffer_skip(buf, len - bf_buffer_length(buf));

    msg->parsing_state = HTTP_PARSING_DONE; /* XXX temporary */
    return 1;
}

int
http_msg_parse_status_line(struct http_msg *msg, struct bf_buffer *buf,
                           const struct http_cfg *cfg,
                           enum http_status_code *http_error) {
    const char *ptr;
    size_t sz;

    ptr = bf_buffer_data(buf);
    sz = bf_buffer_length(buf);

    *http_error = 0;

    return 0;
}

int
http_msg_parse_headers(struct http_msg *msg, struct bf_buffer *buf,
                       const struct http_cfg *cfg,
                       enum http_status_code *http_error) {
    const char *ptr;
    size_t sz;

    ptr = bf_buffer_data(buf);
    sz = bf_buffer_length(buf);

    *http_error = 0;

    return 0;
}

int
http_msg_parse_body(struct http_msg *msg, struct bf_buffer *buf,
                    const struct http_cfg *cfg,
                    enum http_status_code *http_error) {
    const char *ptr;
    size_t sz;

    ptr = bf_buffer_data(buf);
    sz = bf_buffer_length(buf);

    *http_error = 0;

    return 0;
}

static int
http_method_parse(const char *str, size_t len, enum http_method *method) {
    switch (str[0]) {
    case 'C':
        if (memcmp(str, "CONNECT", len) == 0) {
            *method = HTTP_CONNECT;
            return 1;
        } else {
            goto unknown;
        }

    case 'D':
        if (memcmp(str, "DELETE", len) == 0) {
            *method = HTTP_DELETE;
            return 1;
        } else {
            goto unknown;
        }

    case 'G':
        if (memcmp(str, "GET", len) == 0) {
            *method = HTTP_GET;
            return 1;
        } else {
            goto unknown;
        }

    case 'H':
        if (memcmp(str, "HEAD", len) == 0) {
            *method = HTTP_HEAD;
            return 1;
        } else {
            goto unknown;
        }

    case 'O':
        if (memcmp(str, "OPTIONS", len) == 0) {
            *method = HTTP_OPTIONS;
            return 1;
        } else {
            goto unknown;
        }

    case 'P':
        if (memcmp(str, "POST", len) == 0) {
            *method = HTTP_POST;
            return 1;
        } else if (memcmp(str, "PUT", len) == 0) {
            *method = HTTP_PUT;
            return 1;
        } else {
            goto unknown;
        }

    case 'T':
        if (memcmp(str, "TRACE", len) == 0) {
            *method = HTTP_TRACE;
            return 1;
        } else {
            goto unknown;
        }

    default:
        goto unknown;
    }

unknown:
    http_set_error("unknown method");
    return -1;
}

static int
http_version_parse(const char *str, size_t len, enum http_version *version) {
    if (memcmp(str, "HTTP/1.1", len) == 0) {
        *version = HTTP_1_1;
        return 1;
    } else if (memcmp(str, "HTTP/1.0", len) == 0) {
        *version = HTTP_1_0;
        return 1;
    } else {
        http_set_error("unknown http version");
        return -1;
    }
}
