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
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "http.h"
#include "internal.h"

static int http_msg_process_headers(struct http_parser *);
static int http_msg_finalize_body(struct http_msg *msg,
                                  const struct http_cfg *);

static bool http_is_token_char(unsigned char);

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
        [HTTP_OPTIONS] = "OPTIONS",
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
        /* 1xx */
        [HTTP_CONTINUE]                        = "Continue",
        [HTTP_SWITCHING_PROTOCOLS]             = "Switching Protocols",

        /* 2xx */
        [HTTP_OK]                              = "OK",
        [HTTP_CREATED]                         = "Created",
        [HTTP_ACCEPTED]                        = "Accepted",
        [HTTP_NON_AUTHORITATIVE_INFORMATION]   = "Non-Authoritative Information",
        [HTTP_NO_CONTENT]                      = "No Content",
        [HTTP_RESET_CONTENT]                   = "Reset Content",
        [HTTP_PARTIAL_CONTENT]                 = "Partial Content",
        [HTTP_MULTI_STATUS]                    = "Multi-Status",

        /* 3xx */
        [HTTP_MULTIPLE_CHOICES]                = "Multiple Choices",
        [HTTP_MOVED_PERMANENTLY]               = "Moved Permanently",
        [HTTP_FOUND]                           = "Found",
        [HTTP_SEE_OTHERS]                      = "See Other",
        [HTTP_NOT_MODIFIED]                    = "Not Modified",
        [HTTP_USE_PROXY]                       = "Use Proxy",
        [HTTP_TEMPORARY_REDIRECT]              = "Temporary Redirect",

        /* 4xx */
        [HTTP_BAD_REQUEST]                     = "Bad Request",
        [HTTP_UNAUTHORIZED]                    = "Unauthorized",
        [HTTP_PAYMENT_REQUIRED]                = "Payment Required",
        [HTTP_FORBIDDEN]                       = "Forbidden",
        [HTTP_NOT_FOUND]                       = "Not Found",
        [HTTP_METHOD_NOT_ALLOWED]              = "Method Not Allowed",
        [HTTP_NOT_ACCEPTABLE]                  = "Not Acceptable",
        [HTTP_PROXY_AUTHENTICATION_REQUIRED]   = "Proxy Authentication Required",
        [HTTP_REQUEST_TIMEOUT]                 = "Request Time-out",
        [HTTP_CONFLICT]                        = "Conflict",
        [HTTP_GONE]                            = "Gone",
        [HTTP_LENGTH_REQUIRED]                 = "Length Required",
        [HTTP_PRECONDITION_FAILED]             = "Precondition Failed",
        [HTTP_REQUEST_ENTITY_TOO_LARGE]        = "Request Entity Too Large",
        [HTTP_REQUEST_URI_TOO_LONG]            = "Request-URI Too Large",
        [HTTP_UNSUPPORTED_MEDIA_TYPE]          = "Unsupported Media Type",
        [HTTP_REQUEST_RANGE_NOT_SATISFIABLE]   = "Requested range not satisfiable",
        [HTTP_EXPECTATION_FAILED]              = "Expectation Failed",
        [HTTP_UNPROCESSABLE_ENTITY]            = "Unprocessable Entity",
        [HTTP_LOCKED]                          = "Locked",
        [HTTP_FAILED_DEPENDENCY]               = "Failed Dependency",

        /* 5xx */
        [HTTP_INTERNAL_SERVER_ERROR]           = "Internal Server Error",
        [HTTP_NOT_IMPLEMENTED]                 = "Not Implemented",
        [HTTP_BAD_GATEWAY]                     = "Bad Gateway",
        [HTTP_SERVICE_UNAVAILABLE]             = "Service Unavailable",
        [HTTP_GATEWAY_TIMEOUT]                 = "Gateway Time-out",
        [HTTP_HTTP_VERSION_NOT_SUPPORTED]      = "HTTP Version not supported",

        [HTTP_INSUFFICIENT_STORAGE]            = "Insufficient Storage",
        [HTTP_NETWORK_AUTHENTICATION_REQUIRED] = "Network Authentication Required",
    };
    static size_t nb_strings;

    nb_strings = HTTP_ARRAY_NB_ELEMENTS(strings);
    if (status_code >= nb_strings)
        return NULL;

    return strings[status_code];
}

enum http_version
http_msg_version(const struct http_msg *msg) {
    return msg->version;
}

size_t
http_msg_nb_headers(const struct http_msg *msg) {
    return msg->nb_headers;
}

const struct http_header *
http_msg_header(const struct http_msg *msg, size_t idx) {
    assert(idx < msg->nb_headers);
    return msg->headers + idx;
}

const char *
http_msg_get_header(const struct http_msg *msg, const char *name) {
    for (size_t i = 0; i < msg->nb_headers; i++) {
        const struct http_header *header;
        header = msg->headers + i;

        /* RFC 2616 4.2: Field names are case-insensitive. */
        if(strcasecmp(header->name, name) == 0)
            return header->value;
    }

    return NULL;
}

bool
http_msg_is_complete(const struct http_msg *msg) {
    return msg->is_complete;
}

bool
http_msg_aborted(const struct http_msg *msg) {
    return msg->aborted;
}

bool
http_msg_has_content_length(const struct http_msg *msg) {
    return msg->has_content_length;
}

size_t
http_msg_content_length(const struct http_msg *msg) {
    return msg->content_length;
}

const struct http_media_type *
http_msg_content_type(const struct http_msg *msg) {
    return msg->content_type;
}

bool
http_msg_content_type_is(const struct http_msg *msg, const char *content_type) {
    const struct http_media_type *media_type;

    if (!msg->content_type)
        return false;

    media_type = msg->content_type;
    return strcmp(http_media_type_base_string(media_type), content_type) == 0;
}

const char *
http_msg_body(const struct http_msg *msg) {
    return msg->body;
}

size_t
http_msg_body_length(const struct http_msg *msg) {
    return msg->body_length;
}

const char *
http_header_name(const struct http_header *header) {
    return header->name;
}

const char *
http_header_value(const struct http_header *header) {
    return header->value;
}

struct http_headers *
http_headers_new(void) {
    struct http_headers *headers;

    headers = http_malloc0(sizeof(struct http_headers));

    return headers;
}

void
http_headers_delete(struct http_headers *headers) {
    if (!headers)
        return;

    for (size_t i = 0; i < headers->nb_headers; i++)
        http_header_free(headers->headers + i);
    http_free(headers->headers);

    memset(headers, 0, sizeof(struct http_headers));
    http_free(headers);
}

const char *
http_headers_get_header(struct http_headers *headers, const char *name) {
    for (size_t i = 0; i < headers->nb_headers; i++) {
        struct http_header *header;

        header = headers->headers + i;

        if (strcasecmp(header->name, name) == 0)
            return header->value;
    }

    return NULL;
}

void
http_headers_add_header(struct http_headers *headers,
                        const char *name, const char *value) {
    struct http_header *header;

    if (headers->nb_headers == 0) {
        headers->headers = http_malloc(sizeof(struct http_header));
    } else {
        size_t nsz;

        nsz = (headers->nb_headers + 1) * sizeof(struct http_header);
        headers->headers = http_realloc(headers->headers, nsz);
    }

    header = headers->headers + headers->nb_headers;
    header->name = http_strdup(name);
    header->value = http_strdup(value);

    headers->nb_headers++;
}

void
http_headers_add_headers(struct http_headers *headers,
                         const struct http_headers *src) {
    struct http_header *header;
    size_t nsz;

    if (src->nb_headers == 0)
        return;

    headers->nb_headers += src->nb_headers;
    nsz = headers->nb_headers * sizeof(struct http_header);
    headers->headers = http_realloc(headers->headers, nsz);
    header = headers->headers + headers->nb_headers - src->nb_headers;

    for (size_t i = 0; i < src->nb_headers; i++) {
        header->name = http_strdup(src->headers[i].name);
        header->value = http_strdup(src->headers[i].value);

        header++;
    }
}

void
http_headers_set_header(struct http_headers *headers,
                        const char *name, const char *value) {
    for (size_t i = 0; i < headers->nb_headers; i++) {
        struct http_header *header;

        header = headers->headers + i;

        if (strcasecmp(header->name, name) == 0) {
            http_free(header->value);
            header->value = http_strdup(value);
            return;
        }
    }

    http_headers_add_header(headers, name, value);
}

void
http_headers_format_header(struct http_headers *headers, const char *name,
                           const char *fmt, ...) {
    va_list ap;
    char *value;

    va_start(ap, fmt);
    http_vasprintf(&value, fmt, ap);
    va_end(ap);

    for (size_t i = 0; i < headers->nb_headers; i++) {
        struct http_header *header;

        header = headers->headers + i;

        if (strcasecmp(header->name, name) == 0) {
            http_free(header->value);
            header->value = value;
            return;
        }
    }

    http_headers_add_header(headers, name, value);
    http_free(value);
}

void
http_headers_remove_header(struct http_headers *headers, const char *name) {
    for (size_t i = 0; i < headers->nb_headers; i++) {
        struct http_header *header;

        header = headers->headers + i;

        if (strcasecmp(header->name, name) == 0) {
            size_t nb_moved;
            size_t nsz;

            nb_moved = headers->nb_headers - i - 1;
            memmove(header, headers->headers + i + 1,
                    nb_moved * sizeof(struct http_header));

            headers->nb_headers--;

            if (headers->nb_headers == 0) {
                http_free(headers->headers);
                headers->headers = NULL;
            } else {
                nsz = headers->nb_headers * sizeof(struct http_header);
                headers->headers = http_realloc(headers->headers, nsz);
            }

            break;
        }
    }
}

char *
http_format_content_disposition_attachment(const char *filename) {
    const char *prefix, *suffix;
    const char *iptr;
    char *header, *optr;
    size_t len, prefix_len, suffix_len;

    prefix = "attachment; filename=\"";
    suffix = "\"";

    prefix_len = strlen(prefix);
    suffix_len = strlen(suffix);

    len = prefix_len;

    iptr = filename;
    while (*iptr != '\0') {
        if (*iptr == '\\' || *iptr == '"')
            len++;
        len++;
        iptr++;
    }

    len += suffix_len;

    header = http_malloc(len + 1);
    optr = header;

    memcpy(optr, prefix, prefix_len);
    optr += prefix_len;

    iptr = filename;
    while (*iptr != '\0') {
        if (*iptr == '\\' || *iptr == '"')
            *optr++ = '\\';
        *optr++ = *iptr++;
    }

    memcpy(optr, suffix, suffix_len);
    optr += suffix_len;
    *optr = '\0';

    return header;
}

const void *
http_msg_content(const struct http_msg *msg) {
    return msg->content;
}

bool
http_msg_has_form_data(const struct http_msg *msg) {
    if (!msg->content_type)
        return false;

    return strcmp(http_media_type_base_string(msg->content_type),
                  "application/x-www-form-urlencoded") == 0;
}

int
http_msg_content_disposition_filename(const struct http_msg *msg,
                                      char **pfilename) {
    struct http_pvalue pvalue;
    const char *str, *filename, *ptr;

    str = http_msg_get_header(msg, "Content-Disposition");
    if (!str)
        return 0;

    if (http_pvalue_parse(&pvalue, str, NULL) == -1)
        return -1;

    filename = http_pvalue_get_parameter(&pvalue, "filename");
    if (!filename)
        return 0;

    ptr = filename + strlen(filename);
    while (ptr > filename) {
        if (*ptr == '/') {
            ptr++;
            break;
        }

        ptr--;
    }

    *pfilename = http_strdup(ptr);

    http_pvalue_free(&pvalue);
    return 1;
}

enum http_method
http_request_method(const struct http_msg *msg) {
    assert(msg->type == HTTP_MSG_REQUEST);
    return msg->u.request.method;
}

const char *
http_request_uri(const struct http_msg *msg) {
    assert(msg->type == HTTP_MSG_REQUEST);
    return msg->u.request.uri_string;
}

const char *
http_request_named_parameter(const struct http_msg *msg, const char *name) {
    assert(msg->type == HTTP_MSG_REQUEST);

    for (size_t i = 0; i < msg->u.request.nb_named_parameters; i++) {
        struct http_named_parameter *parameter;

        parameter = msg->u.request.named_parameters + i;

        if (strcmp(parameter->name, name) == 0)
            return parameter->value;
    }

    return NULL;
}

bool
http_request_has_query_parameter(const struct http_msg *msg, const char *name) {
    assert(msg->type == HTTP_MSG_REQUEST);

    if (!msg->u.request.uri)
        return false;

    return http_uri_has_query_parameter(msg->u.request.uri, name);
}

const char *
http_request_query_parameter(const struct http_msg *msg, const char *name) {
    assert(msg->type == HTTP_MSG_REQUEST);

    if (!msg->u.request.uri)
        return false;

    return http_uri_query_parameter(msg->u.request.uri, name);
}

bool
http_request_has_ranges(const struct http_msg *msg) {
    return msg->u.request.has_ranges;
}

const struct http_ranges *
http_request_ranges(const struct http_msg *msg) {
    if (!msg->u.request.has_ranges)
        return NULL;

    return &msg->u.request.ranges;
}

enum http_status_code
http_response_status_code(const struct http_msg *msg) {
    assert(msg->type == HTTP_MSG_RESPONSE);
    return msg->u.response.status_code;
}

const char *
http_response_reason_phrase(const struct http_msg *msg) {
    assert(msg->type == HTTP_MSG_RESPONSE);
    return msg->u.response.reason_phrase;
}

char *
http_decode_header_value(const char *str, size_t sz) {
    char *value;
    size_t nb_chars;
    size_t value_sz;

    size_t last_non_sp;

    const char *iptr;
    size_t ilen;

#define HTTP_WRITE_CHAR(c_)                        \
    do {                                           \
        if (nb_chars + 1 >= value_sz) {            \
            value_sz *= 2;                         \
            value = http_realloc(value, value_sz); \
        }                                          \
                                                   \
        value[nb_chars++] = c_;                    \
    } while (0)

    nb_chars = 0;
    value_sz = sz;
    value = http_malloc(sz);

    last_non_sp = 0;

    iptr = str;
    ilen = sz;

    while (ilen > 0) {
        if (*iptr == '\r') {
            /* RFC 2616 4.2: Any LWS that occurs between field-content MAY be
             * replaced with a single SP. */
            if (ilen < 3) {
                http_set_error("truncated linear whitespace");
                goto error;
            }

            if (iptr[1] == '\n' && (iptr[2] == ' ' || iptr[2] == '\t')) {
                iptr += 3;
                ilen -= 3;
            } else {
                http_set_error("invalid linear whitespace");
                goto error;
            }

            /* Discard trailing SP/HT in the last line */
            while (nb_chars != 0) {
                if (value[nb_chars - 1] != ' ' && value[nb_chars - 1] != '\t')
                    break;

                nb_chars--;
            }

            /* Skip leading SP/HT in the next line */
            while (ilen > 0 && (*iptr == ' ' || *iptr == '\t')) {
                iptr++;
                ilen--;
            }

            HTTP_WRITE_CHAR(' ');
        } else {
            HTTP_WRITE_CHAR(*iptr);

            if (*iptr != ' ' && *iptr != '\t')
                last_non_sp = nb_chars;

            iptr++;
            ilen--;
        }
    }

    value[last_non_sp] = '\0';
    return value;

error:
    http_free(value);
    return NULL;
}

void
http_header_init(struct http_header *header) {
    memset(header, 0, sizeof(struct http_header));
}

void
http_header_free(struct http_header *header) {
    if (!header)
        return;

    http_free(header->name);
    http_free(header->value);

    memset(header, 0, sizeof(struct http_header));
}

void
http_named_parameter_free(struct http_named_parameter *parameter) {
    if (!parameter)
        return;

    http_free(parameter->name);
    http_free(parameter->value);

    memset(parameter, 0, sizeof(struct http_named_parameter));
}

void
http_query_parameter_free(struct http_query_parameter *parameter) {
    if (!parameter)
        return;

    http_free(parameter->name);
    http_free(parameter->value);

    memset(parameter, 0, sizeof(struct http_query_parameter));
}

int
http_query_parameters_parse(const char *query,
                            struct http_query_parameter **pparameters,
                            size_t *p_nb_parameters) {
    struct http_query_parameter *parameters, *parameter;
    size_t nb_parameters;
    const char *ptr, *start;
    size_t idx, toklen;

    ptr = query;

    /* Count the parameters */
    nb_parameters = 0;
    for (;;) {
        if (*ptr == '&' || *ptr == ';' || *ptr == '\0') {
            if (ptr > query)
                nb_parameters++;

            if (*ptr == '\0')
                break;
        }

        ptr++;
    }

    if (nb_parameters == 0) {
        *pparameters = NULL;
        *p_nb_parameters = 0;
        return 0;
    }

    /* Decode the parameters */
    ptr = query;

    parameters = http_calloc(nb_parameters,
                             sizeof(struct http_query_parameter));

    idx = 0;
    for (;;) {
        if (idx >= nb_parameters) {
            /* We did not correctly count the number of parameters */
            http_set_error("error while parsing query");
            goto error;
        }

        parameter = parameters + idx;

        /* Key */
        start = ptr;

        for (;;) {
            if (*ptr == '&' || *ptr == ';' || *ptr == '=' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty query parameter name");
                    goto error;
                }

                parameter->name = http_uri_decode_query_component(start,
                                                                  toklen);
                if (!parameter->name)
                    goto error;

                break;
            }

            ptr++;
        }

        if (*ptr == '\0') {
            break;
        } else if (*ptr == '&' || *ptr == ';') {
            ptr++;
            idx++;
            continue;
        }

        /* Value (optional) */
        ptr++; /* skip '=' */
        start = ptr;

        for (;;) {
            if (*ptr == '&' || *ptr == ';' || *ptr == '\0') {
                toklen = (size_t)(ptr - start);
                if (toklen == 0) {
                    http_set_error("empty query parameter value");
                    goto error;
                }

                parameter->value = http_uri_decode_query_component(start,
                                                                   toklen);
                if (!parameter->value)
                    goto error;

                break;
            }

            ptr++;
        }

        if (*ptr == '\0') {
            break;
        } else {
            ptr++;
            idx++;
        }
    }

    *pparameters = parameters;
    *p_nb_parameters = nb_parameters;
    return 0;

error:
    for (size_t i = 0; i < nb_parameters; i++)
        http_query_parameter_free(parameters + i);
    http_free(parameters);
    return -1;
}

void
http_request_free(struct http_request *request) {
    http_free(request->uri_string);
    http_uri_delete(request->uri);

    for (size_t i = 0; i < request->nb_named_parameters; i++)
        http_named_parameter_free(request->named_parameters + i);
    http_free(request->named_parameters);

    http_ranges_free(&request->ranges);
}

void
http_response_free(struct http_response *response) {
    http_free(response->reason_phrase);
}

void
http_msg_init(struct http_msg *msg, enum http_msg_type type) {
    memset(msg, 0, sizeof(struct http_msg));

    msg->is_bufferized = true;
    msg->type = type;
}

void
http_msg_free(struct http_msg *msg) {
    if (!msg)
        return;

    switch (msg->type) {
    case HTTP_MSG_REQUEST:
        http_request_free(&msg->u.request);
        break;

    case HTTP_MSG_RESPONSE:
        http_response_free(&msg->u.response);
        break;
    }

    for (size_t i = 0; i < msg->nb_headers; i++)
        http_header_free(msg->headers + i);
    http_free(msg->headers);

    http_free(msg->body);

    if (msg->content_decoder)
        msg->content_decoder->delete(msg->content);

    http_media_type_delete(msg->content_type);

    memset(msg, 0, sizeof(struct http_msg));
}

void
http_msg_add_header(struct http_msg *msg, const struct http_header *header) {
    if (msg->nb_headers == 0) {
        msg->headers_sz = 1;
        msg->headers = http_malloc(sizeof(struct http_header));
    } else if (msg->nb_headers + 1 > msg->headers_sz) {
        size_t nsz;

        msg->headers_sz *= 2;

        nsz = msg->headers_sz * sizeof(struct http_header);
        msg->headers = http_realloc(msg->headers, nsz);
    }

    msg->headers[msg->nb_headers++] = *header;
}

bool
http_msg_can_have_body(const struct http_msg *msg) {
    if (msg->type == HTTP_MSG_REQUEST) {
        enum http_method method;

        method = msg->u.request.method;

        return method == HTTP_POST || method == HTTP_PUT;
    } else if (msg->type == HTTP_MSG_RESPONSE)  {
        enum http_status_code status_code;

        status_code = msg->u.response.status_code;

        return status_code >= 200;
    }

    return false;
}

struct http_request_info *
http_request_info_new(void) {
    struct http_request_info *info;

    info = http_malloc0(sizeof(struct http_request_info));

    return info;
}

void
http_request_info_delete(struct http_request_info *info) {
    if (!info)
        return;

    http_free(info->uri_string);

    memset(info, 0, sizeof(struct http_request_info));
    http_free(info);
}

enum http_version
http_request_info_version(const struct http_request_info *info) {
    return info->version;
}

enum http_method
http_request_info_method(const struct http_request_info *info) {
    return info->method;
}

const char *
http_request_info_uri_string(const struct http_request_info *info) {
    return info->uri_string;
}

time_t
http_request_info_date(const struct http_request_info *info) {
    return info->date;
}

enum http_status_code
http_request_info_status_code(const struct http_request_info *info) {
    return info->status_code;
}

int
http_request_process_uri(struct http_msg *msg) {
    const char *uri;

    assert(msg->type == HTTP_MSG_REQUEST);

    uri = msg->u.request.uri_string;

    if (strcmp(uri, "*") == 0) {
        msg->u.request.uri = NULL;
    } else {
        /* Absolute URI or absolute path */
        msg->u.request.uri = http_uri_new(uri);
        if (!msg->u.request.uri)
            return -1;

        /* TODO If the URI has a host make sure that it is our own. If it is
         * not, reject the request since we are not a proxy. */
    }

    return 0;
}

int
http_parser_init(struct http_parser *parser, enum http_msg_type msg_type,
                 const struct http_cfg *cfg) {
    memset(parser, 0, sizeof(struct http_parser));

    parser->cfg = cfg;
    parser->state = HTTP_PARSER_START;

    http_msg_init(&parser->msg, msg_type);

    return 0;
}

void
http_parser_free(struct http_parser *parser) {
    if (!parser)
        return;

    http_msg_free(&parser->msg);

    memset(parser, 0, sizeof(struct http_parser));
}

int
http_parser_reset(struct http_parser *parser, enum http_msg_type msg_type,
                  const struct http_cfg *cfg) {
    http_parser_free(parser);
    return http_parser_init(parser, msg_type, cfg);
}

bool
http_parser_are_headers_read(struct http_parser *parser) {
    switch (parser->state) {
    case HTTP_PARSER_START:
    case HTTP_PARSER_HEADER:
    case HTTP_PARSER_ERROR:
        return false;

    case HTTP_PARSER_BODY:
    case HTTP_PARSER_TRAILER:
    case HTTP_PARSER_DONE:
        return true;
    }

    /* Should never happen */
    return false;
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
    int ret;

    do {
        switch (parser->state) {
        case HTTP_PARSER_START:
            if (parser->msg.type == HTTP_MSG_REQUEST) {
                ret = http_msg_parse_request_line(buf, parser);
            } else if (parser->msg.type == HTTP_MSG_RESPONSE) {
                ret = http_msg_parse_status_line(buf, parser);
                if (ret == 1 && parser->status_code == 1)
                    return -1;
            } else {
                http_set_error("unknown message type %d", parser->msg.type);
                return -1;
            }
            break;

        case HTTP_PARSER_HEADER:
        case HTTP_PARSER_TRAILER:
            ret = http_msg_parse_headers(buf, parser);
            break;

        case HTTP_PARSER_BODY:
            if (parser->msg.is_body_chunked) {
                ret = http_msg_parse_chunk(buf, parser);
            } else {
                ret = http_msg_parse_body(buf, parser);
            }
            break;

        case HTTP_PARSER_ERROR:
            ret = 1;
            break;

        case HTTP_PARSER_DONE:
            ret = 1;
            break;
        }

        if (ret <= 0)
            return ret;
    } while (parser->state != HTTP_PARSER_DONE
          && parser->state != HTTP_PARSER_ERROR);

    if (parser->state == HTTP_PARSER_DONE) {
        if (http_msg_finalize_body(&parser->msg, parser->cfg) == -1)
            return -1;
    }

    return 1;
}

/* These macros are helpers for parsers, and depend on three variables:
 *
 * - struct http_parser *parser: the current parser;
 * - const char *ptr: a pointer to the buffer being parsed;
 * - size_t len: the number of bytes left in the current buffer.
 */

#define HTTP_ERROR(status_code_, fmt_, ...)                          \
    do {                                                             \
        http_parser_fail(parser, status_code_, fmt_, ##__VA_ARGS__); \
        return 1;                                                    \
    } while (0)

#define HTTP_SKIP_MULTIPLE_SP()      \
    while (len > 0 && *ptr == ' ') { \
        ptr++;                       \
        len--;                       \
    }

#define HTTP_SKIP_CRLF()                                   \
    if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') {    \
        ptr += 2;                                          \
        len -= 2;                                          \
    }

#define HTTP_SKIP_MULTIPLE_CRLF()                          \
    while (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') { \
        ptr += 2;                                          \
        len -= 2;                                          \
    }

#define HTTP_SKIP_LWS()                                    \
    do {                                                   \
        HTTP_SKIP_CRLF();                                  \
        while (len > 0 && (*ptr == ' ' || *ptr == '\t')) { \
            ptr++;                                         \
            len--;                                         \
        }                                                  \
    } while (0)

int
http_msg_parse_request_line(struct bf_buffer *buf, struct http_parser *parser) {
    const struct http_cfg *cfg;
    struct http_msg *msg;
    const char *ptr, *start;
    size_t len, toklen;
    bool found;

    cfg = parser->cfg;
    msg = &parser->msg;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    /* RFC 2616 4.1: In the interest of robustness, servers SHOULD ignore any
     * empty line(s) received where a Request-Line is expected. */
    HTTP_SKIP_MULTIPLE_CRLF();

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
            } else if (memcmp(start, "OPTIONS", toklen) == 0) {
                msg->u.request.method = HTTP_OPTIONS;
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

    if (!found) {
        /* The longest method is OPTIONS, i.e. eight characters */
        if ((size_t)(ptr - start) > 8)
            HTTP_ERROR(HTTP_NOT_IMPLEMENTED, "unsupported method");

        return 0;
    }

    /* Request URI */
    HTTP_SKIP_MULTIPLE_SP();

    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == ' ') {
            char *uri_string;

            toklen = (size_t)(ptr - start);
            if (toklen > cfg->u.server.max_request_uri_length)
                HTTP_ERROR(HTTP_REQUEST_URI_TOO_LONG, "request uri too large");

            uri_string = http_strndup(start, toklen);
            msg->u.request.uri_string = uri_string;

            if (strcmp(uri_string, "*") != 0) {
                msg->u.request.uri = http_uri_new(uri_string);
                if (!msg->u.request.uri) {
                    HTTP_ERROR(HTTP_BAD_REQUEST,
                               "cannot parse uri: %s", http_get_error());
                }
            }

            found = true;
            break;
        } else if (*ptr == '\r' || *ptr == '\n') {
            HTTP_ERROR(HTTP_BAD_REQUEST, "invalid character in request uri");
        }

        ptr++;
        len--;
    }

    if (!found) {
        if ((size_t)(ptr - start) > cfg->u.server.max_request_uri_length)
            HTTP_ERROR(HTTP_REQUEST_URI_TOO_LONG, "request uri too large");

        return 0;
    }

    /* HTTP version */
    HTTP_SKIP_MULTIPLE_SP();

    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == '\r') {
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
                msg->version = HTTP_1_0;
            } else if (memcmp(start, "1.1", toklen) == 0) {
                msg->version = HTTP_1_1;
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

    if (!found) {
        /* The longest version string is HTTP/x.y with x < 9 and y < 9 */
        if ((size_t)(ptr - start) > 8)
            HTTP_ERROR(HTTP_HTTP_VERSION_NOT_SUPPORTED,
                       "unsupported http version");

        return 0;
    }

    HTTP_SKIP_CRLF();

    bf_buffer_skip(buf, bf_buffer_length(buf) - len);

    parser->state = HTTP_PARSER_HEADER;
    return 1;
}

int
http_msg_parse_status_line(struct bf_buffer *buf, struct http_parser *parser) {
    const struct http_cfg *cfg;
    struct http_msg *msg;
    const char *ptr, *start;
    size_t len, toklen;
    bool found;

    cfg = parser->cfg;
    msg = &parser->msg;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    /* HTTP Version */
    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == ' ') {
            const char *prefix;
            size_t prefix_sz;

            toklen = (size_t)(ptr - start);

            prefix = "HTTP/";
            prefix_sz = strlen(prefix);

            if (toklen < prefix_sz || memcmp(start, prefix, prefix_sz) != 0)
                HTTP_ERROR(1, "invalid http version format");

            start += prefix_sz;
            toklen -= prefix_sz;

            if (toklen < 3)
                HTTP_ERROR(1, "invalid http version format");

            if (memcmp(start, "1.0", toklen) == 0) {
                msg->version = HTTP_1_0;
            } else if (memcmp(start, "1.1", toklen) == 0) {
                msg->version = HTTP_1_1;
            } else {
                HTTP_ERROR(1, "unsupported http version");
            }

            found = true;
            break;
        }

        ptr++;
        len--;
    }

    if (!found) {
        /* The longest version string is HTTP/x.y with x < 9 and y < 9 */
        if ((size_t)(ptr - start) > 8)
            HTTP_ERROR(HTTP_HTTP_VERSION_NOT_SUPPORTED,
                       "unsupported http version");

        return 0;
    }

    /* Status Code */
    HTTP_SKIP_MULTIPLE_SP();

    start = ptr;
    while (len > 0) {
        if (*ptr == ' ') {
            int code;

            toklen = (size_t)(ptr - start);
            if (toklen == 0)
                HTTP_ERROR(1, "empty status code");

            if (toklen != 3)
                HTTP_ERROR(1, "invalid status code");

            code = (start[0] - '0') * 100
                 + (start[1] - '0') * 10
                 + (start[2] - '0');
            msg->u.response.status_code = (enum http_status_code)code;

            found = true;
            break;
        } else if (*ptr < '0' || *ptr > '9') {
            HTTP_ERROR(1, "invalid character \\%hhu in status code", *ptr);
        }

        ptr++;
        len--;
    }

    if (!found) {
        if ((size_t)(ptr - start) > 3)
            HTTP_ERROR(1, "invalid status code");

        return 0;
    }

    /* Reason Phrase */
    HTTP_SKIP_MULTIPLE_SP();

    start = ptr;
    while (len > 0) {
        if (*ptr == '\r') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0)
                HTTP_ERROR(1, "empty reason phrase");

            msg->u.response.reason_phrase = http_strndup(start, toklen);
            found = true;
            break;
        }

        ptr++;
        len--;
    }

    if (!found) {
        if ((size_t)(ptr - start) > cfg->u.client.max_reason_phrase_length)
            HTTP_ERROR(1, "reason phrase too long");

        return 0;
    }

    HTTP_SKIP_CRLF();

    bf_buffer_skip(buf, bf_buffer_length(buf) - len);

    parser->state = HTTP_PARSER_HEADER;
    return 1;
}

int
http_msg_parse_headers(struct bf_buffer *buf, struct http_parser *parser) {
    const struct http_cfg *cfg;
    struct http_msg *msg;
    const char *ptr, *start;
    struct http_header header;
    size_t len, toklen;
    bool found;

    http_header_init(&header);

    cfg = parser->cfg;
    msg = &parser->msg;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') {
        bf_buffer_skip(buf, 2);

        if (!parser->headers_processed && !parser->skip_header_processing) {
            if (http_msg_process_headers(parser) == -1)
                return -1;

            parser->headers_processed = true;
        }

        if (parser->state == HTTP_PARSER_HEADER) {
            parser->state = HTTP_PARSER_BODY;
        } else if (parser->state == HTTP_PARSER_TRAILER) {
            parser->state = HTTP_PARSER_DONE;
        }

        return 1;
    }

    /* Name */
    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == ':') {
            toklen = (size_t)(ptr - start);
            if (toklen > cfg->max_header_name_length) {
                HTTP_ERROR(HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                           "header name too long");
            }

            header.name = http_strndup(start, toklen);
            found = true;
            break;
        } else if (!http_is_token_char((unsigned char)*ptr)) {
            HTTP_ERROR(HTTP_BAD_REQUEST,
                       "invalid character \\%hhu in header name",
                       (unsigned char)(*ptr));
        }

        ptr++;
        len--;
    }

    if (!found) {
        http_header_free(&header);

        if ((size_t)(ptr - start) > cfg->max_header_name_length) {
            HTTP_ERROR(HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                       "header name too long");
        }

        return 0;
    }

    ptr++;
    len--;

    /* Value */
    HTTP_SKIP_MULTIPLE_SP();

    start = ptr;
    found = false;
    while (len > 0) {
        if (*ptr == '\r') {
            if (len < 3) {
                http_header_free(&header);
                return 0;
            }

            if (ptr[1] == '\n' && (ptr[2] == ' ' || ptr[2] == '\t')) {
                /* The header value continues next line */
                HTTP_SKIP_LWS();
                continue;
            } else {
                toklen = (size_t)(ptr - start);
                if (toklen > cfg->max_header_value_length) {
                    http_header_free(&header);

                    HTTP_ERROR(HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                               "header value too long");
                }

                header.value = http_decode_header_value(start, toklen);
                if (!header.value)
                    return -1;

                found = true;
                break;
            }
        }

        ptr++;
        len--;
    }

    if (!found) {
        http_header_free(&header);

        if ((size_t)(ptr - start) > cfg->max_header_value_length) {
            HTTP_ERROR(HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                       "header value too long");
        }

        return 0;
    }

    HTTP_SKIP_CRLF();

    http_msg_add_header(msg, &header);

    bf_buffer_skip(buf, bf_buffer_length(buf) - len);
    return 1;
}

int
http_msg_parse_body(struct bf_buffer *buf, struct http_parser *parser) {
    struct http_msg *msg;
    const char *ptr;
    size_t len;

    msg = &parser->msg;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    if (!http_msg_can_have_body(msg)) {
        parser->state = HTTP_PARSER_DONE;
        return 1;
    }

    if (!msg->has_content_length)
        HTTP_ERROR(HTTP_LENGTH_REQUIRED, "missing Content-Length header");

    if (msg->is_bufferized) {
        if (len < msg->content_length)
            return 0;

        msg->body_length = msg->content_length;
        msg->total_body_length = msg->content_length;
    } else {
        size_t remainder;

        http_free(msg->body);

        remainder = msg->content_length - msg->total_body_length;
        if (len <= remainder) {
            msg->body_length = len;
        } else {
            msg->body_length = remainder;
        }

        msg->total_body_length += msg->body_length;
    }

    if (msg->body_length > 0) {
        msg->body = http_strndup(ptr, msg->body_length);
        bf_buffer_skip(buf, msg->body_length);
    }

    if (msg->total_body_length == msg->content_length) {
        parser->state = HTTP_PARSER_DONE;

        return 1;
    } else {
        return 0;
    }
}

int
http_msg_parse_chunk(struct bf_buffer *buf, struct http_parser *parser) {
    const struct http_cfg *cfg;
    struct http_msg *msg;
    const char *ptr, *start, *end;
    size_t len, toklen, chunk_length;
    unsigned long long ullval;
    char token[21]; /* SIZE_MAX can be up to 20 digits long */

    cfg = parser->cfg;
    msg = &parser->msg;

    ptr = bf_buffer_data(buf);
    len = bf_buffer_length(buf);

    HTTP_SKIP_LWS();

    /* Chunk length */
    start = ptr;
    end = NULL;

    while (len > 0) {
        if (isxdigit((unsigned char)*ptr)) {
            ptr++;
            len--;
        } else if (*ptr == ' ' || *ptr == '\t' || *ptr == ';' || *ptr == '\r') {
            end = ptr;
            break;
        } else {
            HTTP_ERROR(HTTP_BAD_REQUEST,
                       "invalid character \\%hhu in chunk length",
                       (unsigned char)*ptr);
        }
    }

    if (!end)
        return 0;

    toklen = (size_t)(end - start);
    if (toklen == 0)
        HTTP_ERROR(HTTP_BAD_REQUEST, "empty chunk length");
    if (toklen > 20)
        HTTP_ERROR(HTTP_BAD_REQUEST, "chunk length too large");

    memcpy(token, start, toklen);
    token[toklen] = '\0';

    errno = 0;
    ullval = strtoull(token, NULL, 16);
    if (errno) {
        HTTP_ERROR(HTTP_BAD_REQUEST, "invalid chunk length");
    } else if (ullval > SIZE_MAX) {
        HTTP_ERROR(HTTP_BAD_REQUEST, "chunk length too large");
    }

    chunk_length = ullval;
    if (chunk_length > cfg->max_chunk_length)
        HTTP_ERROR(HTTP_REQUEST_ENTITY_TOO_LARGE, "chunk length too large");

    /* We do not currently handle any chunk extension */
    start = NULL;

    while (len > 0) {
        if (len < 2)
            return 0;

        if (ptr[0] == '\r' && ptr[1] == '\n') {
            ptr += 2;
            len -= 2;

            start = ptr;
            break;
        }

        ptr++;
        len--;
    }

    if (!start)
        return 0;

    /* Chunk data */
    if (chunk_length > 0) {
        size_t old_length;

        if (len < chunk_length + 2)
            return 0;

        if (!msg->is_bufferized && msg->body_length > 0) {
            http_free(msg->body);
            msg->body_length = 0;
        }

        old_length = msg->body_length;

        if (msg->body_length == 0) {
            msg->body_length = chunk_length;
            msg->body = http_malloc(msg->body_length);
        } else {
            msg->body_length += chunk_length;
            msg->body = http_realloc(msg->body, msg->body_length);
        }

        memcpy(msg->body + old_length, start, chunk_length);

        /* Skip the content and the final CRLF */
        ptr += chunk_length + 2;
        len -= chunk_length - 2;
    }

    bf_buffer_skip(buf, (size_t)(ptr - (char *)bf_buffer_data(buf)));

    if (chunk_length == 0) {
        /* This was the last chunk */
        parser->state = HTTP_PARSER_TRAILER;
    }

    return 1;
}

static int
http_msg_process_headers(struct http_parser *parser) {
    struct http_msg *msg;
    const char *host;
    bool has_transfer_encoding;

    msg = &parser->msg;

    host = NULL;

    has_transfer_encoding = false;

    for (size_t i = 0; i < msg->nb_headers; i++) {
        const struct http_header *header;

        header = msg->headers + i;

#define HTTP_HEADER_IS(name_) (strcasecmp(header->name, name_) == 0)

        if (msg->type == HTTP_MSG_REQUEST && HTTP_HEADER_IS("Host")) {
            struct http_server *server;

            host = header->value;

            if (!parser->connection)
                goto ignore_header;

            server = parser->connection->server;

            if (server) {
                if (!http_server_does_listen_on_host_string(server, host)) {
                    HTTP_ERROR(HTTP_BAD_REQUEST,
                               "Host header '%s' is not a hostname we are "
                               "listening on", host);
                }
            }
        } else if (HTTP_HEADER_IS("Connection")) {
            struct http_pvalues pvalues;

            if (http_pvalues_parse(&pvalues, header->value) == -1) {
                HTTP_ERROR(HTTP_BAD_REQUEST,
                           "invalid Connection header: %s", http_get_error());
            }

            for (size_t i = 0; i < pvalues.nb_pvalues; i++) {
                struct http_pvalue *pvalue;

                pvalue = pvalues.pvalues + i;

                if (strcasecmp(pvalue->value, "keep-alive") == 0) {
                    msg->connection_options |= HTTP_CONNECTION_KEEP_ALIVE;
                } else if (strcasecmp(pvalue->value, "close") == 0) {
                    msg->connection_options |= HTTP_CONNECTION_CLOSE;
                }
            }

            http_pvalues_free(&pvalues);
        } else if (HTTP_HEADER_IS("Content-Length")) {
            if (has_transfer_encoding) {
                /* RFC 2616 4.3: If a message is received with both a
                 * Transfer-Encoding header field and a Content-Length header
                 * field, the latter MUST be ignored. */

                goto ignore_header;
            }

            msg->has_content_length = true;

            if (http_parse_size(header->value, &msg->content_length) == -1) {
                HTTP_ERROR(HTTP_BAD_REQUEST, "cannot parse Content-Length: %s",
                           http_get_error());
            }
        } else if (HTTP_HEADER_IS("Content-Type")) {
            msg->content_type = http_media_type_new(header->value);
            if (!msg->content_type) {
                HTTP_ERROR(HTTP_BAD_REQUEST, "cannot parse Content-Type: %s",
                           http_get_error());
            }
        } else if (HTTP_HEADER_IS("Transfer-Encoding")) {
            struct http_pvalues pvalues;
            bool is_chunked;

            is_chunked = false;

            if (http_pvalues_parse(&pvalues, header->value) == -1) {
                HTTP_ERROR(HTTP_BAD_REQUEST,
                           "invalid Transfer-Encoding header: %s",
                           http_get_error());
            }

            for (size_t i = 0; i < pvalues.nb_pvalues; i++) {
                struct http_pvalue *pvalue;

                pvalue = pvalues.pvalues + i;

                if (strcasecmp(pvalue->value, "chunked") == 0) {
                    if (is_chunked) {
                        http_pvalues_free(&pvalues);
                        HTTP_ERROR(HTTP_BAD_REQUEST,
                                   "duplicate 'chunked' token in "
                                   "Transfer-Encoding header");
                    }

                    has_transfer_encoding = true;
                    is_chunked = true;
                    msg->is_body_chunked = true;
                } else if (strcasecmp(pvalue->value, "identity") == 0) {
                    /* Default transfer encoding */
                } else {
                    http_pvalues_free(&pvalues);
                    HTTP_ERROR(HTTP_NOT_IMPLEMENTED,
                               "unknown transfer encoding");
                }
            }

            http_pvalues_free(&pvalues);
        } else if (msg->type == HTTP_MSG_REQUEST && HTTP_HEADER_IS("Expect")) {
            struct http_pvalues pvalues;

            if (http_pvalues_parse(&pvalues, header->value) == -1) {
                HTTP_ERROR(HTTP_BAD_REQUEST,
                           "invalid Expect header: %s", http_get_error());
            }

            for (size_t i = 0; i < pvalues.nb_pvalues; i++) {
                struct http_pvalue *pvalue;

                pvalue = pvalues.pvalues + i;

                if (strcasecmp(pvalue->value, "100-continue") == 0) {
                    msg->u.request.expects_100_continue = true;
                } else if (strcasecmp(pvalue->value, "close") == 0) {
                    http_pvalues_free(&pvalues);
                    HTTP_ERROR(HTTP_EXPECTATION_FAILED,
                               "unknown expectation value");
                }
            }

            http_pvalues_free(&pvalues);
        } else if (msg->type == HTTP_MSG_REQUEST && HTTP_HEADER_IS("Range")) {
            msg->u.request.has_ranges = true;

            if (http_ranges_parse(&msg->u.request.ranges,
                                  header->value) == -1) {
                HTTP_ERROR(HTTP_BAD_REQUEST, "cannot parse ranges: %s",
                           http_get_error());
            }
        }

ignore_header:
        continue;

#undef HTTP_HEADER_IS
    }

    if (msg->type == HTTP_MSG_REQUEST) {
        /* A client MUST include a Host header field in all HTTP/1.1 request
         * messages [...] All Internet-based HTTP/1.1 servers MUST respond
         * with a 400 (Bad Request) status code to any HTTP/1.1 request
         * message which lacks a Host header field. */
        if (msg->version == HTTP_1_1 && !host)
            HTTP_ERROR(HTTP_BAD_REQUEST, "missing Host header");

        /* RFC 2616 8.2.3: The origin server MUST NOT wait for the request
         * body before sending the 100 (Continue) response. */
        if (msg->u.request.expects_100_continue) {
            if (http_connection_send_response(parser->connection,
                                              HTTP_CONTINUE, NULL) == -1) {
                return -1;
            }
        }
    }

    return 1;
}

#undef HTTP_ERROR
#undef HTTP_SKIP_MULTIPLE_SP
#undef HTTP_SKIP_CRLF
#undef HTTP_SKIP_MULTIPLE_CRLF
#undef HTTP_SKIP_LWS

static int
http_msg_finalize_body(struct http_msg *msg, const struct http_cfg *cfg) {
    /* We add a null byte after the body.
     *
     * - If the body is empty, body_length is still 0.
     * - If the body contains text data, it's now a nice null terminated
     *   string.
     * - If the body contains binary data, body_length is still correct, no
     *   harm done.
     */

    if (msg->body == NULL) {
        assert(msg->body_length == 0);
        msg->body = http_malloc(1);
    } else {
        msg->body = http_realloc(msg->body, msg->body_length + 1);
    }

    msg->body[msg->body_length] = '\0';

    /* If there is a body and if a content decoder available, use it */
    if (msg->content_type) {
        const struct http_content_decoder *decoder;
        const char *media_type;

        media_type = http_media_type_base_string(msg->content_type);

        decoder = http_cfg_content_decoder_get(cfg, media_type);
        if (decoder) {
            msg->content = decoder->decode(msg, cfg);
            if (!msg->content) {
                http_set_error("cannot decode content: %s", http_get_error());
                return -1;
            }

            msg->content_decoder = decoder;
        }
    }

    return 0;
}

static bool
http_is_token_char(unsigned char c) {
    static uint32_t table[8] = {
        0x00000000, /*   0- 31                                          */

        0x03ff6cfa, /*  32- 63  ?>=< ;:98 7654 3210 /.-, +*)( `&%$ #"!  */
                    /*          0000 0011 1111 1111 0110 1100 1111 1010 */

        0xc7fffffe, /*  64- 95  _^]\ [ZYX WVUT SRQP ONML KJIH GFED CBA@ */
                    /*          1100 0111 1111 1111 1111 1111 1111 1110 */

        0x67ffffff, /*  96-127   ~}| {zyx wvut srqp onml kjih gfed cba` */
                    /*          0101 0111 1111 1111 1111 1111 1111 1111 */

        0x00000000, /* 128-159                                          */
        0x00000000, /* 160-191                                          */
        0x00000000, /* 192-223                                          */
        0x00000000, /* 224-255                                          */
    };

    return table[c / 32] & (uint32_t)(1 << (c % 32));
}
