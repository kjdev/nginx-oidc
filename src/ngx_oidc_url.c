/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_url.h"

/**
 * Sanitize string by removing CRLF characters to prevent HTTP response
 * splitting attacks
 *
 * This function removes all CR and LF characters from input string.
 * While nginx core typically validates HTTP headers,
 * this provides defense-in-depth
 * for values that will be used in HTTP headers (especially Location header).
 *
 * @param[in] pool      Memory pool for allocation
 * @param[in] input     Input string (may contain CRLF)
 * @param[out] output   Output string (CRLF removed)
 *
 * @retval NGX_OK     Success (output contains sanitized string)
 * @retval NGX_ERROR  Memory allocation failure
 *
 * Note: If input contains no CRLF characters, output will point to input data
 *       (no copy performed for efficiency).
 */
static ngx_int_t
url_sanitize_crlf(ngx_pool_t *pool, ngx_str_t *input, ngx_str_t *output)
{
    u_char *src, *dst;
    size_t i;
    ngx_uint_t has_crlf = 0;

    if (input == NULL || output == NULL) {
        return NGX_ERROR;
    }

    if (input->len == 0) {
        output->data = input->data;
        output->len = 0;
        return NGX_OK;
    }

    /* Check if input contains CRLF characters */
    for (i = 0; i < input->len; i++) {
        if (input->data[i] == '\r' || input->data[i] == '\n') {
            has_crlf = 1;
            break;
        }
    }

    /* If no CRLF found, return input as-is (optimization) */
    if (!has_crlf) {
        output->data = input->data;
        output->len = input->len;
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, pool->log, 0,
                  "oidc_url: CRLF characters detected and removed from URL");

    /* Allocate buffer for sanitized output (max size = input size) */
    output->data = ngx_pnalloc(pool, input->len);
    if (output->data == NULL) {
        return NGX_ERROR;
    }

    /* Copy data while removing CRLF characters */
    src = input->data;
    dst = output->data;

    for (i = 0; i < input->len; i++) {
        /* Skip CR and LF characters */
        if (src[i] != '\r' && src[i] != '\n') {
            *dst++ = src[i];
        }
    }

    output->len = dst - output->data;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_url_encode(ngx_http_request_t *r, ngx_str_t *src, ngx_str_t *dst)
{
    uintptr_t escape;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_url: encoding parameter, src=%V", src);

    /* Calculate escaping needed */
    escape = ngx_escape_uri(NULL, src->data, src->len, NGX_ESCAPE_ARGS);

    if (escape > 0) {
        /* Need encoding - allocate new buffer */
        dst->len = src->len + escape * 2;
        dst->data = ngx_pnalloc(r->pool, dst->len);
        if (dst->data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_url: failed to allocate memory for encoded "
                          "parameter");
            return NGX_ERROR;
        }
        ngx_escape_uri(dst->data, src->data, src->len, NGX_ESCAPE_ARGS);
    } else {
        /* No encoding needed - use original */
        *dst = *src;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_url: parameter encoded, dst=%V, escape=%ui", dst,
                   escape);

    return NGX_OK;
}

/*
 * Converts a path to an absolute URL using one of:
 * 1. Returns path as-is if already absolute (http:// or https://)
 * 2. Combines with configured base_url if available
 * 3. Auto-detects from request (scheme + host + port + path)
 */
ngx_int_t
ngx_oidc_url_build_absolute(ngx_http_request_t *r, ngx_str_t *path,
    ngx_str_t *absolute_url)
{
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_str_t base_url, temp_url;
    size_t len;
    u_char *p;
    ngx_uint_t secure;
    in_port_t port;
    u_char port_buf[sizeof(":65535")];
    size_t port_len;

    if (path == NULL || absolute_url == NULL) {
        return NGX_ERROR;
    }

    /* Check if path is already a full URL (starts with http:// or https://) */
    if (path->len >= 7
        && (ngx_strncmp(path->data, "http://", 7) == 0
            || (path->len >= 8
                && ngx_strncmp(path->data, "https://", 8) == 0)))
    {
        /* Path is already a full URL, sanitize and return */
        if (url_sanitize_crlf(r->pool, path, absolute_url) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Validate constructed URL for CRLF injection */
        if (ngx_oidc_url_validate(r, absolute_url) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    /* Check if base_url is configured */
    if (olcf->base_url != NULL) {
        if (ngx_http_complex_value(r, olcf->base_url, &base_url) != NGX_OK) {
            return NGX_ERROR;
        }

        if (base_url.len > 0) {
            /* Use configured base_url */
            len = base_url.len + path->len;
            temp_url.data = ngx_pnalloc(r->pool, len);
            if (temp_url.data == NULL) {
                return NGX_ERROR;
            }

            p = ngx_cpymem(temp_url.data, base_url.data, base_url.len);
            p = ngx_cpymem(p, path->data, path->len);
            temp_url.len = p - temp_url.data;

            /* Sanitize CRLF before returning */
            if (url_sanitize_crlf(r->pool, &temp_url, absolute_url)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            /* Validate constructed URL for CRLF injection */
            if (ngx_oidc_url_validate(r, absolute_url) != NGX_OK) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* Auto-detect: build URL from request */
#if (NGX_HTTP_SSL)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    /* Get port number */
    port = ngx_inet_get_port(r->connection->local_sockaddr);

    /* Format port string only if non-standard port */
    port_len = 0;
    if ((secure && port != 443) || (!secure && port != 80)) {
        port_len =
            ngx_snprintf(port_buf, sizeof(port_buf), ":%d", port) - port_buf;
    }

    /* Validate server name is available */
    if (r->headers_in.server.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_url: server name not available "
                      "for URL construction");
        return NGX_ERROR;
    }

    /* Calculate URL length: scheme + "://" + host + port + path */
    len = (secure ? sizeof("https://") - 1 : sizeof("http://") - 1) +
          r->headers_in.server.len + port_len + path->len;

    temp_url.data = ngx_pnalloc(r->pool, len);
    if (temp_url.data == NULL) {
        return NGX_ERROR;
    }

    p = temp_url.data;

    /* Add scheme */
    if (secure) {
        p = ngx_cpymem(p, "https://", sizeof("https://") - 1);
    } else {
        p = ngx_cpymem(p, "http://", sizeof("http://") - 1);
    }

    /* Add host */
    p = ngx_cpymem(p, r->headers_in.server.data, r->headers_in.server.len);

    /* Add port if non-standard */
    if (port_len > 0) {
        p = ngx_cpymem(p, port_buf, port_len);
    }

    /* Add path */
    p = ngx_cpymem(p, path->data, path->len);

    temp_url.len = p - temp_url.data;

    /* Sanitize CRLF to prevent HTTP response splitting */
    if (url_sanitize_crlf(r->pool, &temp_url, absolute_url) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Validate constructed URL for CRLF injection */
    if (ngx_oidc_url_validate(r, absolute_url) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Validates a URL for security:
 * - Maximum length: 2048 bytes (RFC recommended)
 * - Must start with http:// or https://
 * - No NULL bytes or control characters
 * - No whitespace characters
 *
 */
ngx_int_t
ngx_oidc_url_validate(ngx_http_request_t *r, ngx_str_t *url)
{
    static const size_t max_len = 2048;
    size_t i;

    /* NULL/empty check */
    if (url == NULL || url->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_url: URL is NULL");
        return NGX_ERROR;
    }

    /* Length validation */
    if (url->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_url: URL is empty");
        return NGX_ERROR;
    }

    if (url->len > max_len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_url: URL exceeds maximum length: %uz (max: %uz)",
                      url->len, max_len);
        return NGX_ERROR;
    }

    /* Check if it starts with http:// or https:// */
    if (url->len < 7
        || (ngx_strncmp(url->data, "http://", 7) != 0
            && (url->len < 8 || ngx_strncmp(url->data, "https://", 8) != 0)))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_url: URL must start with http:// or https://");
        return NGX_ERROR;
    }

    /* Character validation */
    for (i = 0; i < url->len; i++) {
        u_char c = url->data[i];

        /* Check for NULL byte */
        if (c == '\0') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_url: URL contains NULL byte at position %uz",
                          i);
            return NGX_ERROR;
        }

        /* Check for control characters and whitespace */
        if (c < 0x20 || c == ' ') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_url: URL contains invalid character 0x%02x "
                          "at position %uz", c, i);
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_url: URL validated successfully "
                   "(length: %uz, max: %uz)",
                   url->len, max_len);

    return NGX_OK;
}
