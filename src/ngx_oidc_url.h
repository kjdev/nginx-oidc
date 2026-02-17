/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_URL_H_INCLUDED_
#define _NGX_OIDC_URL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * URL encoding for query parameters
 *
 * Encodes src string using NGX_ESCAPE_ARGS and stores result in dst.
 * If no encoding needed, dst points to src.
 *
 * @param[in] r     HTTP request
 * @param[in] src   Source string to encode
 * @param[out] dst  Destination for encoded string
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_url_encode(ngx_http_request_t *r, ngx_str_t *src,
    ngx_str_t *dst);

/**
 * Build absolute URL from path
 *
 * @param[in] r              HTTP request
 * @param[in] path           Path to convert (can be relative or absolute)
 * @param[out] absolute_url  absolute URL
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_url_build_absolute(ngx_http_request_t *r, ngx_str_t *path,
    ngx_str_t *absolute_url);

/**
 * Validate URL
 *
 * @param[in] r    HTTP request
 * @param[in] url  URL string to validate
 *
 * @return NGX_OK if valid, NGX_ERROR if invalid
 */
ngx_int_t ngx_oidc_url_validate(ngx_http_request_t *r, ngx_str_t *url);

#endif /* _NGX_OIDC_URL_H_INCLUDED_ */
