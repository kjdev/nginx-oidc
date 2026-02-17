/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_HTTP_H_INCLUDED_
#define _NGX_OIDC_HTTP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Forward declaration for HTTP context */
typedef struct ngx_oidc_http_ctx_s ngx_oidc_http_ctx_t;

/**
 * Subrequest completion callback
 * Called when subrequest completes (success or failure)
 * This follows nginx's ngx_http_post_subrequest_pt signature
 *
 * @param[in] r     Subrequest
 * @param[in] data  User data passed to subrequest creation
 * @param[in] rc    Subrequest return code
 *
 * @return NGX_OK to continue, NGX_ERROR to abort
 */
typedef ngx_int_t (*ngx_oidc_http_done_pt)(ngx_http_request_t *r, void *data,
    ngx_int_t rc);

/**
 * Get subrequest response status code
 *
 * @param[in] sr  Subrequest
 *
 * @return HTTP status code (200, 404, etc.) or NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_http_response_status(ngx_http_request_t *sr);

/**
 * Get subrequest response body
 * Combines all buffer chains into a single string
 *
 * @param[in] sr    Subrequest
 * @param[out] body  Response body (allocated from sr->pool)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_http_response_body(ngx_http_request_t *sr, ngx_str_t *body);

/**
 * Fetch external URL via GET request (through proxy location)
 *
 * This function creates a subrequest to the /_oidc_http_fetch proxy location,
 * which then forwards the request to the external URL.
 *
 * @param[in] r     Request context
 * @param[in] url   External URL to fetch
 *                  (e.g., "https://example.com/metadata")
 * @param[in] done  Completion callback (called when fetch finishes)
 * @param[in] data  User data passed to completion callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_http_get(ngx_http_request_t *r, ngx_str_t *url,
    ngx_oidc_http_done_pt done, void *data);

/**
 * Fetch external URL via GET request with Bearer token (through proxy location)
 *
 * This function creates a subrequest to the /_oidc_http_fetch proxy location,
 * which then forwards the GET request with an Authorization: Bearer header.
 *
 * @param[in] r             Request context
 * @param[in] url           External URL to fetch
 *                          (e.g.,"https://example.com/userinfo")
 * @param[in] bearer_token  Bearer token for Authorization header
 * @param[in] done          Completion callback (called when fetch finishes)
 * @param[in] data          User data passed to completion callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_http_get_bearer(ngx_http_request_t *r, ngx_str_t *url,
    ngx_str_t *bearer_token, ngx_oidc_http_done_pt done, void *data);

/**
 * Fetch external URL via POST request (through proxy location)
 *
 * This function creates a subrequest to the /_oidc_http_fetch proxy location,
 * which then forwards the POST request to the external URL with the given body.
 *
 * @param[in] r     Request context
 * @param[in] url   External URL to fetch (e.g., "https://example.com/token")
 * @param[in] body  POST body (application/x-www-form-urlencoded)
 * @param[in] done  Completion callback (called when fetch finishes)
 * @param[in] data  User data passed to completion callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_http_post(ngx_http_request_t *r, ngx_str_t *url,
    ngx_str_t *body, ngx_oidc_http_done_pt done, void *data);

/**
 * Get cookie value from HTTP request by cookie name
 *
 * @param[in] r              HTTP request context
 * @param[in] cookie_name    Cookie name to search for
 * @param[out] cookie_value  Cookie value (allocated from r->pool)
 *
 * @return NGX_OK if cookie found, NGX_DECLINED if not found, NGX_ERROR on error
 */
ngx_int_t ngx_oidc_http_cookie_get(ngx_http_request_t *r,
    ngx_str_t *cookie_name, ngx_str_t *cookie_value);

#endif /* _NGX_OIDC_HTTP_H_INCLUDED_ */
