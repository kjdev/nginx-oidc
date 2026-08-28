/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_HANDLER_BEARER_H_INCLUDED_
#define _NGX_OIDC_HANDLER_BEARER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_oidc_module.h"

/**
 * Extract the Bearer credential from the Authorization request header
 *
 * Matches the "Bearer" auth-scheme case-insensitively (RFC 7235 Section 2.1).
 * The returned token points into r->headers_in, no copy is made.
 *
 * @param[in]  r      HTTP request context
 * @param[out] token  Bearer credential (may be empty, e.g. "Authorization:
 *                    Bearer" with no credentials)
 *
 * @return NGX_OK if the Authorization header uses the Bearer scheme,
 *         NGX_DECLINED if the header is absent or uses another scheme
 */
ngx_int_t ngx_oidc_handler_bearer_token(ngx_http_request_t *r,
    ngx_str_t *token);

/**
 * Verify an externally obtained Bearer access token and authorize the
 * request
 *
 * Verifies ctx->bearer.token (already extracted by
 * ngx_oidc_handler_bearer_token) against provider issuer/JWKS and, on
 * success, caches the decoded payload in ctx->bearer.payload for
 * $oidc_claim_* / $oidc_authenticated.
 *
 * @param[in] r         HTTP request context
 * @param[in] provider  Resolved OIDC provider configuration
 *
 * @return NGX_OK if the token is valid, NGX_HTTP_UNAUTHORIZED if rejected,
 *         NGX_HTTP_INTERNAL_SERVER_ERROR on server-side failure
 */
ngx_int_t ngx_oidc_handler_bearer(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider);

#endif /* _NGX_OIDC_HANDLER_BEARER_H_INCLUDED_ */
