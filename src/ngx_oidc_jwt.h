/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_JWT_H_INCLUDED_
#define _NGX_OIDC_JWT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "nxe_jwx.h"

typedef struct ngx_oidc_jwks_cache_node_s ngx_oidc_jwks_cache_node_t;

/**
 * JWT token kind, controls nonce validation branching
 *
 * NGX_OIDC_JWT_TOKEN_UNSET is deliberately the zero value: params structs
 * are stack-declared by callers, so a missed initialization must not
 * silently skip nonce validation for an ID token. A flag such as
 * `skip_nonce` would not give this fail-closed guarantee.
 */
typedef enum {
    NGX_OIDC_JWT_TOKEN_UNSET  = 0,
    NGX_OIDC_JWT_TOKEN_ID     = 1,
    NGX_OIDC_JWT_TOKEN_ACCESS = 2
} ngx_oidc_jwt_token_type_t;

/**
 * JWT Validation Parameters
 *
 * Configuration for JWT validation process.
 * Specifies expected values and validation options.
 *
 * Required Fields:
 * - token: JWT to validate (header.payload.signature)
 * - token_type: ID or ACCESS; controls nonce validation
 *
 * Expected Values (for validation):
 * - expected_issuer: Expected iss claim value
 * - expected_audience: Expected aud claim value
 * - expected_nonce: Expected nonce claim value (mandatory for ID tokens,
 *   ignored for access tokens)
 * - access_token: Access token for at_hash validation (optional)
 *
 * Validation Options:
 * - clock_skew_tolerance: Allowed time difference in seconds (default: 300)
 * - token_type: Expected typ header value (e.g., "JWT")
 */
typedef struct {
    ngx_str_t *token;
    /** expected claim values */
    struct {
        ngx_str_t *issuer;
        ngx_str_t *audience;
        ngx_str_t *nonce;
    } expected;
    /** access token for at_hash validation */
    ngx_str_t *access_token;
    /** clock skew tolerance (seconds) */
    time_t     clock_skew;
    /** ID token or access token; controls nonce validation */
    ngx_oidc_jwt_token_type_t token_type;
} ngx_oidc_jwt_validation_params_t;

/**
 * Validate at_hash claim
 *
 * Validates the at_hash claim in the ID Token against the access token.
 * This binds the access token to the ID token and prevents token substitution.
 *
 * @param[in] r             HTTP request context
 * @param[in] algorithm     JWT algorithm (e.g., RS256)
 * @param[in] at_hash       at_hash claim value from ID Token
 * @param[in] access_token  Access token to validate
 *
 * @return NGX_OK if valid, NGX_ERROR if mismatch or validation error
 */
ngx_int_t ngx_oidc_jwt_validate_at_hash(ngx_http_request_t *r,
    const char *algorithm, const ngx_str_t *at_hash,
    ngx_str_t *access_token);

/**
 * High-level JWT verification with JWKS cache (signature + claims)
 *
 * Decodes the token via nxe-jwx, verifies the signature using the supplied
 * keyset, and then enforces the OIDC-specific claim policy
 * (iss / aud / exp / iat / nbf / nonce / at_hash with clock skew).
 *
 * @param[in] r           Request context for logging
 * @param[in] token       JWT to verify
 * @param[in] jwks_cache  JWKS cache node (required)
 * @param[in] params      Validation parameters (expected values, options)
 *
 * @return NGX_OK if both signature and claims are valid, NGX_ERROR otherwise
 */
ngx_int_t ngx_oidc_jwt_verify(ngx_http_request_t *r, ngx_str_t *token,
    ngx_oidc_jwks_cache_node_t *jwks_cache,
    const ngx_oidc_jwt_validation_params_t *params);

#endif /* _NGX_OIDC_JWT_H_INCLUDED_ */
