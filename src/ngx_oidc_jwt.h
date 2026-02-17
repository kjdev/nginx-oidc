/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_JWT_H_INCLUDED_
#define _NGX_OIDC_JWT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include "ngx_oidc_json.h"

typedef struct ngx_oidc_jwks_cache_node_s ngx_oidc_jwks_cache_node_t;

/**
 * JWT Validation Parameters
 *
 * Configuration for JWT validation process.
 * Specifies expected values and validation options.
 *
 * Required Fields:
 * - token: JWT to validate (header.payload.signature)
 *
 * Expected Values (for validation):
 * - expected_issuer: Expected iss claim value
 * - expected_audience: Expected aud claim value
 * - expected_nonce: Expected nonce claim value (mandatory for ID tokens)
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
} ngx_oidc_jwt_validation_params_t;

/**
 * Decode JWT payload
 *
 * Extracts and Base64url-decodes the JWT payload (second part between dots).
 *
 * @param[in] token    JWT string (header.payload.signature)
 * @param[in] payload  Decoded payload JSON (allocated from pool)
 * @param[in] pool     nginx memory pool
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwt_decode_payload(ngx_str_t *token, ngx_str_t *payload,
    ngx_pool_t *pool);

/**
 * Decode JWT header
 *
 * Extracts and Base64url-decodes the JWT header (first part before dot).
 *
 * @param[in] token   JWT string (header.payload.signature)
 * @param[in] header  Decoded header JSON (allocated from pool)
 * @param[in] pool    nginx memory pool
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwt_decode_header(ngx_str_t *token, ngx_str_t *header,
    ngx_pool_t *pool);

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
    const char *algorithm, const char *at_hash, ngx_str_t *access_token);

/**
 * High-level JWT verification with JWKS cache (signature + claims)
 *
 * @param[in] r           Request context for logging
 * @param[in] token       JWT to verify
 * @param[in] jwks_cache  JWKS cache node
 *                        (required, contains pre-parsed EVP_PKEY)
 * @param[in] params      Validation parameters (expected values, options)
 *
 * @return NGX_OK if both signature and claims are valid, NGX_ERROR otherwise
 */
ngx_int_t ngx_oidc_jwt_verify(ngx_http_request_t *r, ngx_str_t *token,
    ngx_oidc_jwks_cache_node_t *jwks_cache,
    const ngx_oidc_jwt_validation_params_t *params);

#endif /* _NGX_OIDC_JWT_H_INCLUDED_ */
