/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_RANDOM_H_INCLUDED_
#define _NGX_OIDC_RANDOM_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * Generate random state parameter for OAuth 2.0 CSRF protection
 *
 * Generates a 32-character random string using cryptographically
 * secure random bytes (OpenSSL RAND_bytes) and base64url encoding.
 *
 * @param[in]  r      HTTP request
 * @param[out] state  generated state
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_random_state(ngx_http_request_t *r, ngx_str_t *state);

/**
 * Generate random nonce parameter for OIDC replay attack protection
 *
 * Generates a 32-character random string using cryptographically
 * secure random bytes (OpenSSL RAND_bytes) and base64url encoding.
 *
 * @param[in]  r      HTTP request
 * @param[out] nonce  generated nonce
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_random_nonce(ngx_http_request_t *r, ngx_str_t *nonce);

/**
 * Generate PKCE code_verifier
 *
 * Generates a 43-character random string as specified in RFC 7636.
 * Uses cryptographically secure random bytes and base64url encoding.
 *
 * @param[in]  r         HTTP request
 * @param[out] verifier  generated code_verifier
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_random_code_verifier(ngx_http_request_t *r,
    ngx_str_t *verifier);

/**
 * Generate PKCE code_challenge from code_verifier
 *
 * Computes SHA256 hash of code_verifier and encodes it using base64url
 * as specified in RFC 7636 (S256 method).
 *
 * @param[in]  r              HTTP request
 * @param[in]  code_verifier  code_verifier string
 * @param[out] challenge      generated code_challenge
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_random_code_challenge(ngx_http_request_t *r,
    ngx_str_t *code_verifier, ngx_str_t *challenge);

/**
 * Generate random session ID
 *
 * Generates a session ID using 32 bytes (256 bits) of cryptographically
 * secure random data, base64url encoded.
 *
 * @param[in] r            HTTP request
 * @param[out] session_id  generated session ID
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_random_session_id(ngx_http_request_t *r,
    ngx_str_t *session_id);

#endif /* _NGX_OIDC_RANDOM_H_INCLUDED_ */
