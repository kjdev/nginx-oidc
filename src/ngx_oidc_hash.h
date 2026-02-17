/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_HASH_H_INCLUDED_
#define _NGX_OIDC_HASH_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Maximum hash output size
 * SHA-512 produces 64 bytes, which is the largest hash we support
 */
#define NGX_OIDC_HASH_MAX_SIZE  64

/**
 * Compute SHA-256 hash of input data
 *
 * @param[in] r            HTTP request context
 * @param[in] input        Input data to hash
 * @param[out] output      Output buffer
 *                         (must be at least NGX_OIDC_HASH_MAX_SIZE bytes)
 * @param[out] output_len  Pointer to store actual hash length
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_hash_sha256(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len);

/**
 * Compute SHA-384 hash of input data
 *
 * @param[in] r            HTTP request context
 * @param[in] input        Input data to hash
 * @param[out] output      Output buffer
 *                         (must be at least NGX_OIDC_HASH_MAX_SIZE bytes)
 * @param[out] output_len  Pointer to store actual hash length
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_hash_sha384(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len);

/**
 * Compute SHA-512 hash of input data
 *
 * @param[in] r            HTTP request context
 * @param[in] input        Input data to hash
 * @param[out] output      Output buffer
 *                         (must be at least NGX_OIDC_HASH_MAX_SIZE bytes)
 * @param[out] output_len  Pointer to store actual hash length
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_hash_sha512(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len);

/**
 * Get EVP_MD algorithm from JWT algorithm name
 *
 * Supports: RS256/384/512, ES256/384/512, PS256/384/512, HS256/384/512, EdDSA
 * Returns appropriate SHA-256/384/512 based on algorithm suffix
 *
 * @param[in] algorithm  JWT algorithm name (e.g., "RS256", "ES384")
 *
 * @return const EVP_MD* on success, NULL if algorithm not supported
 */
const void * ngx_oidc_hash_get_md(const char *algorithm);

#endif /* _NGX_OIDC_HASH_H_INCLUDED_ */
