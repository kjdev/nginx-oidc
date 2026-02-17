/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * Provides cryptographic hash functions using OpenSSL EVP API
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>

#include "ngx_oidc_hash.h"

/**
 * Compute hash using specified EVP_MD algorithm
 *
 * @param[in] r               HTTP request context for logging
 * @param[in] input           Input data to hash
 * @param[out] output         Output buffer for hash result
 * @param[out] output_len     Actual hash length
 * @param[in] md              OpenSSL EVP_MD algorithm
 * @param[in] algorithm_name  Algorithm name for log messages
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
static ngx_int_t
hash_compute(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len, const EVP_MD *md,
    const char *algorithm_name)
{
    EVP_MD_CTX *ctx;

    /* Create EVP context */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_hash: EVP_MD_CTX_new failed for %s",
                      algorithm_name);
        return NGX_ERROR;
    }

    /* Calculate hash */
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1
        || EVP_DigestUpdate(ctx, input->data, input->len) != 1
        || EVP_DigestFinal_ex(ctx, output, output_len) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_hash: %s digest operation failed",
                      algorithm_name);
        EVP_MD_CTX_free(ctx);
        return NGX_ERROR;
    }

    EVP_MD_CTX_free(ctx);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_hash: %s hash computed, length=%ui",
                   algorithm_name, *output_len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_hash_sha256(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len)
{
    const EVP_MD *md;

    md = EVP_sha256();
    if (md == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_hash: EVP_sha256 failed");
        return NGX_ERROR;
    }

    return hash_compute(r, input, output, output_len, md, "SHA-256");
}

ngx_int_t
ngx_oidc_hash_sha384(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len)
{
    const EVP_MD *md;

    md = EVP_sha384();
    if (md == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_hash: EVP_sha384 failed");
        return NGX_ERROR;
    }

    return hash_compute(r, input, output, output_len, md, "SHA-384");
}

ngx_int_t
ngx_oidc_hash_sha512(ngx_http_request_t *r, ngx_str_t *input,
    u_char *output, unsigned int *output_len)
{
    const EVP_MD *md;

    md = EVP_sha512();
    if (md == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_hash: EVP_sha512 failed");
        return NGX_ERROR;
    }

    return hash_compute(r, input, output, output_len, md, "SHA-512");
}

const void *
ngx_oidc_hash_get_md(const char *algorithm)
{
    if (algorithm == NULL) {
        return NULL;
    }

    /* SHA-256: RS256, ES256, PS256, HS256, ES256K */
    if (ngx_strcmp(algorithm, "RS256") == 0
        || ngx_strcmp(algorithm, "ES256") == 0
        || ngx_strcmp(algorithm, "PS256") == 0
        || ngx_strcmp(algorithm, "HS256") == 0
        || ngx_strcmp(algorithm, "ES256K") == 0)
    {
        return EVP_sha256();
    }

    /* SHA-384: RS384, ES384, PS384, HS384 */
    if (ngx_strcmp(algorithm, "RS384") == 0
        || ngx_strcmp(algorithm, "ES384") == 0
        || ngx_strcmp(algorithm, "PS384") == 0
        || ngx_strcmp(algorithm, "HS384") == 0)
    {
        return EVP_sha384();
    }

    /* SHA-512: RS512, ES512, PS512, HS512 */
    if (ngx_strcmp(algorithm, "RS512") == 0
        || ngx_strcmp(algorithm, "ES512") == 0
        || ngx_strcmp(algorithm, "PS512") == 0
        || ngx_strcmp(algorithm, "HS512") == 0)
    {
        return EVP_sha512();
    }

    /* EdDSA (Ed25519/Ed448) uses SHA-512 equivalent for at_hash */
    if (ngx_strcmp(algorithm, "EdDSA") == 0) {
        return EVP_sha512();
    }

    /* Unsupported algorithm */
    return NULL;
}
