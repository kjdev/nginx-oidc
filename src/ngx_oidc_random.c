/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "ngx_oidc_random.h"
#include "ngx_oidc_hash.h"

/**
 * Generate cryptographically secure random base64url-encoded string
 *
 * Uses OpenSSL RAND_bytes for random data and base64url encoding.
 * Sensitive random bytes are zeroed after encoding.
 *
 * @param[in] r       HTTP request context
 * @param[out] result Generated random string
 * @param[in] length  Desired length of the output string
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
static ngx_int_t
generate_random_string(ngx_http_request_t *r, ngx_str_t *result, size_t length)
{
    unsigned char *random_bytes;
    size_t random_bytes_len;
    ngx_str_t random_str, encoded;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: generating random string, length=%uz",
                   length);

    /* Check for multiplication overflow */
    if (length > NGX_MAX_SIZE_T_VALUE / 3) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_random: length overflow (length=%uz)", length);
        return NGX_ERROR;
    }

    random_bytes_len = (length * 3) / 4 + 1;

    /* Allocate memory for random bytes */
    random_bytes = ngx_palloc(r->pool, random_bytes_len);
    if (random_bytes == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_random: failed to allocate memory "
                      "for random bytes");
        return NGX_ERROR;
    }

    /* Generate random bytes using OpenSSL (cryptographically secure) */
    if (RAND_bytes(random_bytes, (int) random_bytes_len) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_random: RAND_bytes failed");
        /* Zero out sensitive data before returning */
        ngx_memzero(random_bytes, random_bytes_len);
        return NGX_ERROR;
    }

    /* Allocate memory for encoded result */
    encoded.len = ngx_base64_encoded_length(random_bytes_len);
    encoded.data = ngx_pnalloc(r->pool, encoded.len + 1);
    if (encoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_random: failed to allocate memory "
                      "for encoded string");
        /* Zero out sensitive data before returning */
        ngx_memzero(random_bytes, random_bytes_len);
        return NGX_ERROR;
    }

    /* Encode using nginx base64url function */
    random_str.data = random_bytes;
    random_str.len = random_bytes_len;
    ngx_encode_base64url(&encoded, &random_str);

    /* Trim to requested length */
    if (encoded.len > length) {
        encoded.len = length;
    }
    encoded.data[encoded.len] = '\0';

    result->data = encoded.data;
    result->len = encoded.len;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: random string generated, "
                   "length=%uz, value=%V",
                   result->len, result);

    /* Zero out sensitive data */
    ngx_memzero(random_bytes, random_bytes_len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_random_state(ngx_http_request_t *r, ngx_str_t *state)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: generating state");

    return generate_random_string(r, state, 32);
}

ngx_int_t
ngx_oidc_random_nonce(ngx_http_request_t *r, ngx_str_t *nonce)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: generating nonce");

    return generate_random_string(r, nonce, 32);
}

ngx_int_t
ngx_oidc_random_code_verifier(ngx_http_request_t *r, ngx_str_t *verifier)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: generating code_verifier");

    return generate_random_string(r, verifier, 43);
}

ngx_int_t
ngx_oidc_random_code_challenge(ngx_http_request_t *r, ngx_str_t *code_verifier,
    ngx_str_t *challenge)
{
    unsigned char hash[NGX_OIDC_HASH_MAX_SIZE];
    unsigned int hash_len;
    ngx_str_t hash_str;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: generating code_challenge, verifier=%V",
                   code_verifier);

    /* Calculate SHA256 hash using abstraction layer */
    if (ngx_oidc_hash_sha256(r, code_verifier, hash, &hash_len) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_random: SHA-256 hash computation failed");
        return NGX_ERROR;
    }

    /* Base64url encode the hash using nginx API */
    challenge->len = ngx_base64_encoded_length(hash_len);
    challenge->data = ngx_pnalloc(r->pool, challenge->len + 1);
    if (challenge->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_random: failed to allocate memory for challenge");
        return NGX_ERROR;
    }

    hash_str.data = hash;
    hash_str.len = hash_len;

    ngx_encode_base64url(challenge, &hash_str);
    challenge->data[challenge->len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: code_challenge generated, value=%V",
                   challenge);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_random_session_id(ngx_http_request_t *r, ngx_str_t *session_id)
{
    /* Generate 32 bytes (256 bits) of random data for session ID */
    size_t length = ngx_base64_encoded_length(32);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_random: generating session_id");

    return generate_random_string(r, session_id, length);
}
