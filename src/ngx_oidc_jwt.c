/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * OIDC-specific JWT validation on top of the nxe-jwx library.
 *
 * JWT decode, signature verification (RS, PS, ES, EdDSA), and JWKS
 * parsing are delegated to nxe-jwx. The none algorithm and HMAC
 * variants are rejected by nxe-jwx itself.
 *
 * Claim validation (iss, aud, exp, iat, nbf, nonce, at_hash with
 * clock skew) is performed here, because the policy is OIDC-specific
 * and outside the scope of nxe-jwx.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "nxe_jwx.h"

#include "ngx_oidc_jwt.h"
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_hash.h"

/*
 * JWT Validation Result
 */
typedef enum {
    JWT_SUCCESS = 0,           /* Validation successful */
    JWT_ERR_INVALID_FORMAT,    /* JWT format error */
    JWT_ERR_INVALID_ISSUER,    /* Issuer mismatch */
    JWT_ERR_INVALID_AUDIENCE,  /* Audience mismatch */
    JWT_ERR_TOKEN_EXPIRED,     /* Token expired */
    JWT_ERR_INVALID_NONCE,     /* Nonce mismatch */
    JWT_ERR_SIGNATURE_FAILED,  /* Signature / at_hash mismatch */
    JWT_ERR_MISSING_CLAIM,     /* Required claim missing */
    JWT_ERR_JSON_PARSE,        /* JSON parsing error */
    JWT_ERR_MEMORY             /* Memory allocation failure */
} jwt_validation_result_t;

/*
 * JWT Claims Structure (extracted from the payload).
 */
typedef struct {
    char   *issuer;
    char   *audience;       /* first audience (for backward compat) */
    char  **audiences;      /* all audiences (NULL-terminated array) */
    size_t  audience_count;
    char   *subject;
    time_t  expiration;
    time_t  issued_at;
    time_t  not_before;
    char   *nonce;
    time_t  auth_time;
    char   *at_hash;
} jwt_claims_t;

/*
 * Get OpenSSL error message
 */
static void
jwt_get_openssl_error(char *buf, size_t buf_len)
{
    unsigned long err = ERR_get_error();
    u_char *p;

    if (err != 0) {
        ERR_error_string_n(err, buf, buf_len);
    } else {
        p = ngx_snprintf((u_char *) buf, buf_len - 1,
                         "no error information");
        *p = '\0';
    }
}

/*
 * Duplicate an ngx_str_t into the pool with a trailing NUL.
 * Returns NULL on allocation failure.
 */
static char *
jwt_str_to_cstr(ngx_pool_t *pool, const ngx_str_t *src)
{
    char *copy;

    if (src == NULL || src->data == NULL) {
        return NULL;
    }

    copy = ngx_pnalloc(pool, src->len + 1);
    if (copy == NULL) {
        return NULL;
    }

    ngx_memcpy(copy, src->data, src->len);
    copy[src->len] = '\0';
    return copy;
}

/*
 * Extract a time claim from JWT payload.
 *
 * Handles both integer and floating-point time values; floating-point
 * values are truncated to seconds.  This is broader than
 * nxe_jwx_claims_get_integer (which is integer-only), so we keep this
 * helper to preserve compatibility with providers that emit real-valued
 * timestamps.
 */
static ngx_int_t
jwt_get_time_claim(nxe_json_t *root, const char *claim_name,
    time_t *result, ngx_int_t required, ngx_pool_t *pool)
{
    nxe_json_t *value;
    int64_t int_value;
    double real_value;

    value = nxe_json_object_get(root, claim_name);
    if (value == NULL) {
        if (required) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: %s claim is missing", claim_name);
            return NGX_ERROR;
        }
        return NGX_DECLINED;
    }

    if (nxe_json_is_integer(value)) {
        if (nxe_json_integer(value, &int_value) != NGX_OK) {
            return NGX_ERROR;
        }
        *result = (time_t) int_value;
        return NGX_OK;
    } else if (nxe_json_is_real(value)) {
        if (nxe_json_real(value, &real_value) != NGX_OK) {
            return NGX_ERROR;
        }
        *result = (time_t) real_value;
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "oidc_jwt: %s claim is floating-point: %f -> %T",
                       claim_name, real_value, *result);
        return NGX_OK;
    } else {
        if (required) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: %s claim has invalid type", claim_name);
            return NGX_ERROR;
        }
        return NGX_DECLINED;
    }
}

/*
 * Parse JWT claims from a payload JSON object owned by the caller.
 */
static ngx_int_t
jwt_parse_claims(nxe_json_t *root, jwt_claims_t *claims, ngx_pool_t *pool)
{
    nxe_json_t *value;
    ngx_str_t str_value;
    ngx_int_t rc;

    ngx_memzero(claims, sizeof(jwt_claims_t));

    /* iss (REQUIRED) */
    rc = nxe_jwx_claims_get_string(root, "iss", &str_value);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: issuer claim is missing or invalid");
        return NGX_ERROR;
    }
    claims->issuer = jwt_str_to_cstr(pool, &str_value);
    if (claims->issuer == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: failed to allocate memory for issuer claim");
        return NGX_ERROR;
    }

    /* aud: string OR array */
    value = nxe_json_object_get(root, "aud");
    if (nxe_json_is_string(value)
        && nxe_json_string(value, &str_value) == NGX_OK)
    {
        claims->audience = jwt_str_to_cstr(pool, &str_value);
        if (claims->audience == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: failed to allocate memory "
                          "for audience claim");
            return NGX_ERROR;
        }

        claims->audiences = ngx_pcalloc(pool, sizeof(char *) * 2);
        if (claims->audiences == NULL) {
            return NGX_ERROR;
        }
        claims->audiences[0] = claims->audience;
        claims->audiences[1] = NULL;
        claims->audience_count = 1;

    } else if (nxe_json_is_array(value)
               && nxe_json_array_size(value) > 0)
    {
        size_t aud_count = nxe_json_array_size(value);
        size_t i;

        claims->audiences = ngx_pcalloc(pool,
                                        sizeof(char *) * (aud_count + 1));
        if (claims->audiences == NULL) {
            return NGX_ERROR;
        }
        claims->audience_count = aud_count;

        for (i = 0; i < aud_count; i++) {
            nxe_json_t *aud_elem = nxe_json_array_get(value, i);
            if (!nxe_json_is_string(aud_elem)
                || nxe_json_string(aud_elem, &str_value) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                              "oidc_jwt: audience claim array element "
                              "at index %uz is not a string", i);
                return NGX_ERROR;
            }
            claims->audiences[i] = jwt_str_to_cstr(pool, &str_value);
            if (claims->audiences[i] == NULL) {
                return NGX_ERROR;
            }
        }
        claims->audiences[aud_count] = NULL;
        claims->audience = claims->audiences[0];

    } else {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: audience claim is missing or invalid");
        return NGX_ERROR;
    }

    /* sub (REQUIRED) */
    rc = nxe_jwx_claims_get_string(root, "sub", &str_value);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: subject claim is missing or invalid");
        return NGX_ERROR;
    }
    claims->subject = jwt_str_to_cstr(pool, &str_value);
    if (claims->subject == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: failed to allocate memory for subject claim");
        return NGX_ERROR;
    }

    /* exp (REQUIRED) */
    if (jwt_get_time_claim(root, "exp", &claims->expiration, 1, pool)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* iat (REQUIRED) */
    if (jwt_get_time_claim(root, "iat", &claims->issued_at, 1, pool)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* nbf (OPTIONAL) */
    jwt_get_time_claim(root, "nbf", &claims->not_before, 0, pool);

    /* nonce (OPTIONAL but typically required for ID tokens) */
    if (nxe_jwx_claims_get_string(root, "nonce", &str_value) == NGX_OK) {
        claims->nonce = jwt_str_to_cstr(pool, &str_value);
        /* Nonce allocation failure is not fatal; validation will catch
         * it if nonce is required. */
    }

    /* auth_time (OPTIONAL) */
    jwt_get_time_claim(root, "auth_time", &claims->auth_time, 0, pool);

    /* at_hash (OPTIONAL) */
    if (nxe_jwx_claims_get_string(root, "at_hash", &str_value) == NGX_OK) {
        claims->at_hash = jwt_str_to_cstr(pool, &str_value);
        if (claims->at_hash == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: failed to allocate at_hash");
        }
    }

    return NGX_OK;
}

/*
 * Validate JWT claims against expected values
 */
static jwt_validation_result_t
jwt_validate_claims(ngx_http_request_t *r, const jwt_claims_t *claims,
    const char *algorithm,
    const ngx_oidc_jwt_validation_params_t *params)
{
    time_t now = ngx_time();

    if (!claims) {
        return JWT_ERR_INVALID_FORMAT;
    }

    /* Validate issuer */
    if (!claims->issuer || !params->expected.issuer) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: issuer (iss) claim is missing");
        return JWT_ERR_INVALID_ISSUER;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: validating issuer "
                   "- claims->issuer='%s' (len=%d), expected='%V' (len=%d)",
                   claims->issuer,
                   claims->issuer ? (int) ngx_strlen(claims->issuer) : 0,
                   params->expected.issuer,
                   (int) params->expected.issuer->len);

    if (ngx_strncmp(claims->issuer, params->expected.issuer->data,
                    params->expected.issuer->len) != 0
        || ngx_strlen(claims->issuer) != params->expected.issuer->len)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: issuer validation failed "
                      "- claims->issuer='%s', expected='%V'",
                      claims->issuer, params->expected.issuer);
        return JWT_ERR_INVALID_ISSUER;
    }

    /* Validate audience (OIDC Core §3.1.3.7) */
    if (!claims->audiences || claims->audience_count == 0
        || !params->expected.audience)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: audience (aud) claim is missing");
        return JWT_ERR_INVALID_AUDIENCE;
    }

    {
        size_t i;
        ngx_int_t aud_matched = 0;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwt: validating audience "
                       "- %uz audience(s), expected='%V'",
                       claims->audience_count, params->expected.audience);

        for (i = 0; i < claims->audience_count; i++) {
            if (ngx_strlen(claims->audiences[i])
                == params->expected.audience->len
                && ngx_strncmp(claims->audiences[i],
                               params->expected.audience->data,
                               params->expected.audience->len) == 0)
            {
                aud_matched = 1;
                break;
            }
        }

        if (!aud_matched) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: audience validation failed "
                          "- expected='%V' not found in %uz audience(s)",
                          params->expected.audience, claims->audience_count);
            return JWT_ERR_INVALID_AUDIENCE;
        }
    }

    /* Check expiration */
    if (claims->expiration == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: expiration (exp) claim is missing or zero");
        return JWT_ERR_TOKEN_EXPIRED;
    }

    if (claims->expiration
        > (time_t) (NGX_MAX_INT_T_VALUE - params->clock_skew))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: expiration time overflow (exp=%T, skew=%T)",
                      claims->expiration, params->clock_skew);
        return JWT_ERR_TOKEN_EXPIRED;
    }

    if (now > claims->expiration + params->clock_skew) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: token expired (exp=%T, now=%T, skew=%T)",
                      claims->expiration, now, params->clock_skew);
        return JWT_ERR_TOKEN_EXPIRED;
    }

    /* Check issued_at */
    if (claims->issued_at == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: issued_at (iat) claim is missing or zero");
        return JWT_ERR_TOKEN_EXPIRED;
    }

    if (now > (time_t) (NGX_MAX_INT_T_VALUE - params->clock_skew)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: time value overflow (now=%T, skew=%T)",
                      now, params->clock_skew);
        return JWT_ERR_TOKEN_EXPIRED;
    }

    if (claims->issued_at > now + params->clock_skew) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: token issued in the future "
                      "(iat=%T, now=%T, skew=%T)",
                      claims->issued_at, now, params->clock_skew);
        return JWT_ERR_TOKEN_EXPIRED;
    }

    /* Check not_before */
    if (claims->not_before != 0) {
        if (claims->not_before < params->clock_skew) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: not_before time underflow "
                          "(nbf=%T, skew=%T)",
                          claims->not_before, params->clock_skew);
            return JWT_ERR_TOKEN_EXPIRED;
        }

        if (now < claims->not_before - params->clock_skew) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: token not yet valid "
                          "(nbf=%T, now=%T, skew=%T)",
                          claims->not_before, now, params->clock_skew);
            return JWT_ERR_TOKEN_EXPIRED;
        }
    }

    /* Validate nonce (mandatory for ID tokens) */
    if (!claims->nonce || !params->expected.nonce) {
        return JWT_ERR_MISSING_CLAIM;
    }

    if (ngx_strlen(claims->nonce) != params->expected.nonce->len
        || CRYPTO_memcmp(claims->nonce, params->expected.nonce->data,
                         params->expected.nonce->len) != 0)
    {
        return JWT_ERR_INVALID_NONCE;
    }

    /* Validate at_hash if access_token provided and at_hash exists */
    if (params->access_token && params->access_token->len > 0
        && claims->at_hash)
    {
        if (algorithm == NULL || *algorithm == '\0') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: could not extract algorithm from JWT "
                          "header for at_hash validation");
            return JWT_ERR_SIGNATURE_FAILED;
        }

        if (ngx_oidc_jwt_validate_at_hash(r, algorithm, claims->at_hash,
                                          params->access_token)
            != NGX_OK)
        {
            return JWT_ERR_SIGNATURE_FAILED;
        }
    }

    return JWT_SUCCESS;
}

/*
 * Algorithm (OpenID Connect Core 1.0 Section 3.1.3.3):
 * 1. Hash the access token using the hash algorithm specified in the JWT alg
 * 2. Take the left-most half of the hash
 * 3. Base64url encode the result
 * 4. Compare with at_hash claim
 *
 * SECURITY: Always validate at_hash when using implicit or hybrid flows.
 */
ngx_int_t
ngx_oidc_jwt_validate_at_hash(ngx_http_request_t *r, const char *algorithm,
    const char *at_hash, ngx_str_t *access_token)
{
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    size_t hash_half_len;
    unsigned char encoded_hash[128];
    ngx_str_t hash_str, encoded;
    char err_buf[256];

    /* Validate input parameters */
    if (r == NULL) {
        return NGX_ERROR;
    }

    /* Clear OpenSSL error stack to avoid stale errors */
    ERR_clear_error();

    if (!algorithm || !at_hash || !access_token || access_token->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: at_hash validation failed due to "
                      "invalid parameters (algorithm=%s, at_hash=%s, "
                      "access_token=%p, access_token_len=%uz)",
                      algorithm ? algorithm : "(null)",
                      at_hash ? at_hash : "(null)",
                      access_token,
                      access_token ? access_token->len : 0);
        return NGX_ERROR;
    }

    /* Get hash algorithm from JWT algorithm name */
    md = (const EVP_MD *) ngx_oidc_hash_get_md(algorithm);
    if (!md) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: unsupported algorithm for at_hash: %s",
                      algorithm);
        return NGX_ERROR;
    }

    if (ngx_strstr(algorithm, "256")) {
        hash_half_len = 16;  /* SHA-256 produces 32 bytes, take left 16 */
    } else if (ngx_strstr(algorithm, "384")) {
        hash_half_len = 24;  /* SHA-384 produces 48 bytes, take left 24 */
    } else {
        /* 512 or EdDSA */
        hash_half_len = 32;  /* SHA-512 produces 64 bytes, take left 32 */
    }

    /* Compute hash of access token */
    if (!EVP_Digest(access_token->data, access_token->len, hash, &hash_len,
                    md, NULL))
    {
        jwt_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: EVP_Digest failed for at_hash computation: %s",
                      err_buf);
        return NGX_ERROR;
    }

    /* Take left-most half of hash */
    hash_str.data = hash;
    hash_str.len = hash_half_len;

    /* Base64url encode */
    encoded.data = encoded_hash;
    encoded.len = sizeof(encoded_hash);
    ngx_encode_base64url(&encoded, &hash_str);

    /* Compare with at_hash from token using constant-time comparison */
    size_t at_hash_len = ngx_strlen(at_hash);
    if (encoded.len != at_hash_len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: at_hash validation failed (length mismatch) "
                      "(algorithm: %s, expected_len: %uz, computed_len: %uz)",
                      algorithm, at_hash_len, encoded.len);
        return NGX_ERROR;
    }

    /* Use OpenSSL constant-time comparison to prevent timing attacks */
    if (CRYPTO_memcmp(encoded.data, at_hash, encoded.len) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: at_hash validation failed (value mismatch) "
                      "(algorithm: %s, expected: %s, computed: %*s)",
                      algorithm, at_hash, (int) encoded.len, encoded.data);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: at_hash validation succeeded "
                   "(algorithm: %s, hash: %s)",
                   algorithm, at_hash);

    return NGX_OK;
}

/*
 * High-level JWT verification using nxe-jwx + OIDC claim policy.
 */
ngx_int_t
ngx_oidc_jwt_verify(ngx_http_request_t *r, ngx_str_t *token,
    ngx_oidc_jwks_cache_node_t *jwks_cache,
    const ngx_oidc_jwt_validation_params_t *params)
{
    nxe_jwx_token_t *jwt_token;
    nxe_jwx_jwks_t *jwks;
    nxe_json_t *payload_json;
    const ngx_str_t *alg_str;
    char *alg_cstr = NULL;
    jwt_claims_t claims;
    jwt_validation_result_t result;

    /* Validate input parameters */
    if (r == NULL || token == NULL || params == NULL) {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt_verify: NULL parameter");
        }
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: Starting JWT verification");

    /* Validate JWKS cache */
    if (jwks_cache == NULL || ngx_oidc_jwks_get_key_count(jwks_cache) == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWKS cache is not available or empty");
        return NGX_ERROR;
    }

    jwks = ngx_oidc_jwks_cache_node_get_jwx_jwks(jwks_cache);
    if (jwks == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWKS cache has no parsed keyset");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: Using JWKS cache with %ui keys",
                   ngx_oidc_jwks_get_key_count(jwks_cache));

    /* Decode the JWT (alg whitelist + "none" rejection happen inside
     * nxe-jwx). */
    jwt_token = nxe_jwx_decode(token, r->pool);
    if (jwt_token == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: nxe_jwx_decode failed");
        return NGX_ERROR;
    }

    /* Verify signature */
    if (nxe_jwx_jws_verify(jwt_token, jwks, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWT signature verification failed");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: JWT signature verified successfully with cache");

    /* Extract payload JSON */
    payload_json = nxe_jwx_token_payload(jwt_token);
    if (payload_json == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: token has no payload JSON");
        return NGX_ERROR;
    }

    /* Parse claims */
    if (jwt_parse_claims(payload_json, &claims, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to parse JWT claims");
        return NGX_ERROR;
    }

    /* Algorithm string for at_hash validation */
    alg_str = nxe_jwx_token_alg(jwt_token);
    if (alg_str != NULL) {
        alg_cstr = jwt_str_to_cstr(r->pool, alg_str);
    }

    /* Validate claims */
    result = jwt_validate_claims(r, &claims, alg_cstr, params);
    if (result != JWT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWT claims validation failed "
                      "with error code: %d",
                      result);
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: JWT verification completed successfully");

    return NGX_OK;
}
