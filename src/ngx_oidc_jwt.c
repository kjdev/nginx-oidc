/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * This module implements JWT (JSON Web Token) processing for OIDC
 * authentication.
 * It provides cryptographic signature verification using OpenSSL 3.0 and
 * validates
 * JWT claims according to OpenID Connect Core 1.0 and RFC 7519.
 *
 * Key Features:
 * - JWT parsing (header, payload, signature extraction)
 * - Signature verification with multiple algorithms:
 *   - RSA: RS256, RS384, RS512 (PKCS#1 v1.5), PS256, PS384, PS512 (PSS)
 *   - EC: ES256, ES384, ES512, ES256K (secp256k1)
 *   - EdDSA: Ed25519, Ed448
 *   Note: HMAC algorithms (HS256/HS384/HS512) are not supported
 * - Claims validation:
 *   - Issuer (iss) matching
 *   - Audience (aud) matching
 *   - Expiration (exp) checking with configurable clock skew
 *   - Not-before (nbf) checking
 *   - Nonce validation for replay attack prevention
 *   - at_hash validation for token binding
 * - JWK (JSON Web Key) support for public key extraction
 *
 * Security Implementation:
 * - OpenSSL 3.0 EVP API for all cryptographic operations
 * - Time-based validation with clock skew tolerance (default: 300 seconds)
 * - Base64url decoding according to RFC 4648
 * - Memory-safe operations with nginx pool allocation
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include "ngx_oidc_jwt.h"
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_json.h"
#include "ngx_oidc_hash.h"

/*
 * JWT Validation Result
 *
 * Enumeration of possible JWT validation outcomes.
 * Success (0) and various error conditions for detailed error reporting.
 */
typedef enum {
    JWT_SUCCESS = 0,           /* Validation successful */
    JWT_ERR_INVALID_FORMAT,    /* JWT format error (not 3 parts) */
    JWT_ERR_INVALID_ISSUER,    /* Issuer mismatch */
    JWT_ERR_INVALID_AUDIENCE,  /* Audience mismatch */
    JWT_ERR_TOKEN_EXPIRED,     /* Token expired (exp claim) */
    JWT_ERR_INVALID_NONCE,     /* Nonce mismatch */
    JWT_ERR_SIGNATURE_FAILED,  /* Signature verification failed */
    JWT_ERR_MISSING_CLAIM,     /* Required claim missing */
    JWT_ERR_JSON_PARSE,        /* JSON parsing error */
    JWT_ERR_MEMORY             /* Memory allocation failure */
} jwt_validation_result_t;

/*
 * Allowed JWT Algorithms Whitelist
 */
static const char *ngx_oidc_jwt_allowed_algs[] = {
    "RS256", "RS384", "RS512",  /* RSA PKCS#1 v1.5 with SHA-256/384/512 */
    "PS256", "PS384", "PS512",  /* RSA-PSS with SHA-256/384/512 */
    "ES256", "ES384", "ES512",  /* ECDSA with SHA-256/384/512 */
    "ES256K",                   /* ECDSA with SHA-256 and secp256k1 curve */
    "EdDSA",                    /* EdDSA with Ed25519 or Ed448 */
    NULL                        /* Terminator */
};

/**
 * Validate JWT Algorithm
 *
 * Verifies that the JWT algorithm is in the allowed whitelist and
 * explicitly rejects the "none" algorithm.
 *
 * @param[in] r    HTTP request
 * @param[in] alg  Algorithm string from JWT header
 *
 * @return NGX_OK if valid, NGX_ERROR if invalid
 */
static ngx_int_t
ngx_oidc_jwt_validate_algorithm(ngx_http_request_t *r, const char *alg)
{
    size_t i;

    /* NULL/empty check */
    if (alg == NULL || *alg == '\0') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWT algorithm is missing");
        return NGX_ERROR;
    }

    /* Explicit rejection of "none" */
    if (ngx_strcmp(alg, "none") == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWT algorithm 'none' is not allowed");
        return NGX_ERROR;
    }

    /* Whitelist check */
    for (i = 0; ngx_oidc_jwt_allowed_algs[i] != NULL; i++) {
        if (ngx_strcmp(alg, ngx_oidc_jwt_allowed_algs[i]) == 0) {
            return NGX_OK;
        }
    }

    /* Unknown algorithm rejection */
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "oidc_jwt: JWT algorithm '%s' is not in whitelist", alg);

    return NGX_ERROR;
}

/**
 * JWT Claims Structure
 *
 * Represents standard OIDC claims extracted from the JWT payload.
 * All string fields are null-terminated C strings allocated from nginx pool.
 * Time fields are Unix timestamps (seconds since epoch).
 *
 * Standard Claims (RFC 7519):
 * - iss (issuer): Token issuer identifier
 * - aud (audience): Intended audience (client_id)
 * - sub (subject): Subject identifier (user ID)
 * - exp (expiration): Token expiration time
 * - iat (issued at): Token issuance time
 * - nbf (not before): Token not valid before this time
 *
 * OIDC-specific Claims (OpenID Connect Core 1.0):
 * - nonce: String value used to associate client session with ID Token
 * - auth_time: Time when authentication occurred
 * - at_hash: Access Token hash value (for implicit flow)
 *
 * JWK Claims:
 * - kid: Key ID to match against JWKS
 */
typedef struct {
    char   *issuer;
    char   *audience;       /* first audience (for backward compat) */
    char  **audiences;      /* all audiences (NULL-terminated array) */
    size_t  audience_count; /* number of audiences */
    char   *subject;
    time_t  expiration;
    time_t  issued_at;
    time_t  not_before;
    char   *nonce;
    time_t  auth_time;
    char   *at_hash;
    char   *kid;
} jwt_claims_t;

/**
 * Get OpenSSL error message
 *
 * Helper function to retrieve and format OpenSSL error messages.
 * Uses ERR_get_error() to get the error code and ERR_error_string_n()
 * to format it into a human-readable string.
 *
 * @param[in] buf      Buffer to store error message
 * @param[in] buf_len  Buffer length
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

/**
 * Extract time claim from JWT payload
 *
 * Handles both integer and floating-point time values.
 * Floating-point values are truncated to seconds.
 *
 * @param[in] root        Parsed JSON root object
 * @param[in] claim_name  Claim name (e.g., "exp", "iat", "nbf")
 * @param[out] result     Extracted time value
 * @param[in] required    1 if claim is required, 0 if optional
 * @param[in] pool        Memory pool for logging
 *
 * @return NGX_OK on success, NGX_DECLINED if optional claim not present,
 *         NGX_ERROR if required claim missing or invalid type
 */
static ngx_int_t
jwt_get_time_claim(ngx_oidc_json_t *root, const char *claim_name,
    time_t *result, ngx_int_t required, ngx_pool_t *pool)
{
    ngx_oidc_json_t *value;
    ngx_int_t int_value;

    value = ngx_oidc_json_object_get(root, claim_name);
    if (value == NULL) {
        if (required) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: %s claim is missing", claim_name);
            return NGX_ERROR;
        }
        return NGX_DECLINED; /* Optional claim not present */
    }

    if (ngx_oidc_json_is_integer(value)) {
        int_value = ngx_oidc_json_integer(value);
        *result = (time_t) int_value;
        return NGX_OK;
    } else if (ngx_oidc_json_type(value) == NGX_OIDC_JSON_REAL) {
        /* Handle floating-point time (e.g., with microseconds) */
        double real_value = ngx_oidc_json_real(value);
        *result = (time_t) real_value; /* Truncate to seconds */
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
        return NGX_DECLINED; /* Optional claim has wrong type */
    }
}

/**
 * Parse JWT claims from decoded payload JSON
 *
 * Extracts required (iss, aud, sub, exp, iat) and optional
 * (nbf, nonce, auth_time, at_hash) claims from the JWT payload.
 *
 * @param[in] payload_json  Decoded JWT payload as JSON string
 * @param[out] claims       Parsed claims structure
 * @param[in] pool          Memory pool for allocation
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
static ngx_int_t
jwt_parse_claims(const char *payload_json, jwt_claims_t *claims,
    ngx_pool_t *pool)
{
    ngx_oidc_json_t *root, *value;
    const char *string_value;
    ngx_str_t json_str;

    ngx_memzero(claims, sizeof(jwt_claims_t));

    json_str.data = (u_char *) payload_json;
    json_str.len = ngx_strlen(payload_json);

    root = ngx_oidc_json_parse(&json_str, pool);
    if (!root) {
        return NGX_ERROR;
    }

    /* Extract issuer (REQUIRED claim) */
    value = ngx_oidc_json_object_get(root, "iss");
    if (ngx_oidc_json_is_string(value)) {
        string_value = ngx_oidc_json_string(value);
        size_t len = ngx_strlen(string_value);
        claims->issuer = ngx_pcalloc(pool, len + 1);
        if (claims->issuer == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: failed to allocate memory "
                          "for issuer claim");
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }
        ngx_memcpy(claims->issuer, string_value, len);
    } else {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: issuer claim is missing or invalid");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Extract audience (REQUIRED claim) */
    value = ngx_oidc_json_object_get(root, "aud");
    if (ngx_oidc_json_is_string(value)) {
        string_value = ngx_oidc_json_string(value);
        size_t len = ngx_strlen(string_value);
        claims->audience = ngx_pcalloc(pool, len + 1);
        if (claims->audience == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: failed to allocate memory "
                          "for audience claim");
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }
        ngx_memcpy(claims->audience, string_value, len);

        /* Single audience: store as array with one element */
        claims->audiences = ngx_pcalloc(pool, sizeof(char *) * 2);
        if (claims->audiences == NULL) {
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }
        claims->audiences[0] = claims->audience;
        claims->audiences[1] = NULL;
        claims->audience_count = 1;

    } else if (ngx_oidc_json_is_array(value)
               && ngx_oidc_json_array_size(value) > 0)
    {
        size_t aud_count = ngx_oidc_json_array_size(value);
        size_t i;

        claims->audiences = ngx_pcalloc(pool,
                                        sizeof(char *) * (aud_count + 1));
        if (claims->audiences == NULL) {
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }
        claims->audience_count = aud_count;

        for (i = 0; i < aud_count; i++) {
            ngx_oidc_json_t *aud_elem = ngx_oidc_json_array_get(value, i);
            if (!ngx_oidc_json_is_string(aud_elem)) {
                ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                              "oidc_jwt: audience claim array element "
                              "at index %uz is not a string", i);
                ngx_oidc_json_free(root);
                return NGX_ERROR;
            }
            string_value = ngx_oidc_json_string(aud_elem);
            size_t len = ngx_strlen(string_value);
            claims->audiences[i] = ngx_pcalloc(pool, len + 1);
            if (claims->audiences[i] == NULL) {
                ngx_oidc_json_free(root);
                return NGX_ERROR;
            }
            ngx_memcpy(claims->audiences[i], string_value, len);
        }
        claims->audiences[aud_count] = NULL;

        /* Set audience to first element for backward compatibility */
        claims->audience = claims->audiences[0];

    } else {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: audience claim is missing or invalid");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Extract subject (REQUIRED claim) */
    value = ngx_oidc_json_object_get(root, "sub");
    if (ngx_oidc_json_is_string(value)) {
        string_value = ngx_oidc_json_string(value);
        size_t len = ngx_strlen(string_value);
        claims->subject = ngx_pcalloc(pool, len + 1);
        if (claims->subject == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt: failed to allocate memory "
                          "for subject claim");
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }
        ngx_memcpy(claims->subject, string_value, len);
    } else {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: subject claim is missing or invalid");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Extract expiration (REQUIRED claim) */
    if (jwt_get_time_claim(root, "exp", &claims->expiration, 1, pool)
        != NGX_OK)
    {
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Extract issued_at (REQUIRED claim) */
    if (jwt_get_time_claim(root, "iat", &claims->issued_at, 1, pool)
        != NGX_OK)
    {
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Extract not_before (OPTIONAL claim) */
    jwt_get_time_claim(root, "nbf", &claims->not_before, 0, pool);

    /* Extract nonce (OPTIONAL claim, but may be required by validation) */
    value = ngx_oidc_json_object_get(root, "nonce");
    if (ngx_oidc_json_is_string(value)) {
        string_value = ngx_oidc_json_string(value);
        size_t len = ngx_strlen(string_value);
        claims->nonce = ngx_pcalloc(pool, len + 1);
        if (claims->nonce) {
            ngx_memcpy(claims->nonce, string_value, len);
        }
        /* Note: nonce allocation failure is not fatal, validation will catch
         * it if nonce is required */
    }

    /* Extract auth_time (OPTIONAL claim) */
    jwt_get_time_claim(root, "auth_time", &claims->auth_time, 0, pool);

    /* Extract at_hash (OPTIONAL claim) */
    value = ngx_oidc_json_object_get(root, "at_hash");
    if (ngx_oidc_json_is_string(value)) {
        string_value = ngx_oidc_json_string(value);
        size_t len = ngx_strlen(string_value);
        claims->at_hash = ngx_pcalloc(pool, len + 1);
        if (claims->at_hash == NULL) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "oidc_jwt: failed to allocate at_hash");
        } else {
            ngx_memcpy(claims->at_hash, string_value, len);
        }
    }

    ngx_oidc_json_free(root);

    return NGX_OK;
}

/**
 * Validate JWT claims against expected values
 *
 * Checks issuer, audience, nonce, expiration (exp), not-before (nbf),
 * issued-at (iat), and at_hash with configurable clock skew tolerance.
 *
 * @param[in] r       HTTP request context for logging
 * @param[in] claims  Parsed JWT claims
 * @param[in] params  Validation parameters (expected values and options)
 *
 * @return JWT_OK if all checks pass, JWT_ERR_* on validation failure
 */
static jwt_validation_result_t
jwt_validate_claims(ngx_http_request_t *r, const jwt_claims_t *claims,
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

    /* Validate issuer with exact string match (including length) */
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

    /* Validate audience (OIDC Core §3.1.3.7: client_id must be in aud) */
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

    /* Check for overflow before addition */
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

    /* Check issued_at - reject tokens issued too far in the future */
    if (claims->issued_at == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: issued_at (iat) claim is missing or zero");
        return JWT_ERR_TOKEN_EXPIRED;
    }

    /* Check for overflow before addition */
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
        /* Check for underflow before subtraction */
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

    /* Validate nonce using constant-time comparison */
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
        /* Extract algorithm from JWT header */
        ngx_str_t header;
        ngx_oidc_json_t *header_json, *alg_value;
        const char *algorithm = NULL;

        if (ngx_oidc_jwt_decode_header(params->token, &header, r->pool)
            == NGX_OK)
        {
            /* Parse header JSON */
            header_json = ngx_oidc_json_parse(&header, r->pool);
            if (header_json) {
                alg_value = ngx_oidc_json_object_get(header_json, "alg");
                if (ngx_oidc_json_is_string(alg_value)) {
                    algorithm = ngx_oidc_json_string(alg_value);
                }

                if (algorithm) {
                    /* Validate at_hash with correct algorithm */
                    if (ngx_oidc_jwt_validate_at_hash(r, algorithm,
                                                      claims->at_hash,
                                                      params->access_token)
                        != NGX_OK)
                    {
                        ngx_oidc_json_free(header_json);
                        return JWT_ERR_SIGNATURE_FAILED;
                    }
                }

                ngx_oidc_json_free(header_json);
            }
        }

        /* If algorithm extraction failed, reject token */
        if (!algorithm) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: could not extract algorithm from JWT "
                          "header for at_hash validation");
            return JWT_ERR_SIGNATURE_FAILED;
        }
    }

    return JWT_SUCCESS;
}

/** Context for JWT signature verification iterator */
typedef struct {
    ngx_http_request_t *r;
    const char         *algorithm;
    const char         *kid_str;
    /** signed data (header.payload) */
    struct {
        u_char *buf;
        size_t  len;
    } header_payload;
    ngx_str_t  *signature_decoded;
    ngx_int_t   result;
    /** number of keys tried */
    ngx_uint_t  key_count;
} jwt_signature_verify_ctx_t;

static ngx_inline ngx_str_t *
empty_str(void)
{
    static ngx_str_t empty = ngx_string("");
    return &empty;
}

/**
 * JWKS key iteration callback for JWT signature verification
 *
 * Attempts to verify the JWT signature using the given JWK key.
 * Supports RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384/512),
 * and EdDSA algorithms.
 *
 * @param[in] r     HTTP request context
 * @param[in] key   JWKS key to try for verification
 * @param[in] data  jwt_signature_verify_ctx_t context
 *
 * @return NGX_OK if verified (stops iteration), NGX_DECLINED to try next key,
 *         NGX_ERROR on fatal error
 */
static ngx_int_t
jwt_verify_key_callback(ngx_http_request_t *r, const ngx_oidc_jwks_key_t *key,
    void *data)
{
    jwt_signature_verify_ctx_t *ctx = data;
    ngx_str_t *key_kid, *key_alg;
    ngx_oidc_jwk_type_t key_kty;
    EVP_PKEY *key_pkey;
    ngx_int_t result = NGX_OK;

    /* OpenSSL resources (initialized to NULL for cleanup safety) */
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    ECDSA_SIG *ec_sig = NULL;
    unsigned char *der_sig = NULL;
    BIGNUM *bn_r = NULL, *bn_s = NULL;

    /* Clear OpenSSL error stack to avoid stale errors */
    ERR_clear_error();

    key_kid = ngx_oidc_jwks_key_get_kid(key);
    key_alg = ngx_oidc_jwks_key_get_alg(key);
    key_kty = ngx_oidc_jwks_key_get_kty(key);
    key_pkey = ngx_oidc_jwks_key_get_pkey(key);

    /* Check kid match if present in JWT */
    if (ctx->kid_str && key_kid && key_kid->len > 0) {
        size_t jwt_kid_len = ngx_strlen(ctx->kid_str);
        if (jwt_kid_len != key_kid->len
            || ngx_strncmp(ctx->kid_str,
                           (char *) key_kid->data, key_kid->len) != 0)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: Key kid mismatch: JWT=%s, key=%V",
                           ctx->kid_str, key_kid);
            return NGX_OK; /* Continue to next key */
        }
    }

    /* Check algorithm match if present in key */
    if (key_alg && key_alg->len > 0) {
        size_t jwt_alg_len = ngx_strlen(ctx->algorithm);
        if (jwt_alg_len != key_alg->len
            || ngx_strncmp(ctx->algorithm,
                           (char *) key_alg->data, key_alg->len) != 0)
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: Key alg mismatch: JWT=%s, key=%V",
                           ctx->algorithm, key_alg);
            return NGX_OK; /* Continue to next key */
        }
    }

    /* Check key type compatibility with algorithm */
    if (key_kty == NGX_OIDC_JWK_RSA) {
        if (ngx_strncmp(ctx->algorithm, "RS", 2) != 0
            && ngx_strncmp(ctx->algorithm, "PS", 2) != 0)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: RSA key incompatible with algorithm: %s",
                           ctx->algorithm);
            return NGX_OK; /* Continue to next key */
        }
    } else if (key_kty == NGX_OIDC_JWK_EC) {
        if (ngx_strncmp(ctx->algorithm, "ES", 2) != 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: EC key incompatible with algorithm: %s",
                           ctx->algorithm);
            return NGX_OK; /* Continue to next key */
        }
    } else if (key_kty == NGX_OIDC_JWK_OKP) {
        if (ngx_strcmp(ctx->algorithm, "EdDSA") != 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: OKP key incompatible with algorithm: %s",
                           ctx->algorithm);
            return NGX_OK; /* Continue to next key */
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: Trying key: kty=%d, alg=%V, kid=%V", key_kty,
                   key_alg ? key_alg : empty_str(),
                   key_kid ? key_kid : empty_str());

    /* Verify signature with this key */
    if (key_pkey == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Key has NULL EVP_PKEY");
        return NGX_OK; /* Continue to next key */
    }

    /* RSA signature verification */
    if (key_kty == NGX_OIDC_JWK_RSA) {
        const EVP_MD *md = NULL;

        /* Get hash algorithm from JWT algorithm name */
        md = (const EVP_MD *) ngx_oidc_hash_get_md(ctx->algorithm);
        if (!md) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Unsupported digest algorithm: %s",
                          ctx->algorithm);
            goto cleanup;
        }

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to create EVP_MD_CTX");
            goto cleanup;
        }

        int verify_init_result = EVP_DigestVerifyInit(mdctx, &pkey_ctx,
                                                      md, NULL, key_pkey);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwt: EVP_DigestVerifyInit returned %d",
                       verify_init_result);

        if (verify_init_result != 1) {
            unsigned long ssl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: EVP_DigestVerifyInit failed: %s",
                          err_buf);
            goto cleanup;
        }

        /* Handle PSS padding if needed */
        if (ngx_strncmp(ctx->algorithm, "PS", 2) == 0) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING)
                != 1)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_jwt: Failed to set RSA PSS padding");
                goto cleanup;
            }
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_AUTO)
                != 1)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_jwt: Failed to set RSA PSS saltlen");
                goto cleanup;
            }
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwt: Calling EVP_DigestVerify "
                       "(sig_len=%uz, msg_len=%uz, alg=%s)",
                       ctx->signature_decoded->len, ctx->header_payload.len,
                       ctx->algorithm);

        int verify_result = EVP_DigestVerify(
            mdctx, ctx->signature_decoded->data,
            ctx->signature_decoded->len,
            (unsigned char *) ctx->header_payload.buf,
            ctx->header_payload.len);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwt: EVP_DigestVerify returned %d",
                       verify_result);

        if (verify_result == 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: RSA signature verification succeeded");
            ctx->result = NGX_OK;
            result = NGX_DONE; /* Found valid signature, stop */
            goto cleanup;
        } else {
            unsigned long ssl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: EVP_DigestVerify failed: %s", err_buf);
            goto cleanup;
        }
    } else if (key_kty == NGX_OIDC_JWK_EC) {
        /* ECDSA signature verification */
        const EVP_MD *md = NULL;

        /* Get hash algorithm from JWT algorithm name */
        md = (const EVP_MD *) ngx_oidc_hash_get_md(ctx->algorithm);
        if (!md) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Unsupported ECDSA algorithm: %s",
                          ctx->algorithm);
            goto cleanup;
        }

        int key_bits = EVP_PKEY_bits(key_pkey);
        if (key_bits <= 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Invalid key size from EVP_PKEY_bits: %d",
                          key_bits);
            goto cleanup;
        }
        int coord_size = (key_bits + 7) / 8;

        if (ctx->signature_decoded->len != (size_t) (coord_size * 2)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Invalid ECDSA signature length: "
                          "expected %d, got %uz",
                          coord_size * 2, ctx->signature_decoded->len);
            goto cleanup;
        }

        /* JWT signature is R||S format, convert to DER */
        unsigned char *r_bytes = ctx->signature_decoded->data;
        unsigned char *s_bytes = ctx->signature_decoded->data + coord_size;

        bn_r = BN_bin2bn(r_bytes, coord_size, NULL);
        if (!bn_r) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to create BIGNUM for r");
            goto cleanup;
        }

        bn_s = BN_bin2bn(s_bytes, coord_size, NULL);
        if (!bn_s) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to create BIGNUM for s");
            goto cleanup;
        }

        ec_sig = ECDSA_SIG_new();
        if (!ec_sig) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to create ECDSA_SIG");
            goto cleanup;
        }

        /* ECDSA_SIG_set0 takes ownership of bn_r and bn_s */
        if (!ECDSA_SIG_set0(ec_sig, bn_r, bn_s)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to set ECDSA_SIG parameters");
            goto cleanup;
        }
        /* After successful ECDSA_SIG_set0, bn_r and bn_s are owned by ec_sig */
        bn_r = NULL;
        bn_s = NULL;

        int der_len = i2d_ECDSA_SIG(ec_sig, &der_sig);
        if (der_len <= 0 || !der_sig) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to convert ECDSA_SIG to DER");
            goto cleanup;
        }

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to create EVP_MD_CTX for ECDSA");
            goto cleanup;
        }

        if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, key_pkey) != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: EVP_DigestVerifyInit failed for ECDSA");
            goto cleanup;
        }

        int verify_result = EVP_DigestVerify(
            mdctx, der_sig, der_len,
            (unsigned char *) ctx->header_payload.buf,
            ctx->header_payload.len);

        if (verify_result == 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: ECDSA signature verification succeeded");
            ctx->result = NGX_OK;
            result = NGX_DONE; /* Found valid signature, stop */
            goto cleanup;
        } else {
            unsigned long ssl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: ECDSA signature verification failed: %s",
                          err_buf);
            goto cleanup;
        }
    } else if (key_kty == NGX_OIDC_JWK_OKP) {
        /* EdDSA signature verification */
        int key_id = EVP_PKEY_id(key_pkey);
        if (key_id != EVP_PKEY_ED25519 && key_id != EVP_PKEY_ED448) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Unsupported OKP key type: %d", key_id);
            goto cleanup;
        }

        mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: Failed to create EVP_MD_CTX for EdDSA");
            goto cleanup;
        }

        /* EdDSA uses NULL as the digest */
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, key_pkey) != 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: EVP_DigestVerifyInit failed for EdDSA");
            goto cleanup;
        }

        int verify_result = EVP_DigestVerify(
            mdctx, ctx->signature_decoded->data,
            ctx->signature_decoded->len,
            (unsigned char *) ctx->header_payload.buf,
            ctx->header_payload.len);

        if (verify_result == 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwt: EdDSA signature verification succeeded");
            ctx->result = NGX_OK;
            result = NGX_DONE; /* Found valid signature, stop */
            goto cleanup;
        } else {
            unsigned long ssl_err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwt: EdDSA signature verification failed: %s",
                          err_buf);
            goto cleanup;
        }
    }

cleanup:
    /* Clean up OpenSSL resources */
    /* Note: pkey_ctx is owned by mdctx and will be freed */
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    if (der_sig) {
        OPENSSL_free(der_sig);
    }
    if (ec_sig) {
        ECDSA_SIG_free(ec_sig);
    }
    /* bn_r and bn_s are freed only if ECDSA_SIG_set0 failed */
    if (bn_r) {
        BN_free(bn_r);
    }
    if (bn_s) {
        BN_free(bn_s);
    }

    return result; /* Continue to next key or stop if signature verified */
}

/**
 * Verify JWT signature using pre-parsed EVP_PKEY from JWKS cache
 *
 * Parses the JWT header to extract algorithm and key ID,
 * then iterates JWKS keys to find a matching key for verification.
 *
 * @param[in] r     HTTP request context
 * @param[in] token JWT string (header.payload.signature)
 * @param[in] jwks  JWKS cache node with pre-parsed EVP_PKEY objects
 * @param[in] pool  Memory pool for temporary allocations
 *
 * @return NGX_OK if signature is valid, NGX_ERROR on failure
 */
static ngx_int_t
jwt_verify_signature(ngx_http_request_t *r, ngx_str_t *token,
    const ngx_oidc_jwks_cache_node_t *jwks, ngx_pool_t *pool)
{
    u_char *dot1, *dot2, *header_payload_end;
    ngx_str_t header_b64, signature_b64;
    ngx_str_t header_decoded, signature_decoded;
    ngx_oidc_json_t *header_json = NULL;
    ngx_oidc_json_t *alg_value = NULL, *kid_value = NULL;
    const char *algorithm = NULL, *kid_str = NULL;
    u_char *header_payload_buf = NULL;
    size_t header_payload_len;
    jwt_signature_verify_ctx_t verify_ctx;
    ngx_int_t rc;
    ngx_uint_t key_count;

    key_count = ngx_oidc_jwks_get_key_count(jwks);

    if (!token || !jwks || token->len == 0 || key_count == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Invalid arguments for signature verification");
        return NGX_ERROR;
    }

    /* Parse JWT structure: header.payload.signature */
    dot1 = ngx_strlchr(token->data, token->data + token->len, '.');
    if (!dot1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Invalid JWT format (missing first dot)");
        return NGX_ERROR;
    }

    dot2 = ngx_strlchr(dot1 + 1, token->data + token->len, '.');
    if (!dot2) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Invalid JWT format (missing second dot)");
        return NGX_ERROR;
    }

    /* Extract header and signature */
    header_b64.data = token->data;
    header_b64.len = dot1 - token->data;

    signature_b64.data = dot2 + 1;
    signature_b64.len = token->data + token->len - (dot2 + 1);

    /* Decode header */
    header_decoded.len = ngx_base64_decoded_length(header_b64.len);
    header_decoded.data = ngx_pnalloc(pool, header_decoded.len + 1);
    if (header_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to allocate memory for header");
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&header_decoded, &header_b64) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to decode JWT header");
        return NGX_ERROR;
    }

    /* Parse header JSON */
    header_decoded.data[header_decoded.len] = '\0';
    ngx_str_t header_json_str = { header_decoded.len, header_decoded.data };
    header_json = ngx_oidc_json_parse(&header_json_str, pool);
    if (!header_json) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to parse JWT header JSON");
        return NGX_ERROR;
    }

    /* Get algorithm */
    alg_value = ngx_oidc_json_object_get(header_json, "alg");
    if (!ngx_oidc_json_is_string(alg_value)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Missing or invalid 'alg' in JWT header");
        ngx_oidc_json_free(header_json);
        return NGX_ERROR;
    }

    algorithm = ngx_oidc_json_string(alg_value);
    if (!algorithm) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to get algorithm from JWT header");
        ngx_oidc_json_free(header_json);
        return NGX_ERROR;
    }

    /* Validate algorithm against whitelist */
    if (ngx_oidc_jwt_validate_algorithm(r, algorithm) != NGX_OK) {
        ngx_oidc_json_free(header_json);
        return NGX_ERROR;
    }

    /* Get kid (optional) */
    kid_value = ngx_oidc_json_object_get(header_json, "kid");
    if (ngx_oidc_json_is_string(kid_value)) {
        kid_str = ngx_oidc_json_string(kid_value);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: JWT header: alg=%s, kid=%s", algorithm,
                   kid_str ? kid_str : "(none)");

    /* Calculate header.payload length */
    header_payload_end = dot2;
    header_payload_len = header_payload_end - token->data;

    /* Allocate buffer from pool instead of stack */
    header_payload_buf = ngx_pnalloc(pool, header_payload_len + 1);
    if (header_payload_buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to allocate memory for header.payload "
                      "(%uz bytes)", header_payload_len);
        ngx_oidc_json_free(header_json);
        return NGX_ERROR;
    }

    ngx_memcpy(header_payload_buf, token->data, header_payload_len);
    header_payload_buf[header_payload_len] = '\0';

    /* Decode signature */
    signature_decoded.len = ngx_base64_decoded_length(signature_b64.len);
    signature_decoded.data = ngx_pnalloc(pool, signature_decoded.len);
    if (signature_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to allocate memory for signature");
        ngx_oidc_json_free(header_json);
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&signature_decoded, &signature_b64) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to decode JWT signature");
        ngx_oidc_json_free(header_json);
        return NGX_ERROR;
    }

    /* Try each key from the JWKS cache */
    /* Setup verification context */
    verify_ctx.r = r;
    verify_ctx.algorithm = algorithm;
    verify_ctx.kid_str = kid_str;
    verify_ctx.header_payload.buf = header_payload_buf;
    verify_ctx.header_payload.len = header_payload_len;
    verify_ctx.signature_decoded = &signature_decoded;
    verify_ctx.result = NGX_ERROR;
    verify_ctx.key_count = key_count;

    /* Iterate through keys and try verification */
    rc = ngx_oidc_jwks_iterate_keys(r, jwks, jwt_verify_key_callback,
                                    &verify_ctx);

    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwt: key iteration returned %d", rc);
    }
    ngx_oidc_json_free(header_json);

    if (verify_ctx.result != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWT signature verification failed "
                      "(tried %ui keys)",
                      key_count);
    }

    return verify_ctx.result;
}

ngx_int_t
ngx_oidc_jwt_decode_payload(ngx_str_t *token, ngx_str_t *payload,
    ngx_pool_t *pool)
{
    u_char *start, *end, *decoded;
    ngx_str_t base64_payload;
    size_t decoded_len;

    /* Validate input parameters */
    if (token == NULL || payload == NULL || pool == NULL) {
        if (pool != NULL && pool->log != NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_jwt_decode_payload: NULL parameter");
        }
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_jwt: decoding payload, token_len=%uz", token->len);

    /* JWT format: header.payload.signature */
    /* Find the first dot */
    start = ngx_strlchr(token->data, token->data + token->len, '.');
    if (start == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: invalid JWT format, first dot not found");
        return NGX_ERROR;
    }
    start++; /* Skip the dot */

    /* Find the second dot */
    end = ngx_strlchr(start, token->data + token->len, '.');
    if (end == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: invalid JWT format, second dot not found");
        return NGX_ERROR;
    }

    /* Extract payload part */
    base64_payload.data = start;
    base64_payload.len = end - start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_jwt: payload base64_len=%uz", base64_payload.len);

    /* Calculate decoded length for base64url */
    decoded_len = ngx_base64_decoded_length(base64_payload.len);
    decoded = ngx_pnalloc(pool, decoded_len + 1);
    if (decoded == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: failed to allocate memory for payload");
        return NGX_ERROR;
    }

    /* Decode base64url directly */
    payload->data = decoded;
    if (ngx_decode_base64url(payload, &base64_payload) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_jwt: base64url decode failed for payload");
        return NGX_ERROR;
    }

    payload->data[payload->len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_jwt: payload decoded, len=%uz", payload->len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_jwt_decode_header(ngx_str_t *token, ngx_str_t *header,
    ngx_pool_t *pool)
{
    u_char *end, *decoded;
    ngx_str_t base64_header;
    size_t decoded_len;

    /* Find first dot in JWT */
    end = ngx_strlchr(token->data, token->data + token->len, '.');
    if (end == NULL) {
        return NGX_ERROR;
    }

    /* Extract header part */
    base64_header.data = token->data;
    base64_header.len = end - token->data;

    /* Decode base64url */
    decoded_len = ngx_base64_decoded_length(base64_header.len);
    decoded = ngx_pnalloc(pool, decoded_len + 1);
    if (decoded == NULL) {
        return NGX_ERROR;
    }

    header->data = decoded;
    if (ngx_decode_base64url(header, &base64_header) != NGX_OK) {
        return NGX_ERROR;
    }

    header->data[header->len] = '\0';

    return NGX_OK;
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
 * Uses pre-parsed EVP_PKEY from JWKS cache:
 * - Uses JWKS cache node with pre-parsed EVP_PKEY objects
 * - Performs signature verification and claims validation
 * - Fast path: no JSON parsing required per request
 */
ngx_int_t
ngx_oidc_jwt_verify(ngx_http_request_t *r, ngx_str_t *token,
    ngx_oidc_jwks_cache_node_t *jwks_cache,
    const ngx_oidc_jwt_validation_params_t *params)
{
    ngx_str_t payload;
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: Using JWKS cache with %ui keys",
                   ngx_oidc_jwks_get_key_count(jwks_cache));

    /* Verify signature using pre-parsed EVP_PKEY */
    if (jwt_verify_signature(r, token, jwks_cache, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: JWT signature verification failed");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwt: JWT signature verified successfully with cache");

    /* Parse JWT payload */
    if (ngx_oidc_jwt_decode_payload(token, &payload, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to decode JWT payload");
        return NGX_ERROR;
    }

    /* Parse claims from payload */
    if (jwt_parse_claims((char *) payload.data, &claims, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwt: Failed to parse JWT claims");
        return NGX_ERROR;
    }

    /* Validate claims */
    result = jwt_validate_claims(r, &claims, params);
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
