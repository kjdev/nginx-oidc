/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_http.h"
#include "ngx_oidc_json.h"

/** JWKS shared memory node (stores JSON strings only) */
typedef struct {
    /** rbtree node (must be first) */
    ngx_rbtree_node_t  node;
    /** CRC32 hash of jwks_uri */
    ngx_uint_t         key_hash;
    ngx_str_t          jwks_uri;
    ngx_str_t          jwks_json;
    time_t             fetched_at;
    time_t             expires_at;
    /** generation counter for cache invalidation */
    ngx_uint_t         generation;
    /** 1 if fetch ongoing, 0 otherwise */
    ngx_uint_t         fetching;
} jwks_shm_node_t;

/** JWKS cache node structure (encapsulated) */
struct ngx_oidc_jwks_cache_node_s {
    ngx_str_t    jwks_uri;
    /** array of ngx_oidc_jwks_key_t */
    ngx_array_t *keys;
    time_t       fetched_at;
    time_t       expires_at;
};

/** JWKS key structure (opaque type) */
struct ngx_oidc_jwks_key_s {
    ngx_str_t            kid;
    ngx_str_t            alg;
    ngx_oidc_jwk_type_t  kty;
    /** OpenSSL public key */
    EVP_PKEY            *pkey;
    time_t               fetched_at;
    time_t               expires_at;
};

/** JWKS shared memory zone structure */
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_slab_pool_t   *shpool;
} jwks_shm_t;

/** Context for JWKS fetch subrequest */
typedef struct {
    ngx_http_request_t    *main_request;
    ngx_str_t              jwks_uri;
    ngx_oidc_jwks_done_pt  callback;
    void                  *data;
} jwks_fetch_ctx_t;

/* Module-level shared memory zone pointer */
static jwks_shm_t *jwks_shm = NULL;

/**
 * Get OpenSSL error message
 *
 * Helper function to retrieve and format OpenSSL error messages.
 * Uses ERR_get_error() to get the error code and ERR_error_string_n()
 * to format it into a human-readable string.
 *
 * @param[in] buf     Buffer to store error message
 * @param[in] buf_len Buffer length
 */
static void
jwks_get_openssl_error(char *buf, size_t buf_len)
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
 * Cleanup handler for JWKS cache node
 * Called when request pool is destroyed, frees all EVP_PKEY resources
 */
static void
jwks_cache_node_cleanup(void *data)
{
    ngx_oidc_jwks_cache_node_t *node;
    ngx_oidc_jwks_key_t *keys;
    ngx_uint_t i;

    node = data;
    if (node == NULL || node->keys == NULL) {
        return;
    }

    keys = node->keys->elts;
    for (i = 0; i < node->keys->nelts; i++) {
        if (keys[i].pkey != NULL) {
            EVP_PKEY_free(keys[i].pkey);
            keys[i].pkey = NULL;
        }
    }
}

/**
 * Create RSA EVP_PKEY from JWK JSON object
 *
 * Extracts RSA modulus (n) and exponent (e) from JWK,
 * base64url-decodes them, and constructs an EVP_PKEY
 * using OpenSSL 3.0 EVP_PKEY_fromdata API.
 *
 * @param[in] r    HTTP request context for logging
 * @param[in] jwk  JWK JSON object containing "n" and "e" fields
 *
 * @return EVP_PKEY on success, NULL on failure
 */
static EVP_PKEY *
jwks_create_rsa_key(ngx_http_request_t *r, ngx_oidc_json_t *jwk)
{
    ngx_oidc_json_t *n_value, *e_value;
    ngx_str_t n_str, e_str, n_decoded, e_decoded;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n_bn = NULL, *e_bn = NULL;
    char err_buf[256];

    /* Clear OpenSSL error stack to avoid stale errors */
    ERR_clear_error();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: creating RSA public key from JWK");

    /* Extract 'n' (modulus) from JWK */
    n_value = ngx_oidc_json_object_get(jwk, "n");
    if (n_value == NULL
        || ngx_oidc_json_type(n_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'n' parameter in JWK");
        return NULL;
    }

    /* Extract 'e' (public exponent) from JWK */
    e_value = ngx_oidc_json_object_get(jwk, "e");
    if (e_value == NULL
        || ngx_oidc_json_type(e_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'e' parameter in JWK");
        return NULL;
    }

    /* Get Base64url-encoded strings */
    if (ngx_oidc_json_object_get_string(jwk, "n", &n_str, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'n' string value");
        return NULL;
    }

    if (ngx_oidc_json_object_get_string(jwk, "e", &e_str, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'e' string value");
        return NULL;
    }

    /* Decode Base64url-encoded parameters using nginx built-in function */
    n_decoded.len = ngx_base64_decoded_length(n_str.len);
    n_decoded.data = ngx_pnalloc(r->pool, n_decoded.len);
    if (n_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate buffer for 'n' decoding");
        return NULL;
    }
    if (ngx_decode_base64url(&n_decoded, &n_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to decode 'n' parameter");
        return NULL;
    }

    e_decoded.len = ngx_base64_decoded_length(e_str.len);
    e_decoded.data = ngx_pnalloc(r->pool, e_decoded.len);
    if (e_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate buffer for 'e' decoding");
        return NULL;
    }
    if (ngx_decode_base64url(&e_decoded, &e_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to decode 'e' parameter");
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: decoded n_len=%uz, e_len=%uz",
                   n_decoded.len, e_decoded.len);

    /* Convert binary data to BIGNUM */
    n_bn = BN_bin2bn(n_decoded.data, n_decoded.len, NULL);
    if (n_bn == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: BN_bin2bn failed for 'n': %s", err_buf);
        goto cleanup;
    }

    e_bn = BN_bin2bn(e_decoded.data, e_decoded.len, NULL);
    if (e_bn == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: BN_bin2bn failed for 'e': %s", err_buf);
        goto cleanup;
    }

    /* Create OSSL_PARAM_BLD for OpenSSL 3.0 */
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_new failed: %s", err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n_bn)) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_push_BN failed for 'n': %s",
                      err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e_bn)) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_push_BN failed for 'e': %s",
                      err_buf);
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_to_param failed: %s", err_buf);
        goto cleanup;
    }

    /* Create EVP_PKEY_CTX for RSA */
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pctx == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_CTX_new_from_name failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_fromdata_init failed: %s", err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_fromdata failed: %s", err_buf);
        goto cleanup;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: RSA public key created successfully");

cleanup:
    if (n_bn != NULL) {
        BN_free(n_bn);
    }
    if (e_bn != NULL) {
        BN_free(e_bn);
    }
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return pkey;
}

/*
 * Create ECDSA public key from JWK
 * Supports P-256, P-384, P-521 curves
 */
static EVP_PKEY *
jwks_create_ec_key(ngx_http_request_t *r, ngx_oidc_json_t *jwk)
{
    ngx_oidc_json_t *crv_value, *x_value, *y_value;
    ngx_str_t crv_str, x_str, y_str, x_decoded, y_decoded;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    const char *group_name = NULL;
    u_char *pub_key = NULL;
    size_t pub_key_len;
    char err_buf[256];

    /* Clear OpenSSL error stack to avoid stale errors */
    ERR_clear_error();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: creating EC public key from JWK");

    /* Extract 'crv' (curve) from JWK */
    crv_value = ngx_oidc_json_object_get(jwk, "crv");
    if (crv_value == NULL
        || ngx_oidc_json_type(crv_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'crv' parameter in JWK");
        return NULL;
    }

    /* Extract 'x' coordinate from JWK */
    x_value = ngx_oidc_json_object_get(jwk, "x");
    if (x_value == NULL
        || ngx_oidc_json_type(x_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'x' parameter in JWK");
        return NULL;
    }

    /* Extract 'y' coordinate from JWK */
    y_value = ngx_oidc_json_object_get(jwk, "y");
    if (y_value == NULL
        || ngx_oidc_json_type(y_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'y' parameter in JWK");
        return NULL;
    }

    /* Get curve name */
    if (ngx_oidc_json_object_get_string(jwk, "crv", &crv_str, r->pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'crv' string value");
        return NULL;
    }

    /* Map JWK curve name to OpenSSL group name */
    if (crv_str.len == 5
        && ngx_strncmp(crv_str.data, "P-256", 5) == 0)
    {
        group_name = "prime256v1";
    } else if (crv_str.len == 5
               && ngx_strncmp(crv_str.data, "P-384", 5) == 0)
    {
        group_name = "secp384r1";
    } else if (crv_str.len == 5
               && ngx_strncmp(crv_str.data, "P-521", 5) == 0)
    {
        group_name = "secp521r1";
    } else if (crv_str.len == 9
               && ngx_strncmp(crv_str.data, "secp256k1", 9) == 0)
    {
        group_name = "secp256k1";
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: unsupported curve: %V", &crv_str);
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: EC curve: %s", group_name);

    /* Get x and y coordinates */
    if (ngx_oidc_json_object_get_string(jwk, "x", &x_str, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'x' string value");
        return NULL;
    }

    if (ngx_oidc_json_object_get_string(jwk, "y", &y_str, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'y' string value");
        return NULL;
    }

    /* Decode Base64url-encoded coordinates */
    x_decoded.len = ngx_base64_decoded_length(x_str.len);
    x_decoded.data = ngx_pnalloc(r->pool, x_decoded.len);
    if (x_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate memory for 'x' decode");
        return NULL;
    }

    if (ngx_decode_base64url(&x_decoded, &x_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to decode 'x' coordinate");
        return NULL;
    }

    y_decoded.len = ngx_base64_decoded_length(y_str.len);
    y_decoded.data = ngx_pnalloc(r->pool, y_decoded.len);
    if (y_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate memory for 'y' decode");
        return NULL;
    }

    if (ngx_decode_base64url(&y_decoded, &y_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to decode 'y' coordinate");
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: decoded x_len=%uz, y_len=%uz", x_decoded.len,
                   y_decoded.len);

    /*
     * Create uncompressed EC point format (0x04 || X || Y)
     * This is required for OpenSSL 3.0 OSSL_PKEY_PARAM_PUB_KEY
     */
    pub_key_len = 1 + x_decoded.len + y_decoded.len;
    pub_key = ngx_pnalloc(r->pool, pub_key_len);
    if (pub_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate memory for public key");
        return NULL;
    }

    pub_key[0] = 0x04; /* Uncompressed point indicator */
    ngx_memcpy(pub_key + 1, x_decoded.data, x_decoded.len);
    ngx_memcpy(pub_key + 1 + x_decoded.len, y_decoded.data, y_decoded.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: public key length=%uz", pub_key_len);

    /* Create OSSL_PARAM_BLD for OpenSSL 3.0 */
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_new failed: %s", err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         group_name, 0))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_push_utf8_string failed "
                      "for group: %s",
                      err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub_key, pub_key_len))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_push_octet_string failed "
                      "for public key: %s", err_buf);
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_to_param failed: %s", err_buf);
        goto cleanup;
    }

    /* Create EVP_PKEY_CTX for EC */
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (pctx == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_CTX_new_from_name failed: %s",
                      err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_fromdata_init failed: %s", err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_fromdata failed: %s", err_buf);
        goto cleanup;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: EC public key created successfully");

cleanup:
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return pkey;
}

/*
 * Create EdDSA (Ed25519) public key from JWK
 */
static EVP_PKEY *
jwks_create_okp_key(ngx_http_request_t *r, ngx_oidc_json_t *jwk)
{
    ngx_oidc_json_t *crv_value, *x_value;
    ngx_str_t crv_str, x_str, x_decoded;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    char err_buf[256];

    /* Clear OpenSSL error stack to avoid stale errors */
    ERR_clear_error();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: creating EdDSA public key from JWK");

    /* Extract 'crv' (curve) from JWK */
    crv_value = ngx_oidc_json_object_get(jwk, "crv");
    if (crv_value == NULL
        || ngx_oidc_json_type(crv_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'crv' parameter in JWK");
        return NULL;
    }

    /* Extract 'x' (public key) from JWK */
    x_value = ngx_oidc_json_object_get(jwk, "x");
    if (x_value == NULL
        || ngx_oidc_json_type(x_value) != NGX_OIDC_JSON_STRING)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'x' parameter in JWK");
        return NULL;
    }

    /* Get curve name */
    if (ngx_oidc_json_object_get_string(jwk, "crv", &crv_str, r->pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'crv' string value");
        return NULL;
    }

    /* Check if curve is Ed25519 or Ed448 */
    if (!((crv_str.len == 7 && ngx_strncmp(crv_str.data, "Ed25519", 7) == 0)
          || (crv_str.len == 5
              && ngx_strncmp(crv_str.data, "Ed448", 5) == 0)))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: unsupported OKP curve: %V "
                      "(only Ed25519 and Ed448 supported)",
                      &crv_str);
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: using %V curve", &crv_str);

    /* Get public key data */
    if (ngx_oidc_json_object_get_string(jwk, "x", &x_str, r->pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to get 'x' string value");
        return NULL;
    }

    /* Decode Base64url-encoded public key */
    x_decoded.len = ngx_base64_decoded_length(x_str.len);
    x_decoded.data = ngx_pnalloc(r->pool, x_decoded.len);
    if (x_decoded.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate memory "
                      "for public key decode");
        return NULL;
    }

    if (ngx_decode_base64url(&x_decoded, &x_str) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to decode 'x' public key");
        return NULL;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: decoded public key length=%uz", x_decoded.len);

    /* Validate public key length based on curve */
    size_t expected_len;
    if (crv_str.len == 7) { /* Ed25519 */
        expected_len = 32;
    } else { /* Ed448 */
        expected_len = 57;
    }

    if (x_decoded.len != expected_len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: invalid %V public key length: %uz "
                      "(expected %uz)",
                      &crv_str, x_decoded.len, expected_len);
        return NULL;
    }

    /* Create OSSL_PARAM_BLD for OpenSSL 3.0 */
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_new failed: %s", err_buf);
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                          x_decoded.data, x_decoded.len))
    {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_push_octet_string failed: %s",
                      err_buf);
        goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: OSSL_PARAM_BLD_to_param failed: %s", err_buf);
        goto cleanup;
    }

    /* Create EVP_PKEY_CTX for Ed25519 or Ed448 */
    const char *algorithm = (crv_str.len == 7) ? "ED25519" : "ED448";
    pctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    if (pctx == NULL) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_CTX_new_from_name failed for %s: %s",
                      algorithm, err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_fromdata_init failed: %s", err_buf);
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        jwks_get_openssl_error(err_buf, sizeof(err_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: EVP_PKEY_fromdata failed: %s", err_buf);
        goto cleanup;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: %V public key created successfully", &crv_str);

cleanup:
    if (param_bld != NULL) {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return pkey;
}

/*
 * Parse JWKS JSON and build cache node (allocated in request pool)
 */
static ngx_int_t
jwks_parse_json_to_cache(ngx_http_request_t *r, ngx_str_t *jwks_json,
    ngx_oidc_jwks_cache_node_t **cache_node)
{
    ngx_oidc_json_t *root, *keys_array, *jwk;
    ngx_oidc_jwks_key_t *key;
    ngx_oidc_jwks_cache_node_t *node;
    ngx_str_t kty_str, kid_str, alg_str;
    EVP_PKEY *pkey;
    size_t i, array_size;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: parsing JWKS JSON, length=%uz", jwks_json->len);

    /* Allocate cache node in request pool */
    node = ngx_pcalloc(r->pool, sizeof(ngx_oidc_jwks_cache_node_t));
    if (node == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate cache node");
        return NGX_ERROR;
    }

    /* Parse JSON from external JWKS endpoint (untrusted source) */
    root = ngx_oidc_json_parse_untrusted(jwks_json, r->pool);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to parse JWKS JSON");
        return NGX_ERROR;
    }

    /* Get "keys" array */
    keys_array = ngx_oidc_json_object_get(root, "keys");
    if (keys_array == NULL
        || ngx_oidc_json_type(keys_array) != NGX_OIDC_JSON_ARRAY)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: missing or invalid 'keys' array in JWKS");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    array_size = ngx_oidc_json_array_size(keys_array);
    if (array_size == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_jwks: JWKS contains no keys");

        node->keys =
            ngx_array_create(r->pool, 1, sizeof(ngx_oidc_jwks_key_t));
        if (node->keys == NULL) {
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }

        ngx_oidc_json_free(root);
        *cache_node = node;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: found %uz keys in JWKS", array_size);

    /* Create keys array */
    node->keys = ngx_array_create(r->pool, array_size,
                                  sizeof(ngx_oidc_jwks_key_t));
    if (node->keys == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to create keys array");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Register cleanup handler early to handle errors during key parsing */
    ngx_pool_cleanup_t *cln;
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to register cleanup handler");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    cln->handler = jwks_cache_node_cleanup;
    cln->data = node;

    /* Now safe to add keys - cleanup handler will free them on error */

    /* Iterate over keys */
    for (i = 0; i < array_size; i++) {
        jwk = ngx_oidc_json_array_get(keys_array, i);
        if (jwk == NULL
            || ngx_oidc_json_type(jwk) != NGX_OIDC_JSON_OBJECT)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_jwks: invalid JWK at index %uz, skipping", i);
            continue;
        }

        /* Get kty (key type) */
        if (ngx_oidc_json_object_get_string(jwk, "kty", &kty_str, r->pool)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_jwks: missing 'kty' in JWK at index %uz, "
                          "skipping", i);
            continue;
        }

        /* Create EVP_PKEY based on key type */
        pkey = NULL;
        if (kty_str.len == 3
            && ngx_strncmp(kty_str.data, "RSA", 3) == 0)
        {
            pkey = jwks_create_rsa_key(r, jwk);
        } else if (kty_str.len == 2
                   && ngx_strncmp(kty_str.data, "EC", 2) == 0)
        {
            pkey = jwks_create_ec_key(r, jwk);
        } else if (kty_str.len == 3
                   && ngx_strncmp(kty_str.data, "OKP", 3) == 0)
        {
            pkey = jwks_create_okp_key(r, jwk);
        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_jwks: unsupported key type '%V' "
                          "at index %uz, skipping",
                          &kty_str, i);
            continue;
        }

        if (pkey == NULL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_jwks: failed to create key at index %uz, "
                          "skipping", i);
            continue;
        }

        /* Add key to array */
        key = ngx_array_push(node->keys);
        if (key == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwks: failed to push key to array");
            EVP_PKEY_free(pkey);
            ngx_oidc_json_free(root);
            return NGX_ERROR;
        }

        ngx_memzero(key, sizeof(ngx_oidc_jwks_key_t));

        /* Set key type */
        if (kty_str.len == 3
            && ngx_strncmp(kty_str.data, "RSA", 3) == 0)
        {
            key->kty = NGX_OIDC_JWK_RSA;
        } else if (kty_str.len == 2
                   && ngx_strncmp(kty_str.data, "EC", 2) == 0)
        {
            key->kty = NGX_OIDC_JWK_EC;
        } else if (kty_str.len == 3
                   && ngx_strncmp(kty_str.data, "OKP", 3) == 0)
        {
            key->kty = NGX_OIDC_JWK_OKP;
        }

        /* Get kid (key ID) - optional */
        if (ngx_oidc_json_object_get_string(jwk, "kid", &kid_str, r->pool)
            == NGX_OK)
        {
            key->kid = kid_str;
        } else {
            ngx_str_null(&key->kid);
        }

        /* Get alg (algorithm) - optional */
        if (ngx_oidc_json_object_get_string(jwk, "alg", &alg_str, r->pool)
            == NGX_OK)
        {
            key->alg = alg_str;
        } else {
            ngx_str_null(&key->alg);
        }

        key->pkey = pkey;
        key->fetched_at = ngx_time();
        key->expires_at = key->fetched_at + 3600; /* 1 hour TTL */

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwks: added key kid='%V', alg='%V'", &key->kid,
                       &key->alg);
    }

    /* Set JWKS timestamps */
    time_t now = ngx_time();
    ngx_oidc_jwks_cache_node_set_fetched_at(node, now);
    ngx_oidc_jwks_cache_node_set_expires_at(node, now + 3600); /* 1 hour TTL */

    ngx_oidc_json_free(root);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: successfully parsed %uz keys",
                   node->keys->nelts);

    cln->data = node;
    *cache_node = node;

    return NGX_OK;
}

static void
jwks_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    jwks_shm_node_t *cn, *cnt;
    ngx_int_t cmp;

    cn = (jwks_shm_node_t *) node;

    for (;;) {
        if (node->key < temp->key) {
            if (temp->left == sentinel) {
                temp->left = node;
                break;
            }
            temp = temp->left;
        } else if (node->key > temp->key) {
            if (temp->right == sentinel) {
                temp->right = node;
                break;
            }
            temp = temp->right;
        } else {
            /* Same CRC32 key, compare URI strings */
            cnt = (jwks_shm_node_t *) temp;
            cmp = ngx_memn2cmp(cn->jwks_uri.data, cnt->jwks_uri.data,
                               cn->jwks_uri.len, cnt->jwks_uri.len);
            if (cmp < 0) {
                if (temp->left == sentinel) {
                    temp->left = node;
                    break;
                }
                temp = temp->left;
            } else if (cmp > 0) {
                if (temp->right == sentinel) {
                    temp->right = node;
                    break;
                }
                temp = temp->right;
            } else {
                /* Duplicate URI - keep existing entry */
                break;
            }
        }
    }

    ngx_rbt_red(node);
}

static jwks_shm_node_t *
jwks_shm_lookup(ngx_str_t *jwks_uri)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    jwks_shm_node_t *shm_node;
    jwks_shm_t *shm;
    ngx_int_t cmp;

    shm = jwks_shm;
    if (shm == NULL) {
        return NULL;
    }

    /* Calculate CRC32 hash */
    hash = ngx_crc32_short(jwks_uri->data, jwks_uri->len);

    /* Lock shared memory */
    ngx_shmtx_lock(&shm->shpool->mutex);

    /* Search in Rbtree */
    node = shm->rbtree.root;
    sentinel = shm->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* Key matches, check hash and jwks_uri */
        shm_node = (jwks_shm_node_t *) node;
        if (shm_node->key_hash == hash
            && shm_node->jwks_uri.len == jwks_uri->len
            && ngx_strncmp(shm_node->jwks_uri.data, jwks_uri->data,
                           jwks_uri->len) == 0)
        {
            /* Found - return with lock held */
            return shm_node;
        }

        /* Continue search based on key comparison */
        cmp = ngx_memn2cmp(jwks_uri->data, shm_node->jwks_uri.data,
                           jwks_uri->len, shm_node->jwks_uri.len);
        node = (cmp < 0) ? node->left : node->right;
    }

    /* Not found */
    ngx_shmtx_unlock(&shm->shpool->mutex);
    return NULL;
}

static ngx_int_t
jwks_shm_save(ngx_http_request_t *r, ngx_str_t *jwks_uri, ngx_str_t *jwks_json,
    time_t expires_at)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    jwks_shm_node_t *shm_node;
    jwks_shm_t *shm;
    u_char *p;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: saving JWKS JSON for uri: %V", jwks_uri);

    shm = jwks_shm;
    if (shm == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: shared memory zone not initialized");
        return NGX_ERROR;
    }

    /* Calculate CRC32 hash */
    hash = ngx_crc32_short(jwks_uri->data, jwks_uri->len);

    /* Lock shared memory */
    ngx_shmtx_lock(&shm->shpool->mutex);

    /* Check if entry exists */
    node = shm->rbtree.root;
    sentinel = shm->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* Key matches, check hash and jwks_uri */
        shm_node = (jwks_shm_node_t *) node;
        if (shm_node->key_hash == hash
            && shm_node->jwks_uri.len == jwks_uri->len
            && ngx_strncmp(shm_node->jwks_uri.data, jwks_uri->data,
                           jwks_uri->len) == 0)
        {
            /* Found, update existing entry */

            /* Only update JSON if not empty (skip for placeholder) */
            if (jwks_json->len > 0) {
                /* Free old JSON if different size */
                if (shm_node->jwks_json.len != jwks_json->len) {
                    if (shm_node->jwks_json.data != NULL) {
                        ngx_slab_free_locked(shm->shpool,
                                             shm_node->jwks_json.data);
                    }
                    p = ngx_slab_alloc_locked(shm->shpool, jwks_json->len);
                    if (p == NULL) {
                        ngx_shmtx_unlock(&shm->shpool->mutex);
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "oidc_jwks: failed to allocate memory "
                                      "for JSON");
                        return NGX_ERROR;
                    }
                    shm_node->jwks_json.data = p;
                    shm_node->jwks_json.len = jwks_json->len;
                }

                /* Copy JSON */
                ngx_memcpy(shm_node->jwks_json.data, jwks_json->data,
                           jwks_json->len);
                shm_node->fetched_at = ngx_time();
                shm_node->expires_at = expires_at;
                shm_node->generation++; /* Increment generation for cache
                                         * invalidation */
            }

            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwks: updated cache for uri: %V", jwks_uri);
            return NGX_OK;
        }

        /* Continue search using URI comparison for hash collisions */
        {
            int cmp;
            cmp = ngx_memn2cmp(jwks_uri->data, shm_node->jwks_uri.data,
                               jwks_uri->len, shm_node->jwks_uri.len);
            node = (cmp < 0) ? node->left : node->right;
        }
    }

    /* Not found, allocate new cache node */
    shm_node = ngx_slab_alloc_locked(shm->shpool, sizeof(jwks_shm_node_t));
    if (shm_node == NULL) {
        ngx_shmtx_unlock(&shm->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate cache node "
                      "(out of memory)");
        return NGX_ERROR;
    }

    /* Allocate jwks_uri */
    p = ngx_slab_alloc_locked(shm->shpool, jwks_uri->len);
    if (p == NULL) {
        ngx_slab_free_locked(shm->shpool, shm_node);
        ngx_shmtx_unlock(&shm->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate memory for jwks_uri");
        return NGX_ERROR;
    }
    shm_node->jwks_uri.data = p;
    shm_node->jwks_uri.len = jwks_uri->len;
    ngx_memcpy(shm_node->jwks_uri.data, jwks_uri->data, jwks_uri->len);

    /* Allocate jwks_json only if not empty (placeholder support) */
    if (jwks_json->len > 0) {
        p = ngx_slab_alloc_locked(shm->shpool, jwks_json->len);
        if (p == NULL) {
            ngx_slab_free_locked(shm->shpool, shm_node->jwks_uri.data);
            ngx_slab_free_locked(shm->shpool, shm_node);
            ngx_shmtx_unlock(&shm->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_jwks: failed to allocate memory for JSON");
            return NGX_ERROR;
        }
        shm_node->jwks_json.data = p;
        shm_node->jwks_json.len = jwks_json->len;
        ngx_memcpy(shm_node->jwks_json.data, jwks_json->data, jwks_json->len);
    } else {
        /* Placeholder: no JSON data yet */
        shm_node->jwks_json.data = NULL;
        shm_node->jwks_json.len = 0;
    }

    /* Set metadata */
    shm_node->node.key = hash;
    shm_node->key_hash = hash;
    shm_node->fetched_at = ngx_time();
    shm_node->expires_at = expires_at;
    shm_node->generation = 0; /* Initialize generation counter */
    shm_node->fetching = 0; /* Clear flag after save */

    /* Insert into Rbtree */
    ngx_rbtree_insert(&shm->rbtree, &shm_node->node);

    ngx_shmtx_unlock(&shm->shpool->mutex);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: cached JWKS JSON for uri: %V", jwks_uri);

    return NGX_OK;
}

/** Context for rbtree traversal */
typedef struct {
    ngx_oidc_jwks_iterate_pt  callback;
    void                     *data;
    ngx_int_t                 result;
} jwks_traverse_ctx_t;

static void
jwks_rbtree_traverse(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    jwks_traverse_ctx_t *ctx)
{
    jwks_shm_node_t *shm_node;

    if (node == sentinel) {
        return;
    }

    /* Traverse left subtree */
    if (node->left != sentinel) {
        jwks_rbtree_traverse(node->left, sentinel, ctx);
    }

    /* Process current node */
    if (ctx->result == NGX_OK) {
        shm_node = (jwks_shm_node_t *) node;
        ctx->result = ctx->callback(&shm_node->jwks_uri, shm_node->fetched_at,
                                    shm_node->expires_at,
                                    &shm_node->jwks_json, ctx->data);
    }

    /* Traverse right subtree */
    if (node->right != sentinel && ctx->result == NGX_OK) {
        jwks_rbtree_traverse(node->right, sentinel, ctx);
    }
}

static ngx_int_t
jwks_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    jwks_fetch_ctx_t *ctx = data;
    ngx_str_t body;
    ngx_oidc_jwks_cache_node_t *cache_node;
    ngx_int_t status;
    time_t expires_at;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->main_request->connection->log, 0,
                   "oidc_jwks: subrequest completed");

    /* Always clear fetching flag on completion (success or failure) */
    ngx_oidc_jwks_clear_fetch_flag(ctx->main_request, &ctx->jwks_uri);

    /* Check subrequest completion status */
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_jwks: subrequest failed with rc=%i", rc);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Get response status using Week 2 HTTP module */
    status = ngx_oidc_http_response_status(r);
    if (status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_jwks: subrequest returned HTTP %i", status);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Get response body using Week 2 HTTP module */
    if (ngx_oidc_http_response_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_jwks: failed to get response body");
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->main_request->connection->log, 0,
                   "oidc_jwks: received response body, length=%uz", body.len);

    /* Calculate expiration time (1 hour TTL) */
    expires_at = ngx_time() + 3600;

    /* Save JSON to shared memory */
    /* Double-check: Another request might have already saved JWKS */
    ngx_oidc_jwks_cache_node_t *existing_jwks = NULL;
    rc = ngx_oidc_jwks_get(ctx->main_request, &ctx->jwks_uri, &existing_jwks);
    if (rc == NGX_OK && existing_jwks != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                       ctx->main_request->connection->log, 0,
                       "oidc_jwks: JWKS already saved by another request: %V",
                       &ctx->jwks_uri);
        /* Use existing JWKS instead of saving again */
        return ctx->callback(ctx->main_request, existing_jwks, ctx->data);
    }

    if (jwks_shm_save(ctx->main_request, &ctx->jwks_uri, &body, expires_at)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->main_request->connection->log, 0,
                      "oidc_jwks: failed to save JSON to shared memory, "
                      "continuing anyway");
    }

    /* Parse JSON to cache node (in request pool) */
    if (jwks_parse_json_to_cache(ctx->main_request, &body, &cache_node)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_jwks: failed to parse JWKS JSON");
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Set jwks_uri and timestamps */
    ngx_oidc_jwks_cache_node_set_jwks_uri(cache_node, &ctx->jwks_uri);
    ngx_oidc_jwks_cache_node_set_fetched_at(cache_node, ngx_time());
    ngx_oidc_jwks_cache_node_set_expires_at(cache_node, expires_at);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->main_request->connection->log, 0,
                   "oidc_jwks: JWKS fetch completed, keys=%uz",
                   cache_node->keys->nelts);

    /* Invoke callback with parsed JWKS */
    return ctx->callback(ctx->main_request, cache_node, ctx->data);
}

ngx_int_t
ngx_oidc_jwks_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    jwks_shm_t *shm;
    ngx_slab_pool_t *shpool;

    if (data) {
        /* Zone already initialized (worker process restart) */
        shm_zone->data = data;
        jwks_shm = data;
        return NGX_OK;
    }

    /* Get slab pool */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Allocate shared memory structure */
    shm = ngx_slab_alloc(shpool, sizeof(jwks_shm_t));
    if (shm == NULL) {
        return NGX_ERROR;
    }

    shm->shpool = shpool;

    /* Initialize Rbtree */
    ngx_rbtree_init(&shm->rbtree, &shm->sentinel, jwks_rbtree_insert_value);

    shm_zone->data = shm;
    jwks_shm = shm;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_jwks_get(ngx_http_request_t *r, ngx_str_t *jwks_uri,
    ngx_oidc_jwks_cache_node_t **jwks)
{
    jwks_shm_node_t *shm_node;
    ngx_oidc_jwks_cache_node_t *cache_node;
    ngx_int_t rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: getting JWKS for uri: %V", jwks_uri);

    /* Check shared memory (returns with lock held on success) */
    shm_node = jwks_shm_lookup(jwks_uri);
    if (shm_node == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwks: cache miss for uri: %V", jwks_uri);
        *jwks = NULL;
        return NGX_DECLINED;
    }

    /* Lock is held here - copy data to request pool before releasing */

    /* Check TTL */
    if (ngx_time() > shm_node->expires_at) {
        ngx_shmtx_unlock(&jwks_shm->shpool->mutex);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_jwks: cache expired for uri: %V", jwks_uri);
        *jwks = NULL;
        return NGX_DECLINED;
    }

    /* Copy JWKS JSON and timestamps from shared memory under lock */
    ngx_str_t jwks_json_copy;
    time_t fetched_at, expires_at;

    fetched_at = shm_node->fetched_at;
    expires_at = shm_node->expires_at;

    jwks_json_copy.len = shm_node->jwks_json.len;
    jwks_json_copy.data = ngx_pnalloc(r->pool, jwks_json_copy.len);
    if (jwks_json_copy.data == NULL) {
        ngx_shmtx_unlock(&jwks_shm->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate memory for JSON copy");
        *jwks = NULL;
        return NGX_ERROR;
    }

    ngx_memcpy(jwks_json_copy.data, shm_node->jwks_json.data,
               jwks_json_copy.len);

    ngx_shmtx_unlock(&jwks_shm->shpool->mutex);

    /* Parse copied JSON (lock released) */
    rc = jwks_parse_json_to_cache(r, &jwks_json_copy, &cache_node);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to parse JWKS JSON for uri: %V",
                      jwks_uri);
        *jwks = NULL;
        return NGX_ERROR;
    }

    /* Set timestamps from copied values */
    ngx_oidc_jwks_cache_node_set_jwks_uri(cache_node, jwks_uri);
    ngx_oidc_jwks_cache_node_set_fetched_at(cache_node, fetched_at);
    ngx_oidc_jwks_cache_node_set_expires_at(cache_node, expires_at);

    /* Cache hit */
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: cache hit for uri: %V, keys=%uz", jwks_uri,
                   cache_node->keys->nelts);
    *jwks = cache_node;
    return NGX_OK;
}

ngx_int_t
ngx_oidc_jwks_try_lock_fetch(ngx_http_request_t *r, ngx_str_t *jwks_uri)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    jwks_shm_node_t *shm_node;
    jwks_shm_t *shm;
    time_t now;
    ngx_str_t empty_json = ngx_null_string;
    ngx_int_t rc;

    shm = jwks_shm;
    if (shm == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(jwks_uri->data, jwks_uri->len);
    now = ngx_time();

    ngx_shmtx_lock(&shm->shpool->mutex);

    /* Search for existing entry */
    node = shm->rbtree.root;
    sentinel = shm->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        shm_node = (jwks_shm_node_t *) node;
        if (shm_node->key_hash == hash
            && shm_node->jwks_uri.len == jwks_uri->len
            && ngx_strncmp(shm_node->jwks_uri.data, jwks_uri->data,
                           jwks_uri->len) == 0)
        {
            /* Found existing entry */

            /* Check if fetch already in progress */
            if (shm_node->fetching) {
                ngx_shmtx_unlock(&shm->shpool->mutex);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_jwks: fetch already in progress for: %V",
                               jwks_uri);
                return NGX_BUSY;
            }

            /* Check if entry is still valid */
            if (shm_node->expires_at > now && shm_node->jwks_json.len > 0) {
                ngx_shmtx_unlock(&shm->shpool->mutex);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_jwks: valid entry found for: %V",
                               jwks_uri);
                return NGX_DECLINED;
            }

            /* Entry expired or invalid, acquire lock */
            shm_node->fetching = 1;
            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwks: acquired fetch lock for: %V",
                           jwks_uri);
            return NGX_OK;
        }

        /* Continue search using URI comparison for hash collisions */
        {
            int cmp;
            cmp = ngx_memn2cmp(jwks_uri->data, shm_node->jwks_uri.data,
                               jwks_uri->len, shm_node->jwks_uri.len);
            node = (cmp < 0) ? node->left : node->right;
        }
    }

    /* Entry not found, unlock and create placeholder using jwks_shm_save() */
    ngx_shmtx_unlock(&shm->shpool->mutex);

    /* Create placeholder with empty JSON data */
    rc = jwks_shm_save(r, jwks_uri, &empty_json, 0);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to create placeholder for: %V",
                      jwks_uri);
        return NGX_ERROR;
    }

    /* Re-lock and find the created entry to set fetching flag */
    ngx_shmtx_lock(&shm->shpool->mutex);

    node = shm->rbtree.root;
    sentinel = shm->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        shm_node = (jwks_shm_node_t *) node;
        if (shm_node->key_hash == hash
            && shm_node->jwks_uri.len == jwks_uri->len
            && ngx_strncmp(shm_node->jwks_uri.data, jwks_uri->data,
                           jwks_uri->len) == 0)
        {
            /* Check if another worker already claimed this entry */
            if (shm_node->fetching) {
                ngx_shmtx_unlock(&shm->shpool->mutex);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_jwks: fetch already claimed by "
                               "another worker for: %V",
                               jwks_uri);
                return NGX_BUSY;
            }

            /* Found the placeholder, acquire fetch lock */
            shm_node->fetching = 1;
            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwks: created placeholder and "
                           "acquired fetch lock for: %V",
                           jwks_uri);
            return NGX_OK;
        }

        /* Continue search using URI comparison for hash collisions */
        {
            int cmp;
            cmp = ngx_memn2cmp(jwks_uri->data, shm_node->jwks_uri.data,
                               jwks_uri->len, shm_node->jwks_uri.len);
            node = (cmp < 0) ? node->left : node->right;
        }
    }

    /* Should not reach here */
    ngx_shmtx_unlock(&shm->shpool->mutex);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "oidc_jwks: placeholder disappeared after creation for: %V",
                  jwks_uri);
    return NGX_ERROR;
}

void
ngx_oidc_jwks_clear_fetch_flag(ngx_http_request_t *r, ngx_str_t *jwks_uri)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    jwks_shm_node_t *shm_node;
    jwks_shm_t *shm;

    shm = jwks_shm;
    if (shm == NULL) {
        return;
    }

    hash = ngx_crc32_short(jwks_uri->data, jwks_uri->len);

    ngx_shmtx_lock(&shm->shpool->mutex);

    node = shm->rbtree.root;
    sentinel = shm->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        shm_node = (jwks_shm_node_t *) node;
        if (shm_node->key_hash == hash
            && shm_node->jwks_uri.len == jwks_uri->len
            && ngx_strncmp(shm_node->jwks_uri.data, jwks_uri->data,
                           jwks_uri->len) == 0)
        {
            /* Found - clear flag */
            shm_node->fetching = 0;
            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_jwks: cleared fetch flag for: %V",
                           jwks_uri);
            return;
        }

        /* Continue search using URI comparison for hash collisions */
        {
            int cmp;
            cmp = ngx_memn2cmp(jwks_uri->data, shm_node->jwks_uri.data,
                               jwks_uri->len, shm_node->jwks_uri.len);
            node = (cmp < 0) ? node->left : node->right;
        }
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: entry not found when clearing fetch "
                   "flag for: %V",
                   jwks_uri);
}

EVP_PKEY *
ngx_oidc_jwks_key_get_pkey(const ngx_oidc_jwks_key_t *key)
{
    if (key == NULL) {
        return NULL;
    }
    return key->pkey;
}

ngx_str_t *
ngx_oidc_jwks_key_get_kid(const ngx_oidc_jwks_key_t *key)
{
    if (key == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &key->kid;
}

ngx_str_t *
ngx_oidc_jwks_key_get_alg(const ngx_oidc_jwks_key_t *key)
{
    if (key == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &key->alg;
}

ngx_oidc_jwk_type_t
ngx_oidc_jwks_key_get_kty(const ngx_oidc_jwks_key_t *key)
{
    if (key == NULL) {
        return 0; /* Invalid type */
    }
    return key->kty;
}

ngx_oidc_jwks_key_t *
ngx_oidc_jwks_key_get_at(const ngx_array_t *keys, ngx_uint_t index)
{
    if (keys == NULL || index >= keys->nelts) {
        return NULL;
    }
    return (ngx_oidc_jwks_key_t *) ((u_char *) keys->elts +
                                    index * keys->size);
}

ngx_str_t *
ngx_oidc_jwks_cache_node_get_jwks_uri(const ngx_oidc_jwks_cache_node_t *node)
{
    if (node == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &node->jwks_uri;
}

ngx_array_t *
ngx_oidc_jwks_cache_node_get_keys(const ngx_oidc_jwks_cache_node_t *node)
{
    if (node == NULL) {
        return NULL;
    }
    return node->keys;
}

time_t
ngx_oidc_jwks_cache_node_get_fetched_at(const ngx_oidc_jwks_cache_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    return node->fetched_at;
}

time_t
ngx_oidc_jwks_cache_node_get_expires_at(const ngx_oidc_jwks_cache_node_t *node)
{
    if (node == NULL) {
        return 0;
    }
    return node->expires_at;
}

void
ngx_oidc_jwks_cache_node_set_jwks_uri(ngx_oidc_jwks_cache_node_t *node,
    ngx_str_t *jwks_uri)
{
    if (node == NULL || jwks_uri == NULL) {
        return;
    }
    node->jwks_uri = *jwks_uri;
}

void
ngx_oidc_jwks_cache_node_set_fetched_at(ngx_oidc_jwks_cache_node_t *node,
    time_t fetched_at)
{
    if (node == NULL) {
        return;
    }
    node->fetched_at = fetched_at;
}

void
ngx_oidc_jwks_cache_node_set_expires_at(ngx_oidc_jwks_cache_node_t *node,
    time_t expires_at)
{
    if (node == NULL) {
        return;
    }
    node->expires_at = expires_at;
}

ngx_uint_t
ngx_oidc_jwks_get_key_count(const ngx_oidc_jwks_cache_node_t *jwks)
{
    if (jwks == NULL || jwks->keys == NULL) {
        return 0;
    }
    return jwks->keys->nelts;
}

ngx_int_t
ngx_oidc_jwks_iterate_keys(ngx_http_request_t *r,
    const ngx_oidc_jwks_cache_node_t *jwks,
    ngx_oidc_jwks_key_iterator_pt iterator, void *data)
{
    ngx_uint_t i;
    ngx_oidc_jwks_key_t *key;
    ngx_int_t rc;

    if (jwks == NULL || jwks->keys == NULL || iterator == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < jwks->keys->nelts; i++) {
        key = ngx_oidc_jwks_key_get_at(jwks->keys, i);
        if (key == NULL) {
            continue;
        }

        rc = iterator(r, key, data);
        if (rc == NGX_DONE) {
            /* Iterator requested early termination (e.g., found target) */
            return NGX_OK;
        } else if (rc != NGX_OK) {
            /* Iterator encountered an error */
            return rc;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_oidc_jwks_fetch(ngx_http_request_t *r, ngx_str_t *jwks_uri,
    ngx_oidc_jwks_done_pt callback, void *data)
{
    jwks_fetch_ctx_t *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: fetching JWKS from uri: %V", jwks_uri);

    /* Create context */
    ctx = ngx_pcalloc(r->pool, sizeof(jwks_fetch_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate fetch context");
        return NGX_ERROR;
    }

    ctx->main_request = r;
    ctx->jwks_uri = *jwks_uri;
    ctx->callback = callback;
    ctx->data = data;

    /* Create external URL fetch using Week 2 HTTP module */
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: creating GET request for JWKS endpoint");

    return ngx_oidc_http_get(r, jwks_uri, jwks_subrequest_done, ctx);
}

ngx_int_t
ngx_oidc_jwks_iterate(ngx_http_request_t *r, ngx_oidc_jwks_iterate_pt callback,
    void *data)
{
    jwks_shm_t *shm;
    jwks_traverse_ctx_t ctx;

    shm = jwks_shm;
    if (shm == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: shared memory not initialized");
        return NGX_ERROR;
    }

    ctx.callback = callback;
    ctx.data = data;
    ctx.result = NGX_OK;

    /* Lock shared memory */
    ngx_shmtx_lock(&shm->shpool->mutex);

    /* Traverse rbtree */
    if (shm->rbtree.root != shm->rbtree.sentinel) {
        jwks_rbtree_traverse(shm->rbtree.root, shm->rbtree.sentinel, &ctx);
    }

    /* Unlock shared memory */
    ngx_shmtx_unlock(&shm->shpool->mutex);

    return ctx.result;
}
