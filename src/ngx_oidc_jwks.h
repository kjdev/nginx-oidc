/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_JWKS_H_INCLUDED_
#define _NGX_OIDC_JWKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>

/* JWK key types */
typedef enum {
    NGX_OIDC_JWK_UNKNOWN = 0,
    NGX_OIDC_JWK_RSA,
    NGX_OIDC_JWK_EC,
    NGX_OIDC_JWK_OKP
} ngx_oidc_jwk_type_t;

/* JWKS cache entry structure (single key) */
typedef struct ngx_oidc_jwks_key_s ngx_oidc_jwks_key_t;

/* JWKS cache node (returned to caller, allocated in request pool) */
typedef struct ngx_oidc_jwks_cache_node_s ngx_oidc_jwks_cache_node_t;

/**
 * JWKS fetch completion callback
 *
 * @param[in] r     HTTP request context
 * @param[in] jwks  Fetched JWKS cache node
 * @param[in] data  User data passed to fetch function
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
typedef ngx_int_t (*ngx_oidc_jwks_done_pt)(ngx_http_request_t *r,
    ngx_oidc_jwks_cache_node_t *jwks, void *data);

/**
 * Initialize JWKS shared memory zone
 *
 * @param[in] shm_zone  Shared memory zone
 * @param[in] data      Previous zone data (for reload)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwks_init_zone(ngx_shm_zone_t *shm_zone, void *data);

/**
 * Get JWKS from cache (cache-first)
 *
 * @param[in] r         HTTP request context
 * @param[in] jwks_uri  JWKS endpoint URI
 * @param[out] jwks     Retrieved JWKS cache node
 *
 * @return NGX_OK on success, NGX_DECLINED if not cached, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwks_get(ngx_http_request_t *r, ngx_str_t *jwks_uri,
    ngx_oidc_jwks_cache_node_t **jwks);

/**
 * Try to acquire fetch lock for JWKS URI
 *
 * @param[in] r         HTTP request context
 * @param[in] jwks_uri  JWKS endpoint URI
 *
 * @return NGX_OK if lock acquired, NGX_BUSY if already fetching,
 *         NGX_DECLINED if not found, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwks_try_lock_fetch(ngx_http_request_t *r,
    ngx_str_t *jwks_uri);

/**
 * Clear fetch_in_progress flag for JWKS URI
 *
 * @param[in] r         HTTP request context
 * @param[in] jwks_uri  JWKS endpoint URI
 */
void ngx_oidc_jwks_clear_fetch_flag(ngx_http_request_t *r,
    ngx_str_t *jwks_uri);

/**
 * Get EVP_PKEY from JWKS key
 *
 * @param[in] key  JWKS key structure
 *
 * @return EVP_PKEY pointer, or NULL if not available
 */
EVP_PKEY *ngx_oidc_jwks_key_get_pkey(const ngx_oidc_jwks_key_t *key);

/**
 * Get key ID (kid) from JWKS key
 *
 * @param[in] key  JWKS key structure
 *
 * @return Pointer to kid string
 */
ngx_str_t *ngx_oidc_jwks_key_get_kid(const ngx_oidc_jwks_key_t *key);

/**
 * Get algorithm (alg) from JWKS key
 *
 * @param[in] key  JWKS key structure
 *
 * @return Pointer to alg string
 */
ngx_str_t *ngx_oidc_jwks_key_get_alg(const ngx_oidc_jwks_key_t *key);

/**
 * Get key type (kty) from JWKS key
 *
 * @param[in] key  JWKS key structure
 *
 * @return Key type enum value
 */
ngx_oidc_jwk_type_t ngx_oidc_jwks_key_get_kty(const ngx_oidc_jwks_key_t *key);

/**
 * Get JWKS key at specified index from key array
 *
 * @param[in] keys   Array of JWKS keys
 * @param[in] index  Zero-based index
 *
 * @return Pointer to key structure, or NULL if out of bounds
 */
ngx_oidc_jwks_key_t *ngx_oidc_jwks_key_get_at(const ngx_array_t *keys,
    ngx_uint_t index);

/**
 * Fetch JWKS via subrequest (async)
 *
 * @param[in] r         HTTP request context
 * @param[in] jwks_uri  JWKS endpoint URI
 * @param[in] callback  Completion callback
 * @param[in] data      User data passed to callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwks_fetch(ngx_http_request_t *r, ngx_str_t *jwks_uri,
    ngx_oidc_jwks_done_pt callback, void *data);

/**
 * JWKS cache iteration callback
 *
 * @param[in] jwks_uri   JWKS endpoint URI
 * @param[in] fetched_at Time when JWKS was fetched
 * @param[in] expires_at Time when JWKS cache expires
 * @param[in] jwks_json  Cached JWKS JSON string
 * @param[in] data       User data
 *
 * @return NGX_OK to continue, NGX_ERROR to stop
 */
typedef ngx_int_t (*ngx_oidc_jwks_iterate_pt)(ngx_str_t *jwks_uri,
    time_t fetched_at, time_t expires_at, ngx_str_t *jwks_json, void *data);

/**
 * JWKS key iteration callback
 *
 * @param[in] r     HTTP request context
 * @param[in] key   JWKS key structure
 * @param[in] data  User data
 *
 * @return NGX_OK to continue, NGX_ERROR to stop
 */
typedef ngx_int_t (*ngx_oidc_jwks_key_iterator_pt)(
    ngx_http_request_t *r, const ngx_oidc_jwks_key_t *key, void *data);

/**
 * Get JWKS URI from cache node
 *
 * @param[in] node  JWKS cache node
 *
 * @return Pointer to JWKS URI string
 */
ngx_str_t *ngx_oidc_jwks_cache_node_get_jwks_uri(
    const ngx_oidc_jwks_cache_node_t *node);

/**
 * Get fetch timestamp from cache node
 *
 * @param[in] node  JWKS cache node
 *
 * @return Time when JWKS was fetched
 */
time_t ngx_oidc_jwks_cache_node_get_fetched_at(
    const ngx_oidc_jwks_cache_node_t *node);

/**
 * Get expiration timestamp from cache node
 *
 * @param[in] node  JWKS cache node
 *
 * @return Time when JWKS cache expires
 */
time_t ngx_oidc_jwks_cache_node_get_expires_at(
    const ngx_oidc_jwks_cache_node_t *node);

/**
 * Set JWKS URI on cache node
 *
 * @param[in] node      JWKS cache node
 * @param[in] jwks_uri  JWKS endpoint URI to set
 */
void ngx_oidc_jwks_cache_node_set_jwks_uri(ngx_oidc_jwks_cache_node_t *node,
    ngx_str_t *jwks_uri);

/**
 * Set fetch timestamp on cache node
 *
 * @param[in] node       JWKS cache node
 * @param[in] fetched_at Fetch timestamp to set
 */
void ngx_oidc_jwks_cache_node_set_fetched_at(ngx_oidc_jwks_cache_node_t *node,
    time_t fetched_at);

/**
 * Set expiration timestamp on cache node
 *
 * @param[in] node       JWKS cache node
 * @param[in] expires_at Expiration timestamp to set
 */
void ngx_oidc_jwks_cache_node_set_expires_at(ngx_oidc_jwks_cache_node_t *node,
    time_t expires_at);

/**
 * Get keys array from cache node
 *
 * @param[in] node  JWKS cache node
 *
 * @return Array of ngx_oidc_jwks_key_t entries
 */
ngx_array_t *ngx_oidc_jwks_cache_node_get_keys(
    const ngx_oidc_jwks_cache_node_t *node);

/**
 * Iterate keys in JWKS cache node
 *
 * @param[in] r         HTTP request context
 * @param[in] jwks      JWKS cache node
 * @param[in] iterator  Key iteration callback
 * @param[in] data      User data passed to callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwks_iterate_keys(ngx_http_request_t *r,
    const ngx_oidc_jwks_cache_node_t *jwks,
    ngx_oidc_jwks_key_iterator_pt iterator, void *data);

/**
 * Get number of keys in JWKS cache node
 *
 * @param[in] jwks  JWKS cache node
 *
 * @return Number of keys
 */
ngx_uint_t ngx_oidc_jwks_get_key_count(const ngx_oidc_jwks_cache_node_t *jwks);

/**
 * Iterate JWKS cache entries for status display
 *
 * @param[in] r         HTTP request context
 * @param[in] callback  Cache iteration callback
 * @param[in] data      User data passed to callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_jwks_iterate(ngx_http_request_t *r,
    ngx_oidc_jwks_iterate_pt callback, void *data);

#endif /* _NGX_OIDC_JWKS_H_INCLUDED_ */
