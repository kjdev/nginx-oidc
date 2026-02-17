/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_METADATA_H_INCLUDED_
#define _NGX_OIDC_METADATA_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Metadata cache entry structure */
typedef struct ngx_oidc_metadata_cache_s ngx_oidc_metadata_cache_t;

/**
 * Metadata fetch completion callback
 *
 * @param[in] r         HTTP request context
 * @param[in] metadata  Fetched metadata cache entry
 * @param[in] data      User data passed to fetch function
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
typedef ngx_int_t (*ngx_oidc_metadata_done_pt)(ngx_http_request_t *r,
    ngx_oidc_metadata_cache_t *metadata, void *data);

/**
 * Get metadata from cache (cache-first)
 *
 * @param[in] r         HTTP request context
 * @param[in] issuer    OIDC issuer identifier
 * @param[out] metadata Retrieved metadata cache entry
 *
 * @return NGX_OK on success, NGX_DECLINED if not cached, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_metadata_get(ngx_http_request_t *r, ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t **metadata);

/**
 * Try to acquire fetch lock for metadata
 *
 * @param[in] r       HTTP request context
 * @param[in] issuer  OIDC issuer identifier
 *
 * @return NGX_OK if lock acquired, NGX_BUSY if already fetching,
 *         NGX_DECLINED if not found, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_metadata_try_lock_fetch(ngx_http_request_t *r,
    ngx_str_t *issuer);

/**
 * Clear fetching flag for metadata
 *
 * @param[in] r       HTTP request context
 * @param[in] issuer  OIDC issuer identifier
 */
void ngx_oidc_metadata_clear_fetch_flag(ngx_http_request_t *r,
    ngx_str_t *issuer);

/**
 * Fetch metadata via subrequest (async)
 *
 * @param[in] r              HTTP request context
 * @param[in] issuer         OIDC issuer identifier
 * @param[in] discovery_url  Discovery endpoint URL
 * @param[in] callback       Completion callback
 * @param[in] data           User data passed to callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_metadata_fetch(ngx_http_request_t *r, ngx_str_t *issuer,
    ngx_str_t *discovery_url, ngx_oidc_metadata_done_pt callback, void *data);

/**
 * Initialize metadata shared memory zone
 *
 * @param[in] shm_zone  Shared memory zone
 * @param[in] data      Previous zone data (for reload)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_metadata_init_zone(ngx_shm_zone_t *shm_zone, void *data);

/**
 * Create array for storing metadata structures
 *
 * @param[in] pool  Memory pool for allocation
 * @param[in] n     Initial array capacity
 *
 * @return Allocated array, or NULL on failure
 */
ngx_array_t *ngx_oidc_metadata_create_array(ngx_pool_t *pool, ngx_uint_t n);

/**
 * Metadata cache iteration callback
 *
 * @param[in] issuer    OIDC issuer identifier
 * @param[in] metadata  Metadata cache entry
 * @param[in] data      User data
 *
 * @return NGX_OK to continue, NGX_ERROR to stop
 */
typedef ngx_int_t (*ngx_oidc_metadata_iterate_pt)(ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t *metadata, void *data);

/**
 * Iterate metadata cache entries for status display
 *
 * @param[in] r         HTTP request context
 * @param[in] callback  Cache iteration callback
 * @param[in] data      User data passed to callback
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t
ngx_oidc_metadata_iterate(ngx_http_request_t *r,
    ngx_oidc_metadata_iterate_pt callback, void *data);

/**
 * Get authorization endpoint from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Pointer to authorization_endpoint string
 */
ngx_str_t *ngx_oidc_metadata_get_authorization_endpoint(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get token endpoint from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Pointer to token_endpoint string
 */
ngx_str_t *ngx_oidc_metadata_get_token_endpoint(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get userinfo endpoint from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Pointer to userinfo_endpoint string
 */
ngx_str_t *ngx_oidc_metadata_get_userinfo_endpoint(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get JWKS URI from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Pointer to jwks_uri string
 */
ngx_str_t *ngx_oidc_metadata_get_jwks_uri(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get end session endpoint from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Pointer to end_session_endpoint string
 */
ngx_str_t *ngx_oidc_metadata_get_end_session_endpoint(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get issuer from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Pointer to issuer string
 */
ngx_str_t *ngx_oidc_metadata_get_issuer(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get fetch timestamp from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Time when metadata was fetched
 */
time_t ngx_oidc_metadata_get_fetched_at(
    const ngx_oidc_metadata_cache_t *metadata);

/**
 * Get expiration timestamp from metadata
 *
 * @param[in] metadata  Metadata cache entry
 *
 * @return Time when metadata cache expires
 */
time_t ngx_oidc_metadata_get_expires_at(
    const ngx_oidc_metadata_cache_t *metadata);

#endif /* _NGX_OIDC_METADATA_H_INCLUDED_ */
