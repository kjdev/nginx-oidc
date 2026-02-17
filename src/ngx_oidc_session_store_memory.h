/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_SESSION_STORE_MEMORY_H_INCLUDED_
#define _NGX_OIDC_SESSION_STORE_MEMORY_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_oidc_session_store_s ngx_oidc_session_store_t;

/* State store statistics structure */
typedef struct ngx_oidc_session_store_memory_stats_s
    ngx_oidc_session_store_memory_stats_t;

/**
 * Initialize memory session stores from configuration
 *
 * @param[in] session_stores  Array of session store configurations
 * @param[in] cf              nginx configuration context
 * @param[in] module          nginx module reference
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_init(ngx_array_t *session_stores,
    ngx_conf_t *cf, ngx_module_t *module);

/**
 * Store a key-value pair in memory session store
 *
 * @param[in] r        HTTP request context
 * @param[in] store    Session store instance
 * @param[in] key      Key to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires);

/**
 * Store a key-value pair only if key does not exist in memory store
 *
 * @param[in] r        HTTP request context
 * @param[in] store    Session store instance
 * @param[in] key      Key to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK if stored, NGX_DECLINED if key exists, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_set_nx(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires);

/**
 * Retrieve a value from memory session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 * @param[in] key    Key to retrieve
 * @param[out] value Retrieved value
 *
 * @return NGX_OK on success, NGX_DECLINED if not found, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value);

/**
 * Delete a key from memory session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 * @param[in] key    Key to delete
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key);

/**
 * Clean up expired entries from memory session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_cleanup_expired(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store);

/**
 * Initialize memory session store shared memory zone
 *
 * @param[in] shm_zone  Shared memory zone
 * @param[in] data      Previous zone data (for reload)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_shm_zone_init(ngx_shm_zone_t *shm_zone,
    void *data);

/**
 * Acquire shared memory lock for memory store
 *
 * @param[in] shm_zone  Shared memory zone
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_lock(ngx_shm_zone_t *shm_zone);

/**
 * Release shared memory lock for memory store
 *
 * @param[in] shm_zone  Shared memory zone
 */
void ngx_oidc_session_store_memory_unlock(ngx_shm_zone_t *shm_zone);

/**
 * Get memory store statistics (call after acquiring lock)
 *
 * @param[in] shm_zone  Shared memory zone
 * @param[out] stats    Statistics structure to fill
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_memory_get_stats(ngx_shm_zone_t *shm_zone,
    ngx_oidc_session_store_memory_stats_t *stats);

/**
 * Allocate statistics structure
 *
 * @param[in] pool  Memory pool for allocation
 *
 * @return Allocated statistics structure, or NULL on failure
 */
ngx_oidc_session_store_memory_stats_t *
ngx_oidc_session_store_memory_stats_create(ngx_pool_t *pool);

/**
 * Get current entry count from statistics
 *
 * @param[in] stats  Statistics structure
 *
 * @return Number of stored entries
 */
size_t ngx_oidc_session_store_memory_stats_get_state_entries(
    const ngx_oidc_session_store_memory_stats_t *stats);

/**
 * Get maximum entry count from statistics
 *
 * @param[in] stats  Statistics structure
 *
 * @return Maximum number of entries
 */
size_t ngx_oidc_session_store_memory_stats_get_max_entries(
    const ngx_oidc_session_store_memory_stats_t *stats);

/**
 * Get shared memory size from statistics
 *
 * @param[in] stats  Statistics structure
 *
 * @return Shared memory size in bytes
 */
size_t ngx_oidc_session_store_memory_stats_get_shm_size(
    const ngx_oidc_session_store_memory_stats_t *stats);

#endif /* _NGX_OIDC_SESSION_STORE_MEMORY_H_INCLUDED_ */
