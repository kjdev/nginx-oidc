/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_SESSION_STORE_REDIS_H_INCLUDED_
#define _NGX_OIDC_SESSION_STORE_REDIS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <hiredis/hiredis.h>

typedef struct ngx_oidc_session_store_s ngx_oidc_session_store_t;

/**
 * Initialize Redis session store connection
 *
 * @param[in] store  Session store instance with Redis configuration
 * @param[in] pool   Memory pool for allocation
 * @param[in] log    Log context
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_redis_init(ngx_oidc_session_store_t *store,
    ngx_pool_t *pool, ngx_log_t *log);

/**
 * Store a key-value pair in Redis session store
 *
 * @param[in] r        HTTP request context
 * @param[in] store    Session store instance
 * @param[in] key      Key to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_redis_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires);

/**
 * Store a key-value pair only if key does not exist in Redis
 *
 * @param[in] r        HTTP request context
 * @param[in] store    Session store instance
 * @param[in] key      Key to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK if stored, NGX_DECLINED if key exists, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_redis_set_nx(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires);

/**
 * Retrieve a value from Redis session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 * @param[in] key    Key to retrieve
 * @param[out] value Retrieved value
 *
 * @return NGX_OK on success, NGX_DECLINED if not found, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_redis_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value);

/**
 * Delete a key from Redis session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 * @param[in] key    Key to delete
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_redis_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key);

/**
 * Clean up expired entries from Redis session store
 *
 * Redis handles TTL expiration natively, so this is a no-op.
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_redis_cleanup_expired(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store);

#endif /* _NGX_OIDC_SESSION_STORE_REDIS_H_INCLUDED_ */
