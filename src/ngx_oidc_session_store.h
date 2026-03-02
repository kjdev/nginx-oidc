/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_SESSION_STORE_H_INCLUDED_
#define _NGX_OIDC_SESSION_STORE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_oidc_session_store_memory.h"
#include "ngx_oidc_session_store_redis.h"

typedef enum {
    NGX_OIDC_SESSION_STORE_MEMORY = 0,
    NGX_OIDC_SESSION_STORE_REDIS
} ngx_oidc_session_store_type_t;

typedef struct ngx_oidc_session_store_s ngx_oidc_session_store_t;

/** Session store operations interface */
typedef struct {
    ngx_int_t (*set)(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
        ngx_str_t *key, ngx_str_t *value, time_t expires);
    /** store if not exists */
    ngx_int_t (*set_nx)(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
        ngx_str_t *key, ngx_str_t *value, time_t expires);
    ngx_int_t (*get)(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
        ngx_str_t *key, ngx_str_t *value);
    ngx_int_t (*delete)(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
        ngx_str_t *key);
    ngx_int_t (*expire)(ngx_http_request_t *r,
        ngx_oidc_session_store_t *store);
} ngx_oidc_session_store_ops_t;

/** Session store instance */
struct ngx_oidc_session_store_s {
    ngx_str_t  name;
    ngx_oidc_session_store_type_t type;
    ngx_oidc_session_store_ops_t *ops;
    /** default TTL (seconds) */
    time_t     ttl;
    ngx_str_t  prefix;
    /** memory store settings */
    struct {
        size_t          size;
        ngx_uint_t      max_size;
        ngx_shm_zone_t *shm_zone;
    } memory;
    /** Redis store settings */
    struct {
        ngx_str_t   hostname;
        ngx_uint_t  port;
        ngx_uint_t  database;
        ngx_str_t   password;
        /** connection timeout (ms) */
        ngx_msec_t  connect_timeout;
        /** command timeout (ms) */
        ngx_msec_t  command_timeout;
    } redis;
    void *data;
};

/**
 * Store a key-value pair in session store
 *
 * @param[in] r        HTTP request context
 * @param[in] store    Session store instance
 * @param[in] key      Key to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires);

/**
 * Store a key-value pair only if key does not exist (set if not exists)
 *
 * @param[in] r        HTTP request context
 * @param[in] store    Session store instance
 * @param[in] key      Key to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK if stored, NGX_DECLINED if key exists, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_set_nx(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires);

/**
 * Retrieve a value from session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 * @param[in] key    Key to retrieve
 * @param[out] value Retrieved value
 *
 * @return NGX_OK on success, NGX_DECLINED if not found, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value);

/**
 * Delete a key from session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 * @param[in] key    Key to delete
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key);

/**
 * Clean up expired entries from session store
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store instance
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t
ngx_oidc_session_store_cleanup_expired(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store);

/**
 * Initialize all configured session stores
 *
 * @param[in] session_stores  Array of session store configurations
 * @param[in] cf              nginx configuration context
 * @param[in] module          nginx module reference
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_store_init_all(ngx_array_t *session_stores,
    ngx_conf_t *cf, ngx_module_t *module);

/**
 * Ensure default session store exists
 *
 * Creates a default memory-based session store.
 *
 * @param[in] pool            Memory pool for allocation
 * @param[in] log             Log context
 * @param[in] shm_zone        Shared memory zone for memory store
 *
 * @return Pointer to created session store, or NULL on failure
 */
ngx_oidc_session_store_t *ngx_oidc_session_store_ensure_default(
    ngx_pool_t *pool, ngx_log_t *log, ngx_shm_zone_t *shm_zone);

#endif /* _NGX_OIDC_SESSION_STORE_H_INCLUDED_ */
