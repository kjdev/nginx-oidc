/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_session_store.h"
#include "ngx_oidc_session_store_memory.h"

/* Memory store operations table */
static ngx_oidc_session_store_ops_t memory_ops = {
    ngx_oidc_session_store_memory_set,
    ngx_oidc_session_store_memory_set_nx,
    ngx_oidc_session_store_memory_get,
    ngx_oidc_session_store_memory_delete,
    ngx_oidc_session_store_memory_cleanup_expired
};

/* Redis store operations table */
static ngx_oidc_session_store_ops_t redis_ops = {
    ngx_oidc_session_store_redis_set,
    ngx_oidc_session_store_redis_set_nx,
    ngx_oidc_session_store_redis_get,
    ngx_oidc_session_store_redis_delete,
    ngx_oidc_session_store_redis_cleanup_expired
};

/**
 * Initialize session store based on its type
 *
 * Sets the operations interface and performs type-specific
 * initialization (e.g., Redis connection setup).
 *
 * @param[in] store  Session store to initialize
 * @param[in] pool   Memory pool for allocation
 * @param[in] log    Log context
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
static ngx_int_t
store_init(ngx_oidc_session_store_t *store, ngx_pool_t *pool, ngx_log_t *log)
{
    if (store == NULL) {
        return NGX_ERROR;
    }

    switch (store->type) {
    case NGX_OIDC_SESSION_STORE_MEMORY:
        store->ops = &memory_ops;
        break;

    case NGX_OIDC_SESSION_STORE_REDIS:
        store->ops = &redis_ops;
        if (ngx_oidc_session_store_redis_init(store, pool, log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "oidc_session_store: failed to initialize redis");
            return NGX_ERROR;
        }
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc_session_store: unknown store type %d", store->type);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * Get default session store from main configuration
 *
 * Returns the first configured session store. If no stores are configured,
 * creates and initializes a default memory store.
 *
 * @param[in] r  HTTP request context
 *
 * @return Session store instance, or NULL on failure
 */
static ngx_oidc_session_store_t *
store_get_default(ngx_http_request_t *r)
{
    ngx_http_oidc_main_conf_t *omcf;
    ngx_oidc_session_store_t *default_store;

    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (omcf == NULL || omcf->session_stores == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session_store: main configuration "
                      "or session stores array is NULL");
        return NULL;
    }

    /* Create default memory store if no session stores are configured */
    if (omcf->session_stores->nelts == 0) {
        default_store = ngx_array_push(omcf->session_stores);
        if (default_store == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to allocate memory "
                          "for default session store");
            return NULL;
        }

        ngx_memzero(default_store, sizeof(ngx_oidc_session_store_t));
        ngx_str_set(&default_store->name, "default_memory");
        default_store->type = NGX_OIDC_SESSION_STORE_MEMORY;
        default_store->ttl = 3600; /* 1 hour default */
        ngx_str_set(&default_store->prefix, "oidc_session_store:");

        /* Memory store defaults */
        default_store->memory.size = 10 * 1024 * 1024; /* 10MB */
        default_store->memory.max_size = 1000;

        /* Set operations table */
        default_store->ops = &memory_ops;

        /* Verify shared memory zone is available for memory store */
        if (omcf->shm_zone == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: shared memory zone "
                          "not available for default memory store");
            return NULL;
        }

        if (omcf->shm_zone->data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: shared memory zone "
                          "not initialized for default memory store");
            return NULL;
        }

        /* Set shared memory zone reference for memory store */
        default_store->memory.shm_zone = omcf->shm_zone;

        /* Initialize the default session store */
        if (store_init(default_store, omcf->session_stores->pool,
                       r->connection->log)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to initialize default "
                          "memory session store");
            return NULL;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_session_store: created default memory session "
                       "store");
    }

    /* Return first store as default */
    return (ngx_oidc_session_store_t *) omcf->session_stores->elts;
}

ngx_int_t
ngx_oidc_session_store_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires)
{
    /* Use default store if session store is NULL */
    if (store == NULL) {
        store = store_get_default(r);
        if (store == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to get default "
                          "session store");
            return NGX_ERROR;
        }
    }

    if (store->ops == NULL || store->ops->set == NULL) {
        return NGX_ERROR;
    }

    return store->ops->set(r, store, key, value, expires);
}

ngx_int_t
ngx_oidc_session_store_set_nx(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires)
{
    /* Use default store if session store is NULL */
    if (store == NULL) {
        store = store_get_default(r);
        if (store == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to get default "
                          "session store");
            return NGX_ERROR;
        }
    }

    if (store->ops == NULL || store->ops->set_nx == NULL) {
        return NGX_ERROR;
    }

    return store->ops->set_nx(r, store, key, value, expires);
}

ngx_int_t
ngx_oidc_session_store_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value)
{
    /* Use default store if session store is NULL */
    if (store == NULL) {
        store = store_get_default(r);
        if (store == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to get default "
                          "session store");
            return NGX_ERROR;
        }
    }

    if (store->ops == NULL || store->ops->get == NULL) {
        return NGX_ERROR;
    }

    return store->ops->get(r, store, key, value);
}

ngx_int_t
ngx_oidc_session_store_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key)
{
    /* Use default store if session store is NULL */
    if (store == NULL) {
        store = store_get_default(r);
        if (store == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to get default "
                          "session store");
            return NGX_ERROR;
        }
    }

    if (store->ops == NULL || store->ops->delete == NULL) {
        return NGX_ERROR;
    }

    return store->ops->delete(r, store, key);
}

ngx_int_t
ngx_oidc_session_store_cleanup_expired(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store)
{
    /* Use default store if session store is NULL */
    if (store == NULL) {
        store = store_get_default(r);
        if (store == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_store: failed to get default "
                          "session store");
            return NGX_ERROR;
        }
    }

    if (store->ops == NULL || store->ops->expire == NULL) {
        return NGX_ERROR;
    }

    return store->ops->expire(r, store);
}

ngx_int_t
ngx_oidc_session_store_ensure_default(ngx_array_t *session_stores,
    ngx_pool_t *pool, ngx_log_t *log, ngx_shm_zone_t *shm_zone)
{
    ngx_oidc_session_store_t *default_store;

    if (session_stores == NULL || pool == NULL || log == NULL) {
        return NGX_ERROR;
    }

    /* Create default memory session store for backward compatibility */
    if (session_stores->nelts == 0) {
        default_store = ngx_array_push(session_stores);
        if (default_store == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "oidc_session_store: failed to allocate memory "
                          "for default session store");
            return NGX_ERROR;
        }

        ngx_memzero(default_store, sizeof(ngx_oidc_session_store_t));
        ngx_str_set(&default_store->name, "default_memory");
        default_store->type = NGX_OIDC_SESSION_STORE_MEMORY;
        default_store->ttl = 3600; /* 1 hour default */
        ngx_str_set(&default_store->prefix, "oidc_session_store:");

        /* Memory store defaults */
        default_store->memory.size = 10 * 1024 * 1024; /* 10MB */
        default_store->memory.max_size = 1000;

        /* Set shared memory zone reference for memory store */
        if (shm_zone != NULL) {
            default_store->memory.shm_zone = shm_zone;
        }

        /* Initialize session store operations */
        if (store_init(default_store, pool, log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "oidc_session_store: failed to initialize "
                          "default memory session store");
            return NGX_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "oidc_session_store: created default memory "
                       "session store");
    }

    return NGX_OK;
}

/* Initialize all session stores through abstraction layer */
ngx_int_t
ngx_oidc_session_store_init_all(ngx_array_t *session_stores, ngx_conf_t *cf,
    ngx_module_t *module)
{
    ngx_oidc_session_store_t *store;
    ngx_uint_t i;

    if (session_stores == NULL || session_stores->nelts == 0) {
        return NGX_OK;
    }

    store = session_stores->elts;
    for (i = 0; i < session_stores->nelts; i++) {
        /* Initialize type-specific resources (shared memory, connections) */
        if (store[i].type == NGX_OIDC_SESSION_STORE_MEMORY) {
            /* Initialize memory-specific shared memory zones */
            if (ngx_oidc_session_store_memory_init(session_stores, cf, module)
                != NGX_OK)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "failed to initialize memory "
                                   "session stores");
                return NGX_ERROR;
            }
            break; /* Only need to call once for all memory stores */
        }
        /* Future: Add Redis cluster/sentinel initialization here */
    }

    /* Initialize operations for all stores */
    for (i = 0; i < session_stores->nelts; i++) {
        if (store_init(&store[i], cf->pool, cf->log) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "failed to initialize %s session store \"%V\"",
                               store[i].type == NGX_OIDC_SESSION_STORE_MEMORY
                               ? "memory"
                               : "redis",
                               &store[i].name);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
