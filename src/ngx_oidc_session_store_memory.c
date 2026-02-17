/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "ngx_oidc_session_store_memory.h"
#include "ngx_oidc_session_store.h"

/**
 * State/nonce store node
 *
 * Layout: rbtree_node must be first, key must be second
 * to be compatible with ngx_str_node_t / ngx_str_rbtree_insert_value.
 */
typedef struct {
    /** rbtree node (must be first) */
    ngx_rbtree_node_t  rbtree_node;
    /** state/nonce value (must be second) */
    ngx_str_t          key;
    ngx_str_t          data;
    time_t             expires;
    /** LRU/expiration queue link */
    ngx_queue_t        queue;
} store_node_t;

/** Shared memory zone structure (private to this file) */
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        expire_queue;
    ngx_slab_pool_t   *shpool;
    ngx_uint_t         max_size;
    ngx_uint_t         count;
} shm_zone_t;

/** Memory store statistics structure (opaque type) */
struct ngx_oidc_session_store_memory_stats_s {
    size_t  state_entries;
    size_t  max_entries;
    /** shared memory size (bytes) */
    size_t  shm_size;
};

/* CRC32 hash function for keys */
static uint32_t
mem_hash_key(u_char *data, size_t len)
{
    return ngx_crc32_short(data, len);
}

/**
 * Validate session store and extract shared memory context
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store to validate
 * @param[out] octx  Extracted shared memory zone context
 *
 * @return NGX_OK on success, NGX_ERROR if store or shm_zone is invalid
 */
static ngx_int_t
mem_validate_store(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
    shm_zone_t **octx)
{
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_memory: session store is NULL");
        return NGX_ERROR;
    }

    if (store->type != NGX_OIDC_SESSION_STORE_MEMORY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_memory: invalid store type %d", store->type);
        return NGX_ERROR;
    }

    if (store->memory.shm_zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_memory: shared memory zone is NULL");
        return NGX_ERROR;
    }

    *octx = store->memory.shm_zone->data;
    if (*octx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_memory: shared memory context is NULL");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * Find node in rbtree by hash and key
 *
 * Searches the rbtree for a node matching the given hash,
 * with string comparison for collision resolution.
 *
 * @param[in] octx  Shared memory zone context
 * @param[in] hash  CRC32 hash of the key
 * @param[in] key   Key string to match
 *
 * @return Matching node, or NULL if not found
 */
static store_node_t *
mem_find_node(shm_zone_t *octx, uint32_t hash, ngx_str_t *key)
{
    ngx_rbtree_node_t *node, *sentinel;
    store_node_t *ocn;
    ngx_int_t rc;

    node = octx->rbtree.root;
    sentinel = octx->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
        } else if (hash > node->key) {
            node = node->right;
        } else {
            /* Hash match, check actual key */
            ocn = (store_node_t *) (
                (u_char *) node - offsetof(store_node_t, rbtree_node));

            /* Compare keys */
            rc = ngx_memn2cmp(key->data, ocn->key.data,
                              key->len, ocn->key.len);

            if (rc == 0) {
                /* Exact match found */
                return ocn;
            }

            /* Hash collision: continue searching based on key comparison */
            node = (rc < 0) ? node->left : node->right;
        }
    }

    return NULL;
}

/*
 * Insert node into expire queue sorted by expiration time.
 * Tail has the earliest expiration, head has the latest.
 */
static void
mem_queue_insert_expire(ngx_queue_t *expire_queue, store_node_t *ocn)
{
    ngx_queue_t *q;
    store_node_t *cur;

    /* Walk from tail (earliest expiration) to find insertion point */
    for (q = ngx_queue_last(expire_queue);
         q != ngx_queue_sentinel(expire_queue);
         q = ngx_queue_prev(q))
    {
        cur = ngx_queue_data(q, store_node_t, queue);
        if (cur->expires <= ocn->expires) {
            /* Insert after this entry (closer to head) */
            ngx_queue_insert_after(q, &ocn->queue);
            return;
        }
    }

    /* This entry has the earliest expiration - insert at tail */
    ngx_queue_insert_head(expire_queue, &ocn->queue);
}

/**
 * Update existing node with new value and expiration
 *
 * Replaces the node's value in shared memory slab, updating
 * the expiration queue position.
 *
 * @param[in] octx     Shared memory zone context
 * @param[in] ocn      Node to update
 * @param[in] value    New value to store
 * @param[in] expires  New expiration time (absolute)
 *
 * @return NGX_OK on success, NGX_ERROR on allocation failure
 */
static ngx_int_t
mem_update_node(shm_zone_t *octx, store_node_t *ocn,
    ngx_str_t *value, time_t expires)
{
    if (value->len != ocn->data.len) {
        u_char *new_data;

        /* Allocate new memory first to avoid dangling pointer on failure */
        new_data = ngx_slab_alloc_locked(octx->shpool, value->len);
        if (new_data == NULL) {
            return NGX_ERROR;  /* Keep old data intact on allocation failure */
        }

        /* Free old memory only after successful allocation */
        ngx_slab_free_locked(octx->shpool, ocn->data.data);
        ocn->data.data = new_data;
    }

    ngx_memcpy(ocn->data.data, value->data, value->len);
    ocn->data.len = value->len;
    ocn->expires = expires;

    /* Reinsert into expire queue at correct sorted position */
    ngx_queue_remove(&ocn->queue);
    mem_queue_insert_expire(&octx->expire_queue, ocn);

    return NGX_OK;
}

/**
 * Create and insert new node into rbtree and expiration queue
 *
 * Allocates node, key, and value from shared memory slab,
 * inserts into the rbtree, and adds to the expiration queue.
 * Performs LRU eviction if slab allocation fails.
 *
 * @param[in] octx     Shared memory zone context
 * @param[in] hash     CRC32 hash of the key
 * @param[in] key      Key string to store
 * @param[in] value    Value to store
 * @param[in] expires  Expiration time (absolute)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
static ngx_int_t
mem_create_node(shm_zone_t *octx, uint32_t hash, ngx_str_t *key,
    ngx_str_t *value, time_t expires)
{
    store_node_t *ocn;
    ngx_rbtree_node_t *node;
    size_t size;

    /* Allocate node structure */
    size = sizeof(store_node_t);
    ocn = ngx_slab_alloc_locked(octx->shpool, size);
    if (ocn == NULL) {
        return NGX_ERROR;
    }

    node = &ocn->rbtree_node;
    node->key = hash;

    /* Allocate and copy key */
    ocn->key.data = ngx_slab_alloc_locked(octx->shpool, key->len);
    if (ocn->key.data == NULL) {
        ngx_slab_free_locked(octx->shpool, ocn);
        return NGX_ERROR;
    }
    ngx_memcpy(ocn->key.data, key->data, key->len);
    ocn->key.len = key->len;

    /* Allocate and copy data */
    ocn->data.data = ngx_slab_alloc_locked(octx->shpool, value->len);
    if (ocn->data.data == NULL) {
        ngx_slab_free_locked(octx->shpool, ocn->key.data);
        ngx_slab_free_locked(octx->shpool, ocn);
        return NGX_ERROR;
    }
    ngx_memcpy(ocn->data.data, value->data, value->len);
    ocn->data.len = value->len;
    ocn->expires = expires;

    /* Insert into rbtree and expire queue (sorted by expiration) */
    ngx_rbtree_insert(&octx->rbtree, node);
    mem_queue_insert_expire(&octx->expire_queue, ocn);
    octx->count++;

    return NGX_OK;
}

/* Remove node from rbtree and free memory */
static void
mem_remove_node(shm_zone_t *octx, store_node_t *ocn)
{
    ngx_queue_remove(&ocn->queue);
    ngx_rbtree_delete(&octx->rbtree, &ocn->rbtree_node);
    ngx_slab_free_locked(octx->shpool, ocn->key.data);
    ngx_slab_free_locked(octx->shpool, ocn->data.data);
    ngx_slab_free_locked(octx->shpool, ocn);
    octx->count--;
}

/*
 * Evict entries to make room when at max_size (called with lock held).
 * First removes expired entries, then evicts oldest if still at limit.
 */
static void
mem_evict_if_needed(shm_zone_t *octx)
{
    ngx_queue_t *q;
    store_node_t *ocn;
    time_t now;

    if (octx->count < octx->max_size) {
        return;
    }

    now = ngx_time();

    /* Remove expired entries first */
    while (!ngx_queue_empty(&octx->expire_queue)
           && octx->count >= octx->max_size)
    {
        q = ngx_queue_last(&octx->expire_queue);
        ocn = ngx_queue_data(q, store_node_t, queue);

        if (ocn->expires >= now) {
            break;
        }

        mem_remove_node(octx, ocn);
    }

    /* If still at limit, evict the oldest entry */
    if (octx->count >= octx->max_size
        && !ngx_queue_empty(&octx->expire_queue))
    {
        q = ngx_queue_last(&octx->expire_queue);
        ocn = ngx_queue_data(q, store_node_t, queue);
        mem_remove_node(octx, ocn);
    }
}

ngx_int_t
ngx_oidc_session_store_memory_init(ngx_array_t *session_stores, ngx_conf_t *cf,
    ngx_module_t *module)
{
    ngx_oidc_session_store_t *store;
    ngx_uint_t i;
    ngx_str_t shm_name;
    u_char *p;

    store = session_stores->elts;
    for (i = 0; i < session_stores->nelts; i++) {
        if (store[i].type != NGX_OIDC_SESSION_STORE_MEMORY) {
            continue;
        }

        /* Create shared memory zone name */
        shm_name.len = sizeof("oidc_memory_") - 1 + store[i].name.len;
        shm_name.data = ngx_pnalloc(cf->pool, shm_name.len);
        if (shm_name.data == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(shm_name.data, "oidc_memory_",
                       sizeof("oidc_memory_") - 1);
        ngx_memcpy(p, store[i].name.data, store[i].name.len);

        /* Add shared memory zone */
        store[i].memory.shm_zone =
            ngx_shared_memory_add(cf, &shm_name, store[i].memory.size, module);
        if (store[i].memory.shm_zone == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "failed to add shared memory zone \"%V\"",
                               &shm_name);
            return NGX_ERROR;
        }

        if (store[i].memory.shm_zone->init == NULL) {
            store[i].memory.shm_zone->init =
                ngx_oidc_session_store_memory_shm_zone_init;
            store[i].memory.shm_zone->data = &store[i];
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_memory_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires)
{
    shm_zone_t *octx;
    store_node_t *ocn;
    uint32_t hash;
    ngx_int_t rc;

    /* Validate store and get shared memory context */
    if (mem_validate_store(r, store, &octx) != NGX_OK) {
        return NGX_ERROR;
    }

    hash = mem_hash_key(key->data, key->len);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_store_memory: key=%V, store=%V, shm_zone=%p, octx=%p",
                   key, &store->name, store->memory.shm_zone, octx);

    ngx_shmtx_lock(&octx->shpool->mutex);

    /* Try to find existing node */
    ocn = mem_find_node(octx, hash, key);
    if (ocn != NULL) {
        /* Update existing node */
        rc = mem_update_node(octx, ocn, value, expires);
        ngx_shmtx_unlock(&octx->shpool->mutex);
        return rc;
    }

    /* Evict entries if at capacity */
    mem_evict_if_needed(octx);

    /* Create new node */
    rc = mem_create_node(octx, hash, key, value, expires);
    ngx_shmtx_unlock(&octx->shpool->mutex);

    if (rc == NGX_OK) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_memory: stored key=%V in "
                       "store=%V (new node, expires=%T)",
                       key, &store->name, expires);
    }

    return rc;
}

ngx_int_t
ngx_oidc_session_store_memory_set_nx(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires)
{
    shm_zone_t *octx;
    store_node_t *ocn;
    uint32_t hash;
    ngx_int_t rc;

    /* Validate store and get shared memory context */
    if (mem_validate_store(r, store, &octx) != NGX_OK) {
        return NGX_ERROR;
    }

    hash = mem_hash_key(key->data, key->len);

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_store_memory: set_nx key=%V, store=%V, "
                   "shm_zone=%p, octx=%p",
                   key, &store->name, store->memory.shm_zone, octx);

    /* Lock for atomic check-and-set operation */
    ngx_shmtx_lock(&octx->shpool->mutex);

    /* Check if node already exists */
    ocn = mem_find_node(octx, hash, key);
    if (ocn != NULL) {
        /* Key already exists - return DECLINED without modifying */
        ngx_shmtx_unlock(&octx->shpool->mutex);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_memory: set_nx key=%V already exists "
                       "in store=%V",
                       key, &store->name);
        return NGX_DECLINED;
    }

    /* Evict entries if at capacity */
    mem_evict_if_needed(octx);

    /* Create new node (key doesn't exist) */
    rc = mem_create_node(octx, hash, key, value, expires);
    ngx_shmtx_unlock(&octx->shpool->mutex);

    if (rc == NGX_OK) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_memory: set_nx created key=%V "
                       "in store=%V (expires=%T)",
                       key, &store->name, expires);
    }

    return rc;
}

ngx_int_t
ngx_oidc_session_store_memory_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value)
{
    shm_zone_t *octx;
    store_node_t *ocn;
    uint32_t hash;
    time_t now;

    /* Validate store and get shared memory context */
    if (mem_validate_store(r, store, &octx) != NGX_OK) {
        return NGX_ERROR;
    }

    hash = mem_hash_key(key->data, key->len);
    now = ngx_time();

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_store_memory: key=%V, store=%V, shm_zone=%p, octx=%p",
                   key, &store->name, store->memory.shm_zone, octx);

    ngx_shmtx_lock(&octx->shpool->mutex);

    ocn = mem_find_node(octx, hash, key);
    if (ocn == NULL) {
        ngx_shmtx_unlock(&octx->shpool->mutex);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_memory: key=%V not found", key);
        return NGX_DECLINED;
    }

    /* Check expiration */
    if (ocn->expires < now) {
        /* Expired, remove it */
        mem_remove_node(octx, ocn);
        ngx_shmtx_unlock(&octx->shpool->mutex);
        return NGX_DECLINED;
    }

    /* Copy data to request pool */
    value->len = ocn->data.len;
    value->data = ngx_pnalloc(r->pool, value->len);
    if (value->data == NULL) {
        ngx_shmtx_unlock(&octx->shpool->mutex);
        return NGX_ERROR;
    }
    ngx_memcpy(value->data, ocn->data.data, value->len);

    /* Reinsert into expire queue at correct sorted position */
    ngx_queue_remove(&ocn->queue);
    mem_queue_insert_expire(&octx->expire_queue, ocn);

    ngx_shmtx_unlock(&octx->shpool->mutex);
    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_memory_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key)
{
    shm_zone_t *octx;
    store_node_t *ocn;
    uint32_t hash;

    /* Validate store and get shared memory context */
    if (mem_validate_store(r, store, &octx) != NGX_OK) {
        return NGX_ERROR;
    }

    hash = mem_hash_key(key->data, key->len);

    ngx_shmtx_lock(&octx->shpool->mutex);

    ocn = mem_find_node(octx, hash, key);
    if (ocn == NULL) {
        ngx_shmtx_unlock(&octx->shpool->mutex);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_memory: key=%V not found", key);
        return NGX_DECLINED;
    }

    /* Remove node */
    mem_remove_node(octx, ocn);
    ngx_shmtx_unlock(&octx->shpool->mutex);

    return NGX_OK;
}

/* Memory store expire operation */
ngx_int_t
ngx_oidc_session_store_memory_cleanup_expired(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store)
{
    shm_zone_t *octx;
    ngx_queue_t *q;
    store_node_t *ocn;
    time_t now;
    ngx_uint_t n = 0;

    if (mem_validate_store(r, store, &octx) != NGX_OK) {
        return NGX_ERROR;
    }

    now = ngx_time();

    ngx_shmtx_lock(&octx->shpool->mutex);

    while (!ngx_queue_empty(&octx->expire_queue) && n < 128) {
        q = ngx_queue_last(&octx->expire_queue);
        ocn = ngx_queue_data(q, store_node_t, queue);

        if (ocn->expires >= now) {
            break;
        }

        /* Remove expired node */
        mem_remove_node(octx, ocn);
        n++;
    }

    ngx_shmtx_unlock(&octx->shpool->mutex);
    return NGX_OK;
}

/* Shared memory zone initialization */
ngx_int_t
ngx_oidc_session_store_memory_shm_zone_init(ngx_shm_zone_t *shm_zone,
    void *data)
{
    ngx_oidc_session_store_t *store;
    shm_zone_t *octx;
    ngx_slab_pool_t *shpool;

    (void) data;

    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    /*
     * shm_zone->data points to ngx_oidc_session_store_t when set up
     * by ngx_oidc_session_store_memory_setup_zones(), or NULL for
     * the default backward-compatibility zone.
     */
    store = shm_zone->data;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    octx = ngx_slab_alloc(shpool, sizeof(shm_zone_t));
    if (octx == NULL) {
        return NGX_ERROR;
    }

    octx->shpool = shpool;
    octx->max_size = (store != NULL) ? store->memory.max_size : 1024;
    octx->count = 0;

    /* Initialize rbtree */
    ngx_rbtree_init(&octx->rbtree, &octx->sentinel,
                    ngx_str_rbtree_insert_value);

    /* Initialize expire queue */
    ngx_queue_init(&octx->expire_queue);

    shm_zone->data = octx;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_memory_lock(ngx_shm_zone_t *shm_zone)
{
    shm_zone_t *octx;

    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    octx = shm_zone->data;
    if (octx == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&octx->shpool->mutex);

    return NGX_OK;
}

void
ngx_oidc_session_store_memory_unlock(ngx_shm_zone_t *shm_zone)
{
    shm_zone_t *octx;

    if (shm_zone == NULL) {
        return;
    }

    octx = shm_zone->data;
    if (octx == NULL) {
        return;
    }

    ngx_shmtx_unlock(&octx->shpool->mutex);
}

ngx_int_t
ngx_oidc_session_store_memory_get_stats(ngx_shm_zone_t *shm_zone,
    ngx_oidc_session_store_memory_stats_t *stats)
{
    shm_zone_t *octx;

    if (shm_zone == NULL || stats == NULL) {
        return NGX_ERROR;
    }

    octx = shm_zone->data;
    if (octx == NULL) {
        return NGX_ERROR;
    }

    /* Collect statistics (caller must hold lock) */
    stats->state_entries = octx->count;
    stats->max_entries = octx->max_size;
    stats->shm_size = shm_zone->shm.size;

    return NGX_OK;
}

ngx_oidc_session_store_memory_stats_t *
ngx_oidc_session_store_memory_stats_create(ngx_pool_t *pool)
{
    ngx_oidc_session_store_memory_stats_t *stats;

    stats = ngx_palloc(pool, sizeof(ngx_oidc_session_store_memory_stats_t));
    if (stats == NULL) {
        return NULL;
    }

    ngx_memzero(stats, sizeof(ngx_oidc_session_store_memory_stats_t));

    return stats;
}

size_t
ngx_oidc_session_store_memory_stats_get_state_entries(
    const ngx_oidc_session_store_memory_stats_t *stats)
{
    if (stats == NULL) {
        return 0;
    }
    return stats->state_entries;
}

size_t
ngx_oidc_session_store_memory_stats_get_max_entries(
    const ngx_oidc_session_store_memory_stats_t *stats)
{
    if (stats == NULL) {
        return 0;
    }
    return stats->max_entries;
}

size_t
ngx_oidc_session_store_memory_stats_get_shm_size(
    const ngx_oidc_session_store_memory_stats_t *stats)
{
    if (stats == NULL) {
        return 0;
    }
    return stats->shm_size;
}
