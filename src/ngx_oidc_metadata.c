/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_oidc_metadata.h"
#include "ngx_oidc_http.h"
#include "ngx_oidc_json.h"

/** Metadata cache structure (opaque type) */
struct ngx_oidc_metadata_cache_s {
    ngx_str_t  issuer;
    /** discovered endpoint URIs */
    struct {
        ngx_str_t  authorization;
        ngx_str_t  token;
        ngx_str_t  userinfo;
        ngx_str_t  jwks_uri;
        ngx_str_t  end_session;
    } endpoints;
    time_t  fetched_at;
    time_t  expires_at;
};

/** Metadata cache node (shared memory) */
typedef struct {
    /** rbtree node (must be first) */
    ngx_rbtree_node_t          node;
    /** CRC32 hash of issuer URL */
    ngx_uint_t                 key_hash;
    ngx_oidc_metadata_cache_t  metadata;
    /** 1 if fetch ongoing, 0 otherwise */
    ngx_uint_t                 fetching;
} metadata_cache_node_t;

/** Provider metadata structure (configuration array element) */
typedef struct {
    ngx_str_t  provider_name;
    ngx_str_t  issuer;
    ngx_str_t  redirect_uri;
    /** discovered endpoint URIs */
    struct {
        ngx_str_t  authorization;
        ngx_str_t  token;
        ngx_str_t  userinfo;
        ngx_str_t  jwks_uri;
        ngx_str_t  end_session;
    } endpoints;
    time_t      metadata_expires;
    ngx_flag_t  metadata_valid;
} ngx_oidc_metadata_t;

/** Metadata shared memory zone structure */
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_slab_pool_t   *shpool;
} metadata_shm_t;

/** Context for metadata fetch subrequest */
typedef struct {
    ngx_http_request_t        *main_request;
    ngx_str_t                  issuer;
    ngx_oidc_metadata_done_pt  callback;
    void                      *data;
} metadata_fetch_ctx_t;

/* Module-level shared memory zone pointer */
static metadata_shm_t *metadata_shm = NULL;

/**
 * Custom rbtree insertion with hash collision handling
 *
 * Inserts a node into the rbtree, using issuer string comparison
 * to resolve hash collisions.
 *
 * @param[in] temp      Current tree node being compared
 * @param[in] node      Node to insert
 * @param[in] sentinel  Tree sentinel node
 */
static void
metadata_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    metadata_cache_node_t *cn, *cnt;
    ngx_int_t rc;

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
            /* Same hash key, compare issuer strings for collision handling */
            cn = (metadata_cache_node_t *) node;
            cnt = (metadata_cache_node_t *) temp;
            rc = ngx_memn2cmp(cn->metadata.issuer.data,
                              cnt->metadata.issuer.data,
                              cn->metadata.issuer.len,
                              cnt->metadata.issuer.len);
            if (rc < 0) {
                if (temp->left == sentinel) {
                    temp->left = node;
                    break;
                }
                temp = temp->left;
            } else if (rc > 0) {
                if (temp->right == sentinel) {
                    temp->right = node;
                    break;
                }
                temp = temp->right;
            } else {
                /* Duplicate - same issuer, keep existing */
                break;
            }
        }
    }

    ngx_rbt_red(node);
}

/** Context for rbtree traversal */
typedef struct {
    ngx_oidc_metadata_iterate_pt  callback;
    void *data;
    ngx_int_t                     result;
} metadata_traverse_ctx_t;

/* Recursive rbtree traversal helper */
static void
metadata_rbtree_traverse(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    metadata_traverse_ctx_t *ctx)
{
    metadata_cache_node_t *cache_node;

    if (node == sentinel) {
        return;
    }

    /* Traverse left subtree */
    if (node->left != sentinel) {
        metadata_rbtree_traverse(node->left, sentinel, ctx);
    }

    /* Process current node */
    if (ctx->result == NGX_OK) {
        cache_node = (metadata_cache_node_t *) node;

        /* Extract issuer from metadata */
        ngx_str_t issuer = cache_node->metadata.issuer;

        ctx->result = ctx->callback(&issuer, &cache_node->metadata, ctx->data);
    }

    /* Traverse right subtree */
    if (node->right != sentinel && ctx->result == NGX_OK) {
        metadata_rbtree_traverse(node->right, sentinel, ctx);
    }
}

/**
 * Look up metadata cache entry by issuer (caller must hold shm lock)
 *
 * @param[in] issuer  OIDC issuer identifier
 * @param[in] shm     Shared memory context
 *
 * @return Cache node if found, NULL if not found
 */
static metadata_cache_node_t *
metadata_cache_lookup_locked(ngx_str_t *issuer, metadata_shm_t *shm)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    metadata_cache_node_t *cache_node;
    ngx_int_t rc;

    /* Calculate CRC32 hash */
    hash = ngx_crc32_short(issuer->data, issuer->len);

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

        /* Hash matches, compare issuer string */
        cache_node = (metadata_cache_node_t *) node;
        rc = ngx_memn2cmp(issuer->data, cache_node->metadata.issuer.data,
                          issuer->len, cache_node->metadata.issuer.len);
        if (rc == 0) {
            return cache_node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* Not found */
    return NULL;
}

/* Deep copy a ngx_str_t from shared memory to pool */
static ngx_int_t
metadata_str_copy_to_pool(ngx_pool_t *pool, ngx_str_t *dst,
    const ngx_str_t *src)
{
    if (src->len == 0 || src->data == NULL) {
        dst->len = 0;
        dst->data = NULL;
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->len = src->len;

    return NGX_OK;
}

/**
 * Deep copy metadata from shared memory to pool-allocated structure
 *
 * Must be called while shm lock is held.
 *
 * @param[in] pool  Memory pool for allocation
 * @param[in] src   Source metadata in shared memory
 *
 * @return Pool-allocated copy of metadata, or NULL on failure
 */
static ngx_oidc_metadata_cache_t *
metadata_deep_copy_to_pool(ngx_pool_t *pool,
    const ngx_oidc_metadata_cache_t *src)
{
    ngx_oidc_metadata_cache_t *dst;

    dst = ngx_pcalloc(pool, sizeof(ngx_oidc_metadata_cache_t));
    if (dst == NULL) {
        return NULL;
    }

    if (metadata_str_copy_to_pool(pool, &dst->issuer, &src->issuer) != NGX_OK
        || metadata_str_copy_to_pool(pool, &dst->endpoints.authorization,
                                     &src->endpoints.authorization) != NGX_OK
        || metadata_str_copy_to_pool(pool, &dst->endpoints.token,
                                     &src->endpoints.token) != NGX_OK
        || metadata_str_copy_to_pool(pool, &dst->endpoints.userinfo,
                                     &src->endpoints.userinfo) != NGX_OK
        || metadata_str_copy_to_pool(pool, &dst->endpoints.jwks_uri,
                                     &src->endpoints.jwks_uri) != NGX_OK
        || metadata_str_copy_to_pool(pool, &dst->endpoints.end_session,
                                     &src->endpoints.end_session) != NGX_OK)
    {
        return NULL;
    }

    dst->fetched_at = src->fetched_at;
    dst->expires_at = src->expires_at;

    return dst;
}

/* Saves metadata to shared memory cache */
static ngx_int_t
metadata_shm_save(ngx_http_request_t *r, ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t *metadata)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    metadata_cache_node_t *cache_node;
    metadata_shm_t *shm;
    u_char *new_data[6];
    ngx_str_t *src_fields[6];
    ngx_str_t *dest_fields[6];
    u_char *old_data[6];
    ngx_uint_t i, allocated_count;
    ngx_int_t rc;

    shm = metadata_shm;
    if (shm == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: shared memory zone not initialized");
        return NGX_ERROR;
    }

    /* Calculate CRC32 hash */
    hash = ngx_crc32_short(issuer->data, issuer->len);

    /* Lock shared memory */
    ngx_shmtx_lock(&shm->shpool->mutex);

    /* Check if entry exists (search directly in Rbtree while locked) */
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

        /* Hash matches, compare issuer string */
        cache_node = (metadata_cache_node_t *) node;
        rc = ngx_memn2cmp(issuer->data, cache_node->metadata.issuer.data,
                          issuer->len, cache_node->metadata.issuer.len);
        if (rc == 0) {
            goto update_cache;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* Not found, allocate new cache node */
    cache_node = ngx_slab_alloc_locked(shm->shpool,
                                       sizeof(metadata_cache_node_t));
    if (cache_node == NULL) {
        ngx_shmtx_unlock(&shm->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: failed to allocate cache node "
                      "(out of memory)");
        /* Not fatal, continue without cache */
        return NGX_DECLINED;
    }

    /* Initialize cache node */
    cache_node->node.key = hash;
    cache_node->key_hash = hash;
    ngx_memzero(&cache_node->metadata, sizeof(ngx_oidc_metadata_cache_t));
    cache_node->fetching = 0;

    /* Pre-allocate issuer string for rbtree ordering */
    cache_node->metadata.issuer.data = ngx_slab_alloc_locked(
        shm->shpool, issuer->len);
    if (cache_node->metadata.issuer.data == NULL) {
        ngx_slab_free_locked(shm->shpool, cache_node);
        ngx_shmtx_unlock(&shm->shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: failed to allocate issuer string "
                      "(out of memory)");
        return NGX_DECLINED;
    }

    ngx_memcpy(cache_node->metadata.issuer.data, issuer->data, issuer->len);
    cache_node->metadata.issuer.len = issuer->len;

    /* Insert into Rbtree */
    ngx_rbtree_insert(&shm->rbtree, &cache_node->node);

update_cache:
    /*
     * Transactional memory allocation for all string fields.
     * This ensures that either all fields are successfully updated,
     * or none are (preventing partial memory leaks).
     */

    /* Setup field mappings for transactional processing */
    src_fields[0] = &metadata->issuer;
    src_fields[1] = &metadata->endpoints.authorization;
    src_fields[2] = &metadata->endpoints.token;
    src_fields[3] = &metadata->endpoints.userinfo;
    src_fields[4] = &metadata->endpoints.jwks_uri;
    src_fields[5] = &metadata->endpoints.end_session;

    dest_fields[0] = &cache_node->metadata.issuer;
    dest_fields[1] = &cache_node->metadata.endpoints.authorization;
    dest_fields[2] = &cache_node->metadata.endpoints.token;
    dest_fields[3] = &cache_node->metadata.endpoints.userinfo;
    dest_fields[4] = &cache_node->metadata.endpoints.jwks_uri;
    dest_fields[5] = &cache_node->metadata.endpoints.end_session;

    /* Initialize temporary arrays */
    ngx_memzero(new_data, sizeof(new_data));
    ngx_memzero(old_data, sizeof(old_data));
    allocated_count = 0;

    /* Allocate all required memory (transactional - all or nothing) */
    for (i = 0; i < 6; i++) {
        if (src_fields[i]->len > 0) {
            /* Check if we need to allocate new memory */
            if (dest_fields[i]->data == NULL
                || dest_fields[i]->len != src_fields[i]->len)
            {
                /* Allocate new memory */
                new_data[i] = ngx_slab_alloc_locked(shm->shpool,
                                                    src_fields[i]->len);
                if (new_data[i] == NULL) {
                    ngx_uint_t j;

                    /* Allocation failed - rollback all previous allocations */
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "oidc_metadata: failed to allocate string "
                                  "in shared memory (field %ui)", i);

                    /* Free only newly allocated memory (not reused) */
                    for (j = 0; j < i; j++) {
                        if (new_data[j] != NULL
                            && new_data[j] != dest_fields[j]->data)
                        {
                            ngx_slab_free_locked(shm->shpool, new_data[j]);
                        }
                    }

                    ngx_shmtx_unlock(&shm->shpool->mutex);
                    return NGX_ERROR;
                }

                /* Save old data pointer for later cleanup */
                if (dest_fields[i]->data != NULL) {
                    old_data[i] = dest_fields[i]->data;
                }

                allocated_count++;
            } else {
                /* Reuse existing memory (size matches) */
                new_data[i] = dest_fields[i]->data;
            }
        } else {
            /* Source is empty - mark destination for cleanup */
            if (dest_fields[i]->data != NULL) {
                old_data[i] = dest_fields[i]->data;
            }
        }
    }

    /* All allocations succeeded - now safely update the cache node */

    /* First, copy data to new memory and update pointers */
    for (i = 0; i < 6; i++) {
        if (src_fields[i]->len > 0 && new_data[i] != NULL) {
            /* Copy string data */
            ngx_memcpy(new_data[i], src_fields[i]->data, src_fields[i]->len);
            dest_fields[i]->data = new_data[i];
            dest_fields[i]->len = src_fields[i]->len;
        } else if (src_fields[i]->len == 0 && i > 0) {
            /* Source is empty - clear destination (skip issuer field) */
            dest_fields[i]->data = NULL;
            dest_fields[i]->len = 0;
        }
    }

    /* Free old memory that is no longer needed */
    for (i = 0; i < 6; i++) {
        if (old_data[i] != NULL) {
            ngx_slab_free_locked(shm->shpool, old_data[i]);
        }
    }

    /* Copy time fields */
    cache_node->metadata.fetched_at = metadata->fetched_at;
    cache_node->metadata.expires_at = metadata->expires_at;

    ngx_shmtx_unlock(&shm->shpool->mutex);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: saved cache for issuer: %V", issuer);

    return NGX_OK;
}

static ngx_int_t
metadata_parse_json(ngx_http_request_t *r, ngx_str_t *body,
    ngx_oidc_metadata_cache_t *metadata)
{
    ngx_oidc_json_t *root;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: parsing JSON response, length=%uz",
                   body->len);

    /* Parse JSON from external OIDC provider (untrusted source) */
    root = ngx_oidc_json_parse_untrusted(body, r->pool);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: failed to parse JSON");
        return NGX_ERROR;
    }

    /* Extract issuer */
    if (ngx_oidc_json_object_get_string(root, "issuer", &metadata->issuer,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_null(&metadata->issuer);
    }

    /* Extract authorization_endpoint */
    if (ngx_oidc_json_object_get_string(root, "authorization_endpoint",
                                        &metadata->endpoints.authorization,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_null(&metadata->endpoints.authorization);
    }

    /* Extract token_endpoint */
    if (ngx_oidc_json_object_get_string(root, "token_endpoint",
                                        &metadata->endpoints.token,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_null(&metadata->endpoints.token);
    }

    /* Extract userinfo_endpoint */
    if (ngx_oidc_json_object_get_string(root, "userinfo_endpoint",
                                        &metadata->endpoints.userinfo,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_null(&metadata->endpoints.userinfo);
    }

    /* Extract jwks_uri */
    if (ngx_oidc_json_object_get_string(root, "jwks_uri",
                                        &metadata->endpoints.jwks_uri,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_null(&metadata->endpoints.jwks_uri);
    }

    /* Extract end_session_endpoint (optional) */
    if (ngx_oidc_json_object_get_string(root, "end_session_endpoint",
                                        &metadata->endpoints.end_session,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_null(&metadata->endpoints.end_session);
    }

    /* Set timestamps */
    metadata->fetched_at = ngx_time();
    metadata->expires_at = metadata->fetched_at + 3600; /* 1 hour TTL */

    /* Free JSON */
    ngx_oidc_json_free(root);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: JSON parsing completed successfully");

    return NGX_OK;
}

static ngx_int_t
metadata_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    metadata_fetch_ctx_t *ctx = data;
    ngx_str_t body;
    ngx_oidc_metadata_cache_t *metadata;
    ngx_oidc_metadata_cache_t *existing_metadata;
    ngx_int_t status;
    ngx_int_t cache_rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->main_request->connection->log, 0,
                   "oidc_metadata: subrequest completed");

    /* Check subrequest completion status */
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_metadata: subrequest failed with rc=%i", rc);
        ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Get response status using Week 2 HTTP module */
    status = ngx_oidc_http_response_status(r);
    if (status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_metadata: subrequest returned HTTP %i", status);
        ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Get response body using Week 2 HTTP module */
    if (ngx_oidc_http_response_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_metadata: failed to get response body");
        ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->main_request->connection->log, 0,
                   "oidc_metadata: received response body, length=%uz",
                   body.len);

    /* Allocate metadata from main request pool (not stack) */
    metadata = ngx_pcalloc(ctx->main_request->pool,
                           sizeof(ngx_oidc_metadata_cache_t));
    if (metadata == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_metadata: failed to allocate metadata structure");
        ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Parse JSON */
    if (metadata_parse_json(ctx->main_request, &body, metadata) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->main_request->connection->log, 0,
                      "oidc_metadata: failed to parse metadata JSON");
        ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);
        return ctx->callback(ctx->main_request, NULL, ctx->data);
    }

    /* Double-check: verify another request hasn't already saved valid */
    cache_rc = ngx_oidc_metadata_get(ctx->main_request, &ctx->issuer,
                                     &existing_metadata);
    if (cache_rc == NGX_OK && existing_metadata != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                       ctx->main_request->connection->log, 0,
                       "oidc_metadata: another request already "
                       "saved metadata, skipping save");
        ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);
        return ctx->callback(ctx->main_request, existing_metadata, ctx->data);
    }

    /* Save to cache */
    metadata->issuer = ctx->issuer;
    if (metadata_shm_save(ctx->main_request, &ctx->issuer, metadata)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, ctx->main_request->connection->log, 0,
                      "oidc_metadata: failed to save to cache, "
                      "continuing anyway");
    }

    /* Clear fetch flag after successful save */
    ngx_oidc_metadata_clear_fetch_flag(ctx->main_request, &ctx->issuer);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->main_request->connection->log, 0,
                   "oidc_metadata: metadata fetch and cache save completed");

    /* Invoke callback with pool-allocated metadata */
    return ctx->callback(ctx->main_request, metadata, ctx->data);
}

ngx_int_t
ngx_oidc_metadata_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    metadata_shm_t *shm;
    ngx_slab_pool_t *shpool;

    /* Validate input parameters */
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    if (data) {
        /* Zone already initialized (worker process restart) */
        shm_zone->data = data;
        return NGX_OK;
    }

    /* Get slab pool (shared memory starts with ngx_slab_pool_t) */
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Allocate shared memory structure */
    shm = ngx_slab_alloc(shpool, sizeof(metadata_shm_t));
    if (shm == NULL) {
        return NGX_ERROR;
    }

    shm->shpool = shpool;

    /* Initialize Rbtree */
    ngx_rbtree_init(&shm->rbtree, &shm->sentinel, metadata_rbtree_insert);

    shm_zone->data = shm;
    metadata_shm = shm;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_metadata_get(ngx_http_request_t *r, ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t **metadata)
{
    metadata_cache_node_t *cache_node;
    ngx_oidc_metadata_cache_t *copy;
    metadata_shm_t *shm;
    ngx_int_t rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: getting metadata for issuer: %V", issuer);

    shm = metadata_shm;
    if (shm == NULL) {
        *metadata = NULL;
        return NGX_DECLINED;
    }

    /* Lock shared memory for lookup + copy */
    ngx_shmtx_lock(&shm->shpool->mutex);

    cache_node = metadata_cache_lookup_locked(issuer, shm);
    if (cache_node == NULL) {
        ngx_shmtx_unlock(&shm->shpool->mutex);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_metadata: cache miss for issuer: %V", issuer);
        *metadata = NULL;
        return NGX_DECLINED;
    }

    /* Check TTL before deep copy */
    rc = (ngx_time() > cache_node->metadata.expires_at)
        ? NGX_DECLINED : NGX_OK;

    /* Deep copy metadata to request pool while lock is held */
    copy = metadata_deep_copy_to_pool(r->pool, &cache_node->metadata);

    ngx_shmtx_unlock(&shm->shpool->mutex);

    if (copy == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: failed to copy metadata to request pool");
        *metadata = NULL;
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_metadata: cache expired for issuer: %V", issuer);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_metadata: cache hit for issuer: %V", issuer);
    }

    *metadata = copy;
    return rc;
}

ngx_int_t
ngx_oidc_metadata_fetch(ngx_http_request_t *r, ngx_str_t *issuer,
    ngx_str_t *discovery_url, ngx_oidc_metadata_done_pt callback, void *data)
{
    metadata_fetch_ctx_t *ctx;

    /* Validate input parameters */
    if (r == NULL || issuer == NULL || discovery_url == NULL
        || callback == NULL)
    {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_metadata_fetch: NULL parameter");
        }
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: fetching metadata for issuer=%V from url=%V",
                   issuer, discovery_url);

    /* Create context */
    ctx = ngx_pcalloc(r->pool, sizeof(metadata_fetch_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: failed to allocate fetch context");
        return NGX_ERROR;
    }

    ctx->main_request = r;
    ctx->issuer = *issuer;
    ctx->callback = callback;
    ctx->data = data;

    /* Create external URL fetch using Week 2 HTTP module */
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: creating GET request "
                   "for discovery endpoint");

    return ngx_oidc_http_get(r, discovery_url, metadata_subrequest_done, ctx);
}

ngx_int_t
ngx_oidc_metadata_try_lock_fetch(ngx_http_request_t *r, ngx_str_t *issuer)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    metadata_cache_node_t *cache_node;
    metadata_shm_t *shm;
    time_t now;
    ngx_int_t rc;

    shm = metadata_shm;
    if (shm == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_short(issuer->data, issuer->len);
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

        /* Hash matches, compare issuer string */
        cache_node = (metadata_cache_node_t *) node;
        rc = ngx_memn2cmp(issuer->data, cache_node->metadata.issuer.data,
                          issuer->len, cache_node->metadata.issuer.len);
        if (rc == 0) {
            /* Found existing entry */

            /* Check if fetch already in progress */
            if (cache_node->fetching) {
                ngx_shmtx_unlock(&shm->shpool->mutex);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_metadata: fetch already in progress "
                               "for: %V",
                               issuer);
                return NGX_BUSY;
            }

            /* Check if entry is still valid */
            if (cache_node->metadata.expires_at > now) {
                ngx_shmtx_unlock(&shm->shpool->mutex);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_metadata: valid entry found for: %V",
                               issuer);
                return NGX_DECLINED;
            }

            /* Entry expired, acquire lock */
            cache_node->fetching = 1;
            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_metadata: acquired fetch lock for: %V",
                           issuer);
            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* Entry not found, unlock and create placeholder */
    ngx_shmtx_unlock(&shm->shpool->mutex);

    /* Create placeholder with empty metadata (issuer set for rbtree key) */
    ngx_oidc_metadata_cache_t empty_metadata;
    ngx_memzero(&empty_metadata, sizeof(ngx_oidc_metadata_cache_t));
    empty_metadata.issuer = *issuer;
    empty_metadata.fetched_at = 0;
    empty_metadata.expires_at = 0;

    rc = metadata_shm_save(r, issuer, &empty_metadata);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Re-lock and set fetching flag on the created placeholder */
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

        /* Hash matches, compare issuer string */
        cache_node = (metadata_cache_node_t *) node;
        rc = ngx_memn2cmp(issuer->data, cache_node->metadata.issuer.data,
                          issuer->len, cache_node->metadata.issuer.len);
        if (rc == 0) {
            /* Check if another worker already claimed this entry */
            if (cache_node->fetching) {
                ngx_shmtx_unlock(&shm->shpool->mutex);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_metadata: fetch already claimed by "
                               "another worker for: %V",
                               issuer);
                return NGX_BUSY;
            }

            cache_node->fetching = 1;
            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_metadata: created placeholder "
                           "and acquired fetch lock for: %V",
                           issuer);
            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "oidc_metadata: placeholder not found after creation");
    return NGX_ERROR;
}

void
ngx_oidc_metadata_clear_fetch_flag(ngx_http_request_t *r, ngx_str_t *issuer)
{
    ngx_uint_t hash;
    ngx_rbtree_node_t *node, *sentinel;
    metadata_cache_node_t *cache_node;
    metadata_shm_t *shm;
    ngx_int_t rc;

    shm = metadata_shm;
    if (shm == NULL) {
        return;
    }

    hash = ngx_crc32_short(issuer->data, issuer->len);

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

        /* Hash matches, compare issuer string */
        cache_node = (metadata_cache_node_t *) node;
        rc = ngx_memn2cmp(issuer->data, cache_node->metadata.issuer.data,
                          issuer->len, cache_node->metadata.issuer.len);
        if (rc == 0) {
            /* Found - clear flag */
            cache_node->fetching = 0;
            ngx_shmtx_unlock(&shm->shpool->mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_metadata: cleared fetch flag for: %V",
                           issuer);
            return;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_metadata: entry not found when clearing "
                   "fetch flag for: %V",
                   issuer);
}

ngx_int_t
ngx_oidc_metadata_iterate(ngx_http_request_t *r,
    ngx_oidc_metadata_iterate_pt callback, void *data)
{
    metadata_shm_t *shm;
    metadata_traverse_ctx_t ctx;

    shm = metadata_shm;
    if (shm == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_metadata: shared memory not initialized");
        return NGX_ERROR;
    }

    ctx.callback = callback;
    ctx.data = data;
    ctx.result = NGX_OK;

    /* Lock shared memory */
    ngx_shmtx_lock(&shm->shpool->mutex);

    /* Traverse rbtree */
    if (shm->rbtree.root != shm->rbtree.sentinel) {
        metadata_rbtree_traverse(shm->rbtree.root, shm->rbtree.sentinel, &ctx);
    }

    /* Unlock shared memory */
    ngx_shmtx_unlock(&shm->shpool->mutex);

    return ctx.result;
}

ngx_str_t *
ngx_oidc_metadata_get_authorization_endpoint(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &metadata->endpoints.authorization;
}

ngx_str_t *
ngx_oidc_metadata_get_token_endpoint(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &metadata->endpoints.token;
}

ngx_str_t *
ngx_oidc_metadata_get_userinfo_endpoint(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &metadata->endpoints.userinfo;
}

ngx_str_t *
ngx_oidc_metadata_get_jwks_uri(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &metadata->endpoints.jwks_uri;
}

ngx_str_t *
ngx_oidc_metadata_get_end_session_endpoint(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &metadata->endpoints.end_session;
}

ngx_str_t *
ngx_oidc_metadata_get_issuer(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &metadata->issuer;
}

ngx_array_t *
ngx_oidc_metadata_create_array(ngx_pool_t *pool, ngx_uint_t n)
{
    return ngx_array_create(pool, n, sizeof(ngx_oidc_metadata_t));
}

time_t
ngx_oidc_metadata_get_fetched_at(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return 0;
    }
    return metadata->fetched_at;
}

time_t
ngx_oidc_metadata_get_expires_at(
    const ngx_oidc_metadata_cache_t *metadata)
{
    if (metadata == NULL) {
        return 0;
    }
    return metadata->expires_at;
}
