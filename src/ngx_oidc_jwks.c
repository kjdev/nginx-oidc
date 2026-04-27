/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "nxe_jwx.h"

#include "ngx_oidc_jwks.h"
#include "ngx_oidc_http.h"

/** JWKS shared memory node (stores raw JWKS JSON for re-parse + status) */
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

/** JWKS cache node structure (encapsulated, lives in request pool) */
struct ngx_oidc_jwks_cache_node_s {
    ngx_str_t       jwks_uri;
    /** parsed keyset returned by nxe_jwx_jwks_parse */
    nxe_jwx_jwks_t *jwks;
    time_t          fetched_at;
    time_t          expires_at;
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

/*
 * Parse JWKS JSON via nxe-jwx and build a request-pool cache node
 */
static ngx_int_t
jwks_parse_json_to_cache(ngx_http_request_t *r, ngx_str_t *jwks_json,
    ngx_oidc_jwks_cache_node_t **cache_node)
{
    ngx_oidc_jwks_cache_node_t *node;
    nxe_jwx_jwks_t *jwks;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: parsing JWKS JSON, length=%uz", jwks_json->len);

    /* Validate JWKS JSON size (nxe-jwx enforces its own ceiling, but we
     * keep the OIDC-side limit for parity with the SHM accept path) */
    if (jwks_json->len > NGX_OIDC_MAX_JWKS_SIZE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: JWKS JSON too large: %uz bytes "
                      "(limit: %uz)", jwks_json->len,
                      (size_t) NGX_OIDC_MAX_JWKS_SIZE);
        return NGX_ERROR;
    }

    /* Allocate cache node in request pool */
    node = ngx_pcalloc(r->pool, sizeof(ngx_oidc_jwks_cache_node_t));
    if (node == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: failed to allocate cache node");
        return NGX_ERROR;
    }

    /* Delegate JWKS parsing (alg/kid/EVP_PKEY construction, DoS limits,
     * pool cleanup registration) to nxe-jwx. */
    jwks = nxe_jwx_jwks_parse(jwks_json, r->pool);
    if (jwks == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_jwks: nxe_jwx_jwks_parse failed");
        return NGX_ERROR;
    }

    node->jwks = jwks;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_jwks: successfully parsed %ui keys",
                   nxe_jwx_jwks_count(jwks));

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

    for ( ;; ) {
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

    /* Parse JSON to cache node (in request pool) via nxe-jwx */
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
                   "oidc_jwks: JWKS fetch completed, keys=%ui",
                   nxe_jwx_jwks_count(cache_node->jwks));

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

    /* Parse copied JSON via nxe-jwx (lock released) */
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
                   "oidc_jwks: cache hit for uri: %V, keys=%ui", jwks_uri,
                   nxe_jwx_jwks_count(cache_node->jwks));
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

ngx_str_t *
ngx_oidc_jwks_cache_node_get_jwks_uri(const ngx_oidc_jwks_cache_node_t *node)
{
    if (node == NULL) {
        return NULL;
    }
    return (ngx_str_t *) &node->jwks_uri;
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

nxe_jwx_jwks_t *
ngx_oidc_jwks_cache_node_get_jwx_jwks(const ngx_oidc_jwks_cache_node_t *node)
{
    if (node == NULL) {
        return NULL;
    }
    return node->jwks;
}

ngx_uint_t
ngx_oidc_jwks_get_key_count(const ngx_oidc_jwks_cache_node_t *jwks)
{
    if (jwks == NULL || jwks->jwks == NULL) {
        return 0;
    }
    return nxe_jwx_jwks_count(jwks->jwks);
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
