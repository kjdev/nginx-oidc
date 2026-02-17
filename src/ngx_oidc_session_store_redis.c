/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "ngx_oidc_session_store.h"
#include "ngx_oidc_session_store_redis.h"

/** Redis connection context */
typedef struct {
    /** hiredis connection handle */
    redisContext *context;
    ngx_pool_t   *pool;
    ngx_log_t    *log;
    time_t        last_connect;
    ngx_uint_t    connection_failures;
    ngx_flag_t    connected;
} redis_ctx_t;

/* Redis cleanup handler (called when pool is destroyed) */
static void
redis_cleanup(void *data)
{
    ngx_oidc_session_store_t *store;
    redis_ctx_t *ctx;

    store = data;
    if (store == NULL || store->data == NULL) {
        return;
    }

    ctx = (redis_ctx_t *) store->data;

    if (ctx->context != NULL) {
        redisFree(ctx->context);
        ctx->context = NULL;
    }

    ctx->connected = 0;
}

/**
 * Establish Redis connection with authentication
 *
 * Connects to Redis server using store configuration (host, port, timeout),
 * performs authentication if password is configured, and selects database.
 * Registers a pool cleanup handler for disconnection.
 *
 * @param[in] store  Session store with Redis configuration
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
static ngx_int_t
redis_connect(ngx_oidc_session_store_t *store)
{
    redis_ctx_t *ctx;
    struct timeval timeout;
    redisReply *reply;
    char hostname[256];

    if (store == NULL || store->data == NULL) {
        return NGX_ERROR;
    }

    ctx = (redis_ctx_t *) store->data;

    /* Check if already connected */
    if (ctx->connected && ctx->context != NULL) {
        return NGX_OK;
    }

    /* Set connection timeout */
    timeout.tv_sec = store->redis.connect_timeout / 1000;
    timeout.tv_usec = (store->redis.connect_timeout % 1000) * 1000;

    /* Create null-terminated hostname for hiredis API */
    if (store->redis.hostname.len >= sizeof(hostname)) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                      "oidc_store_redis: hostname too long: %uz",
                      store->redis.hostname.len);
        return NGX_ERROR;
    }

    ngx_memcpy(hostname, store->redis.hostname.data,
               store->redis.hostname.len);
    hostname[store->redis.hostname.len] = '\0';

    /* Connect to Redis */
    ctx->context = redisConnectWithTimeout(hostname,
                                           store->redis.port, timeout);

    if (ctx->context == NULL || ctx->context->err) {
        if (ctx->context) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "oidc_store_redis: connection failed: %s",
                          ctx->context->errstr);
            redisFree(ctx->context);
            ctx->context = NULL;
        } else {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "oidc_store_redis: connection allocation failed");
        }
        ctx->connected = 0;
        ctx->connection_failures++;
        ctx->last_connect = ngx_time();
        return NGX_ERROR;
    }

    /* Set command timeout */
    timeout.tv_sec = store->redis.command_timeout / 1000;
    timeout.tv_usec = (store->redis.command_timeout % 1000) * 1000;

    if (redisSetTimeout(ctx->context, timeout) != REDIS_OK) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                      "oidc_store_redis: failed to set command timeout");
    }

    /* Authenticate if password is provided */
    if (store->redis.password.len > 0) {
        reply =
            redisCommand(ctx->context, "AUTH %b", store->redis.password.data,
                         store->redis.password.len);
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "oidc_store_redis: authentication failed: %s",
                          reply ? reply->str : "connection error");
            if (reply)
                freeReplyObject(reply);
            redisFree(ctx->context);
            ctx->context = NULL;
            ctx->connected = 0;
            return NGX_ERROR;
        }
        freeReplyObject(reply);
    }

    /* Select database if specified */
    if (store->redis.database > 0) {
        reply = redisCommand(ctx->context, "SELECT %d", store->redis.database);
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                          "oidc_store_redis: database selection failed: %s",
                          reply ? reply->str : "connection error");
            if (reply)
                freeReplyObject(reply);
            redisFree(ctx->context);
            ctx->context = NULL;
            ctx->connected = 0;
            return NGX_ERROR;
        }
        freeReplyObject(reply);
    }

    ctx->connected = 1;
    ctx->connection_failures = 0;
    ctx->last_connect = ngx_time();

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
                  "oidc_store_redis: connected to %V:%d",
                  &store->redis.hostname, store->redis.port);

    return NGX_OK;
}

/* Redis connection check */
static ngx_int_t
redis_check_connection(ngx_oidc_session_store_t *store)
{
    redis_ctx_t *ctx;
    redisReply *reply;

    if (store == NULL || store->data == NULL) {
        return NGX_ERROR;
    }

    ctx = (redis_ctx_t *) store->data;

    if (!ctx->connected || ctx->context == NULL) {
        return redis_connect(store);
    }

    /* Send PING command to check connection */
    reply = redisCommand(ctx->context, "PING");
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
                      "oidc_store_redis: connection check failed, "
                      "reconnecting");
        if (reply)
            freeReplyObject(reply);

        redisFree(ctx->context);
        ctx->context = NULL;
        ctx->connected = 0;

        return redis_connect(store);
    }

    freeReplyObject(reply);
    return NGX_OK;
}

/* Format Redis key with prefix */
static ngx_int_t
redis_format_key(ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *key,
    ngx_str_t *formatted_key)
{
    u_char *p;

    if (pool == NULL || key == NULL || formatted_key == NULL) {
        return NGX_ERROR;
    }

    formatted_key->len = (prefix ? prefix->len : 0) + key->len;
    formatted_key->data = ngx_pnalloc(pool, formatted_key->len);
    if (formatted_key->data == NULL) {
        return NGX_ERROR;
    }

    p = formatted_key->data;
    if (prefix && prefix->len > 0) {
        p = ngx_cpymem(p, prefix->data, prefix->len);
    }
    ngx_memcpy(p, key->data, key->len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_redis_init(ngx_oidc_session_store_t *store,
    ngx_pool_t *pool, ngx_log_t *log)
{
    redis_ctx_t *ctx;
    ngx_pool_cleanup_t *cln;

    if (store == NULL || log == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(pool, sizeof(redis_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oidc_store_redis: failed to allocate Redis context");
        return NGX_ERROR;
    }

    ctx->context = NULL;
    ctx->pool = pool;
    ctx->log = log;
    ctx->connected = 0;
    ctx->connection_failures = 0;
    ctx->last_connect = 0;

    store->data = ctx;

    /* Register cleanup handler for Redis connection */
    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = redis_cleanup;
    cln->data = store;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_redis_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires)
{
    redis_ctx_t *ctx;
    redisReply *reply;
    ngx_str_t formatted_key;
    ngx_int_t rc;

    if (r == NULL || store == NULL || key == NULL || value == NULL) {
        return NGX_ERROR;
    }

    ctx = (redis_ctx_t *) store->data;
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* Check and establish connection */
    if (redis_check_connection(store) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Format key with prefix */
    rc =
        redis_format_key(r->pool, &store->prefix, key, &formatted_key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Execute SET command with TTL */
    if (expires > 0) {
        time_t ttl = expires - ngx_time();
        if (ttl <= 0) {
            ttl = 1; /* Minimum TTL */
        }

        reply = redisCommand(ctx->context, "SETEX %b %ld %b",
                             formatted_key.data, formatted_key.len,
                             ttl, value->data, value->len);
    } else {
        reply = redisCommand(ctx->context, "SET %b %b", formatted_key.data,
                             formatted_key.len, value->data, value->len);
    }

    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: SET failed for key \"%V\": %s",
                      key, reply ? reply->str : "connection error");
        if (reply)
            freeReplyObject(reply);
        return NGX_ERROR;
    }

    freeReplyObject(reply);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_store_redis: SET key \"%V\" value_len=%uz",
                   key, value->len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_redis_set_nx(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value,
    time_t expires)
{
    redis_ctx_t *ctx;
    redisReply *reply;
    ngx_str_t formatted_key;
    ngx_int_t rc;

    if (r == NULL || store == NULL || key == NULL || value == NULL) {
        return NGX_ERROR;
    }

    ctx = (redis_ctx_t *) store->data;
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* Check and establish connection */
    if (redis_check_connection(store) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Format key with prefix */
    rc = redis_format_key(r->pool, &store->prefix, key, &formatted_key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Execute SET NX command with TTL for atomic check-and-set */
    if (expires > 0) {
        time_t ttl = expires - ngx_time();
        if (ttl <= 0) {
            ttl = 1; /* Minimum TTL */
        }

        /* SET key value NX EX ttl - only set if not exists */
        reply = redisCommand(ctx->context, "SET %b %b NX EX %ld",
                             formatted_key.data, formatted_key.len,
                             value->data, value->len,
                             ttl);
    } else {
        /* SET key value NX - only set if not exists, no expiry */
        reply = redisCommand(ctx->context, "SET %b %b NX",
                             formatted_key.data, formatted_key.len,
                             value->data, value->len);
    }

    if (reply == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: SET NX failed for key \"%V\": "
                      "connection error",
                      key);
        return NGX_ERROR;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: SET NX failed for key \"%V\": %s",
                      key, reply->str);
        freeReplyObject(reply);
        return NGX_ERROR;
    }

    /* Check result: OK means created, nil means already exists */
    if (reply->type == REDIS_REPLY_NIL) {
        /* Key already exists */
        freeReplyObject(reply);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_redis: SET NX key \"%V\" already exists",
                       key);
        return NGX_DECLINED;
    }

    if (reply->type == REDIS_REPLY_STATUS && ngx_strcmp(reply->str, "OK")
        == 0)
    {
        /* Successfully created */
        freeReplyObject(reply);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_redis: SET NX created key \"%V\" "
                       "value_len=%uz",
                       key, value->len);
        return NGX_OK;
    }

    /* Unexpected response */
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "oidc_store_redis: SET NX unexpected response type %d "
                  "for key \"%V\"",
                  reply->type, key);
    freeReplyObject(reply);
    return NGX_ERROR;
}

ngx_int_t
ngx_oidc_session_store_redis_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key, ngx_str_t *value)
{
    redis_ctx_t *ctx;
    redisReply *reply;
    ngx_str_t formatted_key;
    ngx_int_t rc;

    if (r == NULL || store == NULL || key == NULL || value == NULL) {
        return NGX_ERROR;
    }

    ctx = (redis_ctx_t *) store->data;
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* Check and establish connection */
    if (redis_check_connection(store) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Format key with prefix */
    rc =
        redis_format_key(r->pool, &store->prefix, key, &formatted_key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Execute GET command */
    reply = redisCommand(ctx->context, "GET %b", formatted_key.data,
                         formatted_key.len);

    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: GET failed for key \"%V\": %s",
                      key, reply ? reply->str : "connection error");
        if (reply)
            freeReplyObject(reply);
        return NGX_ERROR;
    }

    if (reply->type == REDIS_REPLY_NIL) {
        /* Key not found */
        freeReplyObject(reply);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_store_redis: key \"%V\" not found", key);
        return NGX_DECLINED;
    }

    if (reply->type != REDIS_REPLY_STRING) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: unexpected reply type %d "
                      "for key \"%V\"",
                      reply->type, key);
        freeReplyObject(reply);
        return NGX_ERROR;
    }

    /* Copy value data */
    value->len = reply->len;
    value->data = ngx_pnalloc(r->pool, value->len);
    if (value->data == NULL) {
        freeReplyObject(reply);
        return NGX_ERROR;
    }

    ngx_memcpy(value->data, reply->str, reply->len);
    freeReplyObject(reply);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_store_redis: GET key \"%V\" value_len=%uz",
                   key, value->len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_redis_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *key)
{
    redis_ctx_t *ctx;
    redisReply *reply;
    ngx_str_t formatted_key;
    ngx_int_t rc;

    if (r == NULL || store == NULL || key == NULL) {
        return NGX_ERROR;
    }

    ctx = (redis_ctx_t *) store->data;
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* Check and establish connection */
    if (redis_check_connection(store) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Format key with prefix */
    rc =
        redis_format_key(r->pool, &store->prefix, key, &formatted_key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Execute DEL command */
    reply = redisCommand(ctx->context, "DEL %b", formatted_key.data,
                         formatted_key.len);

    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: DEL failed for key \"%V\": %s",
                      key, reply ? reply->str : "connection error");
        if (reply)
            freeReplyObject(reply);
        return NGX_ERROR;
    }

    if (reply->type != REDIS_REPLY_INTEGER) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_store_redis: unexpected reply type %d "
                      "for DEL key \"%V\"",
                      reply->type, key);
        freeReplyObject(reply);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_store_redis: DEL key \"%V\" deleted=%lld",
                   key, reply->integer);

    freeReplyObject(reply);
    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_store_redis_cleanup_expired(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store)
{
    /*
     * Redis expire function requires key and expires parameters,
     * but abstraction layer expire doesn't have these.
     * For now, we'll iterate through all session keys and expire them
     * based on the store's default TTL setting.
     * This is a placeholder implementation - in a real scenario,
     * you would need a different approach or modify the interface.
     */

    return NGX_OK;
}
