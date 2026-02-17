/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_oidc_session.h"
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_session_store.h"
#include "ngx_oidc_hash.h"
#include "ngx_oidc_http.h"

/**
 * Format session store key from session ID and suffix
 *
 * Builds a key string in the format "{session_id}:{suffix}".
 *
 * @param[in] r           HTTP request context
 * @param[in] session_id  Session identifier
 * @param[in] suffix      Key suffix (e.g., "state", "nonce")
 *
 * @return Formatted key string (allocated from r->pool), or NULL on failure
 */
static ngx_str_t *
format_key(ngx_http_request_t *r, ngx_str_t *session_id, const char *suffix)
{
    ngx_str_t *key;
    u_char *p;
    size_t suffix_len;

    suffix_len = ngx_strlen(suffix);

    key = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (key == NULL) {
        return NULL;
    }

    /* Check for size overflow (1 for ':' separator) */
    if (session_id->len > NGX_MAX_SIZE_T_VALUE - 1 - suffix_len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: key length overflow "
                      "(session_len=%uz, suffix_len=%uz)",
                      session_id->len, suffix_len);
        return NULL;
    }

    key->len = session_id->len + sizeof(":") - 1 + suffix_len;
    key->data = ngx_pnalloc(r->pool, key->len);
    if (key->data == NULL) {
        return NULL;
    }

    p = ngx_cpymem(key->data, session_id->data, session_id->len);
    *p++ = ':';
    ngx_memcpy(p, suffix, suffix_len);

    return key;
}

/*
 * Validate cookie component (name or value) for CRLF injection
 *
 * [in] component: Cookie name or value to validate
 *
 * Returns NGX_OK if valid, NGX_ERROR if contains CRLF or control characters
 */
static ngx_int_t
validate_cookie_component(ngx_str_t *component)
{
    size_t i;

    if (component == NULL || component->data == NULL || component->len == 0) {
        return NGX_ERROR;
    }

    /* Check for CRLF and control characters */
    for (i = 0; i < component->len; i++) {
        u_char c = component->data[i];

        /* Check for CRLF */
        if (c == '\r' || c == '\n') {
            return NGX_ERROR;
        }

        /* Check for NULL byte */
        if (c == '\0') {
            return NGX_ERROR;
        }

        /* Check for other control characters (except TAB) */
        if (c < 0x20 && c != 0x09) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_set(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
    ngx_str_t *session_id, const char *key_name, ngx_str_t *value,
    time_t expires)
{
    ngx_str_t *key;

    if (store == NULL || store->ops == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: session store not initialized");
        return NGX_ERROR;
    }

    key = format_key(r, session_id, key_name);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: failed to build session key for %s",
                      key_name);
        return NGX_ERROR;
    }

    return store->ops->set(r, store, key, value, expires);
}

ngx_int_t
ngx_oidc_session_get(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
    ngx_str_t *session_id, const char *key_name, ngx_str_t *value)
{
    ngx_str_t *key;

    if (store == NULL || store->ops == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: session store not initialized");
        return NGX_ERROR;
    }

    key = format_key(r, session_id, key_name);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: failed to build session key for %s",
                      key_name);
        return NGX_ERROR;
    }

    return store->ops->get(r, store, key, value);
}

ngx_int_t
ngx_oidc_session_delete(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
    ngx_str_t *session_id, const char *key_name)
{
    ngx_str_t *key;

    if (store == NULL || store->ops == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: session store not initialized");
        return NGX_ERROR;
    }

    key = format_key(r, session_id, key_name);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: failed to build session key for %s",
                      key_name);
        return NGX_ERROR;
    }

    return store->ops->delete(r, store, key);
}

/*
 * Rotate session ID (session fixation prevention)
 *
 * NOTE: This function performs multiple non-atomic operations (get/set/delete).
 * Race conditions are theoretically possible but unlikely in practice because:
 * 1. Session IDs are cryptographically random and unpredictable
 * 2. Rotation only occurs during authentication flow (infrequent)
 * 3. Same session being rotated concurrently is extremely rare
 *
 * Future improvement: Add explicit locking for memory store or use
 * transactional operations for Redis store if stronger atomicity is required.
 */
ngx_int_t
ngx_oidc_session_rotate(ngx_http_request_t *r, ngx_oidc_session_store_t *store,
    ngx_str_t *old_session_id, ngx_str_t *new_session_id, time_t expires)
{
    ngx_str_t token_data;
    ngx_int_t rc;

    /* Validate input parameters */
    if (r == NULL || store == NULL || old_session_id == NULL
        || new_session_id == NULL)
    {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_rotate: NULL parameter");
        }
        return NGX_ERROR;
    }

    /* Move ID Token */
    rc = ngx_oidc_session_get(r, store, old_session_id,
                              NGX_OIDC_SESSION_KEY_ID_TOKEN, &token_data);
    if (rc == NGX_OK) {
        rc = ngx_oidc_session_set(r, store, new_session_id,
                                  NGX_OIDC_SESSION_KEY_ID_TOKEN,
                                  &token_data, expires);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session: failed to move id_token to "
                          "new session, aborting rotation");
            return NGX_ERROR;
        }
    }

    /* Move Access Token */
    rc = ngx_oidc_session_get(r, store, old_session_id,
                              NGX_OIDC_SESSION_KEY_ACCESS_TOKEN,
                              &token_data);
    if (rc == NGX_OK) {
        rc = ngx_oidc_session_set(r, store, new_session_id,
                                  NGX_OIDC_SESSION_KEY_ACCESS_TOKEN,
                                  &token_data, expires);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session: failed to move access_token "
                          "to new session, aborting rotation");
            return NGX_ERROR;
        }
    }

    /* Move Refresh Token (if exists) */
    rc = ngx_oidc_session_get(r, store, old_session_id,
                              NGX_OIDC_SESSION_KEY_REFRESH_TOKEN,
                              &token_data);
    if (rc == NGX_OK) {
        rc = ngx_oidc_session_set(r, store, new_session_id,
                                  NGX_OIDC_SESSION_KEY_REFRESH_TOKEN,
                                  &token_data, expires);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session: failed to move refresh_token "
                          "to new session, aborting rotation");
            return NGX_ERROR;
        }
    }

    /* Move UserInfo (if exists) */
    rc = ngx_oidc_session_get(r, store, old_session_id,
                              NGX_OIDC_SESSION_KEY_USERINFO, &token_data);
    if (rc == NGX_OK) {
        rc = ngx_oidc_session_set(r, store, new_session_id,
                                  NGX_OIDC_SESSION_KEY_USERINFO,
                                  &token_data, expires);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session: failed to move userinfo "
                          "to new session, aborting rotation");
            return NGX_ERROR;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_session: moved userinfo to new session "
                           "(%ui bytes)", token_data.len);
        }
    }

    /* Move Original URI (needed for post-auth redirect) */
    rc = ngx_oidc_session_get(r, store, old_session_id,
                              NGX_OIDC_SESSION_KEY_ORIGINAL_URI, &token_data);
    if (rc == NGX_OK && token_data.len > 0) {
        rc = ngx_oidc_session_set(r, store, new_session_id,
                                  NGX_OIDC_SESSION_KEY_ORIGINAL_URI,
                                  &token_data, expires);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_session: failed to move original_uri "
                          "to new session");
        }
    }

    /* Delete old session data */
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_ID_TOKEN);
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_ACCESS_TOKEN);
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_REFRESH_TOKEN);
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_USERINFO);

    /* Also clear Pre-Auth session data (if any) */
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_STATE);
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_NONCE);
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_CODE_VERIFIER);
    ngx_oidc_session_delete(r, store, old_session_id,
                            NGX_OIDC_SESSION_KEY_ORIGINAL_URI);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_session: session rotated from %V to %V",
                   old_session_id, new_session_id);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_invalidate(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *session_id)
{
    /* Validate input parameters */
    if (r == NULL || store == NULL || session_id == NULL) {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_invalidate: NULL parameter");
        }
        return NGX_ERROR;
    }
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_ID_TOKEN);
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_ACCESS_TOKEN);
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_REFRESH_TOKEN);
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_USERINFO);

    /* Delete Pre-Auth session data (if any) */
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_STATE);
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_NONCE);
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_CODE_VERIFIER);
    ngx_oidc_session_delete(r, store, session_id,
                            NGX_OIDC_SESSION_KEY_ORIGINAL_URI);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_session: invalidated session %V", session_id);

    return NGX_OK;
}

ngx_str_t *
ngx_oidc_session_get_temporary_id(ngx_http_request_t *r)
{
    ngx_str_t cookie_name, cookie_value;
    ngx_str_t *session_id;
    u_char *colon, *copied_data;
    size_t len;

    /* Temporary cookie always uses fixed name */
    ngx_str_set(&cookie_name, NGX_OIDC_SESSION_CALLBACK);

    /* Use ngx_oidc_http_cookie_get which handles multiple Cookie headers */
    if (ngx_oidc_http_cookie_get(r, &cookie_name, &cookie_value) != NGX_OK) {
        return NULL;
    }

    if (cookie_value.len == 0) {
        return NULL;
    }

    /* Extract session ID from "provider:session_id" format */
    colon = ngx_strlchr(cookie_value.data,
                        cookie_value.data + cookie_value.len, ':');
    if (colon == NULL) {
        /* No colon found, use entire value as session ID */
        session_id = ngx_palloc(r->pool, sizeof(ngx_str_t));
        if (session_id == NULL) {
            return NULL;
        }

        session_id->data = cookie_value.data;
        session_id->len = cookie_value.len;
        return session_id;
    }

    /* Skip provider name part, copy session ID after colon */
    len = cookie_value.len - (size_t) (colon + 1 - cookie_value.data);
    session_id = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (session_id == NULL) {
        return NULL;
    }

    copied_data = ngx_pnalloc(r->pool, len);
    if (copied_data == NULL) {
        return NULL;
    }

    ngx_memcpy(copied_data, colon + 1, len);
    session_id->data = copied_data;
    session_id->len = len;

    return session_id;
}

ngx_str_t *
ngx_oidc_session_get_permanent_id(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t cookie_name, cookie_value;
    ngx_str_t *session_id;

    /* Validate input parameters */
    if (r == NULL || provider == NULL) {
        return NULL;
    }

    /* Get cookie name from provider config or use default */
    if (provider->cookie_name) {
        if (ngx_http_complex_value(r, provider->cookie_name, &cookie_name)
            != NGX_OK)
        {
            return NULL;
        }
    } else {
        ngx_str_set(&cookie_name, NGX_OIDC_SESSION);
    }

    /* Use ngx_oidc_http_cookie_get which handles multiple Cookie headers */
    if (ngx_oidc_http_cookie_get(r, &cookie_name, &cookie_value) != NGX_OK) {
        return NULL;
    }

    if (cookie_value.len == 0) {
        return NULL;
    }

    /* Permanent cookie contains session_id only (no provider prefix) */
    session_id = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (session_id == NULL) {
        return NULL;
    }

    session_id->data = cookie_value.data;
    session_id->len = cookie_value.len;

    return session_id;
}

/*
 * Set temporary callback cookie
 * Cookie name: NGX_OIDC_SESSION_CALLBACK
 * Format: "provider:session_id"
 * Max-Age: 600 seconds
 */
ngx_int_t
ngx_oidc_session_set_temporary_cookie(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *session_id)
{
    ngx_table_elt_t *set_cookie;
    ngx_str_t cookie_name, cookie_value;
    u_char *p;
    size_t len;
    ngx_uint_t secure;

    /* Validate input parameters */
    if (r == NULL || provider == NULL || session_id == NULL) {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_session_set_temporary_cookie: NULL parameter");
        }
        return NGX_ERROR;
    }

    /* Use fixed cookie name for temporary session */
    ngx_str_set(&cookie_name, NGX_OIDC_SESSION_CALLBACK);

    /* Build cookie value: "provider_name:session_id" */
    cookie_value.len = provider->name.len + 1 + session_id->len;
    cookie_value.data = ngx_pnalloc(r->pool, cookie_value.len);
    if (cookie_value.data == NULL) {
        return NGX_ERROR;
    }

    p = cookie_value.data;
    p = ngx_cpymem(p, provider->name.data, provider->name.len);
    *p++ = ':';
    ngx_memcpy(p, session_id->data, session_id->len);

    /* Validate cookie components for CRLF injection */
    if (validate_cookie_component(&cookie_name) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: invalid cookie name");
        return NGX_ERROR;
    }

    if (validate_cookie_component(&cookie_value) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: invalid cookie value contains "
                      "CRLF or control characters");
        return NGX_ERROR;
    }

    /* Check if connection is secure (HTTPS) */
#if (NGX_HTTP_SSL)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    /* Calculate Set-Cookie header length */
    len = cookie_name.len + sizeof("=") - 1 + cookie_value.len
          + sizeof("; Path=/; HttpOnly; SameSite=Lax; Max-Age=600") - 1;
    if (secure) {
        len += sizeof("; Secure") - 1;
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");

    set_cookie->value.data = ngx_pnalloc(r->pool, len);
    if (set_cookie->value.data == NULL) {
        return NGX_ERROR;
    }

    if (secure) {
        p = ngx_snprintf(set_cookie->value.data, len,
                         "%V=%V; Path=/; HttpOnly; Secure; "
                         "SameSite=Lax; Max-Age=%d",
                         &cookie_name, &cookie_value,
                         NGX_OIDC_PRE_AUTH_TIMEOUT);
    } else {
        p = ngx_snprintf(set_cookie->value.data, len,
                         "%V=%V; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d",
                         &cookie_name, &cookie_value,
                         NGX_OIDC_PRE_AUTH_TIMEOUT);
    }

    set_cookie->value.len = p - set_cookie->value.data;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_clear_temporary_cookie(ngx_http_request_t *r)
{
    ngx_table_elt_t *set_cookie;
    ngx_str_t cookie_name;
    u_char *p;
    size_t len;
    ngx_uint_t secure;

    /* Validate input parameters */
    if (r == NULL) {
        return NGX_ERROR;
    }

    ngx_str_set(&cookie_name, NGX_OIDC_SESSION_CALLBACK);

    /* Check if connection is secure (HTTPS) */
#if (NGX_HTTP_SSL)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    /* Calculate Set-Cookie header length */
    len = cookie_name.len
          + sizeof("=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; "
                   "Expires=Thu, 01 Jan 1970 00:00:00 GMT") - 1;
    if (secure) {
        len += sizeof("; Secure") - 1;
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");

    set_cookie->value.data = ngx_pnalloc(r->pool, len);
    if (set_cookie->value.data == NULL) {
        return NGX_ERROR;
    }

    if (secure) {
        p = ngx_snprintf(set_cookie->value.data, len,
                         "%V=; Path=/; HttpOnly; Secure; SameSite=Lax; "
                         "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                         &cookie_name);
    } else {
        p = ngx_snprintf(set_cookie->value.data, len,
                         "%V=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; "
                         "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                         &cookie_name);
    }

    set_cookie->value.len = p - set_cookie->value.data;

    return NGX_OK;
}

/*
 * Set permanent session cookie
 * Cookie name: provider->cookie_name or NGX_OIDC_SESSION
 * Format: "session_id" only (no provider prefix)
 * Max-Age: provider->session_timeout
 */
ngx_int_t
ngx_oidc_session_set_permanent_cookie(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *session_id)
{
    ngx_table_elt_t *set_cookie;
    ngx_str_t cookie_name, cookie_value;
    u_char *p;
    size_t len;
    ngx_uint_t secure;
    u_char max_age_buf[NGX_INT64_LEN];
    ngx_str_t max_age_str;

    /* Get cookie name from provider config or use default */
    if (provider->cookie_name) {
        if (ngx_http_complex_value(r, provider->cookie_name, &cookie_name)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        ngx_str_set(&cookie_name, NGX_OIDC_SESSION);
    }

    /* Build cookie value: "session_id" only
       (no provider name for permanent cookie) */
    cookie_value.len = session_id->len;
    cookie_value.data = ngx_pnalloc(r->pool, cookie_value.len);
    if (cookie_value.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(cookie_value.data, session_id->data, session_id->len);

    /* Validate cookie components for CRLF injection */
    if (validate_cookie_component(&cookie_name) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: invalid cookie name contains "
                      "CRLF or control characters");
        return NGX_ERROR;
    }

    if (validate_cookie_component(&cookie_value) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: invalid cookie value contains "
                      "CRLF or control characters");
        return NGX_ERROR;
    }

    /* Check if connection is secure (HTTPS) */
#if (NGX_HTTP_SSL)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    /* Prepare Max-Age attribute based on session_timeout */
    if (provider->session_timeout == 0) {
        /* session_timeout=0: session cookie without Max-Age */
        ngx_str_null(&max_age_str);
    } else {
        max_age_str.data = max_age_buf;
        max_age_str.len = ngx_sprintf(max_age_buf, "%T",
                                      provider->session_timeout) - max_age_buf;
    }

    /* Calculate Set-Cookie header length */
    len = cookie_name.len + sizeof("=") - 1 + cookie_value.len
          + sizeof("; Path=/; HttpOnly; SameSite=Lax") - 1;
    if (secure) {
        len += sizeof("; Secure") - 1;
    }
    if (max_age_str.len > 0) {
        len += sizeof("; Max-Age=") - 1 + max_age_str.len;
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");

    set_cookie->value.data = ngx_pnalloc(r->pool, len);
    if (set_cookie->value.data == NULL) {
        return NGX_ERROR;
    }

    if (max_age_str.len > 0) {
        /* Persistent cookie with Max-Age */
        if (secure) {
            p = ngx_snprintf(
                set_cookie->value.data, len,
                "%V=%V; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=%V",
                &cookie_name, &cookie_value, &max_age_str);
        } else {
            p = ngx_snprintf(set_cookie->value.data, len,
                             "%V=%V; Path=/; HttpOnly; "
                             "SameSite=Lax; Max-Age=%V",
                             &cookie_name, &cookie_value, &max_age_str);
        }
    } else {
        /* Session cookie without Max-Age */
        if (secure) {
            p = ngx_snprintf(set_cookie->value.data, len,
                             "%V=%V; Path=/; HttpOnly; Secure; SameSite=Lax",
                             &cookie_name, &cookie_value);
        } else {
            p = ngx_snprintf(set_cookie->value.data, len,
                             "%V=%V; Path=/; HttpOnly; SameSite=Lax",
                             &cookie_name, &cookie_value);
        }
    }

    set_cookie->value.len = p - set_cookie->value.data;

    return NGX_OK;
}

/*
 * Clear permanent session cookie
 * Sets Max-Age=0 to delete immediately
 */
ngx_int_t
ngx_oidc_session_clear_permanent_cookie(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_table_elt_t *set_cookie;
    ngx_str_t cookie_name;
    u_char *p;
    size_t len;
    ngx_uint_t secure;

    /* Get cookie name from provider config or use default */
    if (provider->cookie_name) {
        if (ngx_http_complex_value(r, provider->cookie_name, &cookie_name)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        ngx_str_set(&cookie_name, NGX_OIDC_SESSION);
    }

    /* Check if connection is secure (HTTPS) */
#if (NGX_HTTP_SSL)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    /* Calculate Set-Cookie header length */
    len = cookie_name.len
          + sizeof("=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; "
                   "Expires=Thu, 01 Jan 1970 00:00:00 GMT") - 1;
    if (secure) {
        len += sizeof("; Secure") - 1;
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");

    set_cookie->value.data = ngx_pnalloc(r->pool, len);
    if (set_cookie->value.data == NULL) {
        return NGX_ERROR;
    }

    if (secure) {
        p = ngx_snprintf(set_cookie->value.data, len,
                         "%V=; Path=/; HttpOnly; Secure; SameSite=Lax; "
                         "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                         &cookie_name);
    } else {
        p = ngx_snprintf(set_cookie->value.data, len,
                         "%V=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; "
                         "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                         &cookie_name);
    }

    set_cookie->value.len = p - set_cookie->value.data;

    return NGX_OK;
}

/*
 * Authorization Code reuse prevention
 *
 * Per OpenID Connect Core 1.0 Section 3.1.3.1:
 * "The Authorization Code MUST expire shortly after it is issued
 *  to mitigate the risk of leaks. [...] If an Authorization Code
 *  is used more than once, the Authorization Server MUST deny
 *  the request and SHOULD revoke (when possible) all tokens previously
 *  issued based on that Authorization Code."
 *
 * Implementation:
 * - Hash the authorization code using SHA-256
 * - Store the hash in session store with key "used_code:<hash>"
 * - TTL set to NGX_OIDC_PRE_AUTH_TIMEOUT (same as state/nonce)
 * - If code is reused, reject the request
 */

/*
 * Compute SHA-256 hash of authorization code
 * Returns hex-encoded hash string
 */
static ngx_int_t
ngx_oidc_session_hash_code(ngx_http_request_t *r, ngx_str_t *code,
    ngx_str_t *hash_out)
{
    u_char hash[NGX_OIDC_HASH_MAX_SIZE];
    u_char *hex_hash;
    unsigned int hash_len;
    ngx_uint_t i;

    /* Compute SHA-256 hash using abstraction layer */
    if (ngx_oidc_hash_sha256(r, code, hash, &hash_len) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: failed to compute SHA-256 hash");
        return NGX_ERROR;
    }

    /* Convert to hex string */
    hex_hash = ngx_pnalloc(r->pool, hash_len * 2);
    if (hex_hash == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < hash_len; i++) {
        hex_hash[i * 2] = "0123456789abcdef"[(hash[i] >> 4) & 0xf];
        hex_hash[i * 2 + 1] = "0123456789abcdef"[hash[i] & 0xf];
    }

    hash_out->data = hex_hash;
    hash_out->len = hash_len * 2;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_session_try_mark_code_used(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *code)
{
    ngx_str_t hash, key, value;
    u_char *p;
    time_t exp;
    ngx_int_t rc;

    /* Compute code hash */
    if (ngx_oidc_session_hash_code(r, code, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Build key: "used_code:<hash>" */
    key.len = sizeof("used_code:") - 1 + hash.len;
    key.data = ngx_pnalloc(r->pool, key.len);
    if (key.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(key.data, "used_code:", sizeof("used_code:") - 1);
    ngx_memcpy(p, hash.data, hash.len);

    /* Set value to "1" */
    ngx_str_set(&value, "1");

    /* Calculate expiration time */
    exp = ngx_time() + NGX_OIDC_PRE_AUTH_TIMEOUT;

    /* Atomically try to mark code as used (set only if not exists) */
    rc = ngx_oidc_session_store_set_nx(r, store, &key, &value, exp);

    if (rc == NGX_OK) {
        /* Code was not used before, successfully marked as used */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_session: authorization code marked "
                       "as used (hash=%V)", &hash);
        return NGX_OK;
    }

    if (rc == NGX_DECLINED) {
        /* Code was already used - replay attack detected */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_session: authorization code reuse "
                      "detected (hash=%V) - possible replay attack", &hash);
        return NGX_DECLINED;
    }

    /* Error occurred */
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "oidc_session: failed to check/mark "
                  "authorization code usage");
    return NGX_ERROR;
}
