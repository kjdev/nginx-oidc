/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_SESSION_H_INCLUDED_
#define _NGX_OIDC_SESSION_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"

#define NGX_OIDC_SESSION_KEY_STATE         "state"
#define NGX_OIDC_SESSION_KEY_NONCE         "nonce"
#define NGX_OIDC_SESSION_KEY_CODE_VERIFIER "code_verifier"
#define NGX_OIDC_SESSION_KEY_ORIGINAL_URI  "original_uri"
#define NGX_OIDC_SESSION_KEY_ID_TOKEN      "id_token"
#define NGX_OIDC_SESSION_KEY_ACCESS_TOKEN  "access_token"
#define NGX_OIDC_SESSION_KEY_REFRESH_TOKEN "refresh_token"
#define NGX_OIDC_SESSION_KEY_USERINFO      "userinfo"

/**
 * Store a value in session
 *
 * @param[in] r           HTTP request context
 * @param[in] store       Session store
 * @param[in] session_id  Session identifier
 * @param[in] key_name    Key name for the value
 * @param[in] value       Value to store
 * @param[in] expires     Expiration time (absolute)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_set(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *session_id,
    const char *key_name, ngx_str_t *value, time_t expires);

/**
 * Retrieve a value from session
 *
 * @param[in] r           HTTP request context
 * @param[in] store       Session store
 * @param[in] session_id  Session identifier
 * @param[in] key_name    Key name to retrieve
 * @param[out] value      Retrieved value
 *
 * @return NGX_OK on success, NGX_DECLINED if not found, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_get(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *session_id,
    const char *key_name, ngx_str_t *value);

/**
 * Delete a value from session
 *
 * @param[in] r           HTTP request context
 * @param[in] store       Session store
 * @param[in] session_id  Session identifier
 * @param[in] key_name    Key name to delete
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_delete(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *session_id,
    const char *key_name);

/**
 * Rotate session ID
 *
 * Migrates all session data from old session ID to new session ID
 * and removes the old session.
 *
 * @param[in] r               HTTP request context
 * @param[in] store           Session store
 * @param[in] old_session_id  Current session identifier
 * @param[in] new_session_id  New session identifier
 * @param[in] expires         Expiration time for new session
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_rotate(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *old_session_id,
    ngx_str_t *new_session_id, time_t expires);

/**
 * Invalidate entire session
 *
 * Removes all data associated with the given session ID.
 *
 * @param[in] r           HTTP request context
 * @param[in] store       Session store
 * @param[in] session_id  Session identifier to invalidate
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_invalidate(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *session_id);

/**
 * Get temporary session ID from cookie
 *
 * @param[in] r  HTTP request context
 *
 * @return Pointer to temporary session ID, or NULL if not found
 */
ngx_str_t *ngx_oidc_session_get_temporary_id(ngx_http_request_t *r);

/**
 * Set temporary session cookie (auth flow, short-lived)
 *
 * @param[in] r           HTTP request context
 * @param[in] provider    OIDC provider configuration
 * @param[in] session_id  Session identifier to set
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_set_temporary_cookie(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *session_id);

/**
 * Clear temporary session cookie
 *
 * @param[in] r  HTTP request context
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_clear_temporary_cookie(ngx_http_request_t *r);

/**
 * Get permanent session ID from cookie
 *
 * @param[in] r         HTTP request context
 * @param[in] provider  OIDC provider configuration
 *
 * @return Pointer to permanent session ID, or NULL if not found
 */
ngx_str_t *ngx_oidc_session_get_permanent_id(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider);

/**
 * Set permanent session cookie (authenticated, long-lived)
 *
 * @param[in] r           HTTP request context
 * @param[in] provider    OIDC provider configuration
 * @param[in] session_id  Session identifier to set
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_set_permanent_cookie(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *session_id);

/**
 * Clear permanent session cookie
 *
 * @param[in] r         HTTP request context
 * @param[in] provider  OIDC provider configuration
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_clear_permanent_cookie(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider);

/* State operations */
static inline ngx_int_t
ngx_oidc_session_set_state(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_STATE,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_state(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_STATE,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_state(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_STATE);
}

/* Nonce operations */
static inline ngx_int_t
ngx_oidc_session_set_nonce(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_NONCE,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_nonce(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_NONCE,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_nonce(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_NONCE);
}

/* Code verifier operations */
static inline ngx_int_t
ngx_oidc_session_set_verifier(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_CODE_VERIFIER,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_verifier(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_CODE_VERIFIER,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_verifier(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_CODE_VERIFIER);
}

/* Original URI operations */
static inline ngx_int_t
ngx_oidc_session_set_orig_uri(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_ORIGINAL_URI,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_orig_uri(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_ORIGINAL_URI,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_orig_uri(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_ORIGINAL_URI);
}

/* ID token operations */
static inline ngx_int_t
ngx_oidc_session_set_id_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_ID_TOKEN,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_id_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_ID_TOKEN,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_id_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_ID_TOKEN);
}

/* Access token operations */
static inline ngx_int_t
ngx_oidc_session_set_access_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_ACCESS_TOKEN,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_access_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_ACCESS_TOKEN,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_access_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_ACCESS_TOKEN);
}

/* Refresh token operations */
static inline ngx_int_t
ngx_oidc_session_set_refresh_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_REFRESH_TOKEN,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_refresh_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_REFRESH_TOKEN,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_refresh_token(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_REFRESH_TOKEN);
}

/* UserInfo operations */
static inline ngx_int_t
ngx_oidc_session_set_userinfo(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val, time_t exp)
{
    return ngx_oidc_session_set(r, store, sid,
                                NGX_OIDC_SESSION_KEY_USERINFO,
                                val, exp);
}

static inline ngx_int_t
ngx_oidc_session_get_userinfo(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid, ngx_str_t *val)
{
    return ngx_oidc_session_get(r, store, sid,
                                NGX_OIDC_SESSION_KEY_USERINFO,
                                val);
}

static inline ngx_int_t
ngx_oidc_session_delete_userinfo(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *sid)
{
    return ngx_oidc_session_delete(r, store, sid,
                                   NGX_OIDC_SESSION_KEY_USERINFO);
}

/**
 * Atomically check and mark authorization code as used
 *
 * Combines check and mark operations to prevent race conditions.
 *
 * @param[in] r      HTTP request context
 * @param[in] store  Session store
 * @param[in] code   Authorization code
 *
 * @return NGX_OK if marked successfully, NGX_DECLINED if already used,
 *         NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_session_try_mark_code_used(ngx_http_request_t *r,
    ngx_oidc_session_store_t *store, ngx_str_t *code);

#endif /* _NGX_OIDC_SESSION_H_INCLUDED_ */
