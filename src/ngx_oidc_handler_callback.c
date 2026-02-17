/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_http.h"
#include "ngx_oidc_session.h"
#include "ngx_oidc_jwt.h"
#include "ngx_oidc_metadata.h"
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_random.h"
#include "ngx_oidc_url.h"
#include "ngx_oidc_handler_callback.h"

/**
 * Constant-time comparison to prevent timing attacks
 *
 * This function compares two byte sequences in constant time to prevent
 * timing attacks that could be used to infer the value of secrets like
 * state or nonce parameters.
 *
 * @retval NGX_OK if the sequences are equal
 * @retval NGX_ERROR if the sequences differ or have different lengths
 */
static ngx_int_t
ngx_oidc_secure_compare(const u_char *a, size_t a_len,
    const u_char *b, size_t b_len)
{
    size_t i;
    volatile u_char result = 0;

    /* Length mismatch - early return (length is not secret) */
    if (a_len != b_len) {
        return NGX_ERROR;
    }

    /* XOR-based constant-time comparison */
    for (i = 0; i < a_len; i++) {
        result |= a[i] ^ b[i];
    }

    return (result == 0) ? NGX_OK : NGX_ERROR;
}

/** Context for token exchange subrequest */
typedef struct {
    ngx_http_oidc_provider_t *provider;
    ngx_http_request_t       *main_request;
} callback_token_subreq_ctx_t;

/** Context for userinfo subrequest */
typedef struct {
    ngx_http_oidc_provider_t *provider;
    ngx_http_request_t       *main_request;
    ngx_str_t                *session_id;
} callback_userinfo_ctx_t;

/* Token endpoint subrequest completion handler */
static ngx_int_t
callback_token_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    callback_token_subreq_ctx_t *ctx = data;
    ngx_http_oidc_provider_t *provider;
    ngx_http_request_t *main_r;
    ngx_str_t body, access_token, id_token, token_type;
    ngx_str_t *session_id;
    ngx_oidc_json_t *root = NULL;
    time_t expires;

    /* Validate context */
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: token subrequest context "
                      "is NULL");
        return NGX_ERROR;
    }

    provider = ctx->provider;
    main_r = ctx->main_request;

    if (provider == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: provider is NULL "
                      "in token subrequest");
        return NGX_ERROR;
    }

    if (main_r == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: main request is NULL "
                      "in token subrequest");
        return NGX_ERROR;
    }

    if (rc != NGX_OK || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: token subrequest failed "
                      "with status: %ui",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    /* Get session ID from temporary cookie and extract actual session ID */
    session_id = ngx_oidc_session_get_temporary_id(main_r);
    if (session_id == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: missing session cookie "
                      "for token storage");
        return NGX_ERROR;
    }

    /* Extract response body using HTTP module function */
    if (ngx_oidc_http_response_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to get token "
                      "response body");
        return NGX_ERROR;
    }

    if (body.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: empty token response");
        return NGX_ERROR;
    }

    /* Parse JSON from token endpoint (untrusted external source) */
    root = ngx_oidc_json_parse_untrusted(&body, r->pool);
    if (!root) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to parse token "
                      "response JSON");
        return NGX_ERROR;
    }

    /* Extract access_token using subrequest pool */
    if (ngx_oidc_json_object_get_string(root, "access_token", &access_token,
                                        r->pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: access_token not found "
                      "in token response");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }

    /* Extract token_type (optional) using subrequest pool */
    if (ngx_oidc_json_object_get_string(root, "token_type", &token_type,
                                        r->pool)
        != NGX_OK)
    {
        ngx_str_set(&token_type, "Bearer"); /* Default to Bearer */
    }

    /* Store access_token using Token Session Service API */
    time_t now;

    /* Check for time_t overflow */
    now = ngx_time();
    if (now > (time_t) (NGX_MAX_INT_T_VALUE - provider->session_timeout)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: session expiration time "
                      "overflow");
        ngx_oidc_json_free(root);
        return NGX_ERROR;
    }
    expires = now + provider->session_timeout;
    if (ngx_oidc_session_set_access_token(main_r, provider->session_store,
                                          session_id, &access_token,
                                          expires)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to store "
                      "access_token in %s",
                      provider->session_store->type
                      == NGX_OIDC_SESSION_STORE_MEMORY
                      ? "shared memory"
                      : "redis");
    }

    /* Extract id_token (optional for OIDC) */
    if (ngx_oidc_json_object_get_string(root, "id_token", &id_token,
                                        r->pool)
        != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: no id_token found "
                       "in token response");
        id_token.len = 0;
        id_token.data = NULL;
    }

    if (id_token.len > 0) {
        /* Store id_token using Token Session Service API */
        if (ngx_oidc_session_set_id_token(main_r, provider->session_store,
                                          session_id, &id_token,
                                          expires)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_handler_callback: failed to store "
                          "id_token in %s",
                          provider->session_store->type
                          == NGX_OIDC_SESSION_STORE_MEMORY
                          ? "shared memory"
                          : "redis");
        }
    }

    ngx_oidc_json_free(root);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: successfully exchanged code "
                   "for tokens (type: %V, session: %V)",
                   &token_type, session_id);

    /* Transition to next state based on token content
     * and provider configuration */
    ngx_http_oidc_ctx_t *main_ctx = ngx_http_get_module_ctx(
        main_r, ngx_http_oidc_module);
    if (main_ctx != NULL) {
        if (id_token.len > 0) {
            /* ID token present - verification is mandatory */
            main_ctx->callback.state =
                NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ID_TOKEN;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: transitioning "
                           "to TOKEN_VERIFY phase");
        } else if (provider->fetch_userinfo) {
            /* No ID token, but userinfo requested */
            main_ctx->callback.state =
                NGX_HTTP_OIDC_CALLBACK_STATE_FETCH_USERINFO;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: transitioning "
                           "to USERINFO phase (no id_token)");
        } else {
            /* No ID token, no userinfo - proceed to session save */
            main_ctx->callback.state =
                NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: transitioning to "
                           "COMPLETED phase (no id_token, no userinfo)");
        }
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: main request context is NULL "
                      "after token exchange");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
callback_exchange_code(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *code, ngx_str_t *state)
{
    ngx_str_t post_body, encoded_client_id,
              encoded_client_secret, encoded_redirect_uri,
              encoded_code, encoded_code_verifier,
              code_verifier_val, client_id_val,
              client_secret_val, redirect_uri_val;
    ngx_str_t *session_id, *token_endpoint;
    u_char *p;
    size_t len;
    ngx_http_complex_value_t *cv;
    ngx_http_oidc_ctx_t *ctx;

    /* Get context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: context not found");
        return NGX_ERROR;
    }

    /* Get session ID from temporary cookie and extract actual session ID */
    session_id = ngx_oidc_session_get_temporary_id(r);
    if (session_id == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: missing session cookie "
                      "in code exchange");
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Metadata retrieved from context (no fetch needed) */
    ngx_oidc_metadata_cache_t *metadata = ctx->cached.metadata;
    token_endpoint = ngx_oidc_metadata_get_token_endpoint(metadata);
    if (metadata == NULL || token_endpoint == NULL
        || token_endpoint->len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: token_endpoint not available "
                      "in cached metadata");
        return NGX_ERROR;
    }
    cv = provider->client_id;
    if (cv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: client_id not configured "
                      "for provider");
        return NGX_ERROR;
    }
    if (ngx_http_complex_value(r, cv, &client_id_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to get client_id value");
        return NGX_ERROR;
    }

    /* Get client_secret value */
    cv = provider->client_secret;
    if (cv == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: client_secret not configured "
                      "for provider");
        return NGX_ERROR;
    }
    if (ngx_http_complex_value(r, cv, &client_secret_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to get "
                      "client_secret value");
        return NGX_ERROR;
    }

    /* Get processed redirect_uri from server metadata */
    /* Get redirect_uri from provider */
    if (ngx_http_complex_value(r, provider->redirect_uri,
                               &redirect_uri_val) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to evaluate redirect_uri");
        return NGX_ERROR;
    }

    if (ngx_oidc_url_validate(r, &redirect_uri_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: redirect_uri parameter "
                      "validation failed");
        return NGX_ERROR;
    }
    if (redirect_uri_val.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: no redirect_uri available "
                      "in server metadata for token exchange");
        return NGX_ERROR;
    }

    /* Get PKCE code_verifier if enabled */
    ngx_str_null(&code_verifier_val);
    ngx_str_null(&encoded_code_verifier);

    if (provider->pkce.enable) {
        /* Retrieve code_verifier from session */
        if (ngx_oidc_session_get_verifier(
                r, provider->session_store,
                session_id, &code_verifier_val) == NGX_OK)
        {
            /* Remove code_verifier from session (one-time use) */
            ngx_oidc_session_delete_verifier(
                r, provider->session_store, session_id);
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: PKCE enabled "
                          "but code_verifier not found in %s",
                          provider->session_store->type
                          == NGX_OIDC_SESSION_STORE_MEMORY
                          ? "shared memory"
                          : "redis");
            return NGX_HTTP_UNAUTHORIZED;
        }
    }

    /* Decode code parameter (ngx_http_arg returns URL-encoded value) */
    ngx_str_t decoded_code;
    u_char *src, *dst;
    decoded_code.len = code->len;
    decoded_code.data = ngx_pnalloc(r->pool, code->len);
    if (decoded_code.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate memory "
                      "for decoded code");
        return NGX_ERROR;
    }
    src = code->data;
    dst = decoded_code.data;
    ngx_unescape_uri(&dst, &src, code->len, NGX_UNESCAPE_URI);
    decoded_code.len = dst - decoded_code.data;

    /* URL encode parameters */
    if (ngx_oidc_url_encode(r, &client_id_val, &encoded_client_id) != NGX_OK
        || ngx_oidc_url_encode(r, &client_secret_val,
                               &encoded_client_secret) != NGX_OK
        || ngx_oidc_url_encode(r, &redirect_uri_val,
                               &encoded_redirect_uri) != NGX_OK
        || ngx_oidc_url_encode(r, &decoded_code, &encoded_code) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to encode parameters "
                      "for token request");
        return NGX_ERROR;
    }

    /* URL encode code_verifier if PKCE is enabled */
    if (provider->pkce.enable && code_verifier_val.len > 0) {
        if (ngx_oidc_url_encode(r, &code_verifier_val,
                                &encoded_code_verifier) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: failed to encode PKCE "
                          "code_verifier for token request");
            return NGX_ERROR;
        }
    }

    /* Build POST body */
    len = sizeof("grant_type=authorization_code") - 1 + sizeof("&code=") - 1
          + encoded_code.len + sizeof("&redirect_uri=") - 1
          + encoded_redirect_uri.len + sizeof("&client_id=") - 1
          + encoded_client_id.len + sizeof("&client_secret=") - 1
          + encoded_client_secret.len;

    /* Add PKCE code_verifier length if enabled */
    if (provider->pkce.enable && code_verifier_val.len > 0) {
        len += sizeof("&code_verifier=") - 1 + encoded_code_verifier.len;
    }

    post_body.data = ngx_pnalloc(r->pool, len);
    if (post_body.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate memory "
                      "for token request body");
        return NGX_ERROR;
    }

    p = ngx_cpymem(post_body.data, "grant_type=authorization_code",
                   sizeof("grant_type=authorization_code") - 1);
    p = ngx_cpymem(p, "&code=", sizeof("&code=") - 1);
    p = ngx_cpymem(p, encoded_code.data, encoded_code.len);
    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    p = ngx_cpymem(p, encoded_redirect_uri.data, encoded_redirect_uri.len);
    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    p = ngx_cpymem(p, encoded_client_id.data, encoded_client_id.len);
    p = ngx_cpymem(p, "&client_secret=", sizeof("&client_secret=") - 1);
    p = ngx_cpymem(p, encoded_client_secret.data, encoded_client_secret.len);

    /* Append PKCE code_verifier if enabled */
    if (provider->pkce.enable && code_verifier_val.len > 0) {
        p = ngx_cpymem(p, "&code_verifier=", sizeof("&code_verifier=") - 1);
        p = ngx_cpymem(p, encoded_code_verifier.data,
                       encoded_code_verifier.len);
    }

    post_body.len = p - post_body.data;

    /* Create context for token subrequest */
    callback_token_subreq_ctx_t *token_ctx;
    token_ctx = ngx_palloc(r->pool, sizeof(callback_token_subreq_ctx_t));
    if (token_ctx == NULL) {
        return NGX_ERROR;
    }
    token_ctx->provider = provider;
    token_ctx->main_request = r;

    /* Create HTTP POST request to token endpoint */
    if (ngx_oidc_http_post(r, token_endpoint, &post_body,
                           callback_token_done, token_ctx)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Return NGX_AGAIN to let subrequest complete */
    return NGX_AGAIN;
}

/**
 * Extract and validate nonce from ID token payload
 *
 * This function extracts the nonce from the ID token JWT payload, validates it
 * against the stored nonce in the session store, and returns the validated
 * nonce for use in JWT verification.
 *
 * @param[in] r           HTTP request
 * @param[in] provider    OIDC provider configuration
 * @param[in] id_token    ID token (JWT string)
 * @param[in] session_id  Session ID for nonce lookup
 *
 * @return Pointer to validated nonce (allocated in request pool) on success
 *         NULL if nonce is not available or validation failed
 */
static ngx_str_t *
callback_extract_and_validate_nonce(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *id_token,
    ngx_str_t *session_id)
{
    ngx_str_t id_token_payload;
    ngx_oidc_json_t *payload_json = NULL, *nonce_json = NULL;
    const char *nonce_str = NULL;
    ngx_str_t nonce_value, stored_nonce;
    ngx_str_t *expected_nonce;

    /* Decode JWT payload */
    if (ngx_oidc_jwt_decode_payload(id_token, &id_token_payload, r->pool)
        != NGX_OK)
    {
        return NULL;
    }

    /* Parse JSON payload */
    payload_json = ngx_oidc_json_parse(&id_token_payload, r->pool);
    if (payload_json == NULL) {
        return NULL;
    }

    /* Get nonce from payload */
    nonce_json = ngx_oidc_json_object_get(payload_json, "nonce");
    if (!ngx_oidc_json_is_string(nonce_json)) {
        ngx_oidc_json_free(payload_json);
        return NULL;
    }

    nonce_str = ngx_oidc_json_string(nonce_json);
    if (nonce_str == NULL) {
        ngx_oidc_json_free(payload_json);
        return NULL;
    }

    /* Setup nonce value */
    nonce_value.data = (u_char *) nonce_str;
    nonce_value.len = ngx_strlen(nonce_str);

    /* Load stored nonce from session */
    if (ngx_oidc_session_get_nonce(r, provider->session_store, session_id,
                                   &stored_nonce)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: nonce not found or expired "
                      "in session store");
        ngx_oidc_json_free(payload_json);
        return NULL;
    }

    /* Validate nonce using constant-time comparison */
    if (ngx_oidc_secure_compare(stored_nonce.data, stored_nonce.len,
                                nonce_value.data, nonce_value.len)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: nonce value mismatch in %s "
                      "(expected_len: %uz, got_len: %uz, session: %V)",
                      provider->session_store->type
                      == NGX_OIDC_SESSION_STORE_MEMORY
                      ? "shared memory"
                      : "redis",
                      stored_nonce.len, nonce_value.len, session_id);
        ngx_oidc_json_free(payload_json);
        return NULL;
    }

    /* Allocate expected_nonce in request pool */
    expected_nonce = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (expected_nonce == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate nonce");
        ngx_oidc_json_free(payload_json);
        return NULL;
    }

    expected_nonce->data = ngx_pnalloc(r->pool, nonce_value.len);
    if (expected_nonce->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate nonce data");
        ngx_oidc_json_free(payload_json);
        return NULL;
    }

    expected_nonce->len = nonce_value.len;
    ngx_memcpy(expected_nonce->data, nonce_value.data, nonce_value.len);

    /* Delete nonce (one-time use) */
    ngx_oidc_session_delete_nonce(r, provider->session_store, session_id);

    ngx_oidc_json_free(payload_json);

    return expected_nonce;
}

static char *
string_copy_to_pool(ngx_pool_t *pool, const char *src,
    ngx_http_request_t *r, const char *name)
{
    size_t len;
    char *copy;

    if (!src) {
        return NULL;
    }

    len = ngx_strlen(src);
    copy = ngx_pnalloc(pool, len + 1);
    if (!copy) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate memory for %s",
                      name);
        return NULL;
    }

    ngx_memcpy(copy, src, len);
    copy[len] = '\0';

    return copy;
}

static ngx_int_t
callback_verify_id_token(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t issuer_url, client_id,
              id_token, access_token;
    ngx_str_t *session_id, *expected_nonce, *jwks_uri;
    ngx_oidc_jwt_validation_params_t params;
    ngx_oidc_metadata_cache_t *metadata;
    ngx_oidc_jwks_cache_node_t *jwks;
    ngx_int_t rc;

    /* Get issuer URL from provider config for validation */
    if (ngx_http_complex_value(r, provider->issuer, &issuer_url) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to get issuer URL "
                      "for verification");
        return NGX_ERROR;
    }

    /* Get client_id from provider config for audience validation */
    if (ngx_http_complex_value(r, provider->client_id, &client_id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to get client_id "
                      "for verification");
        return NGX_ERROR;
    }

    /* Get session ID from temporary cookie and extract actual session ID */
    session_id = ngx_oidc_session_get_temporary_id(r);
    if (session_id == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: missing session cookie "
                      "for token verification");
        return NGX_ERROR;
    }

    /* Get id_token using Token Session Service */
    rc = ngx_oidc_session_get_id_token(r, provider->session_store, session_id,
                                       &id_token);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: id_token not found "
                      "in session store");
        return NGX_ERROR;
    }

    /* Get access_token using Token Session Service (for at_hash validation) */
    rc = ngx_oidc_session_get_access_token(r, provider->session_store,
                                           session_id, &access_token);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: access_token not found "
                      "in session store (at_hash validation may fail)");
        ngx_str_null(&access_token);
    }

    /* Extract and validate nonce from ID token payload */
    expected_nonce = callback_extract_and_validate_nonce(r, provider,
                                                         &id_token, session_id);

    /* Nonce validation is mandatory for CSRF protection */
    if (!expected_nonce) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: nonce validation failed - "
                      "authentication rejected (session: %V)", session_id);
        return NGX_ERROR;
    }

    /* Setup verification parameters */
    params.token = &id_token;
    params.expected.issuer = &issuer_url;
    params.expected.audience = &client_id;
    params.expected.nonce = expected_nonce;
    params.access_token = &access_token; /* For at_hash validation */
    params.clock_skew = provider->clock_skew;

    /* Get metadata to obtain JWKS URI */
    rc = ngx_oidc_metadata_get(r, &issuer_url, &metadata);
    if (rc != NGX_OK || metadata == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: metadata not available "
                      "for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    jwks_uri = ngx_oidc_metadata_get_jwks_uri(metadata);
    if (jwks_uri == NULL || jwks_uri->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: JWKS URI not available "
                      "in metadata for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    /* Get JWKS from shared memory cache using JWKS URI */
    rc = ngx_oidc_jwks_get(r, jwks_uri, &jwks);
    if (rc != NGX_OK || jwks == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: JWKS not available "
                      "for ID token verification (uri: %V)",
                      jwks_uri);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: verify_id_token "
                   "- using JWKS cache for provider %V (%ui keys)",
                   &provider->name,
                   (ngx_oidc_jwks_cache_node_get_keys(jwks) != NULL)
                   ? ngx_oidc_jwks_cache_node_get_keys(jwks)->nelts : 0);

    return ngx_oidc_jwt_verify(r, &id_token, jwks, &params);
}

static ngx_int_t
callback_verify_access_token(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t *session_id;
    ngx_str_t id_token_value, access_token_value, payload, header;
    ngx_oidc_json_t *payload_json, *at_hash_json, *header_json, *alg_json;
    const char *at_hash_str;
    const char *algorithm_str;
    char *at_hash_copy = NULL, *algorithm_copy = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: verifying access_token "
                   "using at_hash from ID token");

    /* Get session ID from temporary cookie and extract actual session ID */
    session_id = ngx_oidc_session_get_temporary_id(r);
    if (session_id == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: missing session cookie "
                      "for at_hash validation");
        return NGX_ERROR;
    }

    /* Get access_token from Session Store using Token Session Service API */
    if (ngx_oidc_session_get_access_token(r, provider->session_store,
                                          session_id, &access_token_value)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: access_token not found "
                      "in session store");
        return NGX_ERROR;
    }

    if (access_token_value.len == 0 || access_token_value.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: access_token is empty or null");
        return NGX_ERROR;
    }

    /* Retrieve id_token using Token Session Service API */
    if (ngx_oidc_session_get_id_token(r, provider->session_store, session_id,
                                      &id_token_value)
        != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: no ID token available "
                       "for at_hash validation, skipping");
        return NGX_OK; /* No ID token, cannot validate at_hash */
    }

    /* Extract JWT payload from ID token */
    if (ngx_oidc_jwt_decode_payload(&id_token_value, &payload, r->pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to decode ID token "
                      "payload for at_hash validation");
        return NGX_ERROR;
    }

    /* Parse payload JSON */
    payload_json = ngx_oidc_json_parse(&payload, r->pool);
    if (!payload_json) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to parse ID token "
                      "payload JSON for at_hash validation");
        return NGX_ERROR;
    }

    /* Get at_hash from ID token */
    at_hash_json = ngx_oidc_json_object_get(payload_json, "at_hash");
    if (!at_hash_json || !ngx_oidc_json_is_string(at_hash_json)) {
        ngx_oidc_json_free(payload_json);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: no at_hash found in ID token, "
                       "skipping access token validation");
        return NGX_OK; /* No at_hash in ID token, cannot validate */
    }

    at_hash_str = ngx_oidc_json_string(at_hash_json);
    if (!at_hash_str) {
        ngx_oidc_json_free(payload_json);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: invalid at_hash value "
                      "in ID token");
        return NGX_ERROR;
    }

    /* Copy at_hash to pool before freeing JSON */
    at_hash_copy = string_copy_to_pool(r->pool, at_hash_str, r, "at_hash");
    if (!at_hash_copy) {
        ngx_oidc_json_free(payload_json);
        return NGX_ERROR;
    }

    /* Extract algorithm from JWT header for proper hash function selection */
    if (ngx_oidc_jwt_decode_header(&id_token_value, &header, r->pool)
        == NGX_OK)
    {
        header_json = ngx_oidc_json_parse(&header, r->pool);
        if (header_json) {
            alg_json = ngx_oidc_json_object_get(header_json, "alg");
            if (alg_json && ngx_oidc_json_is_string(alg_json)) {
                algorithm_str = ngx_oidc_json_string(alg_json);
                if (algorithm_str) {
                    /* Copy algorithm to pool before freeing JSON */
                    algorithm_copy = string_copy_to_pool(
                        r->pool, algorithm_str, r, "algorithm");
                }
            }
            ngx_oidc_json_free(header_json);
        }
    }

    if (!algorithm_copy) {
        ngx_oidc_json_free(payload_json);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to extract algorithm "
                      "from ID token header");
        return NGX_ERROR;
    }

    /* Validate at_hash against access_token */
    if (ngx_oidc_jwt_validate_at_hash(r, algorithm_copy, at_hash_copy,
                                      &access_token_value)
        != NGX_OK)
    {
        ngx_oidc_json_free(payload_json);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: at_hash validation failed "
                      "for access_token");
        return NGX_ERROR;
    }

    ngx_oidc_json_free(payload_json);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: access_token validated "
                   "successfully using at_hash");

    return NGX_OK;
}

static ngx_int_t
callback_redirect(ngx_http_request_t *r, ngx_http_oidc_provider_t *provider,
    ngx_str_t *session_id)
{
    ngx_table_elt_t *location;
    ngx_str_t original_uri, redirect_uri, full_url;
    ngx_int_t rc;

    /* Check if header already sent */
    if (r->header_sent) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: header already sent, "
                       "skipping redirect");
        return NGX_OK;
    }

    /* Try to get original URI using Authorization Session Service */
    ngx_memzero(&original_uri, sizeof(ngx_str_t));
    rc = ngx_oidc_session_get_orig_uri(r, provider->session_store,
                                       session_id, &original_uri);
    if (rc != NGX_OK || original_uri.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: no original URI found, "
                       "redirecting to root");
        ngx_str_set(&redirect_uri, "/");
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: redirecting to original "
                       "URI: %V",
                       &original_uri);
        redirect_uri = original_uri;

        /* Clean up the original URI using Authorization Session Service */
        ngx_oidc_session_delete_orig_uri(r, provider->session_store,
                                         session_id);
    }

    /* Build full URL */
    if (ngx_oidc_url_build_absolute(r, &redirect_uri, &full_url) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Validate redirect URL for CRLF injection */
    if (ngx_oidc_url_validate(r, &full_url) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: invalid redirect URL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set up redirect */
    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = full_url;

    /* Also set r->headers_out.location for nginx's redirect handling */
    r->headers_out.location = location;

    r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    /* Discard request body to prevent reading it */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    if (rc == NGX_ERROR) {
        return rc;
    }

    /* Return NGX_DONE to indicate request processing is complete and skip
     * content phase, preventing "header already sent" alert from proxy_pass */
    return NGX_DONE;
}

static ngx_int_t
callback_userinfo_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    callback_userinfo_ctx_t *ctx = data;
    ngx_http_oidc_provider_t *provider;
    ngx_http_request_t *main_r;
    ngx_http_oidc_ctx_t *main_ctx;
    ngx_str_t body;
    time_t expires;

    /* Validate context */
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: userinfo subrequest context "
                      "is NULL");
        return NGX_ERROR;
    }

    provider = ctx->provider;
    main_r = ctx->main_request;

    if (provider == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: provider is NULL "
                      "in userinfo subrequest");
        return NGX_ERROR;
    }

    if (main_r == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: main request is NULL "
                      "in userinfo subrequest");
        return NGX_ERROR;
    }

    /* Get main request context for state management */
    main_ctx = ngx_http_get_module_ctx(main_r, ngx_http_oidc_module);
    if (main_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: main request context is NULL "
                      "in userinfo subrequest");
        return NGX_ERROR;
    }

    /* Check response status */
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: userinfo subrequest failed "
                      "with rc=%i, continuing without userinfo data",
                      rc);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    if (r->headers_out.status == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: userinfo subrequest completed "
                      "with status 0 (no response received, possibly timeout "
                      "or connection error), continuing without userinfo data");
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    if (r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: userinfo subrequest failed "
                      "with HTTP status: %ui, continuing without userinfo data",
                      r->headers_out.status);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    /* Extract response body using HTTP module function */
    if (ngx_oidc_http_response_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to get userinfo "
                      "response body, continuing without userinfo data");
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    if (body.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: empty userinfo response, "
                      "continuing without userinfo data");
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: received userinfo response "
                   "(%ui bytes): %V",
                   body.len, &body);

    /* Validate Content-Type (should be application/json) */
    if (r->headers_out.content_type.len > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: userinfo Content-Type: %V",
                       &r->headers_out.content_type);
        /* Check if it starts with "application/json" */
        if (r->headers_out.content_type.len < 16
            || ngx_strncasecmp(r->headers_out.content_type.data,
                               (u_char *) "application/json", 16) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_handler_callback: invalid UserInfo "
                          "Content-Type: %V (expected application/json), "
                          "continuing without userinfo data",
                          &r->headers_out.content_type);
            /* Transition to next phase without userinfo data */
            main_ctx->callback.state
                = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
            return NGX_OK;
        }
    }

    /* Parse UserInfo JSON response using abstraction layer */
    ngx_oidc_json_t *userinfo_json = NULL;

    userinfo_json = ngx_oidc_json_parse_untrusted(&body, r->pool);
    if (userinfo_json == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to parse UserInfo JSON, "
                      "continuing without userinfo data");
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    if (ngx_oidc_json_type(userinfo_json) != NGX_OIDC_JSON_OBJECT) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: UserInfo response is not "
                      "a JSON object, continuing without userinfo data");
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    /* Extract sub claim from UserInfo */
    ngx_oidc_json_t *userinfo_sub_json = ngx_oidc_json_object_get(
        userinfo_json, "sub");
    if (userinfo_sub_json == NULL
        || !ngx_oidc_json_is_string(userinfo_sub_json))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: UserInfo response "
                      "missing 'sub' claim, continuing without userinfo data");
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    const char *userinfo_sub_str = ngx_oidc_json_string(userinfo_sub_json);
    if (userinfo_sub_str == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to get UserInfo "
                      "sub value, continuing without userinfo data");
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    ngx_str_t userinfo_sub;
    userinfo_sub.len = ngx_strlen(userinfo_sub_str);
    userinfo_sub.data = ngx_pnalloc(main_r->pool, userinfo_sub.len);
    if (userinfo_sub.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate userinfo sub");
        ngx_oidc_json_free(userinfo_json);
        return NGX_ERROR;
    }
    ngx_memcpy(userinfo_sub.data, userinfo_sub_str, userinfo_sub.len);

    /* Get ID token and extract sub claim for comparison */
    ngx_str_t id_token_str;
    if (ngx_oidc_session_get_id_token(main_r, provider->session_store,
                                      ctx->session_id, &id_token_str)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to retrieve ID token "
                      "for sub validation, continuing without userinfo data");
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    /* Decode ID token payload to extract sub */
    ngx_str_t id_token_payload;
    if (ngx_oidc_jwt_decode_payload(&id_token_str, &id_token_payload,
                                    main_r->pool)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to decode ID token "
                      "for sub validation, continuing without userinfo data");
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    /* Parse ID token payload JSON using abstraction layer */
    ngx_oidc_json_t *id_token_json = ngx_oidc_json_parse(&id_token_payload,
                                                         main_r->pool);
    if (id_token_json == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to parse ID token "
                      "payload JSON, continuing without userinfo data");
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    /* Extract sub claim from ID token */
    ngx_oidc_json_t *id_token_sub_json = ngx_oidc_json_object_get(
        id_token_json, "sub");
    if (id_token_sub_json == NULL
        || !ngx_oidc_json_is_string(id_token_sub_json))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: ID token missing sub claim, "
                      "continuing without userinfo data");
        ngx_oidc_json_free(id_token_json);
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    const char *id_token_sub_str = ngx_oidc_json_string(id_token_sub_json);
    if (id_token_sub_str == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to get ID token "
                      "sub value, continuing without userinfo data");
        ngx_oidc_json_free(id_token_json);
        ngx_oidc_json_free(userinfo_json);
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    ngx_str_t id_token_sub;
    id_token_sub.len = ngx_strlen(id_token_sub_str);
    id_token_sub.data = ngx_pnalloc(main_r->pool, id_token_sub.len);
    if (id_token_sub.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to allocate id_token sub");
        ngx_oidc_json_free(id_token_json);
        ngx_oidc_json_free(userinfo_json);
        return NGX_ERROR;
    }
    ngx_memcpy(id_token_sub.data, id_token_sub_str, id_token_sub.len);

    /* Compare sub claims using constant-time comparison */
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: validating UserInfo sub "
                   "- ID token sub='%V', UserInfo sub='%V'",
                   &id_token_sub, &userinfo_sub);

    if (ngx_oidc_secure_compare(id_token_sub.data, id_token_sub.len,
                                userinfo_sub.data, userinfo_sub.len)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: UserInfo sub validation failed - "
                      "sub mismatch");
        ngx_oidc_json_free(id_token_json);
        ngx_oidc_json_free(userinfo_json);
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: UserInfo sub validation successful");

    ngx_oidc_json_free(id_token_json);

    /* Serialize userinfo JSON to compact format (no whitespace)
     * to avoid newlines that would cause issues in HTTP headers */
    ngx_str_t *compact_body = ngx_oidc_json_stringify_compact(userinfo_json,
                                                              main_r->pool);
    ngx_oidc_json_free(userinfo_json);

    if (compact_body == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to serialize userinfo "
                      "JSON, continuing without userinfo data");
        /* Transition to next phase without userinfo data */
        main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        return NGX_OK;
    }

    /* Store userinfo data using Token Session Service */
    time_t now;

    /* Check for time_t overflow */
    now = ngx_time();
    if (now > (time_t) (NGX_MAX_INT_T_VALUE - provider->session_timeout)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: userinfo expiration "
                      "time overflow");
        return NGX_ERROR;
    }
    expires = now + provider->session_timeout;
    if (ngx_oidc_session_set_userinfo(main_r, provider->session_store,
                                      ctx->session_id, compact_body,
                                      expires)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: failed to store userinfo "
                      "in session store");
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: stored userinfo "
                       "in session store (%ui bytes)",
                       compact_body->len);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: successfully fetched userinfo "
                   "(%ui bytes)",
                   compact_body->len);

    /* Check if parent request already sent response to avoid "http finalize
     * non-active request" alert */
    if (main_r->header_sent) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: parent request already sent "
                       "response, returning NGX_DONE "
                       "to prevent double finalization");
        return NGX_DONE;
    }

    /* Update main request context for phase-based processing */
    main_ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: userinfo fetch completed, "
                   "advancing to SESSION_SAVE phase");

    return NGX_OK;
}

static ngx_int_t
callback_fetch_userinfo(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *session_id)
{
    ngx_str_t issuer;
    ngx_oidc_metadata_cache_t *metadata;
    callback_userinfo_ctx_t *ctx;
    ngx_str_t *userinfo_url;
    ngx_str_t access_token;
    ngx_int_t rc;

    /* Evaluate issuer */
    if (ngx_http_complex_value(r, provider->issuer, &issuer) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: failed to evaluate issuer");
        return NGX_ERROR;
    }

    /* Get metadata to find userinfo_endpoint */
    rc = ngx_oidc_metadata_get(r, &issuer, &metadata);
    if (rc != NGX_OK || metadata == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: metadata not available "
                      "for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    userinfo_url = ngx_oidc_metadata_get_userinfo_endpoint(metadata);
    if (userinfo_url == NULL || userinfo_url->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: userinfo_endpoint "
                      "not available for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    /* Get access_token using Token Session Service */
    rc = ngx_oidc_session_get_access_token(r, provider->session_store,
                                           session_id, &access_token);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_callback: access_token not found "
                      "in session store for userinfo fetch");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: fetching userinfo from %V "
                   "for session %V",
                   userinfo_url, session_id);

    /* Prepare context for callback */
    ctx = ngx_palloc(r->pool, sizeof(callback_userinfo_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->provider = provider;
    ctx->main_request = r;
    ctx->session_id = session_id;

    /* Fetch UserInfo using HTTP Module with Bearer token */
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: creating userinfo subrequest "
                   "with bearer token (token length: %uz)",
                   access_token.len);

    if (ngx_oidc_http_get_bearer(r, userinfo_url, &access_token,
                                 callback_userinfo_done, ctx)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

/*
 * Callback Handler: COMPLETED
 *
 * Handles callback.state: SESSION_SAVE → REDIRECT
 *
 * Purpose: Save session with ID rotation, redirect to original URI
 * Not part of OIDC flow (nginx-specific session management and redirection)
 */
static ngx_int_t
callback_phase_complete(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t *old_session_id, *new_session_id;
    ngx_str_t new_session_id_val = ngx_null_string;
    ngx_str_t saved_session_id;   /* Save session ID at function entry */
    time_t expires;
    ngx_int_t rc;

    /* Save session ID from context immediately,
     * before any operations that might invalidate ctx */
    saved_session_id = ctx->callback.session_id;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: [COMPLETED] "
                   "handler invoked (state=%d)",
                   ctx->callback.state);

    /* Process states using switch + fall-through */
    switch (ctx->callback.state) {
    /* State: Save session and rotate ID */
    case NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [SESSION_SAVE] "
                       "finalizing session and preparing redirect");

        /* Get old session ID from saved copy */
        old_session_id = &saved_session_id;
        if (old_session_id->len == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_handler_callback: [SESSION_SAVE] "
                          "no session ID found in context");
        }

        /* Generate new session ID for security (session rotation) */
        if (ngx_oidc_random_session_id(r, &new_session_id_val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: [SESSION_SAVE] "
                          "failed to generate new session ID");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        new_session_id = &new_session_id_val;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [SESSION_SAVE] "
                       "rotating session: %V -> %V",
                       old_session_id, new_session_id);

        /* Rotate session (copy data from old to new, delete old) */
        if (old_session_id->len > 0) {
            expires = ngx_time() + provider->session_timeout;

            rc = ngx_oidc_session_rotate(r, provider->session_store,
                                         old_session_id, new_session_id,
                                         expires);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "oidc_handler_callback: [SESSION_SAVE] "
                              "session rotation encountered errors, "
                              "continuing");
            }
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: [SESSION_SAVE] "
                           "new session established: %V",
                           new_session_id);
        }

        /* Set new session cookie (permanent) */
        if (ngx_oidc_session_set_permanent_cookie(r, provider, new_session_id)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: [SESSION_SAVE] "
                          "failed to set session cookie");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Clear temporary callback cookie */
        if (ngx_oidc_session_clear_temporary_cookie(r) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "oidc_handler_callback: [SESSION_SAVE] "
                          "failed to clear temporary callback cookie");
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [SESSION_SAVE] "
                       "session finalized, cookies updated");

        /* Transition to next state */
        ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_REDIRECT;

    /* fall through */

    /* State: Generate redirect response */
    case NGX_HTTP_OIDC_CALLBACK_STATE_REDIRECT:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [REDIRECT] "
                       "generating redirect to original URI");

        /* Use saved session ID for redirect */
        old_session_id = &saved_session_id;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [REDIRECT] "
                       "redirecting to original URI");

        /* Redirect to original URI - this returns NGX_DONE */
        /* After session rotation, ORIGINAL_URI is in the new session */
        rc = callback_redirect(r, provider,
                               new_session_id_val.len > 0
                               ? &new_session_id_val
                               : old_session_id);

        return rc;

    case NGX_HTTP_OIDC_CALLBACK_STATE_COMPLETED:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [COMPLETED] "
                       "callback already completed");
        return NGX_DONE;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: [COMPLETED] unexpected state: %d",
                      ctx->callback.state);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/*
 * Callback Handler: USERINFO_FETCH
 *
 * Handles callback.state: FETCH_USERINFO
 *
 * Purpose: Fetch additional user information from UserInfo endpoint
 */
static ngx_int_t
callback_phase_userinfo(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_provider_t *provider)
{
    ngx_int_t rc;
    ngx_str_t *session_id;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: [USERINFO] "
                   "handler invoked (state=%d)",
                   ctx->callback.state);

    /* Process states using switch (single state for this phase) */
    switch (ctx->callback.state) {
    /* State: Fetch UserInfo */
    case NGX_HTTP_OIDC_CALLBACK_STATE_FETCH_USERINFO:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [FETCH_USERINFO] "
                       "starting UserInfo fetch");

        /* Get session_id from cached context */
        session_id = &ctx->callback.session_id;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [FETCH_USERINFO] "
                       "fetching userinfo for session %V",
                       session_id);

        /* Initiate UserInfo fetch - delegate to existing function */
        rc = callback_fetch_userinfo(r, provider, session_id);

        if (rc == NGX_AGAIN) {
            /* Subrequest in progress - will re-enter at same state */
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: [FETCH_USERINFO] "
                           "subrequest in progress");
            return NGX_AGAIN;
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: [FETCH_USERINFO] "
                          "UserInfo fetch failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [FETCH_USERINFO] "
                       "UserInfo fetch completed");

        /* Transition to next phase */
        ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: "
                       "transitioning to COMPLETED phase");

        return callback_phase_complete(r, ctx, provider);

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: [USERINFO] invalid state: %d",
                      ctx->callback.state);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/*
 * Callback Handler: TOKEN_VERIFICATION
 *
 * Handles callback.state: VERIFY_ID_TOKEN
 *
 * Purpose: Verify ID token signature and claims, verify access token (at_hash)
 */
static ngx_int_t
callback_phase_verify(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_provider_t *provider)
{
    ngx_int_t rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: [TOKEN_VERIFY] "
                   "handler invoked (state=%d)",
                   ctx->callback.state);

    /* Process states using switch */
    switch (ctx->callback.state) {
    /* State: Verify ID token and access token */
    case NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ID_TOKEN:
    case NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ACCESS_TOKEN:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                       "starting token verification");

        /* Verify ID token (includes nonce validation) */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                       "verifying ID token");

        rc = callback_verify_id_token(r, provider);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                          "ID token validation failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                       "ID token verified successfully");

        /* Verify access token (at_hash validation) */
        rc = callback_verify_access_token(r, provider);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                          "access token validation failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                       "access token verified successfully");

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [VERIFY_ID_TOKEN] "
                       "token verification completed");

        /* Transition to next phase */
        if (provider->fetch_userinfo) {
            /* Fetch UserInfo endpoint */
            ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_FETCH_USERINFO;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: transitioning to "
                           "USERINFO phase");
            return callback_phase_userinfo(r, ctx, provider);
        } else {
            /* Skip UserInfo - complete callback */
            ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: transitioning to "
                           "COMPLETED phase (skipping userinfo)");
            return callback_phase_complete(r, ctx, provider);
        }

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: [TOKEN_VERIFY] "
                      "invalid state: %d",
                      ctx->callback.state);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/*
 * Callback Handler: CODE_EXCHANGE
 *
 * Handles callback.state: PARAM_PARSE → VALIDATE_STATE → TOKEN_EXCHANGE
 *
 * Purpose: Parse callback parameters, validate state, exchange code for tokens
 */
static ngx_int_t
callback_phase_exchange(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t code, state, error;
    ngx_str_t *session_id;
    ngx_int_t rc;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: [CODE_EXCHANGE] "
                   "handler invoked (state=%d)",
                   ctx->callback.state);

    /* Process states using switch + fall-through */
    switch (ctx->callback.state) {
    /* State: Parse callback parameters */
    case NGX_HTTP_OIDC_CALLBACK_STATE_PARAM_PARSE:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [PARAM_PARSE] "
                       "parsing callback parameters");

        /* Parse callback parameters (code, state) */
        if (ngx_http_arg(r, (u_char *) "code", 4, &code) != NGX_OK) {
            if (ngx_http_arg(r, (u_char *) "error", 5, &error) == NGX_OK) {
                ngx_str_t error_desc;

                if (ngx_http_arg(r, (u_char *) "error_description", 17,
                                 &error_desc)
                    == NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "oidc_handler_callback: authorization error: "
                                  "%V (%V)", &error, &error_desc);
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "oidc_handler_callback: authorization error: "
                                  "%V", &error);
                }
            }
            return NGX_HTTP_UNAUTHORIZED;
        }

        /* Validate code parameter (OAuth2 authorization code) */
        if (code.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: code parameter is empty");
            return NGX_HTTP_UNAUTHORIZED;
        }

        if (code.len > 1024) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: code parameter too long: "
                          "%uz bytes (max: 1024)",
                          code.len);
            return NGX_HTTP_UNAUTHORIZED;
        }

        /* Check for dangerous characters in code */
        for (size_t i = 0; i < code.len; i++) {
            u_char c = code.data[i];
            if (c == '\0' || (c < 0x20 && c != 0x09)) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_handler_callback: code parameter "
                              "contains invalid character at position %uz",
                              i);
                return NGX_HTTP_UNAUTHORIZED;
            }
        }

        /* Parse state parameter (REQUIRED - this module always sends state) */
        if (ngx_http_arg(r, (u_char *) "state", 5, &state) != NGX_OK
            || state.len == 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: missing state parameter "
                          "in callback (CSRF protection)");
            return NGX_HTTP_UNAUTHORIZED;
        }

        /* Validate state parameter length (DoS prevention) */
        if (state.len > 512) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: state parameter exceeds "
                          "maximum length: %uz (max: 512)",
                          state.len);
            return NGX_HTTP_UNAUTHORIZED;
        }
        /* Parse cookie: extract session_id */
        session_id = ngx_oidc_session_get_temporary_id(r);
        if (session_id == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: missing session cookie "
                          "in callback");
            return NGX_HTTP_UNAUTHORIZED;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: parsed session_id: %V",
                       session_id);

        /* Cache parsed values in context */
        ctx->callback.code = code;
        ctx->callback.state_param = state;
        ctx->callback.session_id = *session_id; /* Copy the structure */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [PARAM_PARSE] "
                       "parameters parsed and cached");

        /* Transition to next state */
        ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_VALIDATE_STATE;

    /* fall through */

    /* State: Validate state parameter */
    case NGX_HTTP_OIDC_CALLBACK_STATE_VALIDATE_STATE:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [VALIDATE_STATE] "
                       "validating state");

        /* Reuse cached values (may be re-entry from subrequest) */
        code = ctx->callback.code;
        state = ctx->callback.state_param;
        session_id = &ctx->callback.session_id;

        {
            /* Validate state against stored value */
            ngx_str_t stored_state;
            ngx_int_t store_result = ngx_oidc_session_get_state(
                r, provider->session_store, session_id, &stored_state);

            /* Validate state parameter using constant-time comparison */
            ngx_int_t state_valid = NGX_ERROR;
            if (store_result == NGX_OK) {
                /* Use constant-time comparison to prevent timing attacks */
                state_valid = ngx_oidc_secure_compare(stored_state.data,
                                                      stored_state.len,
                                                      state.data, state.len);
            }

            if (state_valid != NGX_OK) {
                /* Check for re-access (token already exists) */
                ngx_str_t stored_token;
                rc = ngx_oidc_session_get_id_token(r, provider->session_store,
                                                   session_id, &stored_token);
                if (rc == NGX_OK && stored_token.len > 0) {
                    /* Already authenticated
                     * - skip to session save for rotation */
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "oidc_handler_callback: [VALIDATE_STATE] "
                                   "token already exists, skipping to session "
                                   "save for rotation");

                    ctx->callback.state
                        = NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE;
                    return callback_phase_complete(r, ctx, provider);
                }

                /* Invalid state */
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_handler_callback: [VALIDATE_STATE] "
                              "state validation failed");
                return NGX_HTTP_UNAUTHORIZED;
            }

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: [VALIDATE_STATE] "
                           "state validation successful");

            /* Remove state from shared memory (one-time use) */
            ngx_oidc_session_delete_state(r, provider->session_store,
                                          session_id);
        }

        /* Atomically check and mark authorization code as used (race-safe) */
        rc = ngx_oidc_session_try_mark_code_used(r, provider->session_store,
                                                 &code);
        if (rc == NGX_DECLINED) {
            /* Code already used - reject (potential replay attack) */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: authorization code reuse "
                          "detected - rejecting request");
            return NGX_HTTP_UNAUTHORIZED;
        } else if (rc != NGX_OK) {
            /* Error checking/marking code usage */
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Transition to next state */
        ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE;

    /* fall through */

    /* State: Exchange authorization code for tokens */
    case NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [TOKEN_EXCHANGE] "
                       "initiating token exchange");

        /* Reuse cached values */
        code = ctx->callback.code;
        state = ctx->callback.state_param;

        /* Initiate token exchange - delegate to existing function */
        rc = callback_exchange_code(r, provider, &code, &state);

        if (rc == NGX_AGAIN) {
            /* Subrequest initiated
             * - transition to WAIT state before returning */
            ctx->callback.state
                = NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE_WAIT;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_callback: [TOKEN_EXCHANGE] "
                           "subrequest initiated, transitioning to WAIT state");
            return NGX_AGAIN;
        }

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: [TOKEN_EXCHANGE] "
                          "token exchange failed");
            return rc;
        }

        /* Note: NGX_OK should not be returned here as callback_exchange_code
         * always returns NGX_AGAIN for subrequest or an error code. */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: [TOKEN_EXCHANGE] "
                      "unexpected return code from callback_exchange_code");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    /* State: Wait for token exchange to complete */
    case NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE_WAIT:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: [TOKEN_EXCHANGE_WAIT] "
                       "waiting for subrequest completion");

        /* Subrequest is still in progress. callback_token_done will transition
         * to the next state when the subrequest completes. */
        return NGX_AGAIN;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: [CODE_EXCHANGE] "
                      "invalid state: %d",
                      ctx->callback.state);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/*
 * This function processes the authorization callback using a state machine:
 * 1. Exchange Phase: Parse params, validate state, exchange code for tokens
 * 2. Verify Phase: Verify ID token and access token (if enabled)
 * 3. UserInfo Phase: Fetch UserInfo endpoint (if enabled)
 * 4. Complete Phase: Save session, rotate session ID, redirect to original URI
 */
ngx_int_t
ngx_oidc_handler_callback(ngx_http_request_t *r)
{
    ngx_http_oidc_ctx_t *ctx;
    ngx_http_oidc_provider_t *provider;

    /* Validate input parameters */
    if (r == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: invoked");

    /* Check HTTP method (allow GET and HEAD per RFC 7231) */
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: invalid method %ui "
                      "(only GET/HEAD allowed)",
                      r->method);
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* Get or create request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_callback: failed to allocate context");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Initialize state to PARAM_PARSE (Approach A) */
        ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_PARAM_PARSE;

        ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: created new context, "
                       "state=PARAM_PARSE");
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: reusing context, state=%d",
                       ctx->callback.state);
    }

    /* Get provider from context (set by Handler) */
    provider = ctx->callback.provider;
    if (provider == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: provider not cached "
                      "in callback context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_callback: dispatching (state=%d, provider=%V)",
                   ctx->callback.state, &provider->name);

    /* Dispatch based on callback_state (Approach A) */
    switch (ctx->callback.state) {
    /* Code exchange phase states */
    case NGX_HTTP_OIDC_CALLBACK_STATE_PARAM_PARSE:
    case NGX_HTTP_OIDC_CALLBACK_STATE_VALIDATE_STATE:
    case NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE:
    case NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE_WAIT:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: dispatching to "
                       "CODE_EXCHANGE handler");
        return callback_phase_exchange(r, ctx, provider);

    /* Token verification phase states */
    case NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ID_TOKEN:
    case NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ACCESS_TOKEN:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: dispatching to "
                       "TOKEN_VERIFY handler");
        return callback_phase_verify(r, ctx, provider);

    /* UserInfo phase states */
    case NGX_HTTP_OIDC_CALLBACK_STATE_FETCH_USERINFO:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: dispatching to "
                       "USERINFO handler");
        return callback_phase_userinfo(r, ctx, provider);

    /* Completion phase states */
    case NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE:
    case NGX_HTTP_OIDC_CALLBACK_STATE_REDIRECT:
    case NGX_HTTP_OIDC_CALLBACK_STATE_COMPLETED:
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_callback: dispatching to "
                       "COMPLETE handler");
        return callback_phase_complete(r, ctx, provider);

    /* Invalid state */
    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_callback: invalid callback state: %d",
                      ctx->callback.state);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}
