/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_random.h"
#include "ngx_oidc_session.h"
#include "ngx_oidc_metadata.h"
#include "ngx_oidc_url.h"
#include "ngx_oidc_handler_authenticate.h"

/**
 * Build authorization endpoint URL with OIDC parameters
 *
 * Constructs the full authorization URL including query parameters:
 * response_type, client_id, redirect_uri, scope, state, nonce,
 * and PKCE code_challenge (S256).
 *
 * @param[in] r              HTTP request context
 * @param[in] provider       OIDC provider configuration
 * @param[in] state          Generated state parameter
 * @param[in] nonce          Generated nonce parameter
 * @param[in] code_verifier  Generated PKCE code_verifier
 *
 * @return Authorization URL string, or NULL on failure
 */
static ngx_str_t *
authenticate_build_auth_url(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_str_t *state, ngx_str_t *nonce,
    ngx_str_t *code_verifier)
{
    ngx_str_t *auth_url;
    ngx_str_t client_id, redirect_uri, extra_args;
    ngx_str_t scope_value, *scope;
    ngx_str_t encoded_client_id, encoded_redirect_uri,
              encoded_scope, encoded_state, encoded_nonce;
    ngx_str_t *code_challenge, encoded_code_challenge,
              encoded_code_challenge_method;
    u_char *p;
    size_t len;
    ngx_uint_t i;
    ngx_oidc_metadata_cache_t *metadata;
    ngx_http_oidc_ctx_t *ctx;
    ngx_str_t *authorization;

    /* Get metadata from request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->cached.metadata == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: metadata not cached "
                      "in context");
        return NULL;
    }

    metadata = ctx->cached.metadata;

    authorization = ngx_oidc_metadata_get_authorization_endpoint(metadata);
    if (authorization == NULL || authorization->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: authorization_endpoint "
                      "not available from metadata");
        return NULL;
    }

    /* Get client_id from provider */
    if (ngx_http_complex_value(r, provider->client_id, &client_id) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to "
                      "evaluate client_id");
        return NULL;
    }

    if (client_id.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: no client_id available "
                      "from provider");
        return NULL;
    }

    /* Get redirect_uri from provider */
    if (ngx_http_complex_value(r, provider->redirect_uri, &redirect_uri)
        != NGX_OK)
    {
        return NULL;
    }

    /* Build absolute URL from redirect_uri (handles relative paths) */
    {
        ngx_str_t absolute_redirect_uri;

        if (ngx_oidc_url_build_absolute(r, &redirect_uri,
                                        &absolute_redirect_uri)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: redirect_uri parameter "
                          "validation failed");
            return NULL;
        }

        redirect_uri = absolute_redirect_uri;
    }

    if (redirect_uri.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: no redirect_uri available "
                      "from provider");
        return NULL;
    }

    /* Build scope value */
    if (provider->scopes && provider->scopes->nelts > 0) {
        ngx_uint_t has_openid = 0;

        /* Check if openid is already in scopes and calculate total length */
        len = 0;
        scope = provider->scopes->elts;
        for (i = 0; i < provider->scopes->nelts; i++) {
            if (scope[i].len == 6
                && ngx_strncmp(scope[i].data, "openid", 6) == 0)
            {
                has_openid = 1;
            }
            if (len > 0) {
                len += sizeof(" ") - 1; /* Space separator */
            }
            len += scope[i].len;
        }

        /* Add openid if not present */
        if (!has_openid) {
            if (len > 0) {
                len += sizeof(" ") - 1; /* Space separator */
            }
            len += sizeof("openid") - 1;
        }

        scope_value.data = ngx_pnalloc(r->pool, len + 1); /* +1 for safety */
        if (scope_value.data == NULL) {
            return NULL;
        }

        p = scope_value.data;

        /* Add openid first if not already present */
        if (!has_openid) {
            p = ngx_cpymem(p, "openid", sizeof("openid") - 1);
        }

        /* Add configured scopes */
        for (i = 0; i < provider->scopes->nelts; i++) {
            if (p != scope_value.data) {
                *p++ = ' ';
            }
            p = ngx_cpymem(p, scope[i].data, scope[i].len);
        }
        scope_value.len = p - scope_value.data;
        /* Ensure null termination for scope value */
        scope_value.data[scope_value.len] = '\0';
    } else {
        ngx_str_set(&scope_value, "openid");
    }

    /* Get extra auth arguments if configured */
    ngx_str_null(&extra_args);
    if (provider->extra_auth_args) {
        if (ngx_http_complex_value(r, provider->extra_auth_args, &extra_args)
            != NGX_OK)
        {
            return NULL;
        }
    }

    /* Generate PKCE parameters if enabled */
    code_challenge = NULL;
    ngx_str_null(&encoded_code_challenge);
    ngx_str_null(&encoded_code_challenge_method);

    if (provider->pkce.enable && code_verifier && code_verifier->len > 0) {
        ngx_str_t *challenge_method;

        /* Allocate code_challenge */
        code_challenge = ngx_palloc(r->pool, sizeof(ngx_str_t));
        if (code_challenge == NULL) {
            return NULL;
        }

        challenge_method = &provider->pkce.method;

        /* Generate code_challenge based on method */
        if (challenge_method->len == 5
            && ngx_strncmp(challenge_method->data, "plain", 5) == 0)
        {
            /* For plain method, code_challenge is the code_verifier itself */
            code_challenge->data = code_verifier->data;
            code_challenge->len = code_verifier->len;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_authenticate: using plain PKCE "
                           "method, code_challenge: %V",
                           code_challenge);
        } else {
            /* For S256 method, hash the code_verifier */
            if (ngx_oidc_random_code_challenge(r, code_verifier, code_challenge)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_handler_authenticate: failed to "
                              "generate PKCE code_challenge");
                return NULL;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_authenticate: using S256 PKCE "
                           "method, code_challenge: %V",
                           code_challenge);
        }

        /* URL encode PKCE parameters */
        if (ngx_oidc_url_encode(r, code_challenge, &encoded_code_challenge)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: failed to encode "
                          "PKCE code_challenge");
            return NULL;
        }

        if (ngx_oidc_url_encode(r, challenge_method,
                                &encoded_code_challenge_method)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: failed to encode "
                          "PKCE code_challenge_method");
            return NULL;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_authenticate: generated PKCE parameters "
                       "- code_challenge: %V, method: %V",
                       code_challenge, challenge_method);
    }

    /* URL encode each parameter value individually */
    if (ngx_oidc_url_encode(r, &client_id, &encoded_client_id) != NGX_OK) {
        return NULL;
    }

    if (ngx_oidc_url_encode(r, &redirect_uri, &encoded_redirect_uri)
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_oidc_url_encode(r, &scope_value, &encoded_scope) != NGX_OK) {
        return NULL;
    }

    if (ngx_oidc_url_encode(r, state, &encoded_state) != NGX_OK) {
        return NULL;
    }

    if (ngx_oidc_url_encode(r, nonce, &encoded_nonce) != NGX_OK) {
        return NULL;
    }

    size_t base_len, params_len;

    /* Calculate base length */
    base_len = sizeof("?response_type=code&client_id=") - 1
               + sizeof("&redirect_uri=") - 1
               + sizeof("&scope=") - 1
               + sizeof("&state=") - 1
               + sizeof("&nonce=") - 1;

    /* Calculate parameter lengths */
    params_len = encoded_client_id.len + encoded_redirect_uri.len
                 + encoded_scope.len + encoded_state.len + encoded_nonce.len;

    /* Check for overflow */
    if (authorization->len > NGX_MAX_SIZE_T_VALUE - base_len - params_len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: URL length overflow");
        return NULL;
    }

    len = authorization->len + base_len + params_len;

    /* Add PKCE parameters length if enabled */
    if (provider->pkce.enable && code_challenge) {
        size_t pkce_len = sizeof("&code_challenge=") - 1
                          + encoded_code_challenge.len
                          + sizeof("&code_challenge_method=") - 1
                          + encoded_code_challenge_method.len;

        if (len > NGX_MAX_SIZE_T_VALUE - pkce_len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: URL length overflow "
                          "with PKCE");
            return NULL;
        }

        len += pkce_len;
    }

    /* Add extra arguments length if present */
    if (extra_args.len > 0) {
        if (len > NGX_MAX_SIZE_T_VALUE - (sizeof("&") - 1) - extra_args.len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: URL length overflow "
                          "with extra args");
            return NULL;
        }
        len += sizeof("&") - 1 + extra_args.len;
    }

    /* Allocate buffer for final URL */
    auth_url = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (auth_url == NULL) {
        return NULL;
    }

    /* Allocate URL buffer with extra space for null terminator */
    auth_url->data = ngx_pnalloc(r->pool, len + 1);
    if (auth_url->data == NULL) {
        return NULL;
    }

    /* Build final URL with encoded parameters */
    p = ngx_snprintf(auth_url->data, len + 1,
                     "%V?response_type=code&client_id=%V&redirect_uri=%V&scope="
                     "%V&state=%V&nonce=%V",
                     authorization, &encoded_client_id,
                     &encoded_redirect_uri, &encoded_scope, &encoded_state,
                     &encoded_nonce);

    /* Append PKCE parameters if enabled */
    if (provider->pkce.enable && code_challenge) {
        p = ngx_snprintf(p, len + 1 - (p - auth_url->data),
                         "&code_challenge=%V&code_challenge_method=%V",
                         &encoded_code_challenge,
                         &encoded_code_challenge_method);
    }

    /* Append extra auth arguments if present */
    if (extra_args.len > 0) {
        p = ngx_snprintf(p, len + 1 - (p - auth_url->data), "&%V", &extra_args);
    }

    auth_url->len = p - auth_url->data;

    /* Ensure null termination for safety */
    auth_url->data[auth_url->len] = '\0';

    /* Validate constructed authorization URL for CRLF injection */
    if (ngx_oidc_url_validate(r, auth_url) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: invalid authorization URL");
        return NULL;
    }

    return auth_url;
}

/*
 * This function:
 * - Generates state, nonce, and PKCE parameters
 * - Stores them in session store
 * - Builds authorization URL with all required parameters
 * - Redirects user to IdP's authorization endpoint
 */
ngx_int_t
ngx_oidc_handler_authenticate(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t state, nonce, *auth_url, *session_id, code_verifier;
    ngx_table_elt_t *location;
    ngx_int_t rc;

    ngx_memzero(&code_verifier, sizeof(ngx_str_t));

    /* Validate input parameters */
    if (r == NULL || provider == NULL) {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: NULL parameter");
        }
        return NGX_ERROR;
    }

    /* Generate session ID using Util Module */
    ngx_str_t session_id_val;
    if (ngx_oidc_random_session_id(r, &session_id_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to generate "
                      "session ID");
        return NGX_ERROR;
    }
    session_id = &session_id_val;

    /* Generate state using Util Module API */
    rc = ngx_oidc_random_state(r, &state);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to generate state");
        return NGX_ERROR;
    }

    /* Generate nonce using Util Module API */
    rc = ngx_oidc_random_nonce(r, &nonce);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to generate nonce");
        return NGX_ERROR;
    }

    /* Store the original request URI */
    /* Construct the full original URI with query string */
    ngx_str_t original_uri;
    size_t uri_len = r->uri.len;
    if (r->args.len > 0) {
        uri_len += 1 + r->args.len; /* +1 for '?' */
    }
    original_uri.data = ngx_pnalloc(r->pool, uri_len);
    if (original_uri.data == NULL) {
        return NGX_ERROR;
    }
    u_char *p = ngx_cpymem(original_uri.data, r->uri.data, r->uri.len);
    if (r->args.len > 0) {
        *p++ = '?';
        p = ngx_cpymem(p, r->args.data, r->args.len);
    }
    original_uri.len = p - original_uri.data;

    /* Store the original URI in session store */
    if (ngx_oidc_session_set_orig_uri(r, provider->session_store, session_id,
                                      &original_uri,
                                      ngx_time() + NGX_OIDC_PRE_AUTH_TIMEOUT)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to store "
                      "original URI in %s",
                      provider->session_store->type
                      == NGX_OIDC_SESSION_STORE_MEMORY
                      ? "shared memory"
                      : "redis");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_authenticate: stored original URI: %V",
                   &original_uri);

    /* Generate and store PKCE code_verifier if enabled */
    ngx_str_null(&code_verifier);

    if (provider->pkce.enable) {
        /* Generate code_verifier using Util Module API */
        rc = ngx_oidc_random_code_verifier(r, &code_verifier);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: failed to generate "
                          "PKCE code_verifier");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_authenticate: generated PKCE "
                       "code_verifier: %V",
                       &code_verifier);
    }

    /* Store state, nonce, and code_verifier in session store */
    time_t expires = ngx_time() + NGX_OIDC_PRE_AUTH_TIMEOUT;
    if (ngx_oidc_session_set_state(r, provider->session_store, session_id,
                                   &state, expires)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to store state in %s",
                      provider->session_store->type
                      == NGX_OIDC_SESSION_STORE_MEMORY
                      ? "shared memory"
                      : "redis");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_oidc_session_set_nonce(r, provider->session_store, session_id,
                                   &nonce, expires)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_authenticate: failed to store nonce in %s",
                      provider->session_store->type
                      == NGX_OIDC_SESSION_STORE_MEMORY
                      ? "shared memory"
                      : "redis");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (provider->pkce.enable) {
        /* Store the actual code_verifier value */
        if (ngx_oidc_session_set_verifier(r, provider->session_store,
                                          session_id, &code_verifier,
                                          expires)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_authenticate: failed to store PKCE "
                          "code_verifier in %s",
                          provider->session_store->type
                          == NGX_OIDC_SESSION_STORE_MEMORY
                          ? "shared memory"
                          : "redis");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Set temporary session cookie with nonce and state */
    if (ngx_oidc_session_set_temporary_cookie(r, provider, session_id)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Build authorization URL */
    auth_url = authenticate_build_auth_url(r, provider, &state, &nonce,
                                           provider->pkce.enable
                                           ? &code_verifier : NULL);
    if (auth_url == NULL) {
        return NGX_ERROR;
    }

    /* Redirect to authorization endpoint */
    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_ERROR;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = *auth_url;

    return NGX_HTTP_MOVED_TEMPORARILY;
}
