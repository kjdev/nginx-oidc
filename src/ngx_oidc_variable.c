/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * nginx variable implementations
 */

#include "ngx_oidc_variable.h"
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_provider.h"
#include "ngx_oidc_session.h"
#include "ngx_oidc_json.h"
#include "ngx_oidc_jwt.h"

/* Pool cleanup handler for Jansson JSON objects */
static void
oidc_variable_json_cleanup(void *data)
{
    ngx_oidc_json_free((ngx_oidc_json_t *) data);
}

/* Token type enumeration */
typedef enum {
    VAR_TOKEN_ID = 0,     /* ID token (JWT) */
    VAR_TOKEN_ACCESS = 1  /* Access token */
} var_token_type_t;

/**
 * Retrieve OIDC token value for nginx variable
 *
 * Common handler for $oidc_id_token and $oidc_access_token variables.
 * Looks up the token from session store based on token type (data parameter).
 *
 * @param[in] r     HTTP request context
 * @param[out] v    Variable value to set
 * @param[in] data  Token type (VAR_TOKEN_ID or VAR_TOKEN_ACCESS)
 *
 * @return NGX_OK on success (v->not_found set if token unavailable)
 */
static ngx_int_t
var_get_token(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_oidc_main_conf_t *omcf;
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_http_oidc_provider_t *provider;
    ngx_str_t provider_name, token_value;
    ngx_str_t *session_id;
    ngx_int_t rc;
    var_token_type_t token_type;

    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    if (omcf == NULL || omcf->providers == NULL || olcf == NULL
        || olcf->provider_name == NULL
        || olcf->mode == NGX_HTTP_OIDC_MODE_OFF)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, olcf->provider_name, &provider_name)
        != NGX_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    if (provider_name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Find provider configuration using helper function */
    provider = ngx_oidc_provider_by_name(r, &provider_name);
    if (provider == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Get session ID from cookie (permanent cookie contains session_id only) */
    session_id = ngx_oidc_session_get_permanent_id(r, provider);
    if (session_id == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Determine token type and retrieve using appropriate Service API */
    token_type = (var_token_type_t) data;

    switch (token_type) {
    case VAR_TOKEN_ID:
        rc = ngx_oidc_session_get_id_token(r, provider->session_store,
                                           session_id, &token_value);
        break;

    case VAR_TOKEN_ACCESS:
        rc = ngx_oidc_session_get_access_token(r, provider->session_store,
                                               session_id, &token_value);
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
    }

    if (rc == NGX_OK) {
        v->len = token_value.len;
        v->data = token_value.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }

    v->not_found = 1;
    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_id_token(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    return var_get_token(r, v, VAR_TOKEN_ID);
}

ngx_int_t
ngx_oidc_variable_access_token(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    return var_get_token(r, v, VAR_TOKEN_ACCESS);
}

ngx_int_t
ngx_oidc_variable_claim(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_oidc_main_conf_t *omcf;
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_http_oidc_provider_t *provider;
    ngx_http_oidc_ctx_t *ctx;
    ngx_str_t provider_name, token_value, payload, claim_name;
    ngx_str_t *session_id;
    ngx_oidc_json_t *payload_json, *claim_value;
    const char *str_value;
    ngx_flag_t need_to_free_json = 0;
    ngx_int_t rc;

    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    if (omcf == NULL || omcf->providers == NULL || olcf == NULL
        || olcf->provider_name == NULL
        || olcf->mode == NGX_HTTP_OIDC_MODE_OFF)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, olcf->provider_name, &provider_name)
        != NGX_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    if (provider_name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Find provider configuration using helper function */
    provider = ngx_oidc_provider_by_name(r, &provider_name);
    if (provider == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Get session ID from cookie (permanent cookie contains session_id only) */
    session_id = ngx_oidc_session_get_permanent_id(r, provider);
    if (session_id == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Get or create request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
        if (ctx == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);
    }

    /* Check if payload is already cached for this session */
    if (ctx->cached.id_token_payload != NULL
        && ctx->cached.session_id.len == session_id->len
        && ngx_memcmp(ctx->cached.session_id.data, session_id->data,
                      session_id->len) == 0)
    {
        /* Use cached payload */
        payload_json = ctx->cached.id_token_payload;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_variable: using cached JWT payload for session %V",
                       session_id);
    } else {
        /* Not cached, need to decode and parse */
        /* Retrieve id_token using Service Layer API */
        rc = ngx_oidc_session_get_id_token(r, provider->session_store,
                                           session_id, &token_value);
        if (rc != NGX_OK || token_value.len == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        /* Extract JWT payload */
        if (ngx_oidc_jwt_decode_payload(&token_value, &payload, r->pool)
            != NGX_OK)
        {
            v->not_found = 1;
            return NGX_OK;
        }

        /* Parse payload JSON */
        payload_json = ngx_oidc_json_parse(&payload, r->pool);
        if (!payload_json) {
            v->not_found = 1;
            return NGX_OK;
        }

        /* Cache the parsed payload for this request */
        ctx->cached.id_token_payload = payload_json;

        /* Register pool cleanup to free Jansson JSON on request end */
        {
            ngx_pool_cleanup_t *cln;

            cln = ngx_pool_cleanup_add(r->pool, 0);
            if (cln) {
                cln->handler = oidc_variable_json_cleanup;
                cln->data = payload_json;
            }
        }

        ctx->cached.session_id.len = session_id->len;
        ctx->cached.session_id.data = ngx_pnalloc(r->pool, session_id->len);
        if (ctx->cached.session_id.data != NULL) {
            ngx_memcpy(ctx->cached.session_id.data, session_id->data,
                       session_id->len);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_variable: cached JWT payload for session %V",
                           session_id);
        } else {
            /* Failed to allocate session ID, but we can still proceed
             * with this request */
            ctx->cached.session_id.len = 0;
        }

        need_to_free_json = 0; /* Don't free - it's cached in context */
    }

    /* Extract claim name from variable name (skip "oidc_claim_" prefix) */
    ngx_http_variable_t *var = (ngx_http_variable_t *) data;
    if (var->name.len <= 11) { /* "oidc_claim_".length = 11 */
        if (need_to_free_json) {
            ngx_oidc_json_free(payload_json);
        }
        v->not_found = 1;
        return NGX_OK;
    }

    claim_name.data = var->name.data + 11; /* Skip "oidc_claim_" */
    claim_name.len = var->name.len - 11;

    /* Get claim value from JSON */
    char *claim_key = ngx_pnalloc(r->pool, claim_name.len + 1);
    if (claim_key == NULL) {
        if (need_to_free_json) {
            ngx_oidc_json_free(payload_json);
        }
        v->not_found = 1;
        return NGX_OK;
    }
    ngx_memcpy(claim_key, claim_name.data, claim_name.len);
    claim_key[claim_name.len] = '\0';

    claim_value = ngx_oidc_json_object_get(payload_json, claim_key);
    if (!claim_value) {
        /* Claim not found in ID token, try UserInfo data */
        ngx_str_t userinfo_data;
        ngx_oidc_json_t *userinfo_json = NULL;

        rc = ngx_oidc_session_get_userinfo(r, provider->session_store,
                                           session_id, &userinfo_data);
        if (rc == NGX_OK && userinfo_data.len > 0) {
            /* Parse UserInfo JSON */
            userinfo_json = ngx_oidc_json_parse(&userinfo_data, r->pool);
            if (userinfo_json) {
                claim_value =
                    ngx_oidc_json_object_get(userinfo_json, claim_key);
                if (claim_value) {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "oidc_variable: found claim '%s' "
                                   "in userinfo for session %V",
                                   claim_key, session_id);
                    /* Free ID token payload JSON as we'll use userinfo JSON
                     * instead */
                    if (need_to_free_json) {
                        ngx_oidc_json_free(payload_json);
                        need_to_free_json = 0;
                    }
                    /* Mark userinfo JSON for freeing after extracting claim
                     * value */
                    payload_json = userinfo_json;
                    need_to_free_json = 1;
                } else {
                    /* Claim not in userinfo either, free userinfo JSON */
                    ngx_oidc_json_free(userinfo_json);
                }
            }
        }

        if (!claim_value) {
            /* Claim not found in both ID token and UserInfo */
            if (need_to_free_json) {
                ngx_oidc_json_free(payload_json);
            }
            v->not_found = 1;
            return NGX_OK;
        }
    }

    if (ngx_oidc_json_is_string(claim_value)) {
        str_value = ngx_oidc_json_string(claim_value);
        if (str_value) {
            v->len = ngx_strlen(str_value);
            v->data = ngx_pnalloc(r->pool, v->len);
            if (v->data == NULL) {
                if (need_to_free_json) {
                    ngx_oidc_json_free(payload_json);
                }
                v->not_found = 1;
                return NGX_OK;
            }
            ngx_memcpy(v->data, str_value, v->len);
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
        } else {
            v->not_found = 1;
        }
    } else if (ngx_oidc_json_is_integer(claim_value)) {
        ngx_int_t int_value = ngx_oidc_json_integer(claim_value);
        v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
        if (v->data == NULL) {
            if (need_to_free_json) {
                ngx_oidc_json_free(payload_json);
            }
            v->not_found = 1;
            return NGX_OK;
        }
        v->len = ngx_sprintf(v->data, "%L", int_value) - v->data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else if (ngx_oidc_json_is_boolean(claim_value)) {
        const char *bool_str =
            ngx_oidc_json_boolean(claim_value) ? "true" : "false";
        v->len = ngx_strlen(bool_str);
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            if (need_to_free_json) {
                ngx_oidc_json_free(payload_json);
            }
            v->not_found = 1;
            return NGX_OK;
        }
        ngx_memcpy(v->data, bool_str, v->len);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else {
        v->not_found = 1;
    }

    /* Don't free payload_json if it's cached */
    if (need_to_free_json) {
        ngx_oidc_json_free(payload_json);
    }

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_authenticated(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_main_conf_t *omcf;
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_http_oidc_provider_t *provider;
    ngx_str_t provider_name, token_value;
    ngx_str_t *session_id;
    ngx_int_t rc;

    /* Default to not authenticated */
    v->len = 1;
    v->data = (u_char *) "0";
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    if (omcf == NULL || omcf->providers == NULL || olcf == NULL
        || olcf->provider_name == NULL
        || olcf->mode == NGX_HTTP_OIDC_MODE_OFF)
    {
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, olcf->provider_name, &provider_name)
        != NGX_OK)
    {
        return NGX_OK;
    }

    if (provider_name.len == 0) {
        return NGX_OK;
    }

    /* Find provider configuration */
    provider = ngx_oidc_provider_by_name(r, &provider_name);
    if (provider == NULL) {
        return NGX_OK;
    }

    /* Get session ID from permanent cookie */
    session_id = ngx_oidc_session_get_permanent_id(r, provider);
    if (session_id == NULL) {
        return NGX_OK;
    }

    /* Check if ID token exists in session */
    rc = ngx_oidc_session_get_id_token(r, provider->session_store,
                                       session_id, &token_value);
    if (rc == NGX_OK) {
        /* User is authenticated */
        v->data = (u_char *) "1";
    }

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_userinfo(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_http_oidc_main_conf_t *omcf;
    ngx_http_oidc_provider_t *provider;
    ngx_str_t provider_name, userinfo_data;
    ngx_str_t *session_id;
    ngx_int_t rc;

    /* Get location configuration */
    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    if (olcf == NULL || olcf->provider_name == NULL
        || olcf->mode == NGX_HTTP_OIDC_MODE_OFF)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Get provider name */
    if (ngx_http_complex_value(r, olcf->provider_name, &provider_name)
        != NGX_OK)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Find provider */
    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (omcf == NULL || omcf->providers == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    provider = ngx_oidc_provider_by_name(r, &provider_name);
    if (provider == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Get session ID from permanent cookie */
    session_id = ngx_oidc_session_get_permanent_id(r, provider);
    if (session_id == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Get userinfo data using Service Layer API */
    rc = ngx_oidc_session_get_userinfo(r, provider->session_store, session_id,
                                       &userinfo_data);
    if (rc != NGX_OK || userinfo_data.len == 0) {
        /* No userinfo data available */
        v->not_found = 1;
        return NGX_OK;
    }

    /* Copy userinfo data to request pool to avoid binary/shared memory issues
     */
    v->len = userinfo_data.len;
    v->data = ngx_pnalloc(r->pool, userinfo_data.len);
    if (v->data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }
    ngx_memcpy(v->data, userinfo_data.data, userinfo_data.len);

    /* Set variable value */
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_fetch_url(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->fetch.url.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->fetch.url.data;
    v->len = ctx->fetch.url.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_fetch_method(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->fetch.method.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->fetch.method.data;
    v->len = ctx->fetch.method.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_fetch_content_type(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->fetch.content_type.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->fetch.content_type.data;
    v->len = ctx->fetch.content_type.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_fetch_content_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_ctx_t *ctx;
    u_char *p;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->fetch.content_length < 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = p;
    v->len = ngx_sprintf(p, "%O", ctx->fetch.content_length) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

ngx_int_t
ngx_oidc_variable_fetch_bearer(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_ctx_t *ctx;
    u_char *p;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->fetch.bearer.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Return "Bearer <token>" format for direct use in Authorization header */
    v->len = sizeof("Bearer ") - 1 + ctx->fetch.bearer.len;
    p = ngx_pnalloc(r->pool, v->len);
    if (p == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = p;
    p = ngx_cpymem(p, "Bearer ", sizeof("Bearer ") - 1);
    ngx_memcpy(p, ctx->fetch.bearer.data, ctx->fetch.bearer.len);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
