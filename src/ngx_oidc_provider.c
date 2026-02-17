/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_provider.h"
#include "ngx_oidc_http.h"

ngx_http_oidc_provider_t *
ngx_oidc_provider_by_name(ngx_http_request_t *r, ngx_str_t *provider_name)
{
    ngx_http_oidc_main_conf_t *omcf;
    ngx_http_oidc_provider_t *provider;
    ngx_uint_t i;

    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (omcf == NULL || omcf->providers == NULL) {
        return NULL;
    }

    provider = omcf->providers->elts;
    for (i = 0; i < omcf->providers->nelts; i++) {
        if (provider[i].name.len == provider_name->len
            && ngx_strncmp(provider[i].name.data, provider_name->data,
                           provider_name->len) == 0)
        {
            return &provider[i];
        }
    }

    return NULL;
}

ngx_http_oidc_provider_t *
ngx_oidc_provider_from_callback(ngx_http_request_t *r)
{
    ngx_str_t cookie_name;
    ngx_str_t cookie_value;
    ngx_str_t provider_name;
    u_char *colon;
    ngx_int_t rc;

    /* Set callback cookie name */
    ngx_str_set(&cookie_name, NGX_OIDC_SESSION_CALLBACK);

    /* Get callback cookie directly using Infrastructure Layer API */
    rc = ngx_oidc_http_cookie_get(r, &cookie_name, &cookie_value);
    if (rc == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_provider: callback cookie not found");
        return NULL;
    }
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_provider: failed to get callback cookie");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_provider: callback cookie value: %V", &cookie_value);

    /* Parse "provider_name:session_id" format */
    colon = ngx_strlchr(cookie_value.data,
                        cookie_value.data + cookie_value.len, ':');
    if (colon == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_provider: invalid callback cookie format "
                      "(missing ':')");
        return NULL;
    }

    /* Extract provider name */
    provider_name.data = cookie_value.data;
    provider_name.len = colon - cookie_value.data;

    if (provider_name.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_provider: empty provider name in callback cookie");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_provider: selected provider from callback: %V",
                   &provider_name);

    /* Look up provider by name */
    return ngx_oidc_provider_by_name(r, &provider_name);
}

ngx_http_oidc_provider_t *
ngx_oidc_provider_from_config(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *olcf)
{
    ngx_str_t provider_name;

    if (olcf == NULL || olcf->provider_name == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_provider: location config or "
                      "provider name is NULL");
        return NULL;
    }

    /* Get provider name from config */
    if (ngx_http_complex_value(r, olcf->provider_name, &provider_name)
        != NGX_OK)
    {
        return NULL;
    }

    if (provider_name.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_provider: no provider name specified");
        return NULL;
    }

    /* Find provider configuration */
    return ngx_oidc_provider_by_name(r, &provider_name);
}
