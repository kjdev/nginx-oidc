/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_PROVIDER_H_INCLUDED_
#define _NGX_OIDC_PROVIDER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"

/**
 * Find provider by name from main configuration
 *
 * @param[in] r              Request object
 * @param[in] provider_name  Provider name to search for
 *
 * @return Provider pointer or NULL if not found
 */
ngx_http_oidc_provider_t *ngx_oidc_provider_by_name(ngx_http_request_t *r,
    ngx_str_t *provider_name);

/**
 * Get provider for callback request
 * Extracts provider name from callback cookie
 *
 * @param[in] r  Request object
 *
 * @return Provider pointer or NULL on error
 */
ngx_http_oidc_provider_t *ngx_oidc_provider_from_callback(
    ngx_http_request_t *r);

/**
 * Get provider for normal request
 * Gets provider name from location configuration
 *
 * @param[in] r     Request object
 * @param[in] olcf  Location configuration
 *
 * @return Provider pointer or NULL on error
 */
ngx_http_oidc_provider_t *
ngx_oidc_provider_from_config(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *olcf);

#endif /* _NGX_OIDC_PROVIDER_H_INCLUDED_ */
