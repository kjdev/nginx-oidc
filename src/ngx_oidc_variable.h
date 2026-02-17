/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_VARIABLE_H_INCLUDED_
#define _NGX_OIDC_VARIABLE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * Get ID token value ($oidc_id_token)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_id_token(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get access token value ($oidc_access_token)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_access_token(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get claim value from ID token ($oidc_claim_*)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_claim(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get authentication status ($oidc_authenticated)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_authenticated(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get userinfo data ($oidc_userinfo)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_userinfo(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get fetch target URL ($oidc_fetch_url)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_fetch_url(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get fetch HTTP method ($oidc_fetch_method)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_fetch_method(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get fetch Content-Type ($oidc_fetch_content_type)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_fetch_content_type(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get fetch Content-Length ($oidc_fetch_content_length)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_fetch_content_length(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

/**
 * Get fetch Bearer token ($oidc_fetch_bearer)
 *
 * @param[in] r     Request context
 * @param[out] v    Variable
 * @param[in] data  Variable handler data (unused)
 *
 * @return NGX_OK on success
 */
ngx_int_t ngx_oidc_variable_fetch_bearer(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

#endif /* _NGX_OIDC_VARIABLE_H_INCLUDED_ */
