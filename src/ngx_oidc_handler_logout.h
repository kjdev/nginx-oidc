/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_HANDLER_LOGOUT_H_INCLUDED_
#define _NGX_OIDC_HANDLER_LOGOUT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"

/**
 * Handles logout requests and optionally redirects to
 * RP-Initiated Logout endpoint
 *
 * @param[in] r         HTTP request
 * @param[in] provider  OIDC provider configuration
 *
 * @return NGX_HTTP_* status code
 */
ngx_int_t ngx_oidc_handler_logout(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider);

#endif /* _NGX_OIDC_HANDLER_LOGOUT_H_INCLUDED_ */
