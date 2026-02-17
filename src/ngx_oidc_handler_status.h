/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_HANDLER_STATUS_H_INCLUDED_
#define _NGX_OIDC_HANDLER_STATUS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * Handles status endpoint requests for JWKS and Metadata cache statistics
 *
 * @param[in] r  HTTP request
 *
 * @return NGX_OK or NGX_ERROR
 */
ngx_int_t ngx_oidc_handler_status(ngx_http_request_t *r);

#endif /* _NGX_OIDC_HANDLER_STATUS_H_INCLUDED_ */
