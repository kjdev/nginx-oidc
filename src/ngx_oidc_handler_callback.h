/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_HANDLER_CALLBACK_H_INCLUDED_
#define _NGX_OIDC_HANDLER_CALLBACK_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/**
 * Handles OIDC callback (redirect_uri) requests
 *
 * @param[in] r  HTTP request
 *
 * @return NGX_HTTP_* status or NGX_AGAIN for subrequest continuation
 */
ngx_int_t ngx_oidc_handler_callback(ngx_http_request_t *r);

#endif /* _NGX_OIDC_HANDLER_CALLBACK_H_INCLUDED_ */
