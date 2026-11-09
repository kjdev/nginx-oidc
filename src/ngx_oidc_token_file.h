/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_TOKEN_FILE_H_INCLUDED_
#define _NGX_OIDC_TOKEN_FILE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/** Maximum token file size in bytes */
#define NGX_OIDC_TOKEN_FILE_MAX_SIZE 16384

/**
 * Read a Bearer token from a file
 *
 * The file is read on every call so that rotated tokens are picked up
 * without a reload. Leading/trailing whitespace is trimmed. Empty files,
 * oversized files and tokens containing control characters are rejected.
 *
 * @param[in] r      HTTP request (pool and log)
 * @param[in] path   Token file path
 * @param[out] token Token (allocated from r->pool)
 *
 * @return NGX_OK on success, NGX_ERROR on failure
 */
ngx_int_t ngx_oidc_token_file_read(ngx_http_request_t *r, ngx_str_t *path,
    ngx_str_t *token);

#endif /* _NGX_OIDC_TOKEN_FILE_H_INCLUDED_ */
