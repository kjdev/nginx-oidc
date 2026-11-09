/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "ngx_oidc_token_file.h"

ngx_int_t
ngx_oidc_token_file_read(ngx_http_request_t *r, ngx_str_t *path,
    ngx_str_t *token)
{
    ngx_fd_t fd;
    ngx_file_info_t fi;
    ssize_t n;
    off_t size;
    u_char *buf, *start, *end, *p;

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "oidc_token_file: " ngx_open_file_n " \"%V\" failed",
                      path);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "oidc_token_file: " ngx_fd_info_n " \"%V\" failed",
                      path);
        goto failed;
    }

    size = ngx_file_size(&fi);
    if (size <= 0 || size > NGX_OIDC_TOKEN_FILE_MAX_SIZE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_token_file: \"%V\" has invalid size %O "
                      "(must be 1..%d bytes)",
                      path, size, NGX_OIDC_TOKEN_FILE_MAX_SIZE);
        goto failed;
    }

    buf = ngx_pnalloc(r->pool, (size_t) size);
    if (buf == NULL) {
        goto failed;
    }

    n = ngx_read_fd(fd, buf, (size_t) size);
    if (n == -1 || (off_t) n != size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "oidc_token_file: " ngx_read_fd_n " \"%V\" failed",
                      path);
        goto failed;
    }

    ngx_close_file(fd);

    start = buf;
    end = buf + n;
    while (start < end && (*start == ' ' || *start == '\t'
                           || *start == '\r' || *start == '\n'))
    {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'
                           || end[-1] == '\r' || end[-1] == '\n'))
    {
        end--;
    }

    if (start == end) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_token_file: \"%V\" is empty", path);
        return NGX_ERROR;
    }

    /* The token is placed into an HTTP header: reject header injection */
    for (p = start; p < end; p++) {
        if (*p < 0x21 || *p > 0x7e) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_token_file: \"%V\" contains invalid "
                          "character", path);
            return NGX_ERROR;
        }
    }

    token->data = start;
    token->len = end - start;

    return NGX_OK;

failed:

    ngx_close_file(fd);
    return NGX_ERROR;
}
