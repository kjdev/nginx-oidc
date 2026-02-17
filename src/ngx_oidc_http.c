/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * HTTP client and request operations
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_http.h"

/** HTTP subrequest context */
struct ngx_oidc_http_ctx_s {
    ngx_oidc_http_done_pt  done;
    void                  *data;
};

static ngx_int_t
ngx_oidc_http_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_oidc_http_ctx_t *ctx;
    ngx_http_request_t *pr;  /* Parent request */
    ngx_int_t callback_rc;

    ctx = data;
    pr = r->parent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pr->connection->log, 0,
                   "oidc_http: subrequest completed, rc=%i", rc);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pr->connection->log, 0,
                   "oidc_http: subrequest status=%i",
                   ngx_oidc_http_response_status(r));

    /* Call user callback with nginx-compatible signature */
    if (ctx->done) {
        callback_rc = ctx->done(r, ctx->data, rc);

        /* Log error only for NGX_ERROR, not for NGX_DONE or other statuses */
        if (callback_rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0,
                          "oidc_http: user callback returned error");
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pr->connection->log, 0,
                       "oidc_http: user callback returned rc=%i", callback_rc);

        /* Return callback's status as-is (NGX_OK, NGX_DONE, NGX_ERROR, etc.) */
        return callback_rc;
    }

    /* nginx subrequest mechanism will automatically resume parent request */
    /* No need to manually call write_event_handler here */

    return NGX_OK;
}

static ngx_int_t
http_response_body_copy(ngx_http_request_t *sr, ngx_buf_t *b,
    ngx_str_t *body, const char *source)
{
    size_t len;

    len = b->last - b->pos;

    if (len == 0) {
        return NGX_DECLINED;  /* No data */
    }

    /* Allocate buffer for body */
    body->data = ngx_pnalloc(sr->pool, len);
    if (body->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, sr->connection->log, 0,
                      "oidc_http: failed to allocate body buffer");
        return NGX_ERROR;
    }

    /* Copy buffer content */
    ngx_memcpy(body->data, b->pos, len);
    body->len = len;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, sr->connection->log, 0,
                   "oidc_http: response body from %s, length=%uz",
                   source, len);

    return NGX_OK;
}

ngx_int_t
ngx_oidc_http_response_status(ngx_http_request_t *sr)
{
    if (sr == NULL || sr->headers_out.status == 0) {
        return NGX_ERROR;
    }

    return sr->headers_out.status;
}

ngx_int_t
ngx_oidc_http_response_body(ngx_http_request_t *sr, ngx_str_t *body)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;
    ngx_int_t rc;

    if (sr == NULL || body == NULL) {
        return NGX_ERROR;
    }

    /* Priority 1: Check r->out (for subrequest_in_memory) */
    /* postpone filter accumulates response body in r->out chain */
    if (sr->out && sr->out->buf) {
        size_t total_len = 0;
        u_char *p;

        /* Calculate total size across all buffers in chain */
        for (cl = sr->out; cl; cl = cl->next) {
            if (cl->buf) {
                total_len += ngx_buf_size(cl->buf);
            }
        }

        if (total_len > 0) {
            body->data = ngx_pnalloc(sr->pool, total_len);
            if (body->data == NULL) {
                ngx_log_error(NGX_LOG_ERR, sr->connection->log, 0,
                              "oidc_http: failed to allocate body buffer");
                return NGX_ERROR;
            }

            /* Copy data from all buffers */
            p = body->data;
            for (cl = sr->out; cl; cl = cl->next) {
                if (cl->buf && ngx_buf_size(cl->buf) > 0) {
                    p = ngx_cpymem(p, cl->buf->pos, ngx_buf_size(cl->buf));
                }
            }
            body->len = total_len;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, sr->connection->log, 0,
                           "oidc_http: response body from r->out, length=%uz",
                           total_len);

            return NGX_OK;
        }
    }

    /* Priority 2: Check upstream buffers */
    if (sr->upstream == NULL) {
        ngx_log_error(NGX_LOG_ERR, sr->connection->log, 0,
                      "oidc_http: subrequest has no upstream");
        return NGX_ERROR;
    }

    /* Check upstream->buffer */
    b = &sr->upstream->buffer;
    rc = http_response_body_copy(sr, b, body, "upstream->buffer");
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Priority 3: Check upstream->out_bufs chain */
    for (cl = sr->upstream->out_bufs; cl; cl = cl->next) {
        if (cl->buf && ngx_buf_size(cl->buf) > 0) {
            b = cl->buf;
            rc = http_response_body_copy(sr, b, body, "upstream->out_bufs");
            if (rc != NGX_DECLINED) {
                return rc;
            }
        }
    }

    /* No body data found */
    ngx_str_null(body);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sr->connection->log, 0,
                   "oidc_http: no response body found");

    return NGX_OK;
}

ngx_int_t
ngx_oidc_http_get(ngx_http_request_t *r, ngx_str_t *url,
    ngx_oidc_http_done_pt done, void *data)
{
    ngx_str_t proxy_uri;
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_oidc_http_ctx_t *ctx;
    ngx_http_oidc_ctx_t *sr_ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: fetching external URL (GET), url=%V", url);

    /* Use proxy location for external URL fetching */
    ngx_str_set(&proxy_uri, NGX_OIDC_FETCH_PATH);

    /* Allocate context */
    ctx = ngx_palloc(r->pool, sizeof(ngx_oidc_http_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate context");
        return NGX_ERROR;
    }

    ctx->done = done;
    ctx->data = data;

    /* Allocate post subrequest structure */
    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate post subrequest");
        return NGX_ERROR;
    }

    ps->handler = ngx_oidc_http_subrequest_done;
    ps->data = ctx;

    /* Create subrequest (no args - all params via module context) */
    if (ngx_http_subrequest(r, &proxy_uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to create subrequest");
        return NGX_ERROR;
    }

    /* Set fetch parameters on subrequest's module context */
    sr_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
    if (sr_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate subrequest context");
        return NGX_ERROR;
    }

    sr_ctx->fetch.url = *url;
    ngx_str_set(&sr_ctx->fetch.method, "GET");
    sr_ctx->fetch.content_length = 0;
    ngx_http_set_ctx(sr, sr_ctx, ngx_http_oidc_module);

    /* Set empty request body for GET to avoid inheriting parent's body */
    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate request body");
        return NGX_ERROR;
    }
    sr->headers_in.content_length_n = 0;
    sr->headers_in.content_length = NULL;

    /* Clear headers list to prevent inheritance from parent */
    if (ngx_list_init(&sr->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to init headers list");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: external URL GET subrequest created");

    return NGX_OK;
}

ngx_int_t
ngx_oidc_http_get_bearer(ngx_http_request_t *r, ngx_str_t *url,
    ngx_str_t *bearer_token, ngx_oidc_http_done_pt done, void *data)
{
    ngx_str_t proxy_uri;
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_oidc_http_ctx_t *ctx;
    ngx_http_oidc_ctx_t *sr_ctx;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: fetching external URL with Bearer (GET), "
                   "url=%V, token_len=%uz",
                   url, bearer_token ? bearer_token->len : 0);

    /* Use proxy location for external URL fetching */
    ngx_str_set(&proxy_uri, NGX_OIDC_FETCH_PATH);

    /* Allocate context */
    ctx = ngx_palloc(r->pool, sizeof(ngx_oidc_http_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate context");
        return NGX_ERROR;
    }

    ctx->done = done;
    ctx->data = data;

    /* Allocate post subrequest structure */
    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate post subrequest");
        return NGX_ERROR;
    }

    ps->handler = ngx_oidc_http_subrequest_done;
    ps->data = ctx;

    /* Create subrequest (no args - all params via module context) */
    if (ngx_http_subrequest(r, &proxy_uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to create subrequest");
        return NGX_ERROR;
    }

    /* Set fetch parameters on subrequest's module context */
    sr_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
    if (sr_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate subrequest context");
        return NGX_ERROR;
    }

    sr_ctx->fetch.url = *url;
    ngx_str_set(&sr_ctx->fetch.method, "GET");
    sr_ctx->fetch.content_length = 0;
    if (bearer_token && bearer_token->len > 0) {
        sr_ctx->fetch.bearer = *bearer_token;
    }
    ngx_http_set_ctx(sr, sr_ctx, ngx_http_oidc_module);

    /* Set empty request body for GET to avoid inheriting parent's body */
    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate request body");
        return NGX_ERROR;
    }
    sr->headers_in.content_length_n = 0;
    sr->headers_in.content_length = NULL;

    /* Clear headers list to prevent inheritance from parent */
    if (ngx_list_init(&sr->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to init headers list");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: external URL GET with Bearer "
                   "subrequest created");

    return NGX_OK;
}

ngx_int_t
ngx_oidc_http_post(ngx_http_request_t *r, ngx_str_t *url, ngx_str_t *body,
    ngx_oidc_http_done_pt done, void *data)
{
    ngx_str_t proxy_uri;
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_oidc_http_ctx_t *ctx;
    ngx_http_oidc_ctx_t *sr_ctx;
    ngx_buf_t *b;
    ngx_chain_t *cl;

    if (body == NULL || body->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: POST body is NULL");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: fetching external URL (POST), "
                   "url=%V, body_len=%uz", url,
                   body->len);

    /* Use proxy location for external URL fetching */
    ngx_str_set(&proxy_uri, NGX_OIDC_FETCH_PATH);

    /* Allocate context */
    ctx = ngx_palloc(r->pool, sizeof(ngx_oidc_http_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate context");
        return NGX_ERROR;
    }

    ctx->done = done;
    ctx->data = data;

    /* Allocate post subrequest structure */
    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate post subrequest");
        return NGX_ERROR;
    }

    ps->handler = ngx_oidc_http_subrequest_done;
    ps->data = ctx;

    /* Create subrequest (no args - all params via module context) */
    if (ngx_http_subrequest(r, &proxy_uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to create subrequest");
        return NGX_ERROR;
    }

    /* Set fetch parameters on subrequest's module context */
    sr_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
    if (sr_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate subrequest context");
        return NGX_ERROR;
    }

    sr_ctx->fetch.url = *url;
    ngx_str_set(&sr_ctx->fetch.method, "POST");
    ngx_str_set(&sr_ctx->fetch.content_type,
                "application/x-www-form-urlencoded");
    sr_ctx->fetch.content_length = body->len;
    ngx_http_set_ctx(sr, sr_ctx, ngx_http_oidc_module);

    /* Set POST method */
    sr->method = NGX_HTTP_POST;
    ngx_str_set(&sr->method_name, "POST");

    /* Allocate and set request body */
    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate request body");
        return NGX_ERROR;
    }

    /* Allocate buffer for POST body */
    b = ngx_create_temp_buf(r->pool, body->len);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate body buffer");
        return NGX_ERROR;
    }

    /* Copy POST body to buffer */
    b->last = ngx_cpymem(b->pos, body->data, body->len);

    /* Allocate chain link */
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate chain link");
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    /* Set request body */
    sr->request_body->bufs = cl;
    sr->request_body->buf = b;
    sr->headers_in.content_length_n = body->len;

    /* Clear headers list to prevent inheritance from parent */
    if (ngx_list_init(&sr->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to init headers list");
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: external URL POST subrequest created");

    return NGX_OK;
}

/*
 * Note:
 * This function searches for the specified cookie in the request headers.
 * If found, cookie_value will point to the parsed value.
 * If not found, returns NGX_DECLINED (not an error condition).
 */
ngx_int_t
ngx_oidc_http_cookie_get(ngx_http_request_t *r, ngx_str_t *cookie_name,
    ngx_str_t *cookie_value)
{
    ngx_str_t value;

    /* Validate input parameters */
    if (r == NULL || cookie_name == NULL || cookie_value == NULL) {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_http: NULL parameter in cookie_get");
        }
        return NGX_ERROR;
    }

    if (cookie_name->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: empty cookie name");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: searching for cookie: %V", cookie_name);

    /* Initialize output */
    ngx_str_null(cookie_value);

    /* Check if cookie header exists */
    if (r->headers_in.cookie == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_http: no cookie header in request");
        return NGX_DECLINED;
    }

    /* Use nginx built-in parser that handles multiple Cookie headers */
    if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                          cookie_name, &value)
        == NULL)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_http: cookie not found: %V", cookie_name);
        return NGX_DECLINED;
    }

    /* Allocate and copy cookie value to request pool */
    cookie_value->len = value.len;
    cookie_value->data = ngx_pnalloc(r->pool, value.len + 1);
    if (cookie_value->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_http: failed to allocate memory for cookie value");
        return NGX_ERROR;
    }

    ngx_memcpy(cookie_value->data, value.data, value.len);
    cookie_value->data[value.len] = '\0';

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_http: found cookie %V = %V",
                   cookie_name, cookie_value);

    return NGX_OK;
}
