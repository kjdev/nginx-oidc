/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_metadata.h"
#include "ngx_oidc_handler_status.h"

/** Collected JWKS entry data for status output */
typedef struct {
    ngx_str_t  uri;
    ngx_str_t  jwks_json;
    /** pretty-printed JWKS JSON */
    ngx_str_t  jwks_pretty;
    time_t     fetched_at;
    time_t     expires_at;
} status_jwks_entry_t;

/** Context for JWKS iteration */
typedef struct {
    size_t             *count;
    ngx_http_request_t *r;
    ngx_array_t        *entries;
} status_jwks_ctx_t;


static ngx_int_t
status_jwks_collect_callback(ngx_str_t *jwks_uri, time_t fetched_at,
    time_t expires_at, ngx_str_t *jwks_json, void *data)
{
    status_jwks_ctx_t *ctx = data;
    status_jwks_entry_t *entry;

    if (ctx->count) {
        (*ctx->count)++;
    }

    if (ctx->entries != NULL) {
        entry = ngx_array_push(ctx->entries);
        if (entry == NULL) {
            return NGX_ERROR;
        }

        /* Copy URI data to request pool */
        entry->uri.len = jwks_uri->len;
        entry->uri.data = ngx_pnalloc(ctx->r->pool, jwks_uri->len);
        if (entry->uri.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(entry->uri.data, jwks_uri->data, jwks_uri->len);

        /* Copy JWKS JSON data to request pool */
        entry->jwks_json.len = jwks_json->len;
        entry->jwks_json.data = ngx_pnalloc(ctx->r->pool, jwks_json->len);
        if (entry->jwks_json.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(entry->jwks_json.data, jwks_json->data, jwks_json->len);

        entry->fetched_at = fetched_at;
        entry->expires_at = expires_at;
        ngx_str_null(&entry->jwks_pretty);
    }

    return NGX_OK;
}


static ngx_int_t
status_jwks_pretty_print(ngx_pool_t *pool, ngx_str_t *raw_json,
    ngx_str_t *pretty_json)
{
    json_t *root;
    json_error_t error;
    char *pretty;
    size_t len;

    root = json_loadb((const char *) raw_json->data, raw_json->len,
                      0, &error);
    if (root == NULL) {
        /* Fallback to raw JSON if parsing fails */
        *pretty_json = *raw_json;
        return NGX_OK;
    }

    pretty = json_dumps(root, JSON_INDENT(2));
    json_decref(root);

    if (pretty == NULL) {
        *pretty_json = *raw_json;
        return NGX_OK;
    }

    len = ngx_strlen(pretty);

    pretty_json->data = ngx_pnalloc(pool, len);
    if (pretty_json->data == NULL) {
        free(pretty);
        return NGX_ERROR;
    }

    ngx_memcpy(pretty_json->data, pretty, len);
    pretty_json->len = len;

    free(pretty);

    return NGX_OK;
}


static void
status_write_indented(ngx_buf_t *b, ngx_str_t *text, ngx_uint_t indent)
{
    u_char *p, *end, *line_start;
    ngx_uint_t n;

    p = text->data;
    end = text->data + text->len;
    line_start = p;

    while (p <= end) {
        if (p == end || *p == '\n') {
            if (b->last + indent + (p - line_start) + 1 <= b->end) {
                for (n = 0; n < indent; n++) {
                    *b->last++ = ' ';
                }

                b->last = ngx_cpymem(b->last, line_start, p - line_start);
                *b->last++ = '\n';
            }

            line_start = p + 1;
        }

        p++;
    }
}


/** Context for metadata iteration */
typedef struct {
    ngx_buf_t *buf;
    size_t    *size;
    size_t    *count;
} status_metadata_ctx_t;

static ngx_int_t
status_metadata_count_callback(ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t *metadata, void *data)
{
    status_metadata_ctx_t *ctx = data;

    if (ctx->count) {
        (*ctx->count)++;
    }

    return NGX_OK;
}

static ngx_int_t
status_metadata_size_callback(ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t *metadata, void *data)
{
    status_metadata_ctx_t *ctx = data;
    ngx_str_t *authorization, *token, *jwks_uri, *userinfo,
              *end_session, *issuer_str;

    if (ctx->size) {
        /* Get endpoint strings with NULL safety */
        issuer_str = ngx_oidc_metadata_get_issuer(metadata);
        authorization = ngx_oidc_metadata_get_authorization_endpoint(metadata);
        token = ngx_oidc_metadata_get_token_endpoint(metadata);
        jwks_uri = ngx_oidc_metadata_get_jwks_uri(metadata);
        userinfo = ngx_oidc_metadata_get_userinfo_endpoint(metadata);
        end_session = ngx_oidc_metadata_get_end_session_endpoint(metadata);

        *ctx->size += sizeof("Metadata:\n  Issuer: \n") - 1
                      + (issuer_str ? issuer_str->len : 0)
                      + sizeof("    Authorization endpoint: \n") - 1
                      + (authorization ? authorization->len : 0)
                      + sizeof("    Token endpoint: \n") - 1
                      + (token ? token->len : 0)
                      + sizeof("    JWKS URI: \n") - 1
                      + (jwks_uri ? jwks_uri->len : 0)
                      + sizeof("    Userinfo endpoint: \n") - 1
                      + (userinfo ? userinfo->len : 0)
                      + sizeof("    End session endpoint: \n") - 1
                      + (end_session ? end_session->len : 0)
                      + sizeof("    Fetched: 0000-00-00 00:00:00 UTC\n") - 1
                      + sizeof("    Expires: 0000-00-00 00:00:00 UTC\n") - 1
                      + sizeof("\n") - 1;
    }

    return NGX_OK;
}

static ngx_int_t
status_metadata_format_callback(ngx_str_t *issuer,
    ngx_oidc_metadata_cache_t *metadata, void *data)
{
    status_metadata_ctx_t *ctx = data;
    ngx_buf_t *b;
    ngx_str_t *authorization, *token, *jwks_uri, *userinfo,
              *end_session, *issuer_str;
    static ngx_str_t empty_str = ngx_string("");

    if (ctx->buf == NULL) {
        return NGX_ERROR;
    }

    b = ctx->buf;

    /* Get endpoint strings with NULL safety */
    issuer_str = ngx_oidc_metadata_get_issuer(metadata);
    authorization = ngx_oidc_metadata_get_authorization_endpoint(metadata);
    token = ngx_oidc_metadata_get_token_endpoint(metadata);
    jwks_uri = ngx_oidc_metadata_get_jwks_uri(metadata);
    userinfo = ngx_oidc_metadata_get_userinfo_endpoint(metadata);
    end_session = ngx_oidc_metadata_get_end_session_endpoint(metadata);

    b->last = ngx_snprintf(b->last, b->end - b->last, "  Issuer: %V\n",
                           issuer_str ? issuer_str : &empty_str);
    b->last = ngx_snprintf(b->last, b->end - b->last,
                           "    Authorization endpoint: %V\n",
                           authorization ? authorization : &empty_str);
    b->last = ngx_snprintf(b->last, b->end - b->last,
                           "    Token endpoint: %V\n",
                           token ? token : &empty_str);
    b->last = ngx_snprintf(b->last, b->end - b->last, "    JWKS URI: %V\n",
                           jwks_uri ? jwks_uri : &empty_str);

    if (userinfo && userinfo->len > 0) {
        b->last = ngx_snprintf(b->last, b->end - b->last,
                               "    Userinfo endpoint: %V\n",
                               userinfo);
    } else {
        b->last = ngx_cpymem(b->last, "    Userinfo endpoint: (none)\n",
                             sizeof("    Userinfo endpoint: (none)\n") - 1);
    }

    if (end_session && end_session->len > 0) {
        b->last = ngx_snprintf(b->last, b->end - b->last,
                               "    End session endpoint: %V\n",
                               end_session);
    } else {
        b->last = ngx_cpymem(b->last, "    End session endpoint: (none)\n",
                             sizeof("    End session endpoint: (none)\n") - 1);
    }

    /* Format fetched time */
    b->last = ngx_snprintf(b->last, b->end - b->last, "    Fetched: ");
    b->last = ngx_http_time(b->last,
                            ngx_oidc_metadata_get_fetched_at(metadata));
    *b->last++ = '\n';

    /* Format expires time */
    b->last = ngx_snprintf(b->last, b->end - b->last, "    Expires: ");
    b->last = ngx_http_time(b->last,
                            ngx_oidc_metadata_get_expires_at(metadata));
    *b->last++ = '\n';
    *b->last++ = '\n';

    return NGX_OK;
}

/*
 * This function outputs text statistics including:
 * - JWKS cache entries with pretty-printed JSON
 * - Metadata cache entries and endpoints
 */
ngx_int_t
ngx_oidc_handler_status(ngx_http_request_t *r)
{
    ngx_http_oidc_main_conf_t *omcf;
    ngx_oidc_session_store_memory_stats_t *stats;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_int_t rc;
    size_t size;
    size_t metadata_entries, jwks_entries;
    ngx_http_oidc_provider_t *provider;
    ngx_uint_t i;
    ngx_array_t *jwks_entry_array;
    status_jwks_entry_t *jwks_entry;

    /* Validate input parameters */
    if (r == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Only allow GET and HEAD methods */
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* Discard request body */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Get main configuration */
    omcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (omcf == NULL || omcf->shm_zone == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set response headers */
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    /* Allocate statistics structure */
    stats = ngx_oidc_session_store_memory_stats_create(r->pool);
    if (stats == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Lock shared memory for statistics collection */
    rc = ngx_oidc_session_store_memory_lock(omcf->shm_zone);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Get state store statistics and release lock immediately */
    rc = ngx_oidc_session_store_memory_get_stats(omcf->shm_zone, stats);
    ngx_oidc_session_store_memory_unlock(omcf->shm_zone);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Count Metadata entries */
    metadata_entries = 0;
    {
        status_metadata_ctx_t ctx;
        ctx.buf = NULL;
        ctx.size = NULL;
        ctx.count = &metadata_entries;
        ngx_oidc_metadata_iterate(r, status_metadata_count_callback, &ctx);
    }

    /* Count and collect JWKS entries */
    jwks_entries = 0;
    jwks_entry_array = ngx_array_create(r->pool, 4,
                                        sizeof(status_jwks_entry_t));
    if (jwks_entry_array == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        status_jwks_ctx_t ctx;
        ctx.count = &jwks_entries;
        ctx.r = r;
        ctx.entries = jwks_entry_array;
        ngx_oidc_jwks_iterate(r, status_jwks_collect_callback, &ctx);
    }

    /* Pretty-print collected JWKS JSON */
    jwks_entry = jwks_entry_array->elts;
    for (i = 0; i < jwks_entry_array->nelts; i++) {
        rc = status_jwks_pretty_print(r->pool, &jwks_entry[i].jwks_json,
                                      &jwks_entry[i].jwks_pretty);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Calculate approximate output size */
    size = sizeof("OIDC Shared Memory Status\n") - 1
           + sizeof("Shared memory size:  bytes\n") - 1 + NGX_SIZE_T_LEN
           + sizeof("Shared memory max entries:  \n") - 1 + NGX_SIZE_T_LEN
           + sizeof("\n") - 1 + sizeof("State/Nonce entries: \n") - 1
           + NGX_SIZE_T_LEN + sizeof("Metadata entries: \n") - 1
           + NGX_SIZE_T_LEN + sizeof("JWKS entries: \n") - 1 + NGX_SIZE_T_LEN
           + sizeof("\n") - 1;

    /* Add size for session store configuration */
    if (omcf->providers != NULL && omcf->providers->nelts > 0) {
        provider = omcf->providers->elts;
        for (i = 0; i < omcf->providers->nelts; i++) {
            size += sizeof("Session Store Configuration:\n") - 1
                    + sizeof("  Provider: \n") - 1 + provider[i].name.len
                    + sizeof("    Cookie name: \n") - 1
                    + (provider[i].cookie_name
                       ? provider[i].cookie_name->value.len
                       : sizeof("(default)") - 1)
                    + sizeof("    Session timeout:  seconds\n") - 1
                    + NGX_TIME_T_LEN
                    + sizeof("    Session store type: \n") - 1
                    + (provider[i].session_store
                       && provider[i].session_store->name.len > 0
                       ? provider[i].session_store->name.len
                       : sizeof("(not configured)") - 1)
                    + sizeof("\n") - 1;
        }
    }

    /* Add size for Metadata details */
    {
        status_metadata_ctx_t ctx;
        ctx.buf = NULL;
        ctx.size = &size;
        ctx.count = NULL;
        ngx_oidc_metadata_iterate(r, status_metadata_size_callback, &ctx);
    }

    /* Add size for JWKS details */
    if (jwks_entries > 0) {
        ngx_uint_t newline_count;
        u_char *p, *end;

        size += sizeof("JWKS:\n") - 1;

        jwks_entry = jwks_entry_array->elts;
        for (i = 0; i < jwks_entry_array->nelts; i++) {
            size += sizeof("  URI: \n") - 1 + jwks_entry[i].uri.len
                    + sizeof("    Fetched: Thu, 01 Jan 1970 00:00:00 GMT\n") - 1
                    + sizeof("    Expires: Thu, 01 Jan 1970 00:00:00 GMT\n") - 1
                    + sizeof("    Data:\n") - 1
                    + sizeof("\n") - 1;

            /* Calculate indented JSON size: original + 6 spaces per line */
            newline_count = 1;
            p = jwks_entry[i].jwks_pretty.data;
            end = p + jwks_entry[i].jwks_pretty.len;
            while (p < end) {
                if (*p == '\n') {
                    newline_count++;
                }
                p++;
            }

            size += jwks_entry[i].jwks_pretty.len + newline_count * 7;
        }
    }

    /* Allocate buffer */
    b = ngx_create_temp_buf(r->pool, size + 256);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    /* Format output - header */
    b->last = ngx_cpymem(b->last, "OIDC Shared Memory Status\n",
                         sizeof("OIDC Shared Memory Status\n") - 1);
    b->last = ngx_snprintf(
        b->last, b->end - b->last,
        "Shared memory size: %uz bytes\n",
        ngx_oidc_session_store_memory_stats_get_shm_size(stats));
    b->last = ngx_snprintf(
        b->last, b->end - b->last,
        "Shared memory max entries: %uz\n",
        ngx_oidc_session_store_memory_stats_get_max_entries(stats));

    *b->last++ = '\n';

    /* Format counts */
    b->last = ngx_snprintf(
        b->last, b->end - b->last,
        "State/Nonce entries: %uz\n",
        ngx_oidc_session_store_memory_stats_get_state_entries(stats));
    b->last = ngx_snprintf(b->last, b->end - b->last,
                           "Metadata entries: %uz\n", metadata_entries);
    b->last = ngx_snprintf(b->last, b->end - b->last,
                           "JWKS entries: %uz\n", jwks_entries);

    *b->last++ = '\n';

    /* Format session store configuration */
    if (omcf->providers != NULL && omcf->providers->nelts > 0) {
        b->last = ngx_cpymem(b->last, "Session Store Configuration:\n",
                             sizeof("Session Store Configuration:\n") - 1);

        provider = omcf->providers->elts;
        for (i = 0; i < omcf->providers->nelts; i++) {
            b->last =
                ngx_snprintf(b->last, b->end - b->last,
                             "  Provider: %V\n", &provider[i].name);

            /* Cookie name */
            if (provider[i].cookie_name != NULL) {
                b->last = ngx_snprintf(b->last, b->end - b->last,
                                       "    Cookie name: %V\n",
                                       &provider[i].cookie_name->value);
            } else {
                b->last = ngx_cpymem(
                    b->last, "    Cookie name: (default)\n",
                    sizeof("    Cookie name: (default)\n") - 1);
            }

            /* Session timeout */
            b->last = ngx_snprintf(b->last, b->end - b->last,
                                   "    Session timeout: %T seconds\n",
                                   provider[i].session_timeout);

            /* Session store type */
            if (provider[i].session_store != NULL
                && provider[i].session_store->name.len > 0)
            {
                b->last = ngx_snprintf(b->last, b->end - b->last,
                                       "    Session store type: %V\n",
                                       &provider[i].session_store->name);
            } else {
                b->last = ngx_cpymem(
                    b->last, "    Session store type: (not configured)\n",
                    sizeof("    Session store type: (not configured)\n") - 1);
            }

            *b->last++ = '\n';
        }
    }

    /* Format Metadata details */
    if (metadata_entries > 0) {
        b->last = ngx_cpymem(b->last, "Metadata:\n", sizeof("Metadata:\n") - 1);

        status_metadata_ctx_t ctx;
        ctx.buf = b;
        ctx.size = NULL;
        ctx.count = NULL;
        ngx_oidc_metadata_iterate(r, status_metadata_format_callback,
                                  &ctx);
    }

    /* Format JWKS details */
    if (jwks_entries > 0) {
        b->last = ngx_cpymem(b->last, "JWKS:\n", sizeof("JWKS:\n") - 1);

        jwks_entry = jwks_entry_array->elts;
        for (i = 0; i < jwks_entry_array->nelts; i++) {
            b->last = ngx_snprintf(b->last, b->end - b->last,
                                   "  URI: %V\n", &jwks_entry[i].uri);

            /* Format fetched time */
            b->last = ngx_snprintf(b->last, b->end - b->last,
                                   "    Fetched: ");
            b->last = ngx_http_time(b->last, jwks_entry[i].fetched_at);
            *b->last++ = '\n';

            /* Format expires time */
            b->last = ngx_snprintf(b->last, b->end - b->last,
                                   "    Expires: ");
            b->last = ngx_http_time(b->last, jwks_entry[i].expires_at);
            *b->last++ = '\n';

            /* Format pretty-printed JWKS JSON */
            b->last = ngx_cpymem(b->last, "    Data:\n",
                                 sizeof("    Data:\n") - 1);
            status_write_indented(b, &jwks_entry[i].jwks_pretty, 6);

            *b->last++ = '\n';
        }
    }

    /* Set response status and content length */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    /* Send header */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* Send body */
    return ngx_http_output_filter(r, &out);
}
