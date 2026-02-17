/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_session.h"
#include "ngx_oidc_metadata.h"
#include "ngx_oidc_url.h"
#include "ngx_oidc_handler_logout.h"

/* Internal helper to clear session tokens */
static void
logout_clear_session_tokens(ngx_http_request_t *r,
    ngx_oidc_session_store_t *session_store, ngx_str_t *session_id)
{
    /* Use Management Service API to invalidate all session data */
    ngx_oidc_session_invalidate(r, session_store, session_id);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_logout: cleared all session data "
                   "for old session: %V",
                   session_id);
}

/*
 * This function:
 * - Clears session tokens from session store
 * - Clears session cookies
 * - Optionally redirects to end_session_endpoint (RP-Initiated Logout)
 * - Returns 204 No Content for simple logout
 */
ngx_int_t
ngx_oidc_handler_logout(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t *session_id, *end_session;
    ngx_str_t client_id, id_token, post_logout_uri, logout_url;
    ngx_table_elt_t *location;
    ngx_int_t rc;
    ngx_oidc_metadata_cache_t *metadata;
    size_t url_len;
    u_char *p, *encoded_client_id, *encoded_post_logout_uri;
    u_char *encoded_id_token = NULL;

    /* Validate input parameters */
    if (r == NULL || provider == NULL) {
        if (r != NULL && r->connection != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_logout: NULL parameter");
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_logout: logout handler invoked");

    /* Check if header already sent */
    if (r->header_sent) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_logout: header already sent, "
                       "skipping logout");
        return NGX_OK;
    }

    /* Initialize id_token to empty */
    ngx_str_null(&id_token);

    /* Get session ID from permanent cookie */
    session_id = ngx_oidc_session_get_permanent_id(r, provider);
    if (session_id != NULL) {
        /* Get ID token from session store if logout_token_hint is enabled */
        if (provider->logout.token_hint) {
            /* Retrieve id_token using Token Session Service */
            rc = ngx_oidc_session_get_id_token(r, provider->session_store,
                                               session_id, &id_token);
            if (rc != NGX_OK) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_handler_logout: could not retrieve "
                               "id_token for logout");
                ngx_str_null(&id_token);
            }
        }

        /* Clear session tokens from session store */
        logout_clear_session_tokens(r, provider->session_store, session_id);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_logout: cleared session tokens "
                       "for session: %V",
                       session_id);
    }

    /* Clear session cookie */
    if (ngx_oidc_session_clear_permanent_cookie(r, provider) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_logout: failed to clear session "
                      "cookie during logout");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_handler_logout: logout completed successfully");

    /* Check if RP-Initiated Logout is configured */
    if (provider->logout.post_uri != NULL) {
        if (ngx_http_complex_value(r, provider->logout.post_uri,
                                   &post_logout_uri)
            != NGX_OK)
        {
            goto simple_logout;
        }

        if (post_logout_uri.len == 0) {
            goto simple_logout;
        }
        /* Get metadata from context */
        ngx_http_oidc_ctx_t *ctx;
        ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
        if (ctx == NULL || ctx->cached.metadata == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_logout: metadata not cached "
                          "in context");
            goto simple_logout;
        }

        metadata = ctx->cached.metadata;

        end_session = ngx_oidc_metadata_get_end_session_endpoint(metadata);

        /* Check if metadata has end_session_endpoint */
        if (metadata == NULL || end_session == NULL || end_session->len == 0) {
            /* No end_session_endpoint available, redirect directly to
             * post_logout_uri */
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_logout: metadata not available, "
                           "using direct redirect");

            /* Build full URL for post_logout_uri */
            ngx_str_t full_logout_url;
            if (ngx_oidc_url_build_absolute(r, &post_logout_uri,
                                            &full_logout_url)
                != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* Validate logout URL for CRLF injection */
            if (ngx_oidc_url_validate(r, &full_logout_url) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_handler_logout: invalid logout URL");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            location = ngx_list_push(&r->headers_out.headers);
            if (location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            location->hash = 1;
            ngx_str_set(&location->key, "Location");
            location->value = full_logout_url;

            r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
            r->headers_out.content_length_n = 0;
            r->header_only = 1;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_logout: redirecting to "
                           "post_logout_uri: %V",
                           &post_logout_uri);

            rc = ngx_http_send_header(r);
            if (rc == NGX_ERROR || rc > NGX_OK) {
                return rc;
            }

            rc = ngx_http_output_filter(r, NULL);
            if (rc == NGX_ERROR) {
                return rc;
            }

            /* Check if request is still active before finalizing.
             * After output filter completes, the connection may have switched
             * to a different request (c->data != r),
             * making this request non-active.
             * Calling ngx_http_finalize_request on
             * a non-active request triggers
             * an alert: "http finalize non-active request".
             */
            if (r != r->connection->data) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_handler_logout: request no longer "
                               "active after redirect, skipping finalization");
                return NGX_DONE;
            }

            ngx_http_finalize_request(r, rc);
            return NGX_DONE;
        }

        /* RP-Initiated Logout: Redirect to end_session_endpoint */

        /* Get client_id */
        if (ngx_http_complex_value(r, provider->client_id, &client_id)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_logout: failed to evaluate "
                          "client_id for logout");
            goto simple_logout;
        }

        /* Build full URL for post_logout_uri */
        ngx_str_t full_post_logout_uri;
        if (ngx_oidc_url_build_absolute(r, &post_logout_uri,
                                        &full_post_logout_uri)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* URL encode parameters using URL Module */
        ngx_str_t encoded_client_id_str, encoded_post_logout_uri_str;

        /* Encode client_id */
        if (ngx_oidc_url_encode(r, &client_id, &encoded_client_id_str)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        encoded_client_id = encoded_client_id_str.data;
        size_t encoded_client_id_len = encoded_client_id_str.len;

        /* Encode post_logout_redirect_uri */
        if (ngx_oidc_url_encode(r, &full_post_logout_uri,
                                &encoded_post_logout_uri_str)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        encoded_post_logout_uri = encoded_post_logout_uri_str.data;
        size_t encoded_post_logout_uri_len = encoded_post_logout_uri_str.len;

        /* Calculate URL length */
        url_len = end_session->len + sizeof("?client_id=") - 1
                  + encoded_client_id_len
                  + sizeof("&post_logout_redirect_uri=") - 1
                  + encoded_post_logout_uri_len;

        /* Add id_token_hint if available and enabled */
        ngx_str_t encoded_id_token_str;
        size_t encoded_id_token_len = 0;
        if (provider->logout.token_hint && id_token.len > 0) {
            if (ngx_oidc_url_encode(r, &id_token, &encoded_id_token_str)
                != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            encoded_id_token = encoded_id_token_str.data;
            encoded_id_token_len = encoded_id_token_str.len;
            url_len += sizeof("&id_token_hint=") - 1 + encoded_id_token_len;
        }

        /* Allocate URL buffer */
        logout_url.data = ngx_palloc(r->pool, url_len);
        if (logout_url.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Build logout URL */
        p = ngx_cpymem(logout_url.data, end_session->data, end_session->len);

        /* Use '&' if end_session_endpoint already contains query parameters */
        if (ngx_strlchr(end_session->data, end_session->data + end_session->len,
                        '?')
            != NULL)
        {
            p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
        } else {
            p = ngx_cpymem(p, "?client_id=", sizeof("?client_id=") - 1);
        }
        p = ngx_cpymem(p, encoded_client_id, encoded_client_id_len);
        p = ngx_cpymem(p, "&post_logout_redirect_uri=",
                       sizeof("&post_logout_redirect_uri=") - 1);
        p = ngx_cpymem(p, encoded_post_logout_uri, encoded_post_logout_uri_len);

        if (provider->logout.token_hint && encoded_id_token_len > 0) {
            p = ngx_cpymem(p, "&id_token_hint=", sizeof("&id_token_hint=") - 1);
            p = ngx_cpymem(p, encoded_id_token, encoded_id_token_len);
        }

        logout_url.len = p - logout_url.data;

        /* Validate logout URL for CRLF injection */
        if (ngx_oidc_url_validate(r, &logout_url) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_logout: invalid end_session URL");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Set redirect location */
        location = ngx_list_push(&r->headers_out.headers);
        if (location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        location->hash = 1;
        ngx_str_set(&location->key, "Location");
        location->value = logout_url;

        r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_handler_logout: redirecting to "
                       "end_session_endpoint: %V",
                       &logout_url);

        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK) {
            return rc;
        }

        rc = ngx_http_output_filter(r, NULL);
        if (rc == NGX_ERROR) {
            return rc;
        }

        /* Check if request is still active before finalizing.
         * After output filter completes, the connection may have switched
         * to a different request (c->data != r),
         * making this request non-active.
         * Calling ngx_http_finalize_request on a non-active request triggers
         * an alert: "http finalize non-active request".
         */
        if (r != r->connection->data) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_handler_logout: request no longer "
                           "active after redirect, skipping finalization");
            return NGX_DONE;
        }

        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

simple_logout:
    /* Return 204 No Content to indicate successful logout */
    return NGX_HTTP_NO_CONTENT;
}
