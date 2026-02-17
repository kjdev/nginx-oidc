/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_oidc_module.h"
#include "ngx_oidc_http.h"
#include "ngx_oidc_url.h"
#include "ngx_oidc_random.h"
#include "ngx_oidc_variable.h"
#include "ngx_oidc_session.h"
#include "ngx_oidc_session_store.h"
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_metadata.h"
#include "ngx_oidc_provider.h"
#include "ngx_oidc_handler_authenticate.h"
#include "ngx_oidc_handler_callback.h"
#include "ngx_oidc_handler_logout.h"
#include "ngx_oidc_handler_status.h"

/* Helper macro for nested struct offsetof */
#define ngx_offsetof_nested(type, field1, field2) \
        (offsetof(type, field1) \
         + offsetof(__typeof__(((type *) 0)->field1), field2))

/* Configuration lifecycle */
static void *ngx_http_oidc_create_main_conf(ngx_conf_t *cf);
/* Configuration validation */
static char *ngx_http_oidc_validate_provider(ngx_conf_t *cf,
    ngx_http_oidc_provider_t *provider);
static char *ngx_http_oidc_validate_session_store(ngx_conf_t *cf,
    ngx_oidc_session_store_t *store);
static ngx_int_t ngx_http_oidc_search_location_tree(
    ngx_http_location_tree_node_t *node, ngx_str_t *location_name,
    ngx_log_t *log);
static ngx_int_t ngx_http_oidc_search_enabled_in_tree(
    ngx_http_location_tree_node_t *node);
static ngx_int_t ngx_http_oidc_find_location(ngx_conf_t *cf,
    ngx_str_t *location_name);
static ngx_int_t ngx_http_oidc_is_enabled_anywhere(ngx_conf_t *cf);
static char *ngx_http_oidc_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_oidc_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_oidc_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_oidc_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
/* Module initialization */
static ngx_int_t ngx_http_oidc_init(ngx_conf_t *cf);
/* Directive handlers */
static char *ngx_http_oidc_set_complex_value(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_oidc_provider_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_oidc_provider_command(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_oidc_provider_session_store(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_oidc_session_store_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_oidc_session_store_command(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_oidc_scopes(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_oidc_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_oidc_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_oidc_set_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/**
 * Post-handler structure for unsigned integer bounds validation
 *
 * Used with nginx configuration directives to validate that integer values
 * fall within specified ranges (e.g., port numbers, database IDs).
 */
typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_uint_t                low;
    ngx_uint_t                high;
} conf_uint_bounds_t;

/**
 * Post-handler structure for millisecond timeout bounds validation
 *
 * Used to validate timeout values (connect_timeout, command_timeout, etc.)
 * to ensure they fall within acceptable ranges.
 */
typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_msec_t                low;
    ngx_msec_t                high;
} conf_msec_bounds_t;

/**
 * Post-handler structure for size minimum validation
 *
 * Used to validate size values (memory_size, etc.) to ensure they meet
 * minimum requirements (e.g., at least 1MB for memory stores).
 */
typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    /** minimum size (bytes) */
    size_t                    min_size;
} conf_size_min_t;

/*
 * Provider configuration initialization macro
 *
 * Initializes all provider configuration fields to their default values.
 * Used in ngx_http_oidc_provider_block() to set up a new provider.
 */
#define NGX_OIDC_INIT_PROVIDER(p) \
        do { \
            (p)->pkce.enable = NGX_CONF_UNSET; \
            (p)->pkce.method_cv = NULL; \
            (p)->logout.token_hint = NGX_CONF_UNSET; \
            (p)->fetch_userinfo = NGX_CONF_UNSET; \
            (p)->session_timeout = NGX_CONF_UNSET; \
            (p)->clock_skew = NGX_CONF_UNSET; \
        } while (0)

/*
 * Session store configuration initialization macro
 *
 * Initializes all session store configuration fields to their default values.
 * Used in ngx_http_oidc_session_store_block() to set up a new session store.
 *
 * Default values:
 * - type: NGX_OIDC_SESSION_STORE_MEMORY
 * - ttl: 3600 seconds (1 hour)
 * - prefix: "oidc:session:"
 * - memory_size: 10MB
 * - memory_max_size: 1000
 * - redis_hostname: "127.0.0.1"
 * - redis_port: 6379
 * - redis_database: 0
 * - redis_connect_timeout: 5000ms
 * - redis_command_timeout: 5000ms
 */
#define NGX_OIDC_INIT_SESSION_STORE(s) \
        do { \
            (s)->type = NGX_OIDC_SESSION_STORE_MEMORY; \
            (s)->ttl = 3600; \
            ngx_str_set(&(s)->prefix, "oidc:session:"); \
            (s)->memory.size = 10 * 1024 * 1024; \
            (s)->memory.max_size = 1000; \
            ngx_str_set(&(s)->redis.hostname, "127.0.0.1"); \
            (s)->redis.port = 6379; \
            (s)->redis.database = 0; \
            (s)->redis.connect_timeout = 5000; \
            (s)->redis.command_timeout = 5000; \
        } while (0)

/* OIDC nginx variables array */
ngx_http_variable_t ngx_http_oidc_vars[] = {
    { ngx_string("oidc_id_token"), NULL, ngx_oidc_variable_id_token,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("oidc_access_token"), NULL,
      ngx_oidc_variable_access_token, 1,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("oidc_claim_"), NULL, ngx_oidc_variable_claim, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX, 0 },
    { ngx_string("oidc_authenticated"), NULL,
      ngx_oidc_variable_authenticated, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("oidc_userinfo"), NULL, ngx_oidc_variable_userinfo, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("oidc_fetch_url"), NULL, ngx_oidc_variable_fetch_url, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },
    { ngx_string("oidc_fetch_method"), NULL,
      ngx_oidc_variable_fetch_method, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },
    { ngx_string("oidc_fetch_content_type"), NULL,
      ngx_oidc_variable_fetch_content_type, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },
    { ngx_string("oidc_fetch_content_length"), NULL,
      ngx_oidc_variable_fetch_content_length, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },
    { ngx_string("oidc_fetch_bearer"), NULL,
      ngx_oidc_variable_fetch_bearer, 0,
      NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH, 0 },
    ngx_http_null_variable
};

static ngx_command_t ngx_http_oidc_commands[] = {
    /* session_store block */
    { ngx_string("oidc_session_store"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      ngx_http_oidc_session_store_block, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    /* provider block */
    { ngx_string("oidc_provider"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
      ngx_http_oidc_provider_block, NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },
    { ngx_string("issuer"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, issuer), NULL },
    { ngx_string("client_id"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, client_id), NULL },
    { ngx_string("client_secret"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, client_secret), NULL },
    { ngx_string("redirect_uri"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, redirect_uri), NULL },
    { ngx_string("config_url"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, config_url), NULL },
    { ngx_string("cookie_name"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, cookie_name), NULL },
    { ngx_string("extra_auth_args"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      offsetof(ngx_http_oidc_provider_t, extra_auth_args), NULL },
    { ngx_string("scopes"), NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
      ngx_http_oidc_scopes, 0, 0, NULL },
    { ngx_string("enable_pkce"), NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, 0,
      ngx_offsetof_nested(ngx_http_oidc_provider_t, pkce, enable), NULL },
    { ngx_string("code_challenge_method"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      ngx_offsetof_nested(ngx_http_oidc_provider_t, pkce, method_cv), NULL },
    { ngx_string("session_store"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_provider_session_store, 0, 0, NULL },
    { ngx_string("session_timeout"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot, 0,
      offsetof(ngx_http_oidc_provider_t, session_timeout), NULL },
    { ngx_string("clock_skew"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot, 0,
      offsetof(ngx_http_oidc_provider_t, clock_skew), NULL },
    { ngx_string("logout_uri"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      ngx_offsetof_nested(ngx_http_oidc_provider_t, logout, uri), NULL },
    { ngx_string("post_logout_uri"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_oidc_set_complex_value, 0,
      ngx_offsetof_nested(ngx_http_oidc_provider_t, logout, post_uri), NULL },
    { ngx_string("logout_token_hint"), NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, 0,
      ngx_offsetof_nested(ngx_http_oidc_provider_t, logout, token_hint), NULL },
    { ngx_string("userinfo"), NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot, 0,
      offsetof(ngx_http_oidc_provider_t, fetch_userinfo), NULL },
    /* module */
    { ngx_string("auth_oidc"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1, ngx_http_oidc_auth,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("auth_oidc_mode"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1, ngx_http_oidc_set_mode,
      NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("oidc_status"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
      ngx_http_oidc_set_status, 0, 0, NULL },
    { ngx_string("oidc_base_url"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1, ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, base_url), NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_oidc_module_ctx = {
    NULL,                            /* preconfiguration */
    ngx_http_oidc_init,              /* postconfiguration */
    ngx_http_oidc_create_main_conf,  /* create main configuration */
    ngx_http_oidc_init_main_conf,    /* init main configuration */
    ngx_http_oidc_create_srv_conf,   /* create server configuration */
    ngx_http_oidc_merge_srv_conf,    /* merge server configuration */
    ngx_http_oidc_create_loc_conf,   /* create location configuration */
    ngx_http_oidc_merge_loc_conf     /* merge location configuration */
};

ngx_module_t ngx_http_oidc_module = {
    NGX_MODULE_V1,
    &ngx_http_oidc_module_ctx,  /* module context */
    ngx_http_oidc_commands,     /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    NULL,                       /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING
};

/** Metadata fetch subrequest context */
typedef struct {
    ngx_http_oidc_provider_t *provider;
    ngx_http_request_t       *main_request;
} metadata_ctx_t;

/* Check if this request is a callback by inspecting NGX_SESSION_TEMP cookie
 * and matching redirect_uri with request URI */
static ngx_int_t
access_check_callback(ngx_http_request_t *r)
{
    ngx_http_oidc_provider_t *callback_provider;
    ngx_str_t redirect_uri, uri_to_match;

    /* Get provider from callback cookie */
    callback_provider = ngx_oidc_provider_from_callback(r);
    if (callback_provider == NULL) {
        return NGX_DECLINED;
    }

    /* Get redirect_uri from provider configuration */
    if (callback_provider->redirect_uri) {
        if (ngx_http_complex_value(r, callback_provider->redirect_uri,
                                   &redirect_uri)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Handle both relative and absolute redirect_uri */
        if (redirect_uri.len > 0) {
            /* If redirect_uri is relative (starts with '/'), use request URI
             * directly */
            if (redirect_uri.data[0] == '/') {
                uri_to_match = r->uri;
            } else {
                /* Find the path part of the absolute URL */
                u_char *path_start = NULL;
                if (redirect_uri.len >= 7
                    && (ngx_strncmp(redirect_uri.data, "http://", 7) == 0
                        || (redirect_uri.len >= 8
                            && ngx_strncmp(redirect_uri.data,
                                           "https://", 8) == 0)))
                {
                    /* Find the third '/' which marks the start of the path */
                    u_char *p = redirect_uri.data;
                    u_char *end = redirect_uri.data + redirect_uri.len;
                    ngx_uint_t slash_count = 0;

                    while (p < end) {
                        if (*p == '/') {
                            slash_count++;
                            if (slash_count == 3) {
                                path_start = p;
                                break;
                            }
                        }
                        p++;
                    }

                    if (path_start != NULL) {
                        /* Validate pointer order before arithmetic */
                        if (path_start <= end) {
                            u_char *path_end;

                            /* Stop at '?' or '#' to extract path only */
                            path_end = path_start;
                            while (path_end < end
                                   && *path_end != '?'
                                   && *path_end != '#')
                            {
                                path_end++;
                            }

                            uri_to_match.data = path_start;
                            uri_to_match.len = (size_t) (path_end - path_start);
                        } else {
                            /* Invalid pointer order */
                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                          "oidc_module: invalid pointer "
                                          "arithmetic in redirect_uri parsing");
                            return NGX_ERROR;
                        }
                    } else {
                        /* No path in URL, default to '/' */
                        ngx_str_t default_path = ngx_string("/");
                        uri_to_match = default_path;
                    }
                } else {
                    /* Invalid URL format, not a callback */
                    return NGX_DECLINED;
                }
            }

            /* Compare redirect_uri path with request URI */
            if (redirect_uri.data[0] == '/') {
                /* Relative redirect_uri: strip query/fragment for comparison */
                ngx_str_t rel_path;
                u_char *qmark;

                rel_path = redirect_uri;
                qmark = ngx_strlchr(rel_path.data,
                                    rel_path.data + rel_path.len, '?');
                if (qmark != NULL) {
                    rel_path.len = (size_t) (qmark - rel_path.data);
                } else {
                    qmark = ngx_strlchr(rel_path.data,
                                        rel_path.data + rel_path.len, '#');
                    if (qmark != NULL) {
                        rel_path.len = (size_t) (qmark - rel_path.data);
                    }
                }

                if (rel_path.len == r->uri.len
                    && ngx_strncmp(rel_path.data,
                                   r->uri.data, r->uri.len) == 0)
                {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "oidc_module: callback detected "
                                   "- redirect_uri: %V matches request URI: %V",
                                   &redirect_uri, &r->uri);
                    return NGX_OK;
                }
            } else {
                /* Absolute redirect_uri: compare extracted path with request
                 * URI */
                if (uri_to_match.len == r->uri.len
                    && ngx_strncmp(uri_to_match.data, r->uri.data,
                                   r->uri.len) == 0)
                {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "oidc_module: callback detected "
                                   "- redirect_uri path: %V "
                                   "matches request URI: %V",
                                   &uri_to_match, &r->uri);
                    return NGX_OK;
                }
            }
        }
    } else {
        /* Default redirect_uri is NGX_OIDC_DEFAULT_CALLBACK_PATH */
        if (r->uri.len == sizeof(NGX_OIDC_DEFAULT_CALLBACK_PATH) - 1
            && ngx_strncmp(r->uri.data, NGX_OIDC_DEFAULT_CALLBACK_PATH,
                           sizeof(NGX_OIDC_DEFAULT_CALLBACK_PATH) - 1) == 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_module: callback detected "
                           "- default redirect_uri matches");
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

/*
 * Check if this is a logout request
 */
static ngx_int_t
access_is_logout_request(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t logout_uri;

    if (provider->logout.uri == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, provider->logout.uri, &logout_uri)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (logout_uri.len == r->uri.len
        && ngx_strncmp(logout_uri.data, r->uri.data, r->uri.len) == 0)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/*
 * Check if user is already authenticated
 */
static ngx_int_t
access_is_authenticated(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_str_t *session_id;
    ngx_str_t stored_id_token;
    ngx_int_t rc;

    /* Check for session cookie */
    session_id = ngx_oidc_session_get_permanent_id(r, provider);
    if (session_id == NULL) {
        return NGX_DECLINED;
    }

    /* Load id_token from session store */
    rc = ngx_oidc_session_get_id_token(r, provider->session_store, session_id,
                                       &stored_id_token);
    if (rc == NGX_OK && stored_id_token.len > 0) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/*
 * Determine request type (early phase)
 * Can determine types that don't require provider info
 *
 * Updates ctx->request_type directly
 */
static void
access_determine_request_type_early(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx)
{
    /* Check if callback has completed (highest priority) */
    if (ctx->callback.state == NGX_HTTP_OIDC_CALLBACK_STATE_COMPLETED) {
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_COMPLETED;
        return;
    }

    /* Check if callback is in progress (any active processing state)
     * INIT and PARAM_PARSE are initial states
     * - use access_check_callback for those */
    if (ctx->callback.state != NGX_HTTP_OIDC_CALLBACK_STATE_INIT
        && ctx->callback.state != NGX_HTTP_OIDC_CALLBACK_STATE_PARAM_PARSE
        && ctx->callback.state != NGX_HTTP_OIDC_CALLBACK_STATE_COMPLETED)
    {
        /* Callback is in progress - continue callback processing */
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK;
        return;
    }

    /* Check if this is a callback request (initial state) */
    if (access_check_callback(r) == NGX_OK) {
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK;
        return;
    }

    /* Other types need provider info - defer to late determination */
    ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_UNKNOWN;
}

/*
 * Determine request type (late phase)
 * Requires provider info for logout URI and session checks
 *
 * Updates ctx->request_type directly
 */
static void
access_determine_request_type_late(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_provider_t *provider,
    ngx_http_oidc_loc_conf_t *olcf)
{
    /* Check if this is a logout request */
    if (access_is_logout_request(r, provider) == NGX_OK) {
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_LOGOUT;
        return;
    }

    /* Check if user is already authenticated */
    if (access_is_authenticated(r, provider) == NGX_OK) {
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATED;
        return;
    }

    /* Check authentication mode */
    switch (olcf->mode) {
    case NGX_HTTP_OIDC_MODE_OFF:
    case NGX_HTTP_OIDC_MODE_VERIFY:
        /* Don't redirect to authenticate - return as authenticated
         * (will be handled as NGX_DECLINED) */
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATED;
        return;

    case NGX_HTTP_OIDC_MODE_REQUIRE:
    default:
        break;  /* Proceed to authenticate */
    }

    /* Need authentication */
    ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATE;
}

/*
 * Metadata Module callback wrapper
 * Bridges Metadata API with existing Legacy infrastructure
 */
static ngx_int_t
access_metadata_done(ngx_http_request_t *r,
    ngx_oidc_metadata_cache_t *metadata, void *data)
{
    metadata_ctx_t *ctx = data;
    ngx_http_request_t *main_r;

    /* Validate context */
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: metadata callback context is NULL");
        return NGX_ERROR;
    }

    main_r = ctx->main_request;

    /* Check if metadata fetch succeeded */
    if (metadata == NULL) {
        ngx_log_error(NGX_LOG_ERR, main_r->connection->log, 0,
                      "oidc_module: metadata fetch failed for provider %V",
                      &ctx->provider->name);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, main_r->connection->log, 0,
                   "oidc_module: metadata fetched successfully "
                   "for provider: %V",
                   &ctx->provider->name);

    return NGX_OK;
}

static ngx_int_t
access_fetch_metadata(ngx_http_request_t *r, ngx_http_oidc_provider_t *provider,
    ngx_str_t *issuer_url)
{
    ngx_str_t config_url;
    metadata_ctx_t *ctx;

    /* Create context for metadata subrequest */
    ctx = ngx_palloc(r->pool, sizeof(metadata_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->provider = provider;
    ctx->main_request = r;

    /* Check if config_url is explicitly configured */
    if (provider->config_url) {
        if (ngx_http_complex_value(r, provider->config_url, &config_url)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        /* Construct .well-known/openid-configuration URL from issuer */
        size_t suffix_len;

        suffix_len = sizeof("/.well-known/openid-configuration") - 1;

        /* Check for size overflow */
        if (issuer_url->len > NGX_MAX_SIZE_T_VALUE - suffix_len - 1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_module: config URL length overflow "
                          "(issuer_len=%uz, suffix_len=%uz)",
                          issuer_url->len, suffix_len);
            return NGX_ERROR;
        }

        config_url.len = issuer_url->len + suffix_len;
        config_url.data = ngx_pnalloc(r->pool, config_url.len + 1);
        if (config_url.data == NULL) {
            return NGX_ERROR;
        }

        ngx_snprintf(config_url.data, config_url.len + 1,
                     "%V/.well-known/openid-configuration",
                     issuer_url);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_module: fetching provider metadata from: %V",
                   &config_url);

    /* Use Metadata Module API */
    return ngx_oidc_metadata_fetch(r, issuer_url, &config_url,
                                   access_metadata_done, ctx);
}

/*
 * Fetch provider metadata (common for all request types)
 * Caches metadata in context for reuse
 */
static ngx_int_t
access_fetch_metadata_common(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider, ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t issuer_url;
    ngx_oidc_metadata_cache_t *metadata;
    ngx_int_t rc;

    /* Check if metadata is already cached in context */
    if (ctx->cached.metadata != NULL) {
        return NGX_OK;
    }

    /* Get issuer URL from provider config */
    if (ngx_http_complex_value(r, provider->issuer, &issuer_url) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: failed to get issuer URL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Try to get metadata from cache */
    rc = ngx_oidc_metadata_get(r, &issuer_url, &metadata);
    if (rc == NGX_OK && metadata != NULL) {
        /* Cache hit - use cached metadata */
        ctx->cached.metadata = metadata;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_module: using cached provider metadata");
        return NGX_OK;
    }

    /* Cache miss or expired - try to acquire fetch lock */
    rc = ngx_oidc_metadata_try_lock_fetch(r, &issuer_url);

    if (rc == NGX_OK) {
        /* Lock acquired - this request should fetch */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_module: initiating metadata fetch for: %V",
                       &issuer_url);

        rc = access_fetch_metadata(r, provider, &issuer_url);

        if (rc == NGX_AGAIN) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_module: metadata fetch returning NGX_AGAIN");
            return NGX_AGAIN;
        }

        if (rc != NGX_OK) {
            /* Fetch failed - clear flag to allow retry */
            ngx_oidc_metadata_clear_fetch_flag(r, &issuer_url);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_module: failed to fetch metadata");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Fetch initiated successfully */
        return NGX_AGAIN;
    } else if (rc == NGX_BUSY) {
        /* Another request is fetching - wait and retry */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_module: metadata fetch in progress, waiting: %V",
                       &issuer_url);
        return NGX_AGAIN;
    } else if (rc == NGX_DECLINED) {
        /* Entry exists and is valid
         * - shouldn't happen since metadata_get failed */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "oidc_module: metadata appeared "
                       "in cache during check: %V",
                       &issuer_url);
        /* Fall through to re-check cache */
        rc = ngx_oidc_metadata_get(r, &issuer_url, &metadata);
        if (rc == NGX_OK && metadata != NULL) {
            ctx->cached.metadata = metadata;
            return NGX_OK;
        }
        /* Still not available, return error */
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else {
        /* Error */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: failed to acquire metadata fetch lock");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/*
 * JWKS Module callback wrapper
 * Bridges JWKS API with existing Legacy infrastructure
 */
static ngx_int_t
access_jwks_done(ngx_http_request_t *r, ngx_oidc_jwks_cache_node_t *jwks,
    void *data)
{
    metadata_ctx_t *ctx = data;
    ngx_http_oidc_provider_t *provider;
    ngx_http_request_t *main_r;

    /* Validate context */
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: JWKS callback context is NULL");
        return NGX_ERROR;
    }

    provider = ctx->provider;
    main_r = ctx->main_request;

    /* Check if JWKS fetch succeeded */
    if (jwks == NULL) {
        ngx_log_error(NGX_LOG_ERR, main_r->connection->log, 0,
                      "oidc_module: JWKS fetch failed for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, main_r->connection->log, 0,
                   "oidc_module: JWKS fetched successfully for provider: %V",
                   &provider->name);

    return NGX_OK;
}

static ngx_int_t
access_fetch_jwks(ngx_http_request_t *r, ngx_http_oidc_provider_t *provider)
{
    ngx_str_t issuer;
    metadata_ctx_t *ctx;
    ngx_oidc_metadata_cache_t *metadata;
    ngx_int_t rc;
    ngx_str_t *jwks_uri;

    /* Evaluate issuer */
    if (ngx_http_complex_value(r, provider->issuer, &issuer) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: failed to evaluate issuer");
        return NGX_ERROR;
    }

    /* Get metadata from server context */
    rc = ngx_oidc_metadata_get(r, &issuer, &metadata);
    if (rc != NGX_OK || metadata == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: metadata not available for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    jwks_uri = ngx_oidc_metadata_get_jwks_uri(metadata);
    if (jwks_uri == NULL || jwks_uri->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: JWKS URI not available "
                      "in metadata for provider %V",
                      &provider->name);
        return NGX_ERROR;
    }

    /* Create context for JWKS fetch */
    ctx = ngx_palloc(r->pool, sizeof(metadata_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->provider = provider;
    ctx->main_request = r;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "oidc_module: fetching JWKS from: %V",
                   jwks_uri);

    /* Use JWKS Module API */
    return ngx_oidc_jwks_fetch(r, jwks_uri, access_jwks_done, ctx);
}

/* Noop content handler to prevent further processing */
static ngx_int_t
handler_noop(ngx_http_request_t *r)
{
    return NGX_OK;
}

/*
 * Main OIDC access handler - entry point for all OIDC-protected requests
 *
 * This handler is registered in NGX_HTTP_ACCESS_PHASE and processes all
 * requests to OIDC-protected locations. It:
 * 1. Determines the request type
 *    (authenticated, authenticate, callback, logout)
 * 2. Fetches required metadata/JWKS if needed
 * 3. Dispatches to appropriate specialized handler
 */
ngx_int_t
ngx_http_oidc_access_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_http_oidc_provider_t *provider;
    ngx_http_oidc_ctx_t *ctx;
    ngx_int_t rc;

    /* Check if headers already sent */
    if (r->header_sent) {
        r->content_handler = handler_noop;
        return NGX_DECLINED;
    }

    /* Get or create context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->request_type = NGX_HTTP_OIDC_REQUEST_TYPE_UNKNOWN;
        ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);
    }

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    /* auth_oidc off: skip all OIDC processing including callback */
    if (olcf->explicit_off) {
        return NGX_DECLINED;
    }

    /* Determine request type (only once per request) */
    if (ctx->request_type == NGX_HTTP_OIDC_REQUEST_TYPE_UNKNOWN) {
        access_determine_request_type_early(r, ctx);
    }

    /* Early return for completed callback */
    if (ctx->request_type == NGX_HTTP_OIDC_REQUEST_TYPE_COMPLETED) {
        r->content_handler = handler_noop;
        return NGX_DECLINED;
    }

    /* Check if OIDC is enabled (skip for callback requests) */
    if (!olcf->enabled
        && ctx->request_type != NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK)
    {
        return NGX_DECLINED;
    }

    /* Check if OIDC mode is off (skip for callback requests) */
    if (olcf->mode == NGX_HTTP_OIDC_MODE_OFF
        && ctx->request_type != NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK)
    {
        return NGX_DECLINED;
    }

    /* Periodic cleanup */
    if (ngx_random() % 100 == 0) {
        ngx_oidc_session_store_cleanup_expired(r, NULL);
    }

    /* Get provider configuration */
    if (ctx->request_type == NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK) {
        /* Callback: get provider from cookie */
        provider = ngx_oidc_provider_from_callback(r);
        if (provider == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_module: failed to get provider "
                          "from callback cookie");
            return NGX_HTTP_BAD_REQUEST;
        }
        /* Cache provider in context for callback processing */
        if (ctx->callback.provider == NULL) {
            /* First time: cache provider and initialize state */
            ctx->callback.provider = provider;
            /* Initialize callback state for new callback (Approach A) */
            ctx->callback.state = NGX_HTTP_OIDC_CALLBACK_STATE_PARAM_PARSE;
        }
    } else {
        /* Normal request: get provider from config */
        provider = ngx_oidc_provider_from_config(r, olcf);
        if (provider == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Complete request type determination (needs provider info) */
    if (ctx->request_type == NGX_HTTP_OIDC_REQUEST_TYPE_UNKNOWN) {
        access_determine_request_type_late(r, ctx, provider, olcf);
    }

    /* Fetch provider metadata (only once per request) */
    if (ctx->cached.metadata == NULL) {
        rc = access_fetch_metadata_common(r, provider, ctx);
        if (rc == NGX_AGAIN) {
            /* Subrequest completion pending - will re-enter handler */
            return NGX_AGAIN;
        }
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_module: failed to fetch provider metadata, "
                          "rc=%d",
                          rc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (ctx->request_type == NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK) {
        ngx_str_t *jwks_uri = ngx_oidc_metadata_get_jwks_uri(
            ctx->cached.metadata);

        ngx_oidc_jwks_cache_node_t *jwks = NULL;

        /* Check if JWKS is already cached */
        rc = ngx_oidc_jwks_get(r, jwks_uri, &jwks);

        if (rc != NGX_OK || jwks == NULL) {
            /* Try to acquire fetch lock */
            rc = ngx_oidc_jwks_try_lock_fetch(r, jwks_uri);

            if (rc == NGX_OK) {
                /* Lock acquired - this request should fetch */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_module: initiating JWKS fetch for: %V",
                               jwks_uri);

                rc = access_fetch_jwks(r, provider);

                if (rc == NGX_AGAIN) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "oidc_module: JWKS fetch "
                                   "returning NGX_AGAIN");
                    return NGX_AGAIN;
                }

                if (rc != NGX_OK) {
                    /* Fetch failed - clear flag to allow retry */
                    ngx_oidc_jwks_clear_fetch_flag(r, jwks_uri);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "oidc_module: failed to fetch JWKS");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            } else if (rc == NGX_BUSY) {
                /* Another request is fetching - wait and retry */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_module: JWKS fetch in progress, "
                               "waiting: %V",
                               jwks_uri);
                return NGX_AGAIN;
            } else if (rc == NGX_DECLINED) {
                /* Entry exists and is valid
                 * - shouldn't happen since jwks_get failed */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "oidc_module: JWKS appeared in cache during "
                               "check: %V",
                               jwks_uri);
                /* Fall through to continue processing */
            } else {
                /* Error */
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "oidc_module: failed to acquire JWKS fetch lock");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "oidc_module: JWKS already cached for: %V",
                           jwks_uri);
        }
    }
    switch (ctx->request_type) {
    case NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATED:
        /* Already authenticated */
        return NGX_OK;

    case NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATE:
        /* Start authentication */
        return ngx_oidc_handler_authenticate(r, provider);

    case NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK:
        /* Callback processing - metadata already fetched */
        return ngx_oidc_handler_callback(r);

    case NGX_HTTP_OIDC_REQUEST_TYPE_LOGOUT:
        /* Logout processing */
        return ngx_oidc_handler_logout(r, provider);

    default:
        /* Should not reach here */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_module: invalid request type: %d",
                      ctx->request_type);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/* Configuration lifecycle */
static void *
ngx_http_oidc_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_main_conf_t *omcf;

    omcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_main_conf_t));
    if (omcf == NULL) {
        return NULL;
    }

    omcf->providers =
        ngx_array_create(cf->pool, 1, sizeof(ngx_http_oidc_provider_t));
    if (omcf->providers == NULL) {
        return NULL;
    }

    omcf->provider_metadata = ngx_oidc_metadata_create_array(cf->pool, 1);
    if (omcf->provider_metadata == NULL) {
        return NULL;
    }

    omcf->session_stores =
        ngx_array_create(cf->pool, 1, sizeof(ngx_oidc_session_store_t));
    if (omcf->session_stores == NULL) {
        return NULL;
    }

    /* Create default shared memory zone for backward compatibility */
    ngx_str_t default_name;
    ngx_str_set(&default_name, "oidc_default_memory");
    size_t default_size = 8 * 1024 * 1024; /* 8MB default */

    omcf->shm_zone = ngx_shared_memory_add(cf, &default_name, default_size,
                                           &ngx_http_oidc_module);
    if (omcf->shm_zone == NULL) {
        return NULL;
    }

    if (omcf->shm_zone->init) {
        /* Already initialized */
        return omcf;
    }

    omcf->shm_zone->init = ngx_oidc_session_store_memory_shm_zone_init;
    /* data is left NULL; init function uses default max_size */

    return omcf;
}

/**
 * Post-handler for validating unsigned integer bounds
 *
 * Validates that an unsigned integer value falls within specified low/high
 * bounds. Used for port numbers, database IDs, etc.
 *
 * @param[in] cf        nginx configuration context
 * @param[in] post      conf_uint_bounds_t structure with bounds
 * @param[in,out] data  pointer to ngx_uint_t value to validate
 *
 * @return NGX_CONF_OK if valid, NGX_CONF_ERROR otherwise
 */
static char *
ngx_oidc_conf_check_uint_bounds(ngx_conf_t *cf, void *post, void *data)
{
    conf_uint_bounds_t *bounds = post;
    ngx_uint_t *np = data;

    if (*np >= bounds->low && *np <= bounds->high) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "value must be between %ui and %ui",
                       bounds->low, bounds->high);

    return NGX_CONF_ERROR;
}

/**
 * Post-handler for validating millisecond timeout bounds
 *
 * Validates that a timeout value (in milliseconds) falls within specified
 * low/high bounds. Used for connect_timeout, command_timeout, etc.
 *
 * @param[in] cf        nginx configuration context
 * @param[in] post      conf_msec_bounds_t structure with bounds
 * @param[in,out] data  pointer to ngx_msec_t value to validate
 *
 * @return NGX_CONF_OK if valid, NGX_CONF_ERROR otherwise
 */
static char *
ngx_oidc_conf_check_msec_bounds(ngx_conf_t *cf, void *post, void *data)
{
    conf_msec_bounds_t *bounds = post;
    ngx_msec_t *msp = data;

    if (*msp >= bounds->low && *msp <= bounds->high) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "value must be between %M and %M",
                       bounds->low, bounds->high);

    return NGX_CONF_ERROR;
}

/**
 * Post-handler for validating minimum size requirements
 *
 * Validates that a size value meets minimum requirements.
 * Used for memory_size validation (must be at least 1MB).
 *
 * @param[in] cf        nginx configuration context
 * @param[in] post      conf_size_min_t structure with minimum size
 * @param[in,out] data  pointer to size_t value to validate
 *
 * @return NGX_CONF_OK if valid, NGX_CONF_ERROR otherwise
 */
static char *
ngx_oidc_conf_check_size_min(ngx_conf_t *cf, void *post, void *data)
{
    conf_size_min_t *min = post;
    size_t *sp = data;

    if (*sp >= min->min_size) {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "size must be at least %uz",
                       min->min_size);

    return NGX_CONF_ERROR;
}

/**
 * Warning helper for short timeout values
 *
 * Issues a warning when timeout values are less than 1 second (1000ms),
 * which may cause failures on slow networks or servers.
 *
 * @param[in] cf          nginx configuration context
 * @param[in] name        session store name for the warning message
 * @param[in] param_name  parameter name (e.g., "connect_timeout")
 * @param[in] timeout     timeout value in milliseconds
 */
static void
ngx_oidc_warn_short_timeout(ngx_conf_t *cf, ngx_str_t *name,
    const char *param_name, ngx_msec_t timeout)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "session store \"%V\": %s %M "
                       "is very short (< 1 second). This may cause "
                       "failures on slow networks/servers. "
                       "Consider using at least 1000ms",
                       name, param_name, timeout);
}

/**
 * Warning helper for large memory size
 *
 * Issues a warning when memory size exceeds 1GB, suggesting Redis
 * for large-scale deployments.
 *
 * @param[in] cf    nginx configuration context
 * @param[in] name  session store name for the warning message
 * @param[in] size  memory size in bytes
 */
static void
ngx_oidc_warn_large_memory(ngx_conf_t *cf, ngx_str_t *name, size_t size)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "session store \"%V\": memory_size %uz "
                       "is very large (> 1GB). Consider using Redis "
                       "for large-scale deployments",
                       name, size);
}

static char *
ngx_http_oidc_validate_provider(ngx_conf_t *cf,
    ngx_http_oidc_provider_t *provider)
{
    /* Check required parameter: issuer */
    if (provider->issuer == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc provider \"%V\": missing required parameter "
                           "\"issuer\"",
                           &provider->name);
        return NGX_CONF_ERROR;
    }

    /* Check required parameter: client_id */
    if (provider->client_id == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "oidc provider \"%V\": missing required parameter "
                           "\"client_id\"",
                           &provider->name);
        return NGX_CONF_ERROR;
    }

    /* Validate code_challenge_method if configured with constant value */
    if (provider->pkce.method_cv != NULL
        && provider->pkce.method_cv->value.len > 0
        && provider->pkce.method_cv->value.data[0] != '$')
    {
        /* This is a constant value, validate it */
        ngx_str_t *method = &provider->pkce.method_cv->value;

        if ((method->len != 4 || ngx_strncmp(method->data, "S256", 4) != 0)
            && (method->len != 5
                || ngx_strncmp(method->data, "plain", 5) != 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "oidc provider \"%V\": invalid "
                               "code_challenge_method \"%V\", "
                               "must be \"S256\" or \"plain\"",
                               &provider->name, method);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/**
 * Validate required parameters for session store configuration
 *
 * @param[in] cf     nginx configuration
 * @param[in] store  session store configuration to validate
 *
 * @return NGX_CONF_OK on success, NGX_CONF_ERROR on validation failure
 */
static char *
ngx_http_oidc_validate_session_store(ngx_conf_t *cf,
    ngx_oidc_session_store_t *store)
{
    /* Redis-specific validation */
    if (store->type == NGX_OIDC_SESSION_STORE_REDIS) {
        /* hostname has a default value ("127.0.0.1"), but validate it's set */
        if (store->redis.hostname.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "session store \"%V\": missing required "
                               "parameter \"hostname\" for redis type",
                               &store->name);
            return NGX_CONF_ERROR;
        }

        /* Warn if connect timeout is very short (< 1000ms) */
        if (store->redis.connect_timeout != NGX_CONF_UNSET_MSEC
            && store->redis.connect_timeout > 0
            && store->redis.connect_timeout < 1000)
        {
            ngx_oidc_warn_short_timeout(cf, &store->name,
                                        "redis_connect_timeout",
                                        store->redis.connect_timeout);
        }

        /* Warn if command timeout is very short (< 1000ms) */
        if (store->redis.command_timeout != NGX_CONF_UNSET_MSEC
            && store->redis.command_timeout > 0
            && store->redis.command_timeout < 1000)
        {
            ngx_oidc_warn_short_timeout(cf, &store->name,
                                        "redis_command_timeout",
                                        store->redis.command_timeout);
        }
    }

    /* Memory-specific validation */
    if (store->type == NGX_OIDC_SESSION_STORE_MEMORY) {
        /* size has a default value (10MB), validate it's non-zero */
        if (store->memory.size == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "session store \"%V\": size must be greater "
                               "than 0 for memory type",
                               &store->name);
            return NGX_CONF_ERROR;
        }

        /* Warn if memory size is very large (> 1GB) */
        if (store->memory.size > 1024 * 1024 * 1024) {
            ngx_oidc_warn_large_memory(cf, &store->name, store->memory.size);
        }
    }

    return NGX_CONF_OK;
}

/*
 * Port range validation (1-65535)
 *
 * Used to validate Redis port numbers and ensure they fall within
 * the valid TCP port range.
 */
static conf_uint_bounds_t ngx_oidc_conf_port_bounds = {
    ngx_oidc_conf_check_uint_bounds,
    1,
    65535
};

/*
 * Redis database range validation (0-15)
 *
 * Standard Redis supports 16 databases (0-15). This validates that
 * the database parameter falls within this range.
 */
static conf_uint_bounds_t ngx_oidc_conf_redis_db_bounds = {
    ngx_oidc_conf_check_uint_bounds,
    0,
    15
};

/*
 * Timeout range validation (0-60000ms)
 *
 * Validates timeout values to ensure they don't exceed 60 seconds (60000ms).
 * Used for connect_timeout and command_timeout.
 */
static conf_msec_bounds_t ngx_oidc_conf_timeout_bounds = {
    ngx_oidc_conf_check_msec_bounds,
    0,
    60000
};

/*
 * Memory minimum size validation (>= 1MB)
 *
 * Ensures memory store size is at least 1MB to be practical.
 * Smaller sizes would be too limited for session storage.
 */
static conf_size_min_t ngx_oidc_conf_memory_min = {
    ngx_oidc_conf_check_size_min,
    1024 * 1024
};

/**
 * Recursively search static_locations tree for a location by name
 *
 * Helper function that performs depth-first search on the location tree.
 *
 * @param[in] node           Current tree node
 * @param[in] location_name  Name of the location to find
 * @param[in] log            Log context
 *
 * @return NGX_OK if found, NGX_DECLINED otherwise
 */
static ngx_int_t
ngx_http_oidc_search_location_tree(ngx_http_location_tree_node_t *node,
    ngx_str_t *location_name, ngx_log_t *log)
{
    if (node == NULL) {
        return NGX_DECLINED;
    }

    /* Check current node */
    if (node->len == location_name->len
        && ngx_strncmp(node->name, location_name->data,
                       location_name->len) == 0)
    {
        return NGX_OK;
    }

    /* Search left subtree */
    if (ngx_http_oidc_search_location_tree(node->left, location_name, log)
        == NGX_OK)
    {
        return NGX_OK;
    }

    /* Search right subtree */
    if (ngx_http_oidc_search_location_tree(node->right, location_name, log)
        == NGX_OK)
    {
        return NGX_OK;
    }

    /* Search tree (for regex locations) */
    if (ngx_http_oidc_search_location_tree(node->tree, location_name, log)
        == NGX_OK)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/**
 * Recursively search static_locations tree for enabled OIDC
 *
 * Helper function that performs depth-first search on the location tree
 * to find any location with OIDC authentication enabled.
 *
 * @param[in] node  Current tree node
 *
 * @return NGX_OK if found a location with OIDC enabled, NGX_DECLINED otherwise
 */
static ngx_int_t
ngx_http_oidc_search_enabled_in_tree(ngx_http_location_tree_node_t *node)
{
    ngx_http_oidc_loc_conf_t *olcf;

    if (node == NULL) {
        return NGX_DECLINED;
    }

    /* Check exact match location */
    if (node->exact && node->exact->loc_conf) {
        olcf = node->exact->loc_conf[ngx_http_oidc_module.ctx_index];
        if (olcf && olcf->enabled == 1) {
            return NGX_OK;
        }
    }

    /* Check inclusive match location */
    if (node->inclusive && node->inclusive->loc_conf) {
        olcf = node->inclusive->loc_conf[ngx_http_oidc_module.ctx_index];
        if (olcf && olcf->enabled == 1) {
            return NGX_OK;
        }
    }

    /* Search left subtree */
    if (ngx_http_oidc_search_enabled_in_tree(node->left) == NGX_OK) {
        return NGX_OK;
    }

    /* Search right subtree */
    if (ngx_http_oidc_search_enabled_in_tree(node->right) == NGX_OK) {
        return NGX_OK;
    }

    /* Search nested tree (for regex locations) */
    if (ngx_http_oidc_search_enabled_in_tree(node->tree) == NGX_OK) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/**
 * Find a location by name in the nginx configuration
 *
 * This function searches for a location across all virtual hosts.
 * It is used to verify that required internal locations (like
 * /_oidc_http_fetch) are configured before nginx starts.
 *
 * @param[in] cf             Nginx configuration context
 * @param[in] location_name  Name of the location to find
 *                           (e.g., "/_oidc_http_fetch")
 *
 * @return NGX_OK if the location is found, NGX_DECLINED otherwise
 *
 * Implementation notes:
 * - Searches both named_locations array and static_locations tree
 * - Performs exact string match on location name
 * - Searches all virtual hosts (servers) in the configuration
 */
static ngx_int_t
ngx_http_oidc_find_location(ngx_conf_t *cf, ngx_str_t *location_name)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_loc_conf_t **clcfp;
    ngx_str_t search_name;
    ngx_uint_t s;

    /* Get main HTTP configuration */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL || cmcf->servers.nelts == 0) {
        return NGX_DECLINED;
    }

    /* Prepare search name
     * strip leading '/' for static_locations tree search */
    search_name = *location_name;
    if (search_name.len > 0 && search_name.data[0] == '/') {
        search_name.data++;
        search_name.len--;
    }

    /* Search all virtual hosts */
    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];

        /* Search named locations (NULL-terminated array) */
        if (cscf->named_locations) {
            for (clcfp = cscf->named_locations; *clcfp; clcfp++) {
                /* Named locations include the '@' prefix, match full name */
                if ((*clcfp)->name.len == location_name->len
                    && ngx_strncmp((*clcfp)->name.data, location_name->data,
                                   location_name->len) == 0)
                {
                    return NGX_OK;
                }
            }
        }

        /* Search static locations tree */
        if (cscf->ctx) {
            ngx_http_core_loc_conf_t *clcf;
            clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

            if (clcf && clcf->static_locations) {
                if (ngx_http_oidc_search_location_tree(clcf->static_locations,
                                                       &search_name, cf->log)
                    == NGX_OK)
                {
                    return NGX_OK;
                }
            }
        }
    }

    return NGX_DECLINED;
}

/**
 * Check if OIDC authentication is enabled in any location
 *
 * This function scans all locations across all virtual hosts to determine
 * if at least one location has OIDC authentication enabled. Used to decide
 * whether to validate required OIDC infrastructure (like /_oidc_http_fetch).
 *
 * @param[in] cf  Nginx configuration context
 *
 * @return NGX_OK if OIDC is enabled in at least one location,
 *         NGX_DECLINED otherwise
 *
 * Implementation notes:
 * - Recursively searches location trees and arrays
 * - Returns immediately upon finding the first enabled location (early exit)
 * - Checks ngx_http_oidc_loc_conf_t->enabled flag
 */
static ngx_int_t
ngx_http_oidc_is_enabled_anywhere(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_loc_conf_t **clcfp;
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_uint_t s;

    /* Get main HTTP configuration */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL || cmcf->servers.nelts == 0) {
        return NGX_DECLINED;
    }

    /* Search all virtual hosts and their locations */
    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];

        /* Check server-level location */
        if (cscf->ctx && cscf->ctx->loc_conf) {
            olcf = cscf->ctx->loc_conf[ngx_http_oidc_module.ctx_index];
            if (olcf && olcf->enabled == 1) {
                return NGX_OK;
            }
        }

        /* Check named locations */
        if (cscf->named_locations) {
            for (clcfp = cscf->named_locations; *clcfp; clcfp++) {
                olcf = (*clcfp)->loc_conf[ngx_http_oidc_module.ctx_index];
                if (olcf && olcf->enabled == 1) {
                    return NGX_OK;
                }
            }
        }

        /* Check regular locations (static_locations tree) */
        if (cscf->ctx && cscf->ctx->loc_conf) {
            ngx_http_core_loc_conf_t *clcf;
            clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];
            if (clcf && clcf->static_locations) {
                if (ngx_http_oidc_search_enabled_in_tree(clcf->static_locations)
                    == NGX_OK)
                {
                    return NGX_OK;
                }
            }
        }
    }

    return NGX_DECLINED;
}

static char *
ngx_http_oidc_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_oidc_main_conf_t *omcf = conf;
    ngx_http_oidc_provider_t *provider;
    ngx_oidc_session_store_t *store;
    ngx_oidc_session_store_t *default_store;
    ngx_uint_t i;

    /* Initialize all session stores through abstraction layer */
    if (ngx_oidc_session_store_init_all(omcf->session_stores, cf,
                                        &ngx_http_oidc_module)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to initialize session stores");
        return NGX_CONF_ERROR;
    }

    /* Create default memory session store for backward compatibility */
    if (ngx_oidc_session_store_ensure_default(omcf->session_stores, cf->pool,
                                              cf->log, omcf->shm_zone)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to create default memory session store");
        return NGX_CONF_ERROR;
    }

    /* Validate all session stores */
    if (omcf->session_stores) {
        store = omcf->session_stores->elts;
        for (i = 0; i < omcf->session_stores->nelts; i++) {
            if (ngx_http_oidc_validate_session_store(cf, &store[i])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* Initialize PKCE defaults and session stores for all providers */
    if (omcf->providers) {
        provider = omcf->providers->elts;
        /* Use first store as default */
        default_store = omcf->session_stores->elts;

        for (i = 0; i < omcf->providers->nelts; i++) {
            /* Set PKCE default if not explicitly configured
             * Enabled by default */
            ngx_conf_init_value(provider[i].pkce.enable, 1);

            /* Set logout_token_hint default if not explicitly configured
             * Disabled by default */
            ngx_conf_init_value(provider[i].logout.token_hint, 0);

            /* Set fetch_userinfo default if not explicitly configured
             * Disabled by default */
            ngx_conf_init_value(provider[i].fetch_userinfo, 0);

            /* Set default session store if not explicitly configured */
            if (provider[i].session_store == NULL
                && omcf->session_stores->nelts > 0)
            {
                provider[i].session_store = default_store;
            }

            /* Set default session_timeout if not explicitly configured
             * (8 hours = 28800 seconds) */
            if (provider[i].session_timeout == NGX_CONF_UNSET) {
                provider[i].session_timeout = 28800;
            }
            /* Set default clock_skew if not explicitly configured
             * (5 minutes = 300 seconds) */
            if (provider[i].clock_skew == NGX_CONF_UNSET) {
                provider[i].clock_skew = 300;
            }

            /* Initialize code_challenge_method with default
             * or configured value */
            if (provider[i].pkce.method_cv == NULL) {
                /* No configuration, use default S256 */
                ngx_str_set(&provider[i].pkce.method, "S256");
            } else if (provider[i].pkce.method_cv->value.len > 0) {
                /* Use configured value (already validated) */
                provider[i].pkce.method = provider[i].pkce.method_cv->value;
            } else {
                /* Empty value, use default S256 */
                ngx_str_set(&provider[i].pkce.method, "S256");
            }
        }

        /* Validate all providers (after defaults are set) */
        for (i = 0; i < omcf->providers->nelts; i++) {
            if (ngx_http_oidc_validate_provider(cf, &provider[i])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        /* Check for duplicate cookie names only for custom cookie names */
        for (i = 0; i < omcf->providers->nelts; i++) {
            ngx_str_t cookie_name_i, cookie_name_j;
            ngx_uint_t j;

            /* Skip validation if using default fixed name */
            if (provider[i].cookie_name == NULL) {
                continue;
            }

            /* Get cookie name for provider i */
            /* For validation, we'll use a simple string comparison since
             * complex values
             * can't be evaluated at config time. This is a basic check for
             * literal duplicates. */
            if (provider[i].cookie_name->value.len > 0
                && provider[i].cookie_name->value.data[0] != '$')
            {
                cookie_name_i = provider[i].cookie_name->value;
            } else {
                /* Skip validation for complex values */
                continue;
            }

            /* Check against all other providers */
            for (j = i + 1; j < omcf->providers->nelts; j++) {
                /* Skip if provider j uses default fixed name */
                if (provider[j].cookie_name == NULL) {
                    continue;
                }

                /* Get cookie name for provider j */
                if (provider[j].cookie_name->value.len > 0
                    && provider[j].cookie_name->value.data[0] != '$')
                {
                    cookie_name_j = provider[j].cookie_name->value;
                } else {
                    /* Skip validation for complex values */
                    continue;
                }

                /* Check for duplicate */
                if (cookie_name_i.len == cookie_name_j.len
                    && ngx_strncmp(cookie_name_i.data, cookie_name_j.data,
                                   cookie_name_i.len) == 0)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate cookie name \"%V\" found in "
                                       "providers \"%V\" and \"%V\". "
                                       "Each provider must have a unique "
                                       "cookie_name to avoid conflicts.",
                                       &cookie_name_i, &provider[i].name,
                                       &provider[j].name);
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_oidc_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_srv_conf_t *oscf;

    oscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_srv_conf_t));
    if (oscf == NULL) {
        return NULL;
    }

    return oscf;
}

static char *
ngx_http_oidc_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    /* srv_conf is currently empty */
    return NGX_CONF_OK;
}

static void *
ngx_http_oidc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_loc_conf_t *olcf;

    olcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_loc_conf_t));
    if (olcf == NULL) {
        return NULL;
    }

    olcf->enabled = NGX_CONF_UNSET;
    olcf->mode = NGX_HTTP_OIDC_MODE_UNSET;

    return olcf;
}

static char *
ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oidc_loc_conf_t *prev = parent;
    ngx_http_oidc_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    if (conf->mode == NGX_HTTP_OIDC_MODE_UNSET) {
        conf->mode = (prev->mode != NGX_HTTP_OIDC_MODE_UNSET)
                     ? prev->mode
                     : NGX_HTTP_OIDC_MODE_REQUIRE;
    }

    if (conf->provider_name == NULL && !conf->explicit_off) {
        conf->provider_name = prev->provider_name;
    }

    if (conf->base_url == NULL && !conf->explicit_off) {
        conf->base_url = prev->base_url;
    }

    return NGX_CONF_OK;
}

/* Module initialization */
static ngx_int_t
ngx_http_oidc_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_variable_t *var, *oidc_var;
    ngx_shm_zone_t *shm_zone;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oidc_access_handler;

    /* Create shared memory zone for metadata cache */
    shm_zone = ngx_shared_memory_add(
        cf, &(ngx_str_t) ngx_string("oidc_metadata_zone"),
        256 * 1024, &ngx_http_oidc_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    shm_zone->init = ngx_oidc_metadata_init_zone;
    shm_zone->data = NULL;

    /* Create shared memory zone for JWKS cache */
    shm_zone = ngx_shared_memory_add(
        cf, &(ngx_str_t) ngx_string("oidc_jwks_zone"),
        128 * 1024, &ngx_http_oidc_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    shm_zone->init = ngx_oidc_jwks_init_zone;
    shm_zone->data = NULL;

    /* Register OIDC variables from array */
    for (oidc_var = ngx_http_oidc_vars; oidc_var->name.len; oidc_var++) {
        var = ngx_http_add_variable(cf, &oidc_var->name, oidc_var->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = oidc_var->get_handler;
        var->data = oidc_var->data;
    }

    /* Validate _oidc_http_fetch location exists if OIDC is used */
    {
        ngx_http_oidc_main_conf_t *omcf;
        omcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_oidc_module);

        if (omcf->providers != NULL && omcf->providers->nelts > 0) {
            if (ngx_http_oidc_is_enabled_anywhere(cf) == NGX_OK) {
                ngx_str_t fetch_location = ngx_string(NGX_OIDC_FETCH_PATH);

                if (ngx_http_oidc_find_location(cf, &fetch_location)
                    != NGX_OK)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "OIDC module requires internal location "
                                       "\"%s\" to be configured. "
                                       "This location is used for HTTP "
                                       "requests to the OIDC provider. "
                                       "Please refer to the documentation "
                                       "or test_oidc.conf for the "
                                       "required configuration.",
                                       NGX_OIDC_FETCH_PATH);
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}

/* Directive handlers */
static char *
ngx_http_oidc_set_complex_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_provider_t *provider = conf;
    ngx_str_t *value;
    ngx_http_complex_value_t **cv;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

    /* Get pointer to the complex value field */
    cv = (ngx_http_complex_value_t **) ((char *) provider + cmd->offset);

    if (*cv != NULL) {
        return "is duplicate";
    }

    *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (*cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_oidc_provider_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_main_conf_t *omcf = conf;
    ngx_http_oidc_provider_t *provider;
    ngx_str_t *value;
    ngx_conf_t save;
    char *rv;

    value = cf->args->elts;

    provider = ngx_array_push(omcf->providers);
    if (provider == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(provider, sizeof(ngx_http_oidc_provider_t));

    provider->name = value[1];

    /* Initialize provider defaults using macro */
    NGX_OIDC_INIT_PROVIDER(provider);

    /* Save current context */
    save = *cf;

    /* Set provider as the configuration target */
    cf->handler = ngx_http_oidc_provider_command;
    cf->handler_conf = provider;

    rv = ngx_conf_parse(cf, NULL);

    /* Restore original context */
    *cf = save;

    return rv;
}

static char *
ngx_http_oidc_provider_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_provider_t *provider = cf->handler_conf;
    ngx_str_t *name;
    ngx_uint_t i;

    name = cf->args->elts;

    for (i = 0; ngx_http_oidc_commands[i].name.len; i++) {
        /* Skip non-provider directives (block, server, location level) */
        if (ngx_http_oidc_commands[i].type
            & (NGX_CONF_BLOCK | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF))
        {
            continue;
        }

        if (name[0].len != ngx_http_oidc_commands[i].name.len
            || ngx_strncasecmp(name[0].data,
                               ngx_http_oidc_commands[i].name.data,
                               name[0].len) != 0)
        {
            continue;
        }

        /* Found matching command - call its handler with provider as conf */
        return ngx_http_oidc_commands[i].set(cf, &ngx_http_oidc_commands[i],
                                             provider);
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\" in oidc_provider block",
                       &name[0]);

    return NGX_CONF_ERROR;
}

static char *
ngx_http_oidc_provider_session_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_oidc_provider_t *provider = cf->handler_conf;
    ngx_http_oidc_main_conf_t *omcf;
    ngx_oidc_session_store_t *store;
    ngx_str_t *value;
    ngx_uint_t i;

    value = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of arguments "
                           "in \"session_store\" directive");
        return NGX_CONF_ERROR;
    }

    /* Get main conf to access session_stores array */
    omcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_oidc_module);
    if (omcf == NULL || omcf->session_stores == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "session stores not initialized");
        return NGX_CONF_ERROR;
    }

    /* Find session store by name */
    store = omcf->session_stores->elts;
    for (i = 0; i < omcf->session_stores->nelts; i++) {
        if (store[i].name.len == value[1].len
            && ngx_strncmp(store[i].name.data, value[1].data,
                           value[1].len) == 0)
        {
            provider->session_store = &store[i];
            return NGX_CONF_OK;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "session store \"%V\" not found",
                       &value[1]);
    return NGX_CONF_ERROR;
}

static char *
ngx_http_oidc_session_store_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_oidc_main_conf_t *omcf = conf;
    ngx_oidc_session_store_t *store;
    ngx_str_t *value;
    ngx_conf_t save;
    char *rv;

    value = cf->args->elts;

    store = ngx_array_push(omcf->session_stores);
    if (store == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(store, sizeof(ngx_oidc_session_store_t));

    store->name = value[1];

    /* Initialize session store defaults using macro */
    NGX_OIDC_INIT_SESSION_STORE(store);

    /* Save current context */
    save = *cf;

    /* Set store as the configuration target */
    cf->handler = ngx_http_oidc_session_store_command;
    cf->handler_conf = store;

    rv = ngx_conf_parse(cf, NULL);

    /* Restore original context */
    *cf = save;

    return rv;
}

static char *
ngx_http_oidc_session_store_command(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_oidc_session_store_t *store = cf->handler_conf;
    ngx_str_t *value;

    value = cf->args->elts;

    if (cf->args->nelts != 2) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[0].data, "type") == 0) {
        if (ngx_strcmp(value[1].data, "memory") == 0) {
            store->type = NGX_OIDC_SESSION_STORE_MEMORY;
        } else if (ngx_strcmp(value[1].data, "redis") == 0) {
            store->type = NGX_OIDC_SESSION_STORE_REDIS;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid session store type \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "ttl") == 0) {
        store->ttl = ngx_parse_time(&value[1], 1);
        if (store->ttl == (time_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid ttl value \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "prefix") == 0) {
        store->prefix = value[1];
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "size") == 0) {
        ssize_t parsed_size;

        /* Parse size with explicit type handling to avoid unsigned comparison
         * with negative error value */
        parsed_size = (ssize_t) ngx_parse_size(&value[1]);
        if (parsed_size == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid size value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        store->memory.size = (size_t) parsed_size;

        /* Validate minimum size using post_handler */
        return ngx_oidc_conf_check_size_min(cf,
                                            &ngx_oidc_conf_memory_min,
                                            &store->memory.size);
    }

    if (ngx_strcmp(value[0].data, "memory_max_size") == 0) {
        store->memory.max_size = ngx_atoi(value[1].data, value[1].len);
        if (store->memory.max_size == (ngx_uint_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid memory_max_size value \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "hostname") == 0) {
        store->redis.hostname = value[1];
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "port") == 0) {
        ngx_uint_t port;

        port = ngx_atoi(value[1].data, value[1].len);
        if (port == (ngx_uint_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid port value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        store->redis.port = port;

        /* Validate port range using post_handler */
        return ngx_oidc_conf_check_uint_bounds(cf,
                                               &ngx_oidc_conf_port_bounds,
                                               &store->redis.port);
    }

    if (ngx_strcmp(value[0].data, "database") == 0) {
        ngx_uint_t database;

        database = ngx_atoi(value[1].data, value[1].len);
        if (database == (ngx_uint_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid database value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        store->redis.database = database;

        /* Validate database range using post_handler */
        return ngx_oidc_conf_check_uint_bounds(cf,
                                               &ngx_oidc_conf_redis_db_bounds,
                                               &store->redis.database);
    }

    if (ngx_strcmp(value[0].data, "password") == 0) {
        store->redis.password = value[1];
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "connect_timeout") == 0) {
        ngx_msec_t timeout;

        timeout = ngx_parse_time(&value[1], 0);
        if (timeout == (ngx_msec_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid connect_timeout value \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        store->redis.connect_timeout = timeout;

        /* Validate timeout range using post_handler */
        return ngx_oidc_conf_check_msec_bounds(cf,
                                               &ngx_oidc_conf_timeout_bounds,
                                               &store->redis.connect_timeout);
    }

    if (ngx_strcmp(value[0].data, "command_timeout") == 0) {
        ngx_msec_t timeout;

        timeout = ngx_parse_time(&value[1], 0);
        if (timeout == (ngx_msec_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid command_timeout value \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        store->redis.command_timeout = timeout;

        /* Validate timeout range using post_handler */
        return ngx_oidc_conf_check_msec_bounds(cf,
                                               &ngx_oidc_conf_timeout_bounds,
                                               &store->redis.command_timeout);
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown session store command \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}

static char *
ngx_http_oidc_scopes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_provider_t *provider = conf;
    ngx_str_t *value, *scope;
    ngx_uint_t i;

    if (provider->scopes == NULL) {
        provider->scopes = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (provider->scopes == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        scope = ngx_array_push(provider->scopes);
        if (scope == NULL) {
            return NGX_CONF_ERROR;
        }
        *scope = value[i];
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_oidc_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t *olcf = conf;
    ngx_str_t *value;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        olcf->enabled = 0;
        olcf->mode = NGX_HTTP_OIDC_MODE_OFF;
        olcf->explicit_off = 1;
        return NGX_CONF_OK;
    }

    olcf->enabled = 1;

    olcf->provider_name =
        ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (olcf->provider_name == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = olcf->provider_name;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_oidc_set_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t *olcf = conf;
    ngx_str_t *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        olcf->mode = NGX_HTTP_OIDC_MODE_OFF;
    } else if (ngx_strcmp(value[1].data, "verify") == 0) {
        olcf->mode = NGX_HTTP_OIDC_MODE_VERIFY;
    } else if (ngx_strcmp(value[1].data, "require") == 0) {
        olcf->mode = NGX_HTTP_OIDC_MODE_REQUIRE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"auth_oidc_mode\" "
                           "directive, must be \"off\", \"verify\", "
                           "or \"require\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_oidc_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_oidc_handler_status;

    return NGX_CONF_OK;
}
