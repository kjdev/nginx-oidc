/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_HTTP_OIDC_MODULE_H_INCLUDED_
#define _NGX_HTTP_OIDC_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include "ngx_oidc_jwt.h"
#include "ngx_oidc_session_store.h"
#include "ngx_oidc_metadata.h"

#define NGX_OIDC_SESSION               "NGX_OIDC_SESSION"
#define NGX_OIDC_SESSION_CALLBACK      "NGX_OIDC_SESSION_CALLBACK"
#define NGX_OIDC_DEFAULT_CALLBACK_PATH "/oidc_callback"

/* 10 minutes for Pre-Auth Session */
#define NGX_OIDC_PRE_AUTH_TIMEOUT 600

/* Internal location for HTTP requests to OIDC providers */
#define NGX_OIDC_FETCH_PATH "/_oidc_http_fetch"

/** OIDC provider configuration */
typedef struct {
    /** provider name */
    ngx_str_t                 name;
    /** issuer identifier */
    ngx_http_complex_value_t *issuer;
    /** OAuth client ID */
    ngx_http_complex_value_t *client_id;
    /** OAuth client secret */
    ngx_http_complex_value_t *client_secret;
    /** redirect URI */
    ngx_http_complex_value_t *redirect_uri;
    /** discovery URL */
    ngx_http_complex_value_t *config_url;
    /** session cookie name */
    ngx_http_complex_value_t *cookie_name;
    /** requested scopes (ngx_str_t) */
    ngx_array_t              *scopes;
    /** extra authorization args */
    ngx_http_complex_value_t *extra_auth_args;
    /** OIDC endpoint URIs */
    struct {
        /** authorization endpoint */
        ngx_str_t  authorization;
        /** token endpoint */
        ngx_str_t  token;
        /** userinfo endpoint */
        ngx_str_t  userinfo;
        /** JWKS URI */
        ngx_str_t  jwks_uri;
        /** end session endpoint */
        ngx_str_t  end_session;
    } endpoints;
    /** PKCE configuration */
    struct {
        /** PKCE enabled flag */
        ngx_flag_t                enable;
        /** S256 or plain */
        ngx_http_complex_value_t *method_cv;
        /** evaluated method */
        ngx_str_t                 method;
    } pkce;
    /** RP-Initiated Logout configuration */
    struct {
        /** logout URI */
        ngx_http_complex_value_t *uri;
        /** post-logout redirect URI */
        ngx_http_complex_value_t *post_uri;
        /** send id_token_hint flag */
        ngx_flag_t                token_hint;
    } logout;
    /** session store reference */
    ngx_oidc_session_store_t *session_store;
    /** session timeout (seconds) */
    time_t                    session_timeout;
    /** clock skew tolerance */
    time_t                    clock_skew;
    /** fetch userinfo flag */
    ngx_flag_t                fetch_userinfo;
} ngx_http_oidc_provider_t;

/** OIDC module main configuration (http block level) */
typedef struct {
    /** provider list (ngx_http_oidc_provider_t) */
    ngx_array_t    *providers;
    /** metadata list (ngx_oidc_metadata_t) */
    ngx_array_t    *provider_metadata;
    /** shared memory zone for nonce/state */
    ngx_shm_zone_t *shm_zone;
    /** session store list (ngx_oidc_session_store_t) */
    ngx_array_t    *session_stores;
} ngx_http_oidc_main_conf_t;

typedef struct {
    /* srv_conf currently empty */
} ngx_http_oidc_srv_conf_t;

/*
 * Callback state type - State-based callback flow control
 *
 * This enum represents the current state in the callback flow.
 * The callback process uses a state-based approach with 4 handlers,
 * each processing one or more states using switch + fall-through.
 *
 * Architecture:
 *   - State progression: States transition linearly through the callback flow
 *   - Handler dispatch: Based on current state, appropriate handler is called
 *   - State persistence: State is preserved across subrequest re-entries
 */
typedef enum {
    NGX_HTTP_OIDC_CALLBACK_STATE_INIT = 0,
    /* Code exchange phase states (processed in exchange_code handler) */
    NGX_HTTP_OIDC_CALLBACK_STATE_PARAM_PARSE,
    NGX_HTTP_OIDC_CALLBACK_STATE_VALIDATE_STATE,
    NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE,
    NGX_HTTP_OIDC_CALLBACK_STATE_TOKEN_EXCHANGE_WAIT,
    /* Token verification phase states (processed in verify_token handler) */
    NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ID_TOKEN,
    NGX_HTTP_OIDC_CALLBACK_STATE_VERIFY_ACCESS_TOKEN,
    /* UserInfo phase states (processed in fetch_userinfo handler) */
    NGX_HTTP_OIDC_CALLBACK_STATE_FETCH_USERINFO,
    /* Completion phase states (processed in complete handler) */
    NGX_HTTP_OIDC_CALLBACK_STATE_SESSION_SAVE,
    NGX_HTTP_OIDC_CALLBACK_STATE_REDIRECT,
    /* Terminal state */
    NGX_HTTP_OIDC_CALLBACK_STATE_COMPLETED /* All processing done */
} ngx_http_oidc_callback_state_t;

/* Request type enum - corresponds to handler functions */
typedef enum {
    NGX_HTTP_OIDC_REQUEST_TYPE_UNKNOWN = 0,   /* Not yet determined */
    NGX_HTTP_OIDC_REQUEST_TYPE_CALLBACK,      /* ngx_http_oidc_callback() */
    NGX_HTTP_OIDC_REQUEST_TYPE_LOGOUT,        /* ngx_http_oidc_logout() */
    NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATE,  /* ngx_http_oidc_authenticate() */
    NGX_HTTP_OIDC_REQUEST_TYPE_AUTHENTICATED, /* (already authenticated) */
    NGX_HTTP_OIDC_REQUEST_TYPE_COMPLETED      /* (callback completed) */
} ngx_http_oidc_request_type_t;

/** Per-request context for OIDC processing */
typedef struct {
    /** request type */
    ngx_http_oidc_request_type_t  request_type;
    /** Callback flow state */
    struct {
        /** current state */
        ngx_http_oidc_callback_state_t  state;
        /** authorization code */
        ngx_str_t                       code;
        /** state parameter */
        ngx_str_t                       state_param;
        /** session identifier */
        ngx_str_t                       session_id;
        /** resolved provider */
        ngx_http_oidc_provider_t       *provider;
    } callback;
    /** Cached authentication data */
    struct {
        /** decoded ID token */
        ngx_oidc_json_t           *id_token_payload;
        /** session identifier */
        ngx_str_t                  session_id;
        /** provider metadata */
        ngx_oidc_metadata_cache_t *metadata;
    } cached;
    /** HTTP fetch subrequest parameters */
    struct {
        /** target URL */
        ngx_str_t  url;
        /** HTTP method */
        ngx_str_t  method;
        /** Content-Type header */
        ngx_str_t  content_type;
        /** Bearer token */
        ngx_str_t  bearer;
        /** Content-Length */
        off_t      content_length;
    } fetch;
} ngx_http_oidc_ctx_t;

/* Authentication mode for auth_oidc_mode directive */
typedef enum {
    NGX_HTTP_OIDC_MODE_UNSET   = 0,  /* Not configured (inherit) */
    NGX_HTTP_OIDC_MODE_OFF     = 1,  /* Disable OIDC processing */
    NGX_HTTP_OIDC_MODE_VERIFY  = 2,  /* Verify only (no redirect) */
    NGX_HTTP_OIDC_MODE_REQUIRE = 3   /* Require auth (redirect if needed) */
} ngx_http_oidc_mode_t;

/** OIDC module location configuration */
typedef struct {
    /** provider name reference */
    ngx_http_complex_value_t *provider_name;
    /** OIDC enabled flag */
    ngx_flag_t                enabled;
    /** auth mode (off/verify/require) */
    ngx_http_oidc_mode_t      mode;
    /** explicit auth_oidc off flag (blocks inheritance) */
    ngx_uint_t                explicit_off;
    /** base URL (scheme://host:port) */
    ngx_http_complex_value_t *base_url;
    /** resolved provider pointer */
    ngx_http_oidc_provider_t *provider;
    /** session store pointer */
    ngx_oidc_session_store_t *session_store;
    /** cookie name override */
    ngx_http_complex_value_t *cookie_name;
} ngx_http_oidc_loc_conf_t;

extern ngx_module_t ngx_http_oidc_module;

#endif /* _NGX_HTTP_OIDC_MODULE_H_INCLUDED_ */
