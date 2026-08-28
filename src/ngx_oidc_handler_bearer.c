/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "ngx_oidc_handler_bearer.h"
#include "ngx_oidc_jwks.h"
#include "ngx_oidc_jwt.h"
#include "ngx_oidc_metadata.h"

#include "nxe_jwx.h"

/*
 * Fixed challenge strings only. Token/claim values are never interpolated
 * into WWW-Authenticate to avoid opening a header-injection surface.
 */
static ngx_str_t bearer_challenge_invalid_request =
    ngx_string("Bearer error=\"invalid_request\", "
               "error_description=\"Malformed Authorization header\"");
static ngx_str_t bearer_challenge_invalid_token =
    ngx_string("Bearer error=\"invalid_token\", "
               "error_description=\"The access token is invalid or expired\"");


static ngx_int_t
bearer_unauthorized(ngx_http_request_t *r, ngx_str_t *challenge)
{
    ngx_table_elt_t *www_authenticate;

    www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    www_authenticate->hash = 1;
    ngx_str_set(&www_authenticate->key, "WWW-Authenticate");
    www_authenticate->value = *challenge;

    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t
bearer_audience(ngx_http_request_t *r, ngx_http_oidc_provider_t *provider,
    ngx_http_oidc_loc_conf_t *olcf, ngx_str_t *audience)
{
    ngx_http_complex_value_t *cv;

    cv = (olcf->bearer_audience != NULL) ? olcf->bearer_audience :
         provider->client_id;

    if (ngx_http_complex_value(r, cv, audience) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: failed to evaluate "
                      "bearer audience");
        return NGX_ERROR;
    }

    if (audience->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: resolved audience is empty");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Verifies ctx->bearer.token against the provider issuer/JWKS.
 *
 * Returns NGX_OK if valid, NGX_DECLINED if the token is rejected
 * (caller should answer 401), NGX_ERROR on server-side failure
 * (caller should answer 500).
 */
static ngx_int_t
bearer_verify(ngx_http_request_t *r, ngx_http_oidc_provider_t *provider,
    ngx_http_oidc_loc_conf_t *olcf, ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t issuer, audience, typ;
    ngx_str_t *jwks_uri;
    ngx_oidc_jwks_cache_node_t *jwks;
    ngx_oidc_jwt_validation_params_t params;

    if (ngx_http_complex_value(r, provider->issuer, &issuer) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: failed to evaluate issuer");
        return NGX_ERROR;
    }

    if (bearer_audience(r, provider, olcf, &audience) != NGX_OK) {
        return NGX_ERROR;
    }

    if (olcf->bearer_typ != NULL) {
        if (ngx_http_complex_value(r, olcf->bearer_typ, &typ) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "oidc_handler_bearer: failed to evaluate "
                          "bearer typ");
            return NGX_ERROR;
        }
    }

    jwks_uri = ngx_oidc_metadata_get_jwks_uri(ctx->cached.metadata);
    if (jwks_uri == NULL || jwks_uri->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: JWKS URI not available "
                      "in provider metadata");
        return NGX_ERROR;
    }

    if (ngx_oidc_jwks_get(r, jwks_uri, &jwks) != NGX_OK || jwks == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: JWKS not available for "
                      "access token verification (uri: %V)", jwks_uri);
        return NGX_ERROR;
    }

    ngx_memzero(&params, sizeof(ngx_oidc_jwt_validation_params_t));
    params.expected.issuer = &issuer;
    params.expected.audience = &audience;
    if (olcf->bearer_typ != NULL) {
        params.expected.typ = &typ;
    }
    params.clock_skew = provider->clock_skew;
    params.token_type = NGX_OIDC_JWT_TOKEN_ACCESS;

    if (ngx_oidc_jwt_verify(r, &ctx->bearer.token, jwks, &params) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
bearer_cache_payload(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx)
{
    nxe_jwx_token_t *jwt;
    nxe_json_t *payload;

    jwt = nxe_jwx_decode(&ctx->bearer.token, r->pool);
    if (jwt == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: failed to decode verified "
                      "access token payload");
        return NGX_ERROR;
    }

    payload = nxe_jwx_token_payload(jwt);
    if (payload == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "oidc_handler_bearer: verified access token has "
                      "no payload");
        return NGX_ERROR;
    }

    ctx->bearer.payload = payload;

    return NGX_OK;
}


ngx_int_t
ngx_oidc_handler_bearer_token(ngx_http_request_t *r, ngx_str_t *token)
{
    static const char scheme[] = "Bearer";
    ngx_str_t value;

    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    value = r->headers_in.authorization->value;

    if (value.len < sizeof(scheme) - 1
        || ngx_strncasecmp(value.data, (u_char *) scheme,
                           sizeof(scheme) - 1)
        != 0)
    {
        return NGX_DECLINED;
    }

    value.data += sizeof(scheme) - 1;
    value.len -= sizeof(scheme) - 1;

    /*
     * nginx strips trailing header whitespace, so a client-sent "Bearer "
     * with no credentials arrives here as a bare 6-byte "Bearer". Treat
     * that the same as a value with a proper separator (RFC 7235 SS2.1
     * credentials with omitted token68/auth-param): empty credentials,
     * not a different auth-scheme.
     */
    if (value.len > 0) {
        if (value.data[0] != ' ' && value.data[0] != '\t') {
            return NGX_DECLINED;
        }
    }

    while (value.len && (value.data[0] == ' ' || value.data[0] == '\t')) {
        value.data++;
        value.len--;
    }

    while (value.len
           && (value.data[value.len - 1] == ' '
               || value.data[value.len - 1] == '\t'))
    {
        value.len--;
    }

    *token = value;

    return NGX_OK;
}


ngx_int_t
ngx_oidc_handler_bearer(ngx_http_request_t *r,
    ngx_http_oidc_provider_t *provider)
{
    ngx_http_oidc_loc_conf_t *olcf;
    ngx_http_oidc_ctx_t *ctx;
    ngx_int_t rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);

    if (ctx->bearer.payload != NULL) {
        return NGX_OK;
    }

    if (ctx->bearer.token.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "oidc_handler_bearer: empty Bearer credentials");
        return bearer_unauthorized(r, &bearer_challenge_invalid_request);
    }

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    rc = bearer_verify(r, provider, olcf, ctx);

    if (rc == NGX_DECLINED) {
        return bearer_unauthorized(r, &bearer_challenge_invalid_token);
    }

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (bearer_cache_payload(r, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
