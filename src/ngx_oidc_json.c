/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * JSON abstraction layer with Jansson implementation
 *
 * This module provides a thin wrapper around the Jansson JSON library,
 * abstracting the underlying JSON implementation from OIDC module logic.
 * It handles parsing JSON responses from OIDC endpoints (Metadata, Token,
 * UserInfo, JWKS) and provides type-safe value extraction.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_oidc_json.h"
#include <jansson.h>

/* Internal cast macro for Jansson implementation */
#define NGX_OIDC_JSON_CAST(json) ((json_t *) (json))

/**
 * Validate JSON structure against security limits
 *
 * Recursively traverses JSON structure to enforce:
 * - Maximum nesting depth (prevents stack overflow)
 * - Maximum array size (prevents memory exhaustion)
 * - Maximum string length (prevents memory exhaustion)
 *
 * @param[in] json   JSON object to validate
 * @param[in] depth  Current nesting depth
 * @param[in] pool   nginx memory pool for logging
 *
 * @return NGX_OK if valid, NGX_ERROR if limit exceeded
 */
static ngx_int_t
ngx_oidc_json_validate(json_t *json, ngx_uint_t depth, ngx_pool_t *pool)
{
    const char *key;
    json_t *value;
    size_t index, array_size;
    void *iter;

    /* Security limits */
    static const ngx_uint_t max_depth = 10;
    static const size_t max_array_size = 100;
    static const size_t max_string_length = 4096;

    /* NULL should not happen with valid Jansson usage, but check defensively */
    if (!json) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: validation failed, NULL JSON object");
        return NGX_ERROR;
    }

    /* Check nesting depth */
    if (depth > max_depth) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: validation failed, "
                      "nesting depth %ui exceeds limit %ui",
                      depth, max_depth);
        return NGX_ERROR;
    }

    switch (json_typeof(json)) {
    case JSON_STRING: {
        /* Check string length */
        size_t str_len = json_string_length(json);
        if (str_len > max_string_length) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_json: validation failed, "
                          "string length %uz exceeds limit %uz",
                          str_len, max_string_length);
            return NGX_ERROR;
        }
        break;
    }

    case JSON_ARRAY:
        /* Check array size */
        array_size = json_array_size(json);
        if (array_size > max_array_size) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_json: validation failed, "
                          "array size %uz exceeds limit %uz",
                          array_size, max_array_size);
            return NGX_ERROR;
        }

        /* Recursively validate array elements */
        json_array_foreach(json, index, value) {
            if (ngx_oidc_json_validate(value, depth + 1, pool) != NGX_OK) {
                return NGX_ERROR;
            }
        }
        break;

    case JSON_OBJECT: {
        static const size_t max_object_keys = 256;

        if (json_object_size(json) > max_object_keys) {
            ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                          "oidc_json: validation failed, "
                          "object key count %uz exceeds limit %uz",
                          json_object_size(json), max_object_keys);
            return NGX_ERROR;
        }

        /* Recursively validate object values */
        iter = json_object_iter(json);
        while (iter) {
            key = json_object_iter_key(iter);
            value = json_object_iter_value(iter);

            /* Check key length (keys are also strings) */
            if (ngx_strlen(key) > max_string_length) {
                ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                              "oidc_json: validation failed, "
                              "object key length exceeds limit");
                return NGX_ERROR;
            }

            /* Validate nested value */
            if (ngx_oidc_json_validate(value, depth + 1, pool) != NGX_OK) {
                return NGX_ERROR;
            }

            iter = json_object_iter_next(json, iter);
        }
        break;
    }

    case JSON_NULL:
    case JSON_TRUE:
    case JSON_FALSE:
    case JSON_INTEGER:
    case JSON_REAL:
        /* Primitive types are always valid */
        break;

    default:
        /* Unknown type */
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: validation failed, unknown JSON type");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * IMPORTANT:
 * Caller must call ngx_oidc_json_free() when done to avoid memory leaks.
 */
ngx_oidc_json_t *
ngx_oidc_json_parse(ngx_str_t *json_str, ngx_pool_t *pool)
{
    json_t *root;
    json_error_t error;

    if (json_str == NULL || json_str->data == NULL || json_str->len == 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: parse failed, empty input");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: parsing JSON, length=%uz", json_str->len);

    /* Parse JSON using Jansson (binary-safe) */
    root = json_loadb((const char *) json_str->data, json_str->len, 0, &error);
    if (!root) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: parse failed at line %d: %s "
                      "(input length: %uz bytes)",
                      error.line, error.text, json_str->len);
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: parse successful");

    return (ngx_oidc_json_t *) root;
}

/*
 * Use this function for:
 * - OIDC Provider metadata responses
 * - Token endpoint responses
 * - JWKS (JSON Web Key Set) responses
 * - Any JSON from external HTTP endpoints
 *
 * Do NOT use this function for:
 * - JWT payloads (already validated by JWT signature verification)
 * - Session store data (internal, trusted data)
 * - Any JSON that has already been validated
 *
 * IMPORTANT:
 * Caller must call ngx_oidc_json_free() when done to avoid memory leaks.
 *
 * Security: Enforces limits:
 * - Maximum nesting depth
 * - Maximum array size
 * - Maximum string length
 */
ngx_oidc_json_t *
ngx_oidc_json_parse_untrusted(ngx_str_t *json_str, ngx_pool_t *pool)
{
    ngx_oidc_json_t *root;

    /* Parse JSON using the standard parser (includes input validation) */
    root = ngx_oidc_json_parse(json_str, pool);
    if (!root) {
        /* Error already logged by ngx_oidc_json_parse */
        return NULL;
    }

    /* Validate JSON structure against security limits */
    if (ngx_oidc_json_validate(NGX_OIDC_JSON_CAST(root), 0, pool) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: validation failed, security limits exceeded");
        json_decref(NGX_OIDC_JSON_CAST(root));
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: untrusted JSON validation successful");

    return root;
}

/*
 * IMPORTANT:
 * This MUST be called for every parsed JSON object to prevent memory leaks.
 */
void
ngx_oidc_json_free(ngx_oidc_json_t *json)
{
    if (json) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: freeing JSON object");
        json_decref(NGX_OIDC_JSON_CAST(json));
    }
}

ngx_oidc_json_type_t
ngx_oidc_json_type(ngx_oidc_json_t *json)
{
    json_t *j = NGX_OIDC_JSON_CAST(json);

    if (!j) {
        return NGX_OIDC_JSON_NULL;
    }

    switch (json_typeof(j)) {
    case JSON_NULL:
        return NGX_OIDC_JSON_NULL;
    case JSON_TRUE:
    case JSON_FALSE:
        return NGX_OIDC_JSON_BOOLEAN;
    case JSON_INTEGER:
        return NGX_OIDC_JSON_INTEGER;
    case JSON_REAL:
        return NGX_OIDC_JSON_REAL;
    case JSON_STRING:
        return NGX_OIDC_JSON_STRING;
    case JSON_ARRAY:
        return NGX_OIDC_JSON_ARRAY;
    case JSON_OBJECT:
        return NGX_OIDC_JSON_OBJECT;
    default:
        return NGX_OIDC_JSON_NULL;
    }
}

ngx_oidc_json_t *
ngx_oidc_json_object_get(ngx_oidc_json_t *object, const char *key)
{
    json_t *obj = NGX_OIDC_JSON_CAST(object);

    if (!obj || !json_is_object(obj)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: object_get failed, not an object");
        return NULL;
    }

    if (key == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: object_get failed, null key");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: object_get, key=%s", key);

    return (ngx_oidc_json_t *) json_object_get(obj, key);
}

ngx_int_t
ngx_oidc_json_object_get_string(ngx_oidc_json_t *root, const char *key,
    ngx_str_t *value, ngx_pool_t *pool)
{
    ngx_oidc_json_t *json_value;
    const char *str_value;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: get_json_string_value, key=%s", key);

    /* Get the value by key */
    json_value = ngx_oidc_json_object_get(root, key);
    if (!json_value) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "oidc_json: key not found: %s", key);
        return NGX_DECLINED;
    }

    /* Check if the value is a string */
    if (!ngx_oidc_json_is_string(json_value)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "oidc_json: value is not a string for key: %s", key);
        return NGX_DECLINED;
    }

    /* Extract string value */
    str_value = ngx_oidc_json_string(json_value);
    if (!str_value) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: string_value returned null for key: %s", key);
        return NGX_ERROR;
    }

    /* Copy the value to nginx memory pool */
    value->len = ngx_strlen(str_value);
    value->data = ngx_pnalloc(pool, value->len);
    if (value->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: failed to allocate memory for string value");
        return NGX_ERROR;
    }

    ngx_memcpy(value->data, str_value, value->len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: get_json_string_value successful, "
                   "key=%s, value=%V",
                   key, value);

    return NGX_OK;
}

size_t
ngx_oidc_json_array_size(ngx_oidc_json_t *array)
{
    json_t *arr = NGX_OIDC_JSON_CAST(array);
    size_t size;

    if (!arr || !json_is_array(arr)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: array_size failed, not an array");
        return 0;
    }

    size = json_array_size(arr);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: array_size=%uz", size);

    return size;
}

ngx_oidc_json_t *
ngx_oidc_json_array_get(ngx_oidc_json_t *array, size_t index)
{
    json_t *arr = NGX_OIDC_JSON_CAST(array);

    if (!arr || !json_is_array(arr)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: array_get failed, not an array");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: array_get, index=%uz", index);

    return (ngx_oidc_json_t *) json_array_get(arr, index);
}

/*
 * WARNING:
 * The returned string is owned by the JSON object
 * and becomes invalid after ngx_oidc_json_free() is called.
 */
const char *
ngx_oidc_json_string(ngx_oidc_json_t *json)
{
    json_t *j = NGX_OIDC_JSON_CAST(json);
    const char *str;

    if (!j || !json_is_string(j)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: string_value failed, not a string");
        return NULL;
    }

    str = json_string_value(j);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: string_value=%s", str ? str : "(null)");

    return str;
}

ngx_int_t
ngx_oidc_json_integer(ngx_oidc_json_t *json)
{
    json_t *j = NGX_OIDC_JSON_CAST(json);
    ngx_int_t value;

    if (!j || !json_is_integer(j)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: integer_value failed, not an integer");
        return 0;
    }

    value = (ngx_int_t) json_integer_value(j);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: integer_value=%i", value);

    return value;
}

double
ngx_oidc_json_real(ngx_oidc_json_t *json)
{
    json_t *j = NGX_OIDC_JSON_CAST(json);
    double value;

    if (!j || !json_is_real(j)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: real_value failed, not a real number");
        return 0.0;
    }

    value = json_real_value(j);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: real_value=%f", value);

    return value;
}

ngx_int_t
ngx_oidc_json_boolean(ngx_oidc_json_t *json)
{
    json_t *j = NGX_OIDC_JSON_CAST(json);
    ngx_int_t value;

    if (!j || (!json_is_true(j) && !json_is_false(j))) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "oidc_json: boolean_value failed, not a boolean");
        return 0;
    }

    value = json_is_true(j) ? 1 : 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "oidc_json: boolean_value=%i", value);

    return value;
}

/*
 * IMPORTANT:
 * The returned string is allocated in the provided pool and
 * will be freed when the pool is destroyed.
 */
ngx_str_t *
ngx_oidc_json_stringify_compact(ngx_oidc_json_t *json, ngx_pool_t *pool)
{
    json_t *j = NGX_OIDC_JSON_CAST(json);
    char *json_str;
    ngx_str_t *result;
    size_t json_len;

    if (!j) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: stringify_compact failed, NULL JSON object");
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: serializing JSON to compact format");

    /* Serialize JSON to compact string (no whitespace) */
    json_str = json_dumps(j, JSON_COMPACT);
    if (!json_str) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: stringify_compact failed, "
                      "json_dumps returned NULL");
        return NULL;
    }

    json_len = ngx_strlen(json_str);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: serialized JSON length=%uz", json_len);

    /* Allocate result structure in nginx pool */
    result = ngx_palloc(pool, sizeof(ngx_str_t));
    if (!result) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: stringify_compact "
                      "failed to allocate result structure");
        free(json_str); /* Free Jansson-allocated string */
        return NULL;
    }

    /* Allocate data buffer in nginx pool */
    result->data = ngx_pnalloc(pool, json_len);
    if (!result->data) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "oidc_json: stringify_compact "
                      "failed to allocate data buffer");
        free(json_str); /* Free Jansson-allocated string */
        return NULL;
    }

    /* Copy Jansson string to nginx pool memory */
    result->len = json_len;
    ngx_memcpy(result->data, json_str, json_len);

    /* Free Jansson-allocated string (no longer needed) */
    free(json_str);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "oidc_json: stringify_compact successful, "
                   "length=%uz, data=%V",
                   result->len, result);

    return result;
}
