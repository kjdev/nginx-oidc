/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef _NGX_OIDC_JSON_H_INCLUDED_
#define _NGX_OIDC_JSON_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * JSON Type Abstraction
 *
 * Opaque pointer to hide Jansson's json_t* from consumers.
 * This allows the implementation to change without affecting callers.
 */
typedef void *ngx_oidc_json_t;

/*
 * JSON Value Types
 *
 * Maps to Jansson's json_type enum but provides an abstraction layer.
 * Used by ngx_oidc_json_type() to determine value types.
 */
typedef enum {
    NGX_OIDC_JSON_NULL,     /* JSON null value */
    NGX_OIDC_JSON_BOOLEAN,  /* JSON boolean (true/false) */
    NGX_OIDC_JSON_INTEGER,  /* JSON integer number */
    NGX_OIDC_JSON_REAL,     /* JSON floating-point number */
    NGX_OIDC_JSON_STRING,   /* JSON string */
    NGX_OIDC_JSON_ARRAY,    /* JSON array */
    NGX_OIDC_JSON_OBJECT    /* JSON object */
} ngx_oidc_json_type_t;

/**
 * Parse JSON string
 *
 * Parses a JSON string into an opaque JSON object.
 * Uses Jansson's json_loadb() internally.
 *
 * @param[in] json_str  JSON string (may contain binary data)
 * @param[in] pool      nginx memory pool for logging
 *
 * @return Parsed JSON object, or NULL on parse error
 */
ngx_oidc_json_t *ngx_oidc_json_parse(ngx_str_t *json_str, ngx_pool_t *pool);

/**
 * Parse untrusted JSON string with security validation
 *
 * This function parses JSON from external, untrusted sources and validates
 * the structure against security limits to prevent DoS attacks.
 *
 * @param[in] json_str  JSON string from untrusted source
 * @param[in] pool      nginx memory pool for logging and allocation
 *
 * @return Parsed JSON object, or NULL on parse/validation error
 */
ngx_oidc_json_t *ngx_oidc_json_parse_untrusted(ngx_str_t *json_str,
    ngx_pool_t *pool);

/**
 * Free JSON object
 *
 * Releases resources associated with a JSON object.
 * Uses Jansson's json_decref() internally to decrement reference count.
 *
 * @param[in] json  JSON object to free (may be NULL)
 */
void ngx_oidc_json_free(ngx_oidc_json_t *json);

/**
 * Get JSON value type
 *
 * Determines the type of a JSON value.
 *
 * @param[in] json JSON value to inspect
 *
 * @return Type of the JSON value
 */
ngx_oidc_json_type_t ngx_oidc_json_type(ngx_oidc_json_t *json);

/**
 * Get value from JSON object by key
 *
 * Retrieves a value from a JSON object using a key.
 * Returns NULL if the key doesn't exist or if the input is not an object.
 *
 * @param[in] object  JSON object
 * @param[in] key     Key to look up (null-terminated string)
 *
 * @return JSON value at the key, or NULL if not found
 */
ngx_oidc_json_t *ngx_oidc_json_object_get(ngx_oidc_json_t *object,
    const char *key);

/**
 * Helper function for backward compatibility
 *
 * Gets a string value from a JSON object and copies it to nginx memory pool.
 * This is a convenience function that combines object_get, type checking,
 * and memory pool allocation.
 *
 * @param[in] root    JSON object to search
 * @param[in] key     Key to look up
 * @param[out] value  nginx string (allocated from pool)
 * @param[in] pool    nginx memory pool for allocation
 *
 * @return NGX_OK on success, NGX_DECLINED if key not found or not a string,
 *         NGX_ERROR on allocation failure
 */
ngx_int_t ngx_oidc_json_object_get_string(ngx_oidc_json_t *root,
    const char *key, ngx_str_t *value, ngx_pool_t *pool);

/**
 * Get size of JSON array
 *
 * Returns the number of elements in a JSON array.
 * Returns 0 if the input is not an array.
 *
 * @param[in] array  JSON array
 *
 * @return Number of elements in the array
 */
size_t ngx_oidc_json_array_size(ngx_oidc_json_t *array);

/**
 * Get element from JSON array by index
 *
 * Retrieves an element from a JSON array at a specific index.
 * Returns NULL if the index is out of bounds or if the input is not an array.
 *
 * @param[in] array  JSON array
 * @param[in] index  Zero-based index
 *
 * @return JSON value at the index, or NULL if out of bounds
 */
ngx_oidc_json_t *ngx_oidc_json_array_get(ngx_oidc_json_t *array, size_t index);

/**
 * Extract string value from JSON
 *
 * Gets the string value from a JSON string object.
 * Returns NULL if the input is not a string.
 *
 * @param[in] json  JSON string value
 *
 * @return Null-terminated C string, or NULL if not a string
 */
const char *ngx_oidc_json_string(ngx_oidc_json_t *json);

/**
 * Extract integer value from JSON
 *
 * Gets the integer value from a JSON integer object.
 * Returns 0 if the input is not an integer.
 *
 * @param[in] json  JSON integer value
 *
 * @return Integer value, or 0 if not an integer
 */
ngx_int_t ngx_oidc_json_integer(ngx_oidc_json_t *json);

/**
 * Extract double value from JSON
 *
 * Gets the double value from a JSON real number object.
 * Returns 0.0 if the input is not a real number.
 *
 * @param[in] json  JSON real number value
 *
 * @return Double value, or 0.0 if not a real number
 */
double ngx_oidc_json_real(ngx_oidc_json_t *json);

/**
 * Extract boolean value from JSON
 *
 * Gets the boolean value from a JSON boolean object.
 * Returns 0 if the input is not a boolean.
 *
 * @param[in] json  JSON boolean value
 *
 * @return 1 for true, 0 for false or non-boolean
 */
ngx_int_t ngx_oidc_json_boolean(ngx_oidc_json_t *json);

/**
 * Serialize JSON to compact string
 *
 * Converts a JSON object to a compact string representation (no whitespace).
 * This is useful for storing JSON in HTTP headers or session stores where
 * newlines and excessive whitespace should be avoided.
 *
 * @param[in] json  JSON object to serialize
 * @param[in] pool  nginx memory pool for allocation
 *
 * @return Serialized JSON string (allocated in pool), or NULL on error
 */
ngx_str_t *ngx_oidc_json_stringify_compact(ngx_oidc_json_t *json,
    ngx_pool_t *pool);

/*
 * Type Checking Functions
 *
 * Inline functions for checking JSON value types.
 * These provide type safety compared to macro implementations.
 */
static ngx_inline ngx_int_t
ngx_oidc_json_is_string(ngx_oidc_json_t *json)
{
    return ngx_oidc_json_type(json) == NGX_OIDC_JSON_STRING;
}

static ngx_inline ngx_int_t
ngx_oidc_json_is_integer(ngx_oidc_json_t *json)
{
    return ngx_oidc_json_type(json) == NGX_OIDC_JSON_INTEGER;
}

static ngx_inline ngx_int_t
ngx_oidc_json_is_boolean(ngx_oidc_json_t *json)
{
    return ngx_oidc_json_type(json) == NGX_OIDC_JSON_BOOLEAN;
}

static ngx_inline ngx_int_t
ngx_oidc_json_is_array(ngx_oidc_json_t *json)
{
    return ngx_oidc_json_type(json) == NGX_OIDC_JSON_ARRAY;
}

#endif /* _NGX_OIDC_JSON_H_INCLUDED_ */
