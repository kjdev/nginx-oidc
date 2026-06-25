# Changelog

## [e2fd509](../../commit/e2fd509) - 2026-06-25

### Added

- Add the `pre_auth_timeout` (provider) and `oidc_cleanup_interval` (location) directives
  - `pre_auth_timeout` (default 600): makes the lifetime of the pre-auth entries created by the authenticate handler (state, nonce, PKCE code_verifier, original URL) configurable. Replaces the previously hardcoded `NGX_OIDC_PRE_AUTH_TIMEOUT` at the two creation sites and keeps the constant as the default. The temporary-cookie Max-Age and the authorization-code replay guard are separate concerns and keep the fixed value
  - `oidc_cleanup_interval` (default 100): makes the N in the `ngx_random() % N` trigger for memory-store expired-entry cleanup configurable. A value of 1 or less runs cleanup on every request and also avoids a modulo-by-zero
  - Both defaults preserve the previous behavior, so existing configurations are unaffected

## [5c9a282](../../commit/5c9a282) - 2026-06-25

### Fixed

- Treat an empty `client_secret` as unset to close a startup-check bypass
  - A literal empty string (`client_secret "";`) is non-NULL, so the startup guard that rejects "no `client_secret` with `pkce off`" let it pass, and the callback then sent an empty `&client_secret=` with PKCE still off, reproducing the insecure unauthenticated token exchange the guard is meant to block
  - `ngx_http_oidc_validate_provider` now treats a constant zero-length `client_secret` as unset and rejects it together with `pkce off`. A value referencing a variable cannot be evaluated at config time and remains the operator's responsibility
  - The callback now gates `&client_secret=` on the resolved value length instead of the pointer, so a value that resolves to empty at runtime never sends an empty `&client_secret=`. This is body-construction correctness, not an exchange-aborting per-request guard

## [9fa78af](../../commit/9fa78af) - 2026-06-25

### Fixed

- Reject a provider configured with no `client_secret` and `pkce off`
  - A public client (no `client_secret`) combined with `pkce off` made the token exchange carry neither client authentication nor a PKCE proof, removing the defense against authorization code interception. Such an insecure configuration could be created by mistake and was silently accepted
  - `ngx_http_oidc_validate_provider` now rejects the combination so nginx fails to start: a public client must keep PKCE enabled, and a confidential client must provide a `client_secret`. The startup check is the single line of defense, so no redundant per-request guard is added in the callback handler

## [3f44b73](../../commit/3f44b73) - 2026-06-24

### Fixed

- Scan the full LRU queue in `cleanup_expired` to evict head-side expired entries
  - After the LRU conversion, `cleanup_expired` walked only the 128 tail-most nodes. Entries near the LRU head — recently accessed entries whose TTL had just elapsed — were never reached and lingered in shared memory indefinitely. The only removal paths for such entries were an explicit `get` call (which checks expiry on access) or LRU eviction naturally pushing the entry toward the tail
  - Since entry count is always bounded by `memory_max_size`, a full queue walk is safe: lock hold time scales with `memory_max_size`, not with an arbitrary scan limit

## [560d0b9](../../commit/560d0b9) - 2026-06-24

### Fixed

- Match required internal locations by full path, independent of a root prefix
  - `ngx_http_oidc_find_location` stripped the leading `/` from the search name and compared it against static location tree node names. Tree node names are relative to the prefix accumulated along the path, and only the inclusive (prefix) subtree advances that prefix, so whether a node name keeps its leading `/` depends on the surrounding location set. With a root prefix `location /` grouping everything beneath it the `/` was stripped and the search matched by coincidence; without it, top-level node names retained the `/` and `/_oidc_http_fetch` was never found, failing startup with `emerg: OIDC module requires internal location "/_oidc_http_fetch" to be configured`
  - Walk the static location tree with the full path exactly like nginx's own `ngx_http_core_find_static_location`: consume the path while descending inclusive subtrees so the comparison is always against the correct prefix-relative name. A location is reported as configured when the full path lands on a node. This also fixes the more general case of nested inclusive prefixes (e.g. `location /_oidc` alongside `/_oidc_http_fetch`)

## [e700345](../../commit/e700345) - 2026-06-23

### Fixed

- Treat `client_secret` and `redirect_uri` as optional `oidc_provider` options
  - Both are documented as optional, but the handlers dereferenced them unconditionally. With `redirect_uri` unset, `ngx_http_complex_value(r, NULL, ...)` dereferenced a NULL complex value in the authenticate and callback handlers and crashed the worker (SIGSEGV); `client_secret` unset failed the token exchange even for a PKCE public client
  - `redirect_uri`: fall back to the built-in default callback path (`/oidc_callback`) when unset, matching the callback-detection default already used at request dispatch, so the authorization redirect and token exchange both operate on that path
  - `client_secret`: omit it from the token endpoint request when unset (public client using PKCE) instead of failing; an empty `&client_secret=` is never sent

## [a061c2c](../../commit/a061c2c) - 2026-06-23

### Fixed

- Evict the memory session store LRU-first so an in-flight authentication keeps its own state
  - The shared-memory store ordered its queue by expiration and, when full, evicted the soonest-to-expire entry. Pre-auth entries (`state` / `nonce` / `code_verifier` / `original_uri`, ~600s TTL) always expire far earlier than session entries (`id_token` / `access_token` / `userinfo`, session TTL), so once the store reached `memory_max_size` every new authentication evicted its own freshly written `state` / `nonce`, and the callback failed state validation with 401. An nginx reload re-initialized the zone to an empty tree, which is why a reload temporarily restored the flow until the store filled again
  - Reorder the queue as a true LRU list (head = most recently used): insert new nodes at the head and move nodes to the head on get/update, so in-flight pre-auth entries are never the eviction victim; eviction now drops the least-recently-used (idle) entry from the tail instead
  - Replace the custom `mem_find_node()` with `ngx_str_rbtree_lookup()` so the search order (hash, length, bytes) matches `ngx_str_rbtree_insert_value()` and cannot miss an existing node on a CRC32 hash collision
  - Scan a bounded number of tail nodes in `cleanup_expired()` since the queue is no longer ordered by expiration

## [8ee231b](../../commit/8ee231b) - 2026-06-23

### Fixed

- Initialize the inserted node's links in the metadata / JWKS shared-memory rbtree insert callbacks
  - `metadata_rbtree_insert` and `jwks_rbtree_insert_value` linked the new node into its parent but never set the node's own `parent` / `left` / `right` pointers, violating the `ngx_rbtree_insert()` contract whose rebalancing step dereferences `node->parent`. Since nodes come from non-zeroed slab memory, `node->parent` held garbage and the rebalance crashed the worker (SIGSEGV) inside the locked critical section, leaving the shared memory zone locked
  - The first insertion into an empty tree is handled directly by `ngx_rbtree_insert`, so the crash only surfaced on the second and later insertions — i.e. with multiple providers using distinct `issuer` / `jwks_uri` values
  - Set `node->parent` / `left` / `right` after the insertion loop as required by the contract (the duplicate-key branch is unreachable because `shm_save` searches for an existing entry under the same lock before inserting)

## [35e0514](../../commit/35e0514) - 2026-06-03

### Changed

- Bump `nxe-json` submodule `0.3.0` -> `0.5.0`
  - Add `nxe_json_stringify_compact_sorted` (canonical key-sorted output), NUL-terminate all `nxe_json_stringify_*` output (`data[len] == '\0'`, `len` unchanged), and add the remaining scalar constructors / deep copy (`nxe_json_from_integer` / `_boolean` / `_null`, `nxe_json_deep_copy`) so consumers never reach for jansson directly
- Bump `nxe-jwx` submodule `0.1.0` -> `0.2.0`
  - Add `nxe_jwx_jwks_free` for explicit keyset release (prevents key-material leak on pools that survive nginx config reloads), drop the keyval PEM -> HMAC fallback to close a PEM/HMAC algorithm-confusion vector, reject JWKS / keyval entries that declare an empty `kid`, and range-check the RSA modulus by bit length (`NXE_JWX_MIN_RSA_BITS` / `_MAX_RSA_BITS`, default 2048..16384)

## [39de5c9](../../commit/39de5c9) - 2026-06-03

### Fixed

- Build an absolute `redirect_uri` in the callback token exchange
  - The callback handler passed `redirect_uri` to `ngx_oidc_url_validate` without converting relative paths to absolute URLs, unlike the authenticate handler. A relative value such as `/oauth2/callback` failed with "URL must start with http:// or https://" during token exchange, even though the authorization request succeeded
  - Call `ngx_oidc_url_build_absolute` (which validates internally) so the token-request `redirect_uri` matches the one sent in the authorization request, as required by OIDC

## [48bbf42](../../commit/48bbf42) - 2026-05-14

### Fixed

- Make JWT claim comparison binary-safe and structurally close the embedded-NUL bypass
  - Change `jwt_claims_t` iss / aud / sub / nonce / at_hash and the audiences array from `char *` to `ngx_str_t`, and introduce a new internal helper `jwt_str_dup` that copies claim values into the pool with their length preserved (no NUL terminator)
  - Replace `ngx_strncmp` / `ngx_strlen` comparisons in `jwt_validate_claims` with explicit length-prefixed `ngx_memcmp` (nonce / at_hash still use `CRYPTO_memcmp`). A crafted claim value such as `<valid> <garbage>` can no longer compare equal to its `<valid>` prefix and bypass iss / aud / nonce / at_hash checks
  - Lift the `at_hash` parameter of `ngx_oidc_jwt_validate_at_hash` from `const char *` to `const ngx_str_t *` and drop the `at_hash_copy` C-string round-trip in `callback_verify_access_token`
  - Make `jwt_str_dup` failure on an at_hash claim that is present return `NGX_ERROR`, replacing the previous fail-open path that silently skipped at_hash verification on allocation failure

## [04c2060](../../commit/04c2060) - 2026-05-13

### Changed

- Route JWT / JWS / JWKS processing through the `nxe-jwx` submodule
  - Drop the in-tree algorithm parsing, signature verification, and JWKS public-key construction (`src/ngx_oidc_jwt.c` 1,272 lines, `src/ngx_oidc_jwks.c` 1,114 lines) in favour of `nxe_jwx_decode` / `nxe_jwx_jws_verify` / `nxe_jwx_jwks_parse` (net diff: +298 / −2,543)
  - Remove the legacy public API (`ngx_oidc_jwt_decode_payload/header`, `ngx_oidc_jwks_key_*`, `ngx_oidc_jwk_type_t`) and migrate every call site onto the opaque `nxe_jwx_token_t` / `nxe_jwx_jwks_t` handles
  - Hand ID-token payload ownership to nxe-jwx's pool-cleanup lifecycle and drop the bespoke `oidc_variable_json_cleanup`

## [c0e6ab5](../../commit/c0e6ab5) - 2026-05-13

### Changed

- Bump `nxe-json` submodule to `0.3.0`
  - Add object iteration API (`nxe_json_object_size` / `_iter` / `_iter_next` / `_iter_key` / `_iter_value`)
  - Keys are returned in insertion order as borrowed `ngx_str_t` views, letting JWKS / userinfo handlers walk claims without leaking jansson types

## [2af955d](../../commit/2af955d) - 2026-05-13

### Added

- Add `nxe-jwx` as a git submodule (v0.1.0)
  - Shared JWT / JWS / JWKS abstraction layer at `https://github.com/kjdev/nxe-jwx`
  - `config` sources `nxe-jwx/config.ngx`; nxe-jwx reuses the include path exported by nxe-json, so it must be sourced after `nxe-json/config.ngx`
  - Build errors out explicitly when the submodule is not initialized

## [4db1104](../../commit/4db1104) - 2026-04-24

### Changed

- Bump `nxe-json` submodule to `0.2.0`
  - Add `nxe_json_object_get_integer` / `nxe_json_object_get_boolean` helpers for typed object-member extraction
  - Zero-clear extractor out-params on every non-`NGX_OK` exit to prevent silent downgrade when callers skip the return-value check

## [9313e8d](../../commit/9313e8d) - 2026-04-23

### Fixed

- Parse provider-originated JSON with DoS-hardened limits
  - Unify JWT payload/header, UserInfo, and ID token re-parse paths under `nxe_json_parse_untrusted`
  - A valid signature authenticates the source but does not guarantee structural safety, so the full limit set (depth 10, array 100, string 4 KiB, object keys 256, total 1 MiB) is now applied on every path

## [6a94419](../../commit/6a94419) - 2026-04-23

### Added

- Restore pretty-printed JWKS output in the status endpoint
  - Use `nxe_json_stringify_pretty()` with indent=2 for formatted output

## [23c3a72](../../commit/23c3a72) - 2026-04-23

### Changed

- Switch OIDC sources to the `nxe_json` API
  - Remove the in-tree `src/ngx_oidc_json.c/h` and migrate every call site to the `nxe_json_t` / `nxe_json_*` API
  - `nxe_json_string()` returns a borrowed `ngx_str_t`, enabling binary-safe comparisons and copies

## [6948abc](../../commit/6948abc) - 2026-04-23

### Added

- Add `nxe-json` as a git submodule
  - Shared JSON abstraction layer at `https://github.com/kjdev/nxe-json`
  - `config` sources `nxe-json/config.ngx`; build errors out explicitly when the submodule is not initialized
  - Dockerfile copies `nxe-json/` into the build context
  - CI workflows enable submodule checkout

## [5e11050](../../commit/5e11050) - 2026-03-17

### Added

- Implement location mode for custom userinfo endpoint
  - Location mode sends a subrequest to an internal nginx location instead of the IdP's UserInfo endpoint
  - Custom headers (`X-OIDC-Access-Token`, `X-OIDC-Id-Token`, `X-OIDC-Session-Id`) are passed to the internal location
  - Sub claim validation is skipped for location mode responses
  - Supports use cases such as Token Exchange and internal API integration

## [d326a8c](../../commit/d326a8c) - 2026-03-17

### Added

- Extend `userinfo` directive to accept `on | off | <location>` syntax
  - Add `ngx_oidc_userinfo_mode_t` type to distinguish provider/location/off modes
  - Update provider config parsing to handle location name as userinfo value

## [0551cc8](../../commit/0551cc8) - 2026-03-12

### Fixed

- Security hardening for JSON/JWT/JWKS processing
  - Add `JSON_REJECT_DUPLICATES` flag to prevent ambiguity attacks via duplicate keys
  - Add JSON input size limit (1 MiB) before parsing
  - Introduce `NGX_OIDC_JSON_INVALID` to distinguish NULL input from JSON null value
  - Add JWT token length limit (16 KiB) to decode and verify functions
  - Reject empty header/payload segments and JWE (5-segment) tokens
  - Clear decoded payload buffer with `ngx_memzero` after use
  - Explicitly reject HMAC algorithms (HS256/HS384/HS512)
  - Add JWKS JSON size limit (256 KiB) and key count limit (64)
  - Validate RSA minimum key length (2048 bits) and public exponent (odd, >= 3)
  - Validate EC coordinate lengths per curve (P-256: 32B, P-384: 48B, P-521: 66B)
  - Store EC curve name (crv) in key structure for alg-curve compatibility validation
  - Skip encryption keys (`use: "enc"`) during JWKS parsing
  - Distinguish signature mismatch (try next key) from internal error (abort)
  - Ensure `ERR_clear_error()` after each verification failure path

## [dc560ad](../../commit/dc560ad) - 2026-03-11

### Fixed

- Use `ngx_http_parse_cookie_lines` for cookie parsing on nginx 1.29.6+
  - nginx 1.29.6 changed `ngx_http_parse_multi_header_lines` to use comma separator only and introduced `ngx_http_parse_cookie_lines` for semicolon-separated Cookie headers
  - This caused cookie lookup failures resulting in 401 errors during OIDC callback processing

## [2df0445](../../commit/2df0445) - 2026-03-02

### Changed

- `oidc_provider` `session_store` now uses a dedicated default store instead of the first user-defined store

## [d37a500](../../commit/d37a500) - 2026-03-02

### Changed

- **BREAKING:** Renamed `enable_pkce` directive to `pkce` for commercial version compatibility

## [3fc28b4](../../commit/3fc28b4) - 2026-02-17

### Added

- OIDC authentication via Authorization Code Flow with PKCE (S256/plain)
- Session management: memory store (shared memory) and Redis store
- JWT token verification: RSA, ECDSA, EdDSA signature verification; claims verification (iss, aud, exp, iat, nbf, nonce, at_hash)
- UserInfo endpoint retrieval
- Multi-provider support
- nginx variables: `$oidc_id_token`, `$oidc_access_token`, `$oidc_claim_*`, `$oidc_authenticated`, `$oidc_userinfo`
- Authentication mode control (`auth_oidc_mode`): `off`, `verify`, `require`
- RP-Initiated Logout
- Debug status endpoint
