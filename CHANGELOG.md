# Changelog

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
