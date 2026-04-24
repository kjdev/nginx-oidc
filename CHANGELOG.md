# Changelog

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
