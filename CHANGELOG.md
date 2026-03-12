# Changelog

## [0551cc8] - 2026-03-12

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

## [dc560ad] - 2026-03-11

### Fixed

- Use `ngx_http_parse_cookie_lines` for cookie parsing on nginx 1.29.6+
  - nginx 1.29.6 changed `ngx_http_parse_multi_header_lines` to use comma separator only and introduced `ngx_http_parse_cookie_lines` for semicolon-separated Cookie headers
  - This caused cookie lookup failures resulting in 401 errors during OIDC callback processing

## [2df0445] - 2026-03-02

### Changed

- `oidc_provider` `session_store` now uses a dedicated default store instead of the first user-defined store

## [d37a500] - 2026-03-02

### Changed

- **BREAKING:** Renamed `enable_pkce` directive to `pkce` for commercial version compatibility

## [3fc28b4] - 2026-02-17

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

[0551cc8]: https://github.com/kjdev/nginx-oidc/commit/0551cc8
[dc560ad]: https://github.com/kjdev/nginx-oidc/commit/dc560ad
[2df0445]: https://github.com/kjdev/nginx-oidc/commit/2df0445
[d37a500]: https://github.com/kjdev/nginx-oidc/commit/d37a500
[3fc28b4]: https://github.com/kjdev/nginx-oidc/commit/3fc28b4
