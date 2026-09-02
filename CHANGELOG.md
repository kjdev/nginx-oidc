# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.7.0] - 2026-09-03

### Added

- `auth_oidc_bearer` / `auth_oidc_bearer_audience` directives: verify externally obtained access tokens (JWT format) presented via an `Authorization: Bearer <jwt>` header, using an OIDC provider's issuer and JWKS. Supports authenticating clients without a cookie session, such as API clients, SPAs, and mobile apps. The issuer is always verified against the provider's issuer; the audience is set via `auth_oidc_bearer_audience` (falls back to `client_id` if unset). Verification failures return a 401 with an RFC 6750 `WWW-Authenticate: Bearer error="..."` header

### Changed

- ACCESS-phase handler registration now goes through the shared `nxe-phase` submodule with an explicit priority (`NXE_PHASE_PRIO_OIDC = 500`, between webauthn at 450 and gate at 600) instead of depending on `load_module`/`--add-module` order. When multiple `nxe-phase`-registered auth modules are loaded together, the OIDC handler's evaluation order relative to them is now determined by priority rather than by module load order. This guarantee does not extend to ACCESS-phase handlers that register themselves without going through `nxe-phase`; their relative order still depends on module load order

### Dependencies

- Bump `nxe-jwx` `0.2.0` → `0.3.0`: add RFC 7638 JWK thumbprints and `nxe_jwx_jwks_verify_raw()` for detached signature verification, add `nxe_jwx_encode()` for signed JWT issuing, enforce decode size limits on `nxe_jwx_encode()` output

## [0.6.0] - 2026-08-04

### Added

- Support for [Angie](https://github.com/webserver-llc/angie): conditional compilation accounts for Angie's `ngx_http_location_queue_t` layout change, so the module builds and runs on Angie in addition to nginx
- `cookie_domain` directive (provider scope): configures the `Domain` attribute of the session cookies. When set, `Domain=<value>` is added to both the temporary and permanent cookies, enabling session sharing across subdomains (e.g. `foo.example.com` and `bar.example.com`). The `HttpOnly` / `Secure` / `SameSite` safety attributes remain module-controlled and cannot be removed

### Security

- `cookie_domain` values are now restricted to domain-label characters (`A-Z`, `a-z`, `0-9`, `-`, `.`); the previous CRLF-only validation let a value such as `example.com; Max-Age=...` be appended verbatim after `; Domain=`, injecting additional Set-Cookie attributes

## [0.5.0] - 2026-06-29

### Added

- `pre_auth_timeout` directive (provider scope): configures the lifetime of pre-authentication entries (state, nonce, PKCE code_verifier, original URL). The temporary cookie Max-Age now follows this value. Default 600 s preserves prior behavior
- `oidc_cleanup_interval` directive (location scope): configures the random trigger probability (N in `% N`) for memory-store expired-entry cleanup. A value of 1 or less runs cleanup on every request and prevents modulo-by-zero. Default 100 preserves prior behavior
- Array-typed claims rendered as comma-separated `$oidc_claim_*` values (e.g. `nginx_roles: ["admin","editor"]` → `admin,editor`); string elements are verbatim, non-string elements are compact-JSON-serialized; nginx `map` can match individual roles with `~(^|,)admin(,|$)`

### Fixed

- Memory session store eviction: replaced expiry-ordered eviction with LRU, so in-flight pre-auth entries (state/nonce/code_verifier, ~600 s TTL) are no longer evicted by the authentication that just wrote them when the store is full; also fixed an rbtree insert crash caused by uninitialized node links, and extended `cleanup_expired` to scan the full queue so head-side expired entries are reclaimed
- Internal location lookup (`/_oidc_http_fetch` and peers) now uses the full path, independent of a surrounding `location /` root prefix; without a root prefix the match failed and nginx refused to start
- `client_secret` and `redirect_uri` are now treated as optional in `oidc_provider`; dereferencing them when unset caused a SIGSEGV in the authenticate and callback handlers
- An empty-string `client_secret` (`client_secret "";`) is now treated as unset and rejected at startup with `pkce off`, closing a bypass of the "no client secret with pkce off" guard
- A provider configured with no `client_secret` and `pkce off` is now rejected at startup; the combination removes both client authentication and PKCE proof from the token exchange
- `pre_auth_timeout` values outside `[1, 3600]` s are now rejected at startup; `0` caused every login to fail state validation instantly, and an extreme value widened the CSRF window without bound
- `memory_max_size` values outside `[1, 1000000]` are now rejected at startup; a zero or excessively large value could cause lock contention or a modulo-by-zero

## [0.4.1] - 2026-06-04

### Fixed

- Callback handler now builds an absolute `redirect_uri` before the token exchange; a relative path such as `/oauth2/callback` previously failed with "URL must start with http:// or https://"

### Dependencies

- Bump `nxe-json` `0.3.0` → `0.5.0`: add canonical key-sorted stringify (`nxe_json_stringify_compact_sorted`), NUL-terminate all `nxe_json_stringify_*` output, add scalar constructors and `nxe_json_deep_copy`
- Bump `nxe-jwx` `0.1.0` → `0.2.0`: add `nxe_jwx_jwks_free` for explicit keyset release (prevents key-material leak across config reloads), drop PEM→HMAC algorithm-confusion vector, reject empty `kid`, range-check RSA modulus (default 2048–16384 bits)

## [0.4.0] - 2026-05-18

### Changed

- JWT / JWS / JWKS processing delegated to the `nxe-jwx` submodule (`nxe_jwx_decode` / `nxe_jwx_jws_verify` / `nxe_jwx_jwks_parse`); removes 2,386 lines of in-tree algorithm and key-handling code
- JSON processing migrated to the `nxe-json` API; removes the in-tree `ngx_oidc_json.c/h`

### Added

- Status endpoint JWKS output restored to pretty-printed format (`nxe_json_stringify_pretty`)

### Fixed

- JWT claim comparison is now binary-safe: claims are stored as length-prefixed `ngx_str_t` and compared with `ngx_memcmp` / `CRYPTO_memcmp`, closing an embedded-NUL bypass that could make a crafted claim compare equal to a valid prefix
- Provider-originated JSON (JWT payload/header, UserInfo, ID token re-parse) now applies DoS-hardened limits on every path (depth 10, arrays 100, strings 4 KiB, object keys 256, total 1 MiB)

### Dependencies

- Add `nxe-json` submodule at `0.3.0` (`https://github.com/kjdev/nxe-json`): typed object-member extraction, object iteration API, keys returned as borrowed `ngx_str_t` in insertion order
- Add `nxe-jwx` submodule at `0.1.0` (`https://github.com/kjdev/nxe-jwx`): JWT / JWS / JWKS abstraction layer

## [0.3.0] - 2026-03-17

### Added

- `userinfo` directive extended to accept `on | off | <location>`: location mode sends a subrequest to an internal nginx location instead of the IdP's UserInfo endpoint, passing `X-OIDC-Access-Token`, `X-OIDC-Id-Token`, and `X-OIDC-Session-Id` headers; enables Token Exchange and internal API integration

## [0.2.2] - 2026-03-12

### Security

- Harden JSON/JWT/JWKS processing: `JSON_REJECT_DUPLICATES` flag, 1 MiB JSON size limit, 16 KiB JWT token length limit, reject empty header/payload segments and JWE (5-segment) tokens, `ngx_memzero` after payload decode, explicitly reject HS256/HS384/HS512, 256 KiB JWKS size and 64-key count limits, RSA minimum 2048-bit modulus and odd public-exponent validation, EC coordinate length validation per curve, curve-name retention for alg–curve compatibility, skip `use:"enc"` keys, distinguish signature mismatch from internal error, ensure `ERR_clear_error()` on every failure path

## [0.2.1] - 2026-03-11

### Fixed

- Cookie parsing updated for nginx 1.29.6+: `ngx_http_parse_multi_header_lines` now uses comma separator only; switch to `ngx_http_parse_cookie_lines` to prevent 401 errors during OIDC callback processing

## [0.2.0] - 2026-03-02

### Changed

- **BREAKING:** `enable_pkce` directive renamed to `pkce`
- `session_store` in `oidc_provider` now uses a dedicated default store instead of the first user-defined store

## [0.1.0] - 2026-02-20

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
