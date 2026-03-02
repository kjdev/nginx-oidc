# Commercial Version Compatibility

This is a reference on the compatibility between the nginx OIDC module and the [nginx commercial subscription version](https://nginx.org/en/docs/http/ngx_http_oidc_module.html).

## Overview

**Commercial Compatible**: The basic directives `auth_oidc` and `oidc_provider` are compatible with the commercial version.

**Original Extensions**: The following features are provided that are not available in the commercial version:
- `auth_oidc_mode` directive (authentication mode control)
- `oidc_session_store` directive (Redis session store)
- `oidc_base_url` directive (reverse proxy support)
- `oidc_status` directive (status endpoint)
- `$oidc_authenticated` variable

**License**: MIT License

## Directive Comparison Table

| Commercial | OSS Version (This Module) | Compatibility |
|------------|---------------------------|---------------|
| `auth_oidc <name> \| off` | `auth_oidc <name> \| off` | Fully compatible |
| `oidc_provider <name> { ... }` | `oidc_provider <name> { ... }` | Fully compatible |
| &emsp; `issuer` | &emsp; `issuer` | Fully compatible |
| &emsp; `client_id` | &emsp; `client_id` | Fully compatible |
| &emsp; `client_secret` | &emsp; `client_secret` | Fully compatible |
| &emsp; `config_url` | &emsp; `config_url` | Fully compatible |
| &emsp; `cookie_name` | &emsp; `cookie_name` | Fully compatible |
| &emsp; `extra_auth_args` | &emsp; `extra_auth_args` | Fully compatible |
| &emsp; `redirect_uri` | &emsp; `redirect_uri` | Fully compatible |
| &emsp; `scope` | &emsp; `scopes` | Renamed |
| &emsp; `session_store` | &emsp; `session_store` | Fully compatible |
| &emsp; `session_timeout` | &emsp; `session_timeout` | Fully compatible |
| &emsp; `logout_uri` | &emsp; `logout_uri` | Fully compatible |
| &emsp; `post_logout_uri` | &emsp; `post_logout_uri` | Fully compatible |
| &emsp; `logout_token_hint` | &emsp; `logout_token_hint` | Fully compatible |
| &emsp; `userinfo` | &emsp; `userinfo` | Fully compatible |
| &emsp; `pkce` | &emsp; `pkce` | Fully compatible |
| &emsp; `ssl_crl` | — | Not implemented |
| &emsp; `ssl_trusted_certificate` | — | Not implemented |
| &emsp; `frontchannel_logout_uri` | — | Not implemented |
| — | &emsp; `code_challenge_method` | Original extension |
| — | &emsp; `clock_skew` | Original extension |
| — | `auth_oidc_mode` | Original extension |
| — | `oidc_session_store` | Original extension |
| — | `oidc_base_url` | Original extension |
| — | `oidc_status` | Original extension |

## Related Documents

- [README.md](../README.md): Module overview
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (PKCE, HTTPS, cookie security, etc.)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [JWT_SUPPORTED_ALGORITHMS.md](JWT_SUPPORTED_ALGORITHMS.md): JWT supported algorithms
- [nginx OIDC Commercial Module](https://nginx.org/en/docs/http/ngx_http_oidc_module.html)
