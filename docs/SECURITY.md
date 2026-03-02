# Security Considerations

This document describes the security considerations and recommended settings for using the nginx OIDC module in a production environment.

## Enabling PKCE

Enable PKCE (Proof Key for Code Exchange) and use the `S256` method.

**Reason**: This prevents Authorization Code Interception Attacks.

**Configuration**:
```nginx
oidc_provider my_provider {
    # ...
    pkce on;                # Enable PKCE (default: on)
    code_challenge_method S256;    # Use S256 (default: S256)
}
```

**Note**: PKCE is enabled by default. It is automatically enabled unless explicitly disabled.

## Using HTTPS

Always use HTTPS in production environments.

**Reason**: This prevents eavesdropping on tokens and cookies.

**Configuration**:
```nginx
server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Use TLS 1.2 or higher
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

    # HTTP -> HTTPS redirect
    # (configured in a separate server block)
}

server {
    listen 80;
    server_name app.example.com;
    return 301 https://$server_name$request_uri;
}
```

**Note**: If TLS is terminated at a load balancer or reverse proxy and the connection to nginx is HTTP, use the `oidc_base_url` directive to set the externally accessible HTTPS URL. This ensures that the redirect URI is constructed correctly.

```nginx
server {
    listen 80;
    oidc_base_url "https://app.example.com";
    # ...
}
```

## Session Timeout

Configure an appropriate session timeout according to your security requirements.

**Reason**: If the session lifetime is too long, the risk of session hijacking increases.

**Configuration**:
```nginx
oidc_session_store memory_store {
    ttl 28800;  # 8 hours (session store level)
}

oidc_provider my_provider {
    session_timeout 28800;  # 8 hours (provider level)
}
```

**Relationship between `ttl` and `session_timeout`**:
- `ttl` (in `oidc_session_store`): The expiration time for server-side session data. Session data is deleted after this period
- `session_timeout` (in `oidc_provider`): The lifetime of the session cookie sent to the browser (`Max-Age` attribute)

Typically, set `ttl` >= `session_timeout`. If `ttl` is shorter than `session_timeout`, the server-side session data will expire before the cookie, causing re-authentication even while the cookie is still valid.

**Note**: The default values are `ttl` = 3600 seconds (1 hour) and `session_timeout` = 28800 seconds (8 hours), which contradicts the recommended setting (`ttl` >= `session_timeout`). With the default settings, the server-side session will expire (1 hour) before the cookie lifetime (8 hours), causing users to be prompted for re-authentication. Address this by one of the following methods:
- Set `ttl` to be equal to or greater than `session_timeout` (e.g., `ttl 28800;`)
- Reduce `session_timeout` to be equal to or less than `ttl` (e.g., `session_timeout 3600;`)

**Selection Guidelines**:
- **High-security environments**: 1 hour or less
- **Standard business applications**: Approximately 8 hours
- **Public web applications**: Adjust according to requirements

## Client Secret Management

The client secret is sensitive information. Protect it appropriately.

**Reason**: If the client secret is leaked, an attacker can impersonate a legitimate client and obtain tokens fraudulently.

**Best Practices**:

1. **Restrict configuration file permissions**:
```bash
chmod 600 /etc/nginx/nginx.conf
chown root:root /etc/nginx/nginx.conf
```

2. **Use environment variables** (since nginx does not directly support this, use a configuration generation script):
```bash
# Example configuration generation script
CLIENT_SECRET="$(cat /run/secrets/oidc_client_secret)"
envsubst < nginx.conf.template > nginx.conf
```

3. **Exclude from version control**:
```bash
# Add to .gitignore
nginx.conf
*.secret
```

4. **Regular rotation**: Change the client secret periodically

## SSL Verification

Enable SSL verification in the `/_oidc_http_fetch` location.

**Reason**: If SSL verification is disabled, tokens and session information may be intercepted through man-in-the-middle attacks.

**Configuration**:
```nginx
location /_oidc_http_fetch {
    internal;
    auth_oidc off;

    # Always enable SSL verification
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    proxy_ssl_server_name on;
    proxy_ssl_name $proxy_host;

    # ...
}
```

**Warning**: `proxy_ssl_verify off` poses a risk of man-in-the-middle attacks. Do not use it in production environments.

## Cookie Security Settings

In production environments, use HTTPS and verify that the Secure attribute is enabled on cookies.

**Reason**: If cookies are not properly protected, there is a risk of session hijacking and CSRF attacks.

The module automatically sets the following security attributes:
- **HttpOnly**: Prevents JavaScript from accessing the cookie (XSS protection). Always set (fixed)
- **SameSite=Lax**: Mitigates CSRF attacks. Always set (fixed)
- **Secure**: Only added when the connection to nginx is TLS (conditional). Cookies are set without the Secure attribute for non-TLS connections

HttpOnly and SameSite are always set automatically, so no additional configuration is needed. The Secure attribute is automatically determined based on the actual TLS connection state to the nginx process.

**Note**: The Secure attribute is determined by the actual TLS connection state to the nginx process. If TLS is terminated at a load balancer or reverse proxy and the connection to nginx is HTTP, the Secure attribute will not be added.

**Countermeasures for reverse proxy environments**:

- **Configure TLS on nginx as well**: By using TLS communication between the load balancer and nginx, the Secure attribute will be added
- **Restrict to trusted networks**: Limit communication between the load balancer and nginx to a VPC or private network to mitigate the risk of non-TLS communication

**Cookie name configuration when using multiple providers**:

When using multiple OIDC providers, set a different `cookie_name` for each provider. Using the same cookie name will cause session conflicts and prevent proper operation.

```nginx
oidc_provider google {
    cookie_name "oidc_google_session";
    # ...
}

oidc_provider azure {
    cookie_name "oidc_azure_session";
    # ...
}
```

## Automatic Security Protections

The following security features are automatically applied by the module, requiring no additional configuration.

- **State parameter**: A random state parameter is generated and validated for each authentication request, preventing CSRF attacks
- **Nonce**: A nonce bound to the ID Token is generated and validated, preventing replay attacks
- **at_hash verification**: When the ID Token contains an `at_hash` claim, the binding with the access token is automatically verified
- **JWT signature verification**: ID Token signatures are automatically verified using public keys obtained from the JWKS endpoint. See [JWT_SUPPORTED_ALGORITHMS.md](JWT_SUPPORTED_ALGORITHMS.md) for details on supported algorithms

## Related Documents

- [README.md](../README.md): Module overview
- [DIRECTIVES.md](DIRECTIVES.md): Directive and variable reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log inspection)
- [JWT_SUPPORTED_ALGORITHMS.md](JWT_SUPPORTED_ALGORITHMS.md): JWT supported algorithms
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
