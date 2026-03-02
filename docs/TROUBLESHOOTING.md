# Troubleshooting

This document describes how to diagnose and resolve common issues that may occur when operating the nginx OIDC module.

## Common Issues and Solutions

**Note**: For detailed configuration of the `/_oidc_http_fetch` location and environment-specific examples, see [DIRECTIVES.md](DIRECTIVES.md).

### Issue 1: Redirect Loop Occurs

**Symptom**: The browser repeats redirects infinitely

**Cause**:
- `auth_oidc off;` is not set in the `/_oidc_http_fetch` location
- The Callback URI is not correctly registered with the provider

**Solution**:
```nginx
location /_oidc_http_fetch {
    internal;
    auth_oidc off;  # This is required!
    # ...
}
```

### Issue 2: DNS Resolution Error ("could not be resolved")

**Symptom**: "could not be resolved" appears in the nginx error log

**Cause**: The `resolver` configuration is incorrect, or the DNS server is unreachable

**Solution**:
1. Configure an appropriate DNS resolver for your environment:
```nginx
location /_oidc_http_fetch {
    # When using systemd-resolved
    resolver 127.0.0.53 valid=300s;

    # When using public DNS
    # resolver 8.8.8.8 1.1.1.1 valid=300s;

    # In Kubernetes environments
    # resolver kube-dns.kube-system.svc.cluster.local valid=300s;
}
```

2. Verify DNS server reachability:
```bash
nslookup accounts.google.com 127.0.0.53
```

### Issue 3: SSL Verification Error

**Symptom**: "SSL certificate problem: unable to get local issuer certificate"

**Cause**: The CA certificate file does not exist or is incorrect

**Solution**:
1. Verify the CA certificate file path:
```nginx
# Debian/Ubuntu
proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

# RHEL/CentOS/Fedora
proxy_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;

# Alpine Linux
proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
```

2. Install the CA certificate package:
```bash
# Debian/Ubuntu
apt-get install ca-certificates

# RHEL/CentOS
yum install ca-certificates
```

### Issue 4: Timeout Error ("upstream timed out")

**Symptom**: Connections to the OIDC provider time out

**Cause**: The connection to or response from the OIDC provider is slow

**Solution**:
1. Increase the timeout values:
```nginx
location /_oidc_http_fetch {
    proxy_connect_timeout 60s;  # Default: 30s
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

2. Verify network connectivity:
```bash
curl -v https://accounts.google.com/.well-known/openid-configuration
```

### Issue 5: 500 Error During Authentication Redirect

**Symptom**: Internal Server Error (500) is returned when authentication begins

**Cause**:
- Saving state/nonce/PKCE parameters to the session store failed
- Memory Store is running out of capacity, or there is a connection error to the Redis server

**Solution**:
1. Check the error log for "session save" related messages
2. For Memory Store, increase `size` or `memory_max_size`
3. For Redis Store, verify the connection settings and ensure the Redis server is running

### Issue 6: Sessions Are Not Persisted

**Symptom**: Sessions are lost immediately after authentication

**Cause**:
- Cannot connect to the Redis server
- The session store TTL is too short

**Solution**:
1. Verify the Redis connection:
```bash
redis-cli -h redis.example.com -p 6379 -a password ping

# Pass the password via environment variable (to avoid the plaintext password warning with the -a option)
REDISCLI_AUTH=password redis-cli -h redis.example.com -p 6379 ping
```

2. Adjust the TTL:
```nginx
oidc_session_store redis_store {
    ttl 7200;  # Extended to 2 hours
}
```

### Issue 7: Subrequest Response Size Error ("too big subrequest response")

**Symptom**: "too big subrequest response" appears in the nginx error log

**Cause**: The response from the OIDC provider (metadata, JWKS, etc.) exceeds nginx's default subrequest buffer size

**Solution**:
1. Add `subrequest_output_buffer_size` to the `/_oidc_http_fetch` location:
```nginx
location /_oidc_http_fetch {
    # ... other settings ...
    subrequest_output_buffer_size 200k;
}
```
2. Adjust the value according to the response size (recommended: 200k to 500k)
3. Reload nginx: `nginx -s reload`

This error is particularly likely to occur with JWKS endpoints that contain a large number of public keys, or with OIDC providers that return large metadata.

### Issue 8: Sessions Expire Unexpectedly

**Symptom**: After a certain time since login, sessions expire and re-authentication is required earlier than the configured `session_timeout`

**Cause**: The session store's `ttl` (server-side session data expiration) is shorter than the `session_timeout` (cookie lifetime)

**Solution**:
1. Set `ttl` to be equal to or greater than `session_timeout`:
```nginx
oidc_session_store memory_store {
    ttl 28800;  # Set to at least session_timeout
}

oidc_provider my_provider {
    session_timeout 28800;  # 8 hours
}
```

2. Check the default values:
   - Default `ttl`: 3600 seconds (1 hour)
   - Default `session_timeout`: 28800 seconds (8 hours)
   - When using defaults as-is, the server-side session will expire after 1 hour, triggering re-authentication

For details, see [SECURITY.md](SECURITY.md#session-timeout).

## How to Check Logs

### Enabling Debug Logs

```nginx
error_log /var/log/nginx/error.log debug;
```

**Note**: To output debug logs, nginx must be built with the `--with-debug` option (see [INSTALL.md](INSTALL.md)). Disable debug logs in production environments as they impact performance.

### Checking Logs

```bash
# Check error logs
tail -f /var/log/nginx/error.log

# Check access logs
tail -f /var/log/nginx/access.log

# Search for OIDC-related logs
grep "oidc_" /var/log/nginx/error.log

# Search logs by module
grep "oidc_module:" /var/log/nginx/error.log          # Main module
grep "oidc_jwt:" /var/log/nginx/error.log              # JWT verification
grep "oidc_handler_callback:" /var/log/nginx/error.log # Callback processing
grep "oidc_handler_authenticate:" /var/log/nginx/error.log  # Authentication requests
grep "oidc_handler_logout:" /var/log/nginx/error.log   # Logout processing
grep "oidc_session:" /var/log/nginx/error.log          # Session management
grep "oidc_metadata:" /var/log/nginx/error.log         # Metadata retrieval
grep "oidc_jwks:" /var/log/nginx/error.log             # JWKS processing
grep "oidc_http:" /var/log/nginx/error.log             # HTTP fetch processing
grep "oidc_store_memory:" /var/log/nginx/error.log     # Memory store operations
grep "oidc_store_redis:" /var/log/nginx/error.log      # Redis store operations
```

### Key Log Messages

Log messages are output with an `oidc_<component_name>:` prefix.

**Authentication Flow**:
- `[debug]` **"oidc_module: callback detected"**: Callback request detected
- `[debug]` **"oidc_module: metadata fetched successfully"**: Provider metadata fetched successfully
- `[debug]` **"oidc_module: JWKS fetched successfully"**: JWKS (public key set) fetched successfully

**Token Verification**:
- `[debug]` **"oidc_jwt: JWT verification completed successfully"**: JWT verification succeeded
- `[error]` **"oidc_jwt: JWT signature verification failed"**: JWT signature verification failed
- `[error]` **"oidc_jwt: token expired"**: Token has expired
- `[error]` **"oidc_jwt: issuer validation failed"**: Issuer mismatch
- `[error]` **"oidc_jwt: audience validation failed"**: Audience mismatch

**Callback Processing**:
- `[debug]` **"oidc_handler_callback: successfully exchanged code"**: Authorization code successfully exchanged for tokens
- `[error]` **"oidc_handler_callback: token_endpoint not available"**: Token endpoint is unavailable

**Session**:
- `[debug]` **"oidc_session: session rotated"**: Session rotation completed
- `[debug]` **"oidc_session: invalidated session"**: Session invalidated

## Configuration Validation Errors

### Configuration Validation Command

```bash
nginx -t
```

### Key Validation Errors

**Error 1: `oidc provider "xxx": missing required parameter "issuer"`**
- **Cause**: `issuer` is not set in `oidc_provider`
- **Solution**: Add the `issuer` parameter

**Error 2: `oidc provider "xxx": missing required parameter "client_id"`**
- **Cause**: `client_id` is not set in `oidc_provider`
- **Solution**: Add the `client_id` parameter

**Error 3: `session store "xxx" not found`**
- **Cause**: The store name specified in `session_store` of `oidc_provider` is not defined
- **Solution**: Define a session store with the corresponding name using `oidc_session_store`

**Error 4: `size must be at least 1048576`**
- **Cause**: The Memory store size is less than 1MB (1,048,576 bytes)
- **Solution**: Set to `size 1m;` or greater

## Related Documents

- [README.md](../README.md): Module overview
- [DIRECTIVES.md](DIRECTIVES.md): Directives and variables reference
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build instructions)
- [SECURITY.md](SECURITY.md): Security considerations (PKCE, HTTPS, cookie security, etc.)
- [JWT_SUPPORTED_ALGORITHMS.md](JWT_SUPPORTED_ALGORITHMS.md): Supported JWT algorithms
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
