# Directives and Variables Reference

A comprehensive reference for configuration directives, embedded variables, and related settings of the nginx OIDC module.

## Configuration Examples

For configuration examples, refer to the following documents:

- [README.md](../README.md): Quick start (minimal configuration)
- [EXAMPLES.md](EXAMPLES.md): Practical configuration examples for various use cases

## Directives

| Directive | Description | Context |
|---|---|---|
| [auth_oidc](#auth_oidc) | Enable OIDC authentication | http, server, location |
| [auth_oidc_mode](#auth_oidc_mode) | Control authentication mode | http, server, location |
| [oidc_provider](#oidc_provider) | Define an OIDC provider | http |
| [oidc_session_store](#oidc_session_store) | Define a session store | http |
| [oidc_base_url](#oidc_base_url) | Base URL for redirect URIs | http, server, location |
| [oidc_status](#oidc_status) | Status endpoint | server, location |

### auth_oidc

```
Syntax:  auth_oidc <provider_name> | off;
Default: —
Context: http, server, location
```

Enables authentication using the specified OIDC provider.

**Parameters**:
- `provider_name`: Name of the provider to use (defined by `oidc_provider`)
- `off`: Disable OIDC authentication

**Behavior**:
- `auth_oidc provider_name`: Enable authentication with the specified provider
- `auth_oidc off`: Disable authentication (overrides parent context settings)

**Inheritance**:
Child contexts (location) inherit settings from parent contexts (server, http). Use `auth_oidc off` to explicitly disable.

**Usage example**:
```nginx
http {
    oidc_provider my_provider { ... }

    server {
        auth_oidc my_provider;  # Enable authentication for the entire server

        location /protected {
            # Inherits authentication (uses my_provider)
        }

        location /public {
            auth_oidc off;  # Disable authentication
        }
    }
}
```

### auth_oidc_mode

```
Syntax:  auth_oidc_mode off | verify | require;
Default: require
Context: http, server, location
```

Controls the behavior mode of OIDC authentication. Provides three-level control similar to `ssl_verify_client`.

**Modes**:

- **off**: Disable OIDC processing (callback processing continues)
  - No authentication state checking is performed
  - No session information is referenced
  - `$oidc_authenticated` returns `"0"`, other `$oidc_*` variables are empty
  - Callback requests continue to be processed (unlike `auth_oidc off`)
  - **Use case**: Static content, health check endpoints

- **verify**: Verify authentication state but do not redirect unauthenticated users
  - If a session exists, authentication information is verified
  - `$oidc_*` variables are populated (when authenticated)
  - When unauthenticated, `$oidc_authenticated` returns `"0"`, other `$oidc_*` variables are empty
  - **Use case**: Optional authentication, checking authentication state only

- **require**: Redirect to authentication flow if unauthenticated (default)
  - If no session exists, initiates the authentication flow
  - Redirects to the authentication provider
  - **Use case**: Resources that require authentication

**Usage example**:
```nginx
server {
    auth_oidc my_provider;
    auth_oidc_mode verify;  # Default to optional authentication

    location /admin {
        auth_oidc_mode require;  # Admin area requires authentication
    }

    location /public {
        auth_oidc_mode off;  # Public area does not require authentication
    }
}
```

**Difference between `auth_oidc off` and `auth_oidc_mode off`**:

- **`auth_oidc off`**: Removes the provider association entirely. The OIDC module does not process any requests for that location (callback detection is also disabled).
- **`auth_oidc_mode off`**: The provider association is inherited from the parent context, but authentication processing is skipped. `$oidc_authenticated` returns `"0"`, and other `$oidc_*` variables are empty. However, callback requests continue to be processed.

Normally `auth_oidc_mode off` is sufficient, but use `auth_oidc off` when you want to completely exclude OIDC module processing (e.g., static file serving).

### oidc_provider

```
Syntax:  oidc_provider <name> { ... }
Default: —
Context: http
```

Defines an OIDC provider. A provider contains the configuration for the OpenID Connect provider (IdP) used for authentication.

**Parameters**:
- `name`: Provider name (referenced by the `auth_oidc` directive)

#### issuer

```
Syntax:  issuer <url>;
Default: —
Required
```

The Issuer URL of the OIDC provider. This is matched against the `iss` claim of JWT tokens.

#### client_id

```
Syntax:  client_id <id>;
Default: —
Required
```

The OAuth 2.0 client ID. Specify the string issued by the provider.

#### client_secret

```
Syntax:  client_secret <secret>;
Default: —
```

The OAuth 2.0 client secret. Required for Confidential Clients.

The client secret is sensitive information. Protect it appropriately.

#### session_store

```
Syntax:  session_store <name>;
Default: —
```

The name of the session store to use. If not set, a default memory store (TTL: 3600 seconds, size: 10MB) is automatically created and used.

When explicitly specifying a session store, it must be previously defined with `oidc_session_store`.

#### redirect_uri

```
Syntax:  redirect_uri <uri>;
Default: —
```

The OAuth 2.0 redirect URI. Specify a relative path (e.g., `/oauth2/callback`) or an absolute URL (e.g., `https://app.example.com/oauth2/callback`). This is used to construct the authorization URL in the authentication flow (`auth_oidc_mode require`), so it must be set in environments that require authentication redirects. If not set, the default path `/oidc_callback` is used for callback detection, but authentication redirects will not work correctly.

#### config_url

```
Syntax:  config_url <url>;
Default: {issuer}/.well-known/openid-configuration
```

The OpenID Connect Discovery endpoint URL. No configuration is needed if using the standard Discovery endpoint.

#### cookie_name

```
Syntax:  cookie_name <name>;
Default: NGX_OIDC_SESSION
```

The session cookie name. When using multiple providers, set a different cookie name for each provider. Using the same cookie name causes session conflicts and prevents proper operation.

#### scopes

```
Syntax:  scopes <scope1> [<scope2> ...];
Default: openid
```

OAuth 2.0 scopes. If not set, only `openid` is used. If `openid` is not included when configuring, it is automatically added, but it is recommended to include it explicitly (e.g., `scopes openid profile email;`).

#### extra_auth_args

```
Syntax:  extra_auth_args <args>;
Default: —
```

Additional parameters to include in the authentication request. Specify a URL query parameter format string (e.g., `prompt=none`).

#### clock_skew

```
Syntax:  clock_skew <time>;
Default: 300
```

The clock skew tolerance (in seconds) for JWT verification. Used when verifying JWT token exp (expiration time), iat (issued at), and nbf (not before) claims. You can specify any positive integer or time string (e.g., `5m`, `1h`).

#### pkce

```
Syntax:  pkce on | off;
Default: on
```

Enables PKCE (Proof Key for Code Exchange). Compliant with OAuth 2.0 Security Best Current Practice, it is enabled by default for enhanced security.

Enabling PKCE is recommended for security reasons.

#### code_challenge_method

```
Syntax:  code_challenge_method S256 | plain;
Default: S256
```

The PKCE code challenge method. Compliant with RFC 7636. The use of `S256` is recommended for security.

#### session_timeout

```
Syntax:  session_timeout <time>;
Default: 28800
```

Session timeout (in seconds). You can specify any positive integer or time string (e.g., `1h`, `1d`). Specifying 0 creates a session cookie without a Max-Age attribute (deleted when the browser session ends). This is separate from the session store's `ttl` setting (`ttl` controls the expiration of data in the server-side store, while `session_timeout` controls the lifetime of the cookie sent to the browser).

#### logout_uri

```
Syntax:  logout_uri <uri>;
Default: —
```

The RP-Initiated Logout URI. Accessing this URI triggers the logout process.

#### post_logout_uri

```
Syntax:  post_logout_uri <uri>;
Default: —
```

The redirect URI after logout.

#### logout_token_hint

```
Syntax:  logout_token_hint on | off;
Default: off
```

Controls whether to include id_token_hint during logout.

#### userinfo

```
Syntax:  userinfo on | off;
Default: off
```

Retrieves information from the UserInfo endpoint. When enabled, `$oidc_claim_*` variables can supplement claims not present in the ID Token with information from the UserInfo endpoint (ID Token claims take priority).

If the request to the UserInfo endpoint fails (timeout, HTTP error, etc.), a warning is logged but the authentication flow itself continues (graceful degradation). In this case, `$oidc_userinfo` will be empty.

**Full configuration example**:
```nginx
oidc_provider corporate_idp {
    # Required settings
    issuer "https://idp.example.com";
    client_id "webapp-client";
    client_secret "secret";

    # Session store (a default memory store is auto-created if omitted)
    session_store redis_store;

    # Required setting (when using auth_oidc_mode require)
    redirect_uri "https://app.example.com/oauth2/callback";

    # Optional settings
    cookie_name "oidc_session";
    scopes openid profile email;
    clock_skew 300;

    # PKCE settings
    pkce on;
    code_challenge_method S256;

    # Session settings
    session_timeout 28800;  # 8 hours

    # Logout settings
    logout_uri "/logout";
    post_logout_uri "https://app.example.com/";
    logout_token_hint on;

    # UserInfo settings
    userinfo on;
}
```

### oidc_session_store

```
Syntax:  oidc_session_store <name> { ... }
Default: —
Context: http
```

Defines a session store. A session store is a storage backend for persisting OIDC authentication session information.

**Parameters**:
- `name`: Session store name (referenced from provider configuration)

**Storage types**:
- **memory**: Uses shared memory (for single-server environments)
- **redis**: Uses a Redis server (for distributed environments and high availability)

For production environments running multiple nginx instances, using Redis store is recommended.

#### type

```
Syntax:  type memory | redis;
Default: memory
```

The session store type.

#### ttl

```
Syntax:  ttl <time>;
Default: 3600
```

Session expiration time (in seconds). You can specify any positive integer or time string (e.g., `30m`, `1h`, `1d`). This is the expiration of server-side session data. It is a separate setting from the provider's `session_timeout` (cookie lifetime). Adjust according to your operational requirements.

#### prefix

```
Syntax:  prefix <string>;
Default: "oidc:session:"
```

Session key prefix. Useful when sharing the same Redis instance across multiple applications.

#### size

```
Syntax:  size <size>;
Default: 10m
Context: memory type only
```

Shared memory size. Specify at least `1m`. Less than 1MB results in an error, and exceeding 1GB triggers a warning (Redis is recommended for large-scale deployments).

#### memory_max_size

```
Syntax:  memory_max_size <number>;
Default: 1000
Context: memory type only
```

The maximum number of session entries stored in the memory store. When the limit is reached, expired entries are deleted first. If that is insufficient, the oldest entries are evicted.

#### hostname

```
Syntax:  hostname <string>;
Default: "127.0.0.1"
Context: redis type only
```

The hostname or IP address of the Redis server. An empty string is not allowed.

#### port

```
Syntax:  port <number>;
Default: 6379
Context: redis type only
```

The port number of the Redis server. Specify a value in the range `1` to `65535`.

#### database

```
Syntax:  database <number>;
Default: 0
Context: redis type only
```

The Redis database number. Specify a value in the range `0` to `15`.

#### password

```
Syntax:  password <string>;
Default: —
Context: redis type only
```

The Redis authentication password. A Redis instance without a password is a valid configuration (e.g., local development, network-protected environments).

Setting authentication on Redis is recommended for production environments.

#### connect_timeout

```
Syntax:  connect_timeout <time>;
Default: 5000ms
Context: redis type only
```

Redis connection timeout (in milliseconds). Specify a value in the range `0ms` to `60000ms` (60 seconds). Values below 1000ms (1 second) may cause connection failures on slow networks.

#### command_timeout

```
Syntax:  command_timeout <time>;
Default: 5000ms
Context: redis type only
```

Redis command timeout (in milliseconds). Specify a value in the range `0ms` to `60000ms` (60 seconds). Values below 1000ms (1 second) may cause command failures on slow Redis servers.

**Memory Store configuration example**:
```nginx
oidc_session_store memory_store {
    type memory;
    size 10m;
    ttl 3600;
    prefix "oidc:session:";
}
```

**Redis Store configuration example**:
```nginx
oidc_session_store redis_store {
    type redis;
    hostname "redis.example.com";
    port 6379;
    database 0;
    password "your-redis-password";
    connect_timeout 5000ms;
    command_timeout 5000ms;
    ttl 7200;
    prefix "oidc:session:";
}
```

### oidc_base_url

```
Syntax:  oidc_base_url <url>;
Default: —
Context: http, server, location
```

Sets the base URL for redirect URIs.

**Use cases**:
- Constructing redirect URIs in reverse proxy environments
- URL translation when external and internal URLs differ

**Usage example**:
```nginx
server {
    listen 80;
    server_name internal.local;

    # Externally accessed via https://app.example.com
    oidc_base_url "https://app.example.com";

    auth_oidc my_provider;
}
```

This may need to be configured when using a reverse proxy or load balancer.

### oidc_status

```
Syntax:  oidc_status;
Default: —
Context: server, location
```

Configures an endpoint to display OIDC module status information.

**Output**:
- Shared memory statistics (size, max entries)
- State/Nonce, Metadata, and JWKS entry counts
- Session store settings (per provider)
- Metadata details (when cached)
- JWKS details (when cached)

**Usage example**:
```nginx
server {
    location /oidc_status {
        auth_oidc off;  # No authentication required for the status endpoint
        oidc_status;
        allow 10.0.0.0/8;  # Allow access only from the internal network
        deny all;
    }
}
```

For security reasons, access to the status endpoint should be properly restricted (e.g., IP address restrictions). In production environments, it is recommended to configure access restrictions using the `allow`/`deny` directives.

## Required Location Configuration (/_oidc_http_fetch)

`/_oidc_http_fetch` is an internal location used by the OIDC module to make external HTTP requests (metadata retrieval, token exchange, UserInfo retrieval, etc.). This location is **required** and OIDC authentication will not work properly if it is not configured correctly.

**Why it is required**:

The OIDC module needs to communicate with the external OIDC provider for the following operations:

1. **OpenID Connect Discovery**: Retrieving provider metadata (including resolving the `end_session_endpoint` URL for RP-Initiated Logout)
2. **JWKS (JSON Web Key Set)**: Retrieving public keys for token verification
3. **Token Exchange**: Exchanging authorization codes for tokens
4. **UserInfo**: Retrieving user information (when `userinfo on` is set)

In nginx, external HTTP requests are made using subrequests. The `/_oidc_http_fetch` location functions as an internal proxy for handling these subrequests.

### Basic Configuration

```nginx
server {
    location /_oidc_http_fetch {
        internal;

        # DNS resolver configuration (adjust for your environment)
        resolver 127.0.0.53 valid=300s;
        resolver_timeout 5s;

        # Disable authentication for this location
        auth_oidc off;

        # Dynamic proxy configuration (via module variables)
        proxy_pass $oidc_fetch_url;
        proxy_method $oidc_fetch_method;
        proxy_set_header Content-Type $oidc_fetch_content_type;
        proxy_set_header Content-Length $oidc_fetch_content_length;
        proxy_set_header Authorization $oidc_fetch_bearer;

        proxy_set_header Host $proxy_host;
        proxy_set_header Accept-Encoding "";

        # Pass request body
        proxy_pass_request_body on;

        # Keep responses in memory buffer
        proxy_max_temp_file_size 0;

        # Subrequest response buffer size
        # Set this when receiving large responses (e.g., JWKS)
        # subrequest_output_buffer_size 200k;

        # Use HTTP/1.1
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        # SSL verification settings
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 2;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_server_name on;
        proxy_ssl_name $proxy_host;

        # Timeout settings
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

### Configuration Parameter Details

**Required settings**:

- **internal**: Prevents direct external access and allows only internal subrequests (required)
- **resolver**: DNS resolver configuration (specify the appropriate DNS server for your environment)
  - `127.0.0.53`: Linux systems using systemd-resolved
  - `8.8.8.8` or `1.1.1.1`: Public DNS servers
  - `kube-dns.kube-system.svc.cluster.local`: Kubernetes environments
- **auth_oidc off**: Disables OIDC authentication for this location (required to prevent infinite loops)
- **proxy_pass $oidc_fetch_url**: Proxies to a dynamic URL via module variables (required)
- **proxy_method $oidc_fetch_method**: Sets the HTTP method dynamically via module variables (required)

**SSL settings**:

- **proxy_ssl_verify on**: Enables SSL certificate verification (recommended)

**Warning**: Setting `proxy_ssl_verify off` creates a risk of man-in-the-middle attacks. Always set this to `on` in production environments.

- **proxy_ssl_trusted_certificate**: CA certificate file for SSL verification
  - Debian/Ubuntu: `/etc/ssl/certs/ca-certificates.crt`
  - RHEL/CentOS/Fedora: `/etc/pki/tls/certs/ca-bundle.crt`
  - Alpine Linux: `/etc/ssl/certs/ca-certificates.crt`
- **proxy_ssl_server_name on**: Enables SNI (Server Name Indication) (recommended)
- **proxy_ssl_name $proxy_host**: Server name used for SSL verification (recommended)

**Timeout settings**:

- **proxy_connect_timeout**: Connection timeout to the OIDC provider (recommended: 10s to 30s)
- **proxy_send_timeout**: Request send timeout (recommended: 10s to 30s)
- **proxy_read_timeout**: Response read timeout (recommended: 10s to 30s)

If timeouts are too short, authentication may fail on slow OIDC providers or network environments.

**Other recommended settings**:

- **proxy_http_version 1.1**: Use HTTP/1.1 to enable keep-alive
- **proxy_max_temp_file_size 0**: Keep responses in memory buffer (do not write to disk)
- **subrequest_output_buffer_size**: Subrequest response buffer size (default: nginx default, recommended: `200k`). Configure this if you encounter "too big subrequest response" errors

### Environment-Specific Configuration Examples

#### Development Environment (Using Self-Signed Certificates)

```nginx
location /_oidc_http_fetch {
    internal;
    resolver 127.0.0.53 valid=300s;
    auth_oidc off;

    proxy_pass $oidc_fetch_url;
    proxy_method $oidc_fetch_method;
    proxy_set_header Content-Type $oidc_fetch_content_type;
    proxy_set_header Content-Length $oidc_fetch_content_length;
    proxy_set_header Authorization $oidc_fetch_bearer;

    proxy_set_header Host $proxy_host;
    proxy_set_header Accept-Encoding "";
    proxy_pass_request_body on;
    proxy_max_temp_file_size 0;

    # Subrequest response buffer size (enable as needed)
    # subrequest_output_buffer_size 200k;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    # Disable SSL verification for development (do not use in production)
    proxy_ssl_verify off;

    proxy_connect_timeout 10s;
    proxy_read_timeout 10s;
}
```

**Warning**: This configuration is for development environments only. Always enable SSL verification in production environments.

#### Production Environment (Full Configuration)

```nginx
location /_oidc_http_fetch {
    internal;

    # Production DNS resolver
    resolver 10.0.0.1 10.0.0.2 valid=300s;
    resolver_timeout 5s;

    auth_oidc off;

    proxy_pass $oidc_fetch_url;
    proxy_method $oidc_fetch_method;
    proxy_set_header Content-Type $oidc_fetch_content_type;
    proxy_set_header Content-Length $oidc_fetch_content_length;
    proxy_set_header Authorization $oidc_fetch_bearer;

    proxy_set_header Host $proxy_host;
    proxy_set_header Accept-Encoding "";
    proxy_pass_request_body on;
    proxy_max_temp_file_size 0;

    # Subrequest response buffer size (enable as needed)
    # subrequest_output_buffer_size 200k;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    # Always enable SSL verification in production
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    proxy_ssl_server_name on;
    proxy_ssl_name $proxy_host;

    # Production timeout settings
    proxy_connect_timeout 30s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;

    # Log settings (for debugging)
    access_log /var/log/nginx/oidc_http_fetch.log;
    error_log /var/log/nginx/oidc_http_fetch_error.log;
}
```

#### Kubernetes Environment

```nginx
location /_oidc_http_fetch {
    internal;

    # Kubernetes DNS resolver
    resolver kube-dns.kube-system.svc.cluster.local valid=300s;
    resolver_timeout 5s;

    auth_oidc off;

    proxy_pass $oidc_fetch_url;
    proxy_method $oidc_fetch_method;

    proxy_set_header Content-Type $oidc_fetch_content_type;
    proxy_set_header Content-Length $oidc_fetch_content_length;
    proxy_set_header Authorization $oidc_fetch_bearer;

    proxy_set_header Host $proxy_host;
    proxy_set_header Accept-Encoding "";
    proxy_pass_request_body on;
    proxy_max_temp_file_size 0;

    # Subrequest response buffer size (enable as needed)
    # subrequest_output_buffer_size 200k;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    proxy_ssl_server_name on;
    proxy_ssl_name $proxy_host;

    proxy_connect_timeout 30s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;
}
```

### Troubleshooting

**Note**: For detailed diagnostic steps and solutions for each issue, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md). The following is an overview of common issues related to `/_oidc_http_fetch`.

- **"could not be resolved"** (DNS resolution error): Configure `resolver` with a DNS server appropriate for your environment
- **"SSL certificate problem"** (SSL verification error): Check the `proxy_ssl_trusted_certificate` path and the CA certificate bundle
- **"upstream timed out"** (Timeout error): Increase `proxy_connect_timeout`, `proxy_send_timeout`, and `proxy_read_timeout`
- **"too big subrequest response"** (Subrequest response size error): Add `subrequest_output_buffer_size 200k;`

## Embedded Variables

The OIDC module provides variables for accessing authentication information. These variables can be used to set headers for backend applications or for conditional logic within the nginx configuration.

| Variable | Description |
|----------|-------------|
| [$oidc_id_token](#oidc_id_token) | OpenID Connect ID token (JWT) |
| [$oidc_access_token](#oidc_access_token) | OAuth 2.0 access token |
| [$oidc_claim_*](#oidc_claim_) | JWT claim values (prefix variable) |
| [$oidc_authenticated](#oidc_authenticated) | Authentication status flag |
| [$oidc_userinfo](#oidc_userinfo) | Information from the UserInfo endpoint (JSON) |
| [$oidc_fetch_url](#internal-fetch-variables) | Subrequest destination URL (internal use) |
| [$oidc_fetch_method](#internal-fetch-variables) | Subrequest HTTP method (internal use) |
| [$oidc_fetch_content_type](#internal-fetch-variables) | Subrequest Content-Type (internal use) |
| [$oidc_fetch_content_length](#internal-fetch-variables) | Subrequest Content-Length (internal use) |
| [$oidc_fetch_bearer](#internal-fetch-variables) | Subrequest Authorization header (internal use) |

### $oidc_id_token

OpenID Connect ID token (JWT).

**Value**:
- Authenticated: ID token string (JWT format)
- Unauthenticated: Empty (variable undefined)

**Usage example**:
```nginx
location / {
    proxy_pass http://backend;
    proxy_set_header X-ID-Token $oidc_id_token;
}
```

### $oidc_access_token

OAuth 2.0 access token.

**Value**:
- Authenticated: Access token string
- Unauthenticated: Empty (variable undefined)

**Usage example**:
```nginx
location /api {
    proxy_pass http://api_backend;
    proxy_set_header Authorization "Bearer $oidc_access_token";
}
```

### $oidc_claim_*

JWT claim values (prefix variable).

**Syntax**: `$oidc_claim_<claim_name>`

**Value**:
- Authenticated: The value of the specified claim
- Unauthenticated or claim does not exist: Empty (variable undefined)

**Common claims**:
- `$oidc_claim_sub`: Subject (user identifier)
- `$oidc_claim_email`: Email address
- `$oidc_claim_name`: Display name
- `$oidc_claim_given_name`: Given name
- `$oidc_claim_family_name`: Family name
- `$oidc_claim_preferred_username`: Preferred username

**Usage example**:
```nginx
location / {
    proxy_pass http://backend;
    proxy_set_header X-User-ID $oidc_claim_sub;
    proxy_set_header X-User-Email $oidc_claim_email;
    proxy_set_header X-User-Name $oidc_claim_name;
}
```

Claim availability depends on the OIDC provider and configured scopes.

When `userinfo on` is set, claims not present in the ID Token are supplemented from the UserInfo endpoint response (ID Token claims take priority).

### $oidc_authenticated

Authentication status flag.

**Value**:
- Authenticated: `"1"`
- Unauthenticated: `"0"`

**Usage example**:
```nginx
location / {
    auth_oidc_mode verify;  # Optional authentication

    # Notify backend of authentication status
    proxy_pass http://backend;
    proxy_set_header X-Authenticated $oidc_authenticated;

    # Conditional logic based on authentication status
    if ($oidc_authenticated = "1") {
        # Processing for authenticated users
    }
}
```

When using `auth_oidc_mode verify`, use this variable to make authentication decisions on the backend application side.

### $oidc_userinfo

Information retrieved from the UserInfo endpoint (JSON format).

**Value**:
- When `userinfo on` and authenticated: UserInfo JSON string
- Otherwise: Empty (variable undefined)

**Usage example**:
```nginx
oidc_provider my_provider {
    # ...
    userinfo on;  # Enable UserInfo retrieval
}

location / {
    proxy_pass http://backend;
    proxy_set_header X-UserInfo $oidc_userinfo;
}
```

This variable is only populated when `userinfo on` is configured.

### Internal Fetch Variables

The following variables are automatically set by the OIDC module during internal subrequests. They are used in the `/_oidc_http_fetch` location configuration. Users do not need to set these values directly.

#### $oidc_fetch_url

The destination URL for subrequests. Specify in `proxy_pass` to forward requests to the token endpoint, JWKS endpoint, UserInfo endpoint, etc.

#### $oidc_fetch_method

The HTTP method for subrequests (`GET` or `POST`). Specify in `proxy_method` to control the HTTP method.

#### $oidc_fetch_content_type

The Content-Type header value for subrequests. Specify in `proxy_set_header Content-Type`.

#### $oidc_fetch_content_length

The Content-Length header value for subrequests (explicitly set to `0` for GET requests). Specify directly in `proxy_set_header Content-Length` (empty string when no value is present).

#### $oidc_fetch_bearer

The Authorization header value in `"Bearer <token>"` format (set when accessing the UserInfo endpoint). Specify directly in `proxy_set_header Authorization` (empty string when no value is present).

### Usage Examples

**Example 1: Pass all authentication information to the backend**

```nginx
location / {
    proxy_pass http://backend;
    proxy_set_header X-ID-Token $oidc_id_token;
    proxy_set_header X-Access-Token $oidc_access_token;
    proxy_set_header X-User-ID $oidc_claim_sub;
    proxy_set_header X-User-Email $oidc_claim_email;
    proxy_set_header X-User-Name $oidc_claim_name;
    proxy_set_header X-UserInfo $oidc_userinfo;
}
```

**Example 2: Processing based on authentication status**

```nginx
server {
    auth_oidc my_provider;
    auth_oidc_mode verify;  # Optional authentication

    location / {
        # Only allow access for authenticated users
        if ($oidc_authenticated != "1") {
            return 403 "Authentication required";
        }

        proxy_pass http://backend;
        proxy_set_header X-User-ID $oidc_claim_sub;
    }

    location /public {
        # Allow access for unauthenticated users as well
        proxy_pass http://backend;
        proxy_set_header X-Authenticated $oidc_authenticated;
        proxy_set_header X-User-ID $oidc_claim_sub;
    }
}
```

## Session Store Selection Guidelines

| Item | Memory Store | Redis Store |
|------|-------------|-------------|
| **Recommended environment** | Single server | Multiple servers |
| **Session persistence** | None (lost on restart) | Yes |
| **Session sharing** | Not possible | Possible |
| **Configuration complexity** | Simple | Somewhat complex |
| **External dependencies** | None | Redis required |
| **Performance** | Fast (memory access) | Slightly slower (network access) |
| **Capacity limits** | Yes (shared memory size) | Depends on Redis capacity |
| **Production recommendation** | Low (single point of failure) | High |

**Selection guidelines**:

1. **Development/test environments**: Memory store is sufficient
2. **Single-server production**: Memory store is acceptable (but consider the impact of restarts)
3. **Multi-server production**: Redis store is required
4. **High availability required**: Redis store + Redis replication/cluster configuration

For practical configuration examples, see [EXAMPLES.md](EXAMPLES.md).

## Validation Rules

The nginx OIDC module validates configuration values and outputs errors or warnings for inappropriate settings.

### Errors (Startup Failure)

The following conditions cause errors and nginx will fail to start.

**oidc_session_store**:

Memory Store:
- `size` is 0 bytes
- `size` is less than 1MB

Redis Store:
- `hostname` is an empty string
- `port` is 0 or exceeds 65535
- `database` exceeds 15
- `connect_timeout` exceeds 60000ms (60 seconds)
- `command_timeout` exceeds 60000ms (60 seconds)

**oidc_provider**:
- `issuer` is not set
- `client_id` is not set
- `session_store` references a non-existent session store name
- Non-provider directives (`auth_oidc`, `oidc_base_url`, etc.) are written inside the `oidc_provider` block

### Warnings (Startup Succeeds, Log Output)

The following conditions produce warnings where nginx starts but warning messages are output to the log.

**oidc_session_store**:

Memory Store:
- `size` exceeds 1GB: "memory_size is very large (> 1GB). Consider using Redis for large-scale deployments"

Redis Store:
- `connect_timeout` is less than 1000ms: "redis_connect_timeout is very short (< 1 second). This may cause failures on slow networks/servers. Consider using at least 1000ms"
- `command_timeout` is less than 1000ms: "redis_command_timeout is very short (< 1 second). This may cause failures on slow networks/servers. Consider using at least 1000ms"

## Appendix

### Data Type Reference

#### Time Type

Time values can be specified with the following units:

- `ms`: Milliseconds
- `s`: Seconds (default, unit can be omitted)
- `m`: Minutes
- `h`: Hours
- `d`: Days

**Examples**:
```nginx
ttl 3600;                # 3600 seconds
ttl 1h;                  # 1 hour
connect_timeout 5000ms;  # 5000 milliseconds
session_timeout 8h;      # 8 hours
```

#### Size Type

Size values can be specified with the following units:

- (no unit): Bytes
- `k` or `K`: Kilobytes
- `m` or `M`: Megabytes
- `g` or `G`: Gigabytes

**Examples**:
```nginx
size 10m;    # 10 megabytes
size 1024k;  # 1024 kilobytes
size 1g;     # 1 gigabyte
```

#### String Type

String values can be enclosed in quotes (required when they contain spaces):

```nginx
issuer "https://accounts.google.com";
cookie_name oidc_session;
cookie_name "my oidc session";  # When containing spaces
```

#### Flag Type

Flag values are specified as `on` or `off`:

```nginx
pkce on;
logout_token_hint off;
```

### Error Code List

Main error codes output by the OIDC module:

| HTTP Status | Description | Cause |
|-------------|-------------|-------|
| 401 Unauthorized | Authentication failure | Invalid session, State verification failure, Token verification failure, Authorization code reuse detected |
| 500 Internal Server Error | Internal error | Session save failure, Metadata retrieval failure, Redis connection failure, etc. |
| 502 Bad Gateway | Gateway error | Connection failure to the OIDC provider |

## Related Documents

- [README.md](../README.md): Module overview
- [EXAMPLES.md](EXAMPLES.md): Quick start and practical configuration examples
- [INSTALL.md](INSTALL.md): Installation guide (prerequisites, build steps)
- [SECURITY.md](SECURITY.md): Security considerations (PKCE, HTTPS, cookie security, etc.)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): Troubleshooting (common issues, log checking)
- [JWT_SUPPORTED_ALGORITHMS.md](JWT_SUPPORTED_ALGORITHMS.md): JWT supported algorithms
- [COMMERCIAL_COMPATIBILITY.md](COMMERCIAL_COMPATIBILITY.md): Commercial version compatibility
- [nginx proxy_pass directive](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)
- [nginx resolver directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)
- [nginx SSL proxy settings](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify)
- [nginx subrequest_output_buffer_size directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#subrequest_output_buffer_size)
