use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== status
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-test.conf;
--- request eval
[
  "GET /oidc_status",
  "GET /test",
  "GET /oidc_status",
]
--- error_code eval
[
  200,
  200,
  200
]
--- response_body_like eval
[
  "OIDC Shared Memory Status
Shared memory size: 8388608 bytes
Shared memory max entries: 1024

State/Nonce entries: 0
Metadata entries: 0
JWKS entries: 0

Session Store Configuration:
  Provider: test_provider
    Cookie name: \\(default\\)
    Session timeout: 28800 seconds
    Session store type: memory_store",
  "authenticate:1
id-token:.*
access-token:.*
userinfo:\\{.*\\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256",
  "qr|OIDC Shared Memory Status
Shared memory size: 8388608 bytes
Shared memory max entries: 1024

State/Nonce entries: 0
Metadata entries: 1
JWKS entries: 1

Session Store Configuration:
  Provider: test_provider
    Cookie name: \\(default\\)
    Session timeout: 28800 seconds
    Session store type: memory_store

Metadata:
  Issuer: http://127.0.0.1:8888
    Authorization endpoint: http://127.0.0.1:8888/authorize
    Token endpoint: http://127.0.0.1:8888/access_token
    JWKS URI: http://127.0.0.1:8888/jwks
    Userinfo endpoint: http://127.0.0.1:8888/userinfo
    End session endpoint: http://127.0.0.1:8888/end_session
    Fetched: .*
    Expires: .*

JWKS:
  URI: http://127.0.0.1:8888/jwks
    Size: 4949 bytes
    Fetched: .*
    Expires: .*
    Data:
      \\{
        \"keys\" : \\[
        .*
        \\]
      \\}|s"
]
