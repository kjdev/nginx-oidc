use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== bearer: no Authorization header falls back to cookie flow
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer&auth=none
--- error_code: 302
--- response_headers_like
Location: http://127\.0\.0\.1:8888/authorize\?.*

=== bearer: non-Bearer schemes fall back to cookie flow
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request eval
[
  "GET /bearer-helper?path=/bearer&auth=basic",
  "GET /bearer-helper?path=/bearer&auth=malformed"
]
--- error_code eval
[302, 302]

=== bearer: empty credentials return 401 invalid_request
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request eval
[
  "GET /bearer-helper?path=/bearer&auth=empty",
  "GET /bearer-helper?path=/bearer&auth=empty-space",
  "GET /bearer-helper?path=/bearer&auth=no-separator"
]
--- error_code eval
[401, 401, 401]
--- response_headers_like eval
[
  "WWW-Authenticate: Bearer error=\"invalid_request\".*",
  "WWW-Authenticate: Bearer error=\"invalid_request\".*",
  "WWW-Authenticate: Bearer error=\"invalid_request\".*"
]

=== bearer: malformed or forged JWT returns 401 invalid_token
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request eval
[
  "GET /bearer-helper?path=/bearer&auth=invalid",
  "GET /bearer-helper?path=/bearer&auth=bad-signature"
]
--- error_code eval
[401, 401]
--- response_headers_like eval
[
  "WWW-Authenticate: Bearer error=\"invalid_token\".*",
  "WWW-Authenticate: Bearer error=\"invalid_token\".*"
]

=== bearer: auth_oidc_bearer not configured ignores Bearer header
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/no-bearer&auth=invalid
--- error_code: 302

=== bearer: auth_oidc_mode verify with bearer on rejects invalid token
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer-verify&auth=invalid
--- error_code: 401

=== bearer: auth_oidc_mode verify with bearer off does not reject invalid token
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/no-bearer-verify&auth=invalid
--- error_code: 200
--- response_body_like
authenticate:0

=== bearer: logout URI takes priority, invalid Bearer does not cause 401
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/logout&auth=invalid&cookie=valid
--- error_code: 302
--- response_headers_like
Location: http://127\.0\.0\.1:8888/end_session\?.*

=== bearer: valid token without cookie authenticates and exposes claims only
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer&auth=valid
--- error_code: 200
--- response_body_like
authenticate:1
id-token:
access-token:
userinfo:
user id is user-identifier

=== bearer: audience explicit match succeeds, mismatch is rejected
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request eval
[
  "GET /bearer-helper?path=/bearer-aud-test&auth=valid",
  "GET /bearer-helper?path=/bearer-aud-other&auth=valid"
]
--- error_code eval
[200, 401]

=== bearer: valid cookie with invalid Bearer is rejected without fallback
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer&auth=invalid&cookie=valid
--- error_code: 401

=== bearer: valid cookie with valid Bearer prefers the Bearer path
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer&auth=valid&cookie=valid
--- error_code: 200
--- response_body_like
authenticate:1
id-token:
access-token:
userinfo:
user id is user-identifier

=== bearer: auth_oidc_mode verify with valid token authenticates
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer-verify&auth=valid
--- error_code: 200
--- response_body_like
authenticate:1

=== bearer: ID token replayed as Bearer access token is rejected
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-helper?path=/bearer&auth=id-token
--- error_code: 401
--- response_headers_like
WWW-Authenticate: Bearer error="invalid_token".*

=== bearer: auth_oidc_bearer_typ accepts a matching typ header
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-typ-helper?state=typ_at_jwt
--- error_code: 200

=== bearer: auth_oidc_bearer_typ rejects a mismatched typ header
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-bearer.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_bearer_provider;
    include $TEST_NGINX_CONF_DIR/location-bearer.conf;
--- request
GET /bearer-typ-helper
--- error_code: 401
--- response_headers_like
WWW-Authenticate: Bearer error="invalid_token".*
