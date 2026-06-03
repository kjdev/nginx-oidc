use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== relative-redirect-uri: auth request builds absolute redirect_uri
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-relative.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-test.conf;
--- request
GET /
--- error_code: 302
--- response_headers_like
Set-Cookie: NGX_OIDC_SESSION_CALLBACK=test_provider:.*; Path=/; HttpOnly; SameSite=Lax; Max-Age=600
Location: http://127.0.0.1:8888/authorize\?response_type=code&client_id=test&redirect_uri=http://localhost:1984/oidc_callback&scope=openid&state=.+&nonce=.+&code_challenge=.+&code_challenge_method=S256

=== relative-redirect-uri: complete flow
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-relative.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-test.conf;
--- request
GET /test
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:\{.+\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256
