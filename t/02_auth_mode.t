use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== auth_mode: verify
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
  "GET /test-verify",
  "GET /test",
  "GET /test-verify"
]
--- error_code eval
[
  "200",
  "200",
  "200"
]
--- response_body_like eval
[
  "authenticate:0
id-token:
access-token:
userinfo:
user id is 
user email is 
user algorithm is ",
  "authenticate:1
id-token:.*
access-token:.*
userinfo:\\{.*\\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256",
  "authenticate:1
id-token:.*
access-token:.*
userinfo:\\{.*\\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256"
]
