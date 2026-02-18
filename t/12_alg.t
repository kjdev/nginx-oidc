use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== alg: rs256
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_rs256_provider;
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

=== alg: rs384
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_rs384_provider;
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
user algorithm is RS384

=== alg: rs512
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_rs512_provider;
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
user algorithm is RS512

=== alg: ps256
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_ps256_provider;
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
user algorithm is PS256

=== alg: ps384
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_ps384_provider;
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
user algorithm is PS384

=== alg: ps512
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_ps512_provider;
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
user algorithm is PS512

=== alg: es256
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_es256_provider;
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
user algorithm is ES256

=== alg: es256k
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_es256k_provider;
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
user algorithm is ES256K

=== alg: es384
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_es384_provider;
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
user algorithm is ES384

=== alg: es512
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_es512_provider;
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
user algorithm is ES512

=== alg: ed25519
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_ed25519_provider;
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
user algorithm is Ed25519

=== alg: ed448
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-alg.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_ed448_provider;
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
user algorithm is Ed448
