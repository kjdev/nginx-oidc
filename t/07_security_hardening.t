use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== security: hmac algorithm rejection
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test-error {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            oidc.set_state(httpc, "id_token", "hmac_alg")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500
--- error_log
HMAC algorithm

=== security: jwe format rejection
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test-error {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            oidc.set_state(httpc, "id_token", "jwe_format")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500
--- error_log
more than 3 segments

=== security: empty header segment rejection
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test-error {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            oidc.set_state(httpc, "id_token", "empty_header")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500
--- error_log
empty header

=== security: empty payload segment rejection
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test-error {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            oidc.set_state(httpc, "id_token", "empty_payload")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500
--- error_log
empty payload
