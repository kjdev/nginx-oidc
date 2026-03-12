use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== userinfo-error: 401 unauthorized
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
            oidc.set_state(httpc, "userinfo", "error_401")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: 403 forbidden
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
            oidc.set_state(httpc, "userinfo", "error_403")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: 500 server error
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
            oidc.set_state(httpc, "userinfo", "error_500")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: 503 service unavailable
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
            oidc.set_state(httpc, "userinfo", "error_503")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: invalid json
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
            oidc.set_state(httpc, "userinfo", "invalid_json")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: missing sub
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
            oidc.set_state(httpc, "userinfo", "missing_sub")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: empty response
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
            oidc.set_state(httpc, "userinfo", "empty_response")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier

=== userinfo-error: sub mismatch
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
            oidc.set_state(httpc, "id_token", "invalid_sub")
            local res = oidc.full_flow(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500
