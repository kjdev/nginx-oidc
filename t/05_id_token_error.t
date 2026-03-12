use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== id-token-error: invalid issuer
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
            oidc.set_state(httpc, "id_token", "invalid_iss")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: invalid audience
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
            oidc.set_state(httpc, "id_token", "invalid_aud")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: expired token
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
            oidc.set_state(httpc, "id_token", "expired")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: not yet valid
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
            oidc.set_state(httpc, "id_token", "not_yet_valid")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: invalid signature
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
            oidc.set_state(httpc, "id_token", "invalid_signature")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: invalid nonce
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
            oidc.set_state(httpc, "id_token", "invalid_nonce")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: missing nonce
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
            oidc.set_state(httpc, "id_token", "missing_nonce")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: invalid at_hash
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
            oidc.set_state(httpc, "id_token", "invalid_at_hash")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: missing issuer
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
            oidc.set_state(httpc, "id_token", "missing_iss")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: missing subject
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
            oidc.set_state(httpc, "id_token", "missing_sub")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500

=== id-token-error: missing audience
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
            oidc.set_state(httpc, "id_token", "missing_aud")
            local res = oidc.flow_to_callback(httpc)
            oidc.clear_state(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-error
--- error_code: 500
