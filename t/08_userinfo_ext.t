use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== userinfo-ext: location mode normal response
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider-userinfo-ext.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_userinfo_ext_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /_custom_userinfo {
        internal;
        auth_oidc off;
        default_type application/json;
        return 200 '{"name":"Custom User","role":"admin"}';
    }

    location = /test-ext {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-ext
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:\{.*"name":"Custom User".*\}
user id is user-identifier

=== userinfo-ext: custom headers are passed to location
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider-userinfo-ext.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_userinfo_ext_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /_custom_userinfo {
        internal;
        auth_oidc off;
        default_type application/json;
        content_by_lua_block {
            local has_access = ngx.var.http_x_oidc_access_token ~= nil
                and ngx.var.http_x_oidc_access_token ~= ""
            local has_id = ngx.var.http_x_oidc_id_token ~= nil
                and ngx.var.http_x_oidc_id_token ~= ""
            local has_session = ngx.var.http_x_oidc_session_id ~= nil
                and ngx.var.http_x_oidc_session_id ~= ""
            ngx.say('{"has_access_token":' .. tostring(has_access)
                .. ',"has_id_token":' .. tostring(has_id)
                .. ',"has_session_id":' .. tostring(has_session) .. '}')
        }
    }

    location = /test-headers {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-headers
--- error_code: 200
--- response_body_like
userinfo:\{.*"has_access_token":true.*"has_id_token":true.*"has_session_id":true.*\}

=== userinfo-ext: response without sub claim is accepted
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider-userinfo-ext.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_userinfo_ext_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /_custom_userinfo {
        internal;
        auth_oidc off;
        default_type application/json;
        return 200 '{"extra_data":"no_sub_here"}';
    }

    location = /test-nosub {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-nosub
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:\{.*"extra_data":"no_sub_here".*\}

=== userinfo-ext: HTTP error from location continues without userinfo
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider-userinfo-ext.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_userinfo_ext_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /_custom_userinfo {
        internal;
        auth_oidc off;
        return 500 'Internal Server Error';
    }

    location = /test-error {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
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

=== userinfo-ext: non-JSON response continues without userinfo
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider-userinfo-ext.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_userinfo_ext_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /_custom_userinfo {
        internal;
        auth_oidc off;
        default_type text/plain;
        return 200 'not json';
    }

    location = /test-nonjson {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
            ngx.status = res and res.status or 500
            ngx.print(res and res.body or "")
        }
    }
--- request
GET /test-nonjson
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.+
access-token:.+
userinfo:
user id is user-identifier
