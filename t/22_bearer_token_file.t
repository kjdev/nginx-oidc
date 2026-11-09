use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== bearer_token_file: token is sent to discovery and jwks only
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    init_by_lua_block {
        local f = assert(io.open("/tmp/oidc_test_bearer_token", "w"))
        f:write("  token-A\n")
        f:close()
        f = assert(io.open("/tmp/oidc_test_fetch.log", "w"))
        f:close()
    }
    log_format fetchfmt '$oidc_fetch_url => [$oidc_fetch_bearer]';
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token discovery jwks;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    location /_oidc_http_fetch {
        internal;
        auth_oidc off;
        log_subrequest on;
        access_log /tmp/oidc_test_fetch.log fetchfmt;
        proxy_bind 127.0.0.1;
        proxy_pass $oidc_fetch_url;
        proxy_method $oidc_fetch_method;
        proxy_set_header Content-Type $oidc_fetch_content_type;
        proxy_set_header Content-Length $oidc_fetch_content_length;
        proxy_set_header Authorization $oidc_fetch_bearer;
        proxy_set_header Host $proxy_host;
        proxy_set_header Accept-Encoding "";
        proxy_pass_request_body on;
        proxy_max_temp_file_size 0;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        subrequest_output_buffer_size 200k;
    }
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
            local f = assert(io.open("/tmp/oidc_test_fetch.log", "r"))
            local log = f:read("*a")
            f:close()
            ngx.say("status:", res and res.status or "nil")
            ngx.print(log)
        }
    }
--- request
GET /test
--- error_code: 200
--- response_body_like
(?s)status:200\n.*/\.well-known/openid-configuration => \[Bearer token-A\]\n.*/jwks => \[Bearer token-A\]\n.*/access_token => \[-\]

=== bearer_token_file: unreadable token file fails the fetch
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token_missing;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;
--- request
GET /
--- error_code: 500
--- error_log
oidc_token_file:

=== bearer_token_file: empty token file fails the fetch
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    init_by_lua_block {
        local f = assert(io.open("/tmp/oidc_test_bearer_token_empty", "w"))
        f:write("\n")
        f:close()
    }
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token_empty discovery;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;
--- request
GET /
--- error_code: 500
--- error_log
is empty

=== bearer_token_file: target not covered does not read the file
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token_missing jwks;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;
--- request
GET /
--- error_code: 302
--- no_error_log
oidc_token_file:

=== bearer_token_file: rejects an unknown target
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token userinfo;
    }
--- config
    location /t {
        return 200 ok;
    }
--- must_die
--- error_log
invalid target "userinfo" in "bearer_token_file" directive

=== bearer_token_file: rejects a missing argument
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file;
    }
--- config
    location /t {
        return 200 ok;
    }
--- must_die
--- error_log
invalid number of arguments in "bearer_token_file" directive

=== bearer_token_file: jwks_uri on another origin is refused without sending the token
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    init_by_lua_block {
        local f = assert(io.open("/tmp/oidc_test_bearer_token", "w"))
        f:write("token-A\n")
        f:close()
        f = assert(io.open("/tmp/oidc_test_fetch.log", "w"))
        f:close()
    }
    log_format fetchfmt '$oidc_fetch_url => [$oidc_fetch_bearer]';
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        config_url "http://127.0.0.1:1984/meta";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token discovery jwks;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    location /_oidc_http_fetch {
        internal;
        auth_oidc off;
        log_subrequest on;
        access_log /tmp/oidc_test_fetch.log fetchfmt;
        proxy_bind 127.0.0.1;
        proxy_pass $oidc_fetch_url;
        proxy_method $oidc_fetch_method;
        proxy_set_header Content-Type $oidc_fetch_content_type;
        proxy_set_header Content-Length $oidc_fetch_content_length;
        proxy_set_header Authorization $oidc_fetch_bearer;
        proxy_set_header Host $proxy_host;
        proxy_set_header Accept-Encoding "";
        proxy_pass_request_body on;
        proxy_max_temp_file_size 0;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        subrequest_output_buffer_size 200k;
    }
    location = /meta {
        auth_oidc off;
        content_by_lua_block {
            local res = require("resty.http").new():request_uri(
                "http://127.0.0.1:8888/.well-known/openid-configuration")
            local body = res.body:gsub('"jwks_uri":"[^"]*"',
                                       '"jwks_uri":"http:\\/\\/localhost:8888\\/jwks"')
            ngx.header["Content-Type"] = "application/json"
            ngx.print(body)
        }
    }
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            pcall(oidc.full_flow, httpc)
            local f = assert(io.open("/tmp/oidc_test_fetch.log", "r"))
            local log = f:read("*a")
            f:close()
            ngx.say("jwks_sent:", log:find("/jwks", 1, true) and "yes" or "no")
        }
    }
--- request
GET /test
--- error_code: 200
--- response_body
jwks_sent:no
--- error_log
refusing to send bearer token to "http://localhost:8888/jwks"

=== bearer_token_file: config_url origin is allowed for jwks_uri
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    init_by_lua_block {
        local f = assert(io.open("/tmp/oidc_test_bearer_token", "w"))
        f:write("token-A\n")
        f:close()
        f = assert(io.open("/tmp/oidc_test_fetch.log", "w"))
        f:close()
    }
    log_format fetchfmt '$oidc_fetch_url => [$oidc_fetch_bearer]';
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        config_url "http://127.0.0.1:1984/meta";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token discovery jwks;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    location /_oidc_http_fetch {
        internal;
        auth_oidc off;
        log_subrequest on;
        access_log /tmp/oidc_test_fetch.log fetchfmt;
        proxy_bind 127.0.0.1;
        proxy_pass $oidc_fetch_url;
        proxy_method $oidc_fetch_method;
        proxy_set_header Content-Type $oidc_fetch_content_type;
        proxy_set_header Content-Length $oidc_fetch_content_length;
        proxy_set_header Authorization $oidc_fetch_bearer;
        proxy_set_header Host $proxy_host;
        proxy_set_header Accept-Encoding "";
        proxy_pass_request_body on;
        proxy_max_temp_file_size 0;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        subrequest_output_buffer_size 200k;
    }
    location = /meta {
        auth_oidc off;
        content_by_lua_block {
            local res = require("resty.http").new():request_uri(
                "http://127.0.0.1:8888/.well-known/openid-configuration")
            local body = res.body:gsub('"jwks_uri":"[^"]*"',
                                       '"jwks_uri":"http:\\/\\/127.0.0.1:1984\\/jwks_proxy"')
            ngx.header["Content-Type"] = "application/json"
            ngx.print(body)
        }
    }
    location = /jwks_proxy {
        auth_oidc off;
        proxy_pass http://127.0.0.1:8888/jwks;
        proxy_set_header Host 127.0.0.1:8888;
    }
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            local res = oidc.full_flow(httpc)
            local f = assert(io.open("/tmp/oidc_test_fetch.log", "r"))
            local log = f:read("*a")
            f:close()
            ngx.say("status:", res and res.status or "nil")
            ngx.print(log)
        }
    }
--- request
GET /test
--- error_code: 200
--- response_body_like
(?s)status:200\n.*/meta => \[Bearer token-A\]\n.*/jwks_proxy => \[Bearer token-A\]
--- no_error_log
refusing to send bearer token

=== bearer_token_file: unterminated IPv6 host is not treated as same origin
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    init_by_lua_block {
        local f = assert(io.open("/tmp/oidc_test_bearer_token", "w"))
        f:write("token-A\n")
        f:close()
        f = assert(io.open("/tmp/oidc_test_fetch.log", "w"))
        f:close()
    }
    log_format fetchfmt '$oidc_fetch_url => [$oidc_fetch_bearer]';
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://[::1:8888";
        config_url "http://127.0.0.1:1984/meta";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
        bearer_token_file /tmp/oidc_test_bearer_token jwks;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    location /_oidc_http_fetch {
        internal;
        auth_oidc off;
        log_subrequest on;
        access_log /tmp/oidc_test_fetch.log fetchfmt;
        proxy_bind 127.0.0.1;
        proxy_pass $oidc_fetch_url;
        proxy_method $oidc_fetch_method;
        proxy_set_header Content-Type $oidc_fetch_content_type;
        proxy_set_header Content-Length $oidc_fetch_content_length;
        proxy_set_header Authorization $oidc_fetch_bearer;
        proxy_set_header Host $proxy_host;
        proxy_set_header Accept-Encoding "";
        proxy_pass_request_body on;
        proxy_max_temp_file_size 0;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        subrequest_output_buffer_size 200k;
    }
    location = /meta {
        auth_oidc off;
        content_by_lua_block {
            local res = require("resty.http").new():request_uri(
                "http://127.0.0.1:8888/.well-known/openid-configuration")
            local body = res.body:gsub('"issuer":"[^"]*"',
                                       '"issuer":"http://[::1:8888"')
            body = body:gsub('"jwks_uri":"[^"]*"',
                             '"jwks_uri":"http:\\/\\/[::1:8888\\/jwks"')
            ngx.header["Content-Type"] = "application/json"
            ngx.print(body)
        }
    }
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /test {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local httpc = require("resty.http").new()
            pcall(oidc.full_flow, httpc)
            local f = assert(io.open("/tmp/oidc_test_fetch.log", "r"))
            local log = f:read("*a")
            f:close()
            ngx.say("jwks_sent:", log:find("/jwks", 1, true) and "yes" or "no")
        }
    }
--- request
GET /test
--- error_code: 200
--- response_body
jwks_sent:no
--- error_log
refusing to send bearer token to "http://[::1:8888/jwks"
