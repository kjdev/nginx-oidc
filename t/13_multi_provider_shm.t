use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== multi-provider: distinct issuers do not crash the metadata shm rbtree
# Two providers with distinct issuer strings create two separate nodes in the
# metadata shared-memory rbtree. The second insertion goes through the custom
# ngx_rbtree_insert() callback (the first insertion into an empty tree is
# handled directly by ngx_rbtree_insert). A node whose parent/left/right links
# are left uninitialized makes the rebalancing step crash the worker, so the
# second auth request would fail without producing a redirect.
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-multi.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;

    location / {
        auth_oidc off;
        return 200 "root";
    }

    location = /a {
        auth_oidc multi_provider_a;
        proxy_pass http://app;
    }

    location = /b {
        auth_oidc multi_provider_b;
        proxy_pass http://app;
    }
--- request eval
["GET /a", "GET /b"]
--- error_code eval
[302, 302]
--- response_headers_like eval
[
"Location: http://127.0.0.1:8888/authorize\\?.+",
"Location: http://127.0.0.2:8888/authorize\\?.+",
]
--- no_error_log
[alert]
[crit]
[emerg]

=== multi-provider: session cookie from provider a is rejected by provider b (GHSA-598x-mpff-56vc)
# multi_provider_a and multi_provider_b share one oidc_session_store and (with
# no cookie_name configured) the same default cookie name, so a session
# cookie obtained by logging into provider a is sent as-is on a request to
# provider b's location. Before the session-store key included a
# provider-identifying element, provider b's lookup found provider a's
# session by session_id alone and treated the request as authenticated
# without ever contacting provider b's authorization server.
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-multi.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;

    location = /a {
        auth_oidc multi_provider_a;
        proxy_pass http://app;
    }

    location = /b {
        auth_oidc multi_provider_b;
        proxy_pass http://app;
    }

    location = /test-cross-provider-replay {
        auth_oidc off;
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            -- Log in against provider a.
            local res, err = httpc:request_uri("http://127.0.0.1:1984/a", {
                follow_redirects = false,
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            local temp_cookie = res.headers["Set-Cookie"]
            local authorize_url = res.headers["Location"]

            res, err = httpc:request_uri(authorize_url, {
                follow_redirects = false,
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            local callback_url = res.headers["Location"]

            res, err = httpc:request_uri(callback_url, {
                headers = { ["Cookie"] = temp_cookie },
                follow_redirects = false,
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            -- res now carries provider a's permanent session cookie.
            local session_cookie = res.headers["Set-Cookie"]

            -- Replay provider a's session cookie against provider b's
            -- location.
            res, err = httpc:request_uri("http://127.0.0.1:1984/b", {
                headers = { ["Cookie"] = session_cookie },
                follow_redirects = false,
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            ngx.status = res.status

            local location = res.headers["Location"]
            if location then
                ngx.header["Location"] = location
            end

            ngx.print("status=" .. res.status)
        }
    }
--- request
GET /test-cross-provider-replay
--- error_code: 302
--- response_headers_like
Location: http://127.0.0.2:8888/authorize\?.+
--- response_body_like: status=302
--- no_error_log
[alert]
[crit]
[emerg]
