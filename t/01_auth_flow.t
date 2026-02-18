use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== auth-flow: auth request
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
--- request
GET /
--- error_code: 302
--- response_headers_like
Set-Cookie: NGX_OIDC_SESSION_CALLBACK=test_provider:.*; Path=/; HttpOnly; SameSite=Lax; Max-Age=600
Location: http://127.0.0.1:8888/authorize\?response_type=code&client_id=test&redirect_uri=http://127.0.0.1:1984/oidc_callback&scope=openid&state=.+&nonce=.+&code_challenge=.+&code_challenge_method=S256

=== auth-flow: token request
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

    location = /test-token-request {
        auth_oidc off;
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            local res, err = httpc:request_uri("http://127.0.0.1:1984/", {
                follow_redirects = false,
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            local cookie = res.headers["Set-Cookie"]
            local url = res.headers["Location"]

            res, err = httpc:request_uri(url, {
                follow_redirects = false,
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            local url = res.headers["Location"]

            res, err = httpc:request_uri(url, {
                headers = { ["Cookie"] = cookie },
                follow_redirects = false
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            ngx.status = res.status

            local forward_headers = { "Content-Type", "Location", "Set-Cookie" }
            for _, h in ipairs(forward_headers) do
                local val = res.headers[h]
                if val then
                    ngx.header[h] = val
                end
            end

            ngx.print(res.body)
        }
    }
--- request
GET /test-token-request
--- error_code: 302
--- response_headers_like
Set-Cookie: NGX_OIDC_SESSION=.*; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800, NGX_OIDC_SESSION_CALLBACK=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=.*
Location: http://127.0.0.1:1984/

=== auth-flow: complete
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
