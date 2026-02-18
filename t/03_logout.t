use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== logout: rp
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-logout.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_logout_provider;
    include $TEST_NGINX_CONF_DIR/location-test.conf;

    location = /test-logout {
        auth_oidc off;
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            local dict = ngx.shared.cookie_dict
            local cookie = dict:get("authenticated")

            local res, err = httpc:request_uri("http://127.0.0.1:1984/logout", {
                follow_redirects = false,
                headers = { ["Cookie"] = cookie },
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
--- request eval
[
  "GET /test",
  "GET /test-logout"
]
--- error_code eval
[
  200,
  302
]
--- response_body_like eval
[
  "authenticate:1
id-token:.*
access-token:.*
userinfo:\\{.*\\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256",
  ""
]
--- response_headers_like eval
[
  "",
  "Set-Cookie: NGX_OIDC_SESSION=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=.*
Location: http://127\.0\.0\.1:8888/end_session\\?client_id=test&post_logout_redirect_uri=http://127\.0\.0\.1:1984/hello"
]

=== logout: complete
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-logout.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_logout_provider;
    include $TEST_NGINX_CONF_DIR/location-test.conf;

    location = /test-logout {
        auth_oidc off;
        content_by_lua_block {
            local http = require "resty.http"
            local httpc = http.new()

            local dict = ngx.shared.cookie_dict
            local cookie = dict:get("authenticated")

            local res, err = httpc:request_uri("http://127.0.0.1:1984/logout", {
                follow_redirects = false,
                headers = { ["Cookie"] = cookie },
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            local url = res.headers["Location"]

            res, err = httpc:request_uri(url, {
                follow_redirects = false
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            url = res.headers["Location"]

            res, err = httpc:request_uri(url, {
                follow_redirects = false
            })
            if not res then
                ngx.log(ngx.ERR, "Failed: ", err)
                return
            end

            ngx.status = res.status

            ngx.print(res.body)
        }
    }
--- request eval
[
  "GET /test",
  "GET /test-logout"
]
--- error_code eval
[
  200,
  200
]
--- response_body_like eval
[
  "authenticate:1
id-token:.*
access-token:.*
userinfo:\\{.*\\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256",
  "Hello"
]
