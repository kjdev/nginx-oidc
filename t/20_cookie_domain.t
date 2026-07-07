use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== cookie-domain: temporary cookie carries configured Domain attribute
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    oidc_session_store domain_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store domain_store;
        userinfo on;
        cookie_domain ".example.com";
    }
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
Set-Cookie: NGX_OIDC_SESSION_CALLBACK=test_provider:.*; Path=/; HttpOnly; SameSite=Lax; Max-Age=\d+; Domain=\.example\.com

=== cookie-domain: no Domain attribute when cookie_domain is unset
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    oidc_session_store nodomain_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store nodomain_store;
        userinfo on;
    }
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
Set-Cookie: NGX_OIDC_SESSION_CALLBACK=test_provider:[^;]*; Path=/; HttpOnly; SameSite=Lax; Max-Age=\d+$
