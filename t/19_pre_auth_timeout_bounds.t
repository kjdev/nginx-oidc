use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== pre_auth_timeout: accepts a value within bounds
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider bounds_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        session_store bounds_store;
        pre_auth_timeout 600;
    }
--- config
    location /t {
        return 200 ok;
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
ok

=== pre_auth_timeout: accepts the lower bound
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider bounds_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        session_store bounds_store;
        pre_auth_timeout 1;
    }
--- config
    location /t {
        return 200 ok;
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
ok

=== pre_auth_timeout: accepts the upper bound
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider bounds_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        session_store bounds_store;
        pre_auth_timeout 3600;
    }
--- config
    location /t {
        return 200 ok;
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
ok

=== pre_auth_timeout: rejects a value above the upper bound
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider bounds_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        session_store bounds_store;
        pre_auth_timeout 3601;
    }
--- config
    location /t {
        return 200 ok;
    }
--- must_die
--- error_log
value must be between 1 and 3600

=== pre_auth_timeout: rejects zero (below the lower bound)
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider bounds_provider {
        issuer "http://127.0.0.1:8888";
        client_id "test";
        session_store bounds_store;
        pre_auth_timeout 0;
    }
--- config
    location /t {
        return 200 ok;
    }
--- must_die
--- error_log
value must be between 1 and 3600
