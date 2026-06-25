use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== memory_max_size: accepts a value within bounds
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
        memory_max_size 1000000;
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

=== memory_max_size: accepts the lower bound
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
        memory_max_size 1;
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

=== memory_max_size: rejects a value above the upper bound
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
        memory_max_size 1000001;
    }
--- config
    location /t {
        return 200 ok;
    }
--- must_die
--- error_log
value must be between 1 and 1000000

=== memory_max_size: rejects zero (below the lower bound)
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    oidc_session_store bounds_store {
        type memory;
        size 10m;
        ttl 3600;
        memory_max_size 0;
    }
--- config
    location /t {
        return 200 ok;
    }
--- must_die
--- error_log
value must be between 1 and 1000000
