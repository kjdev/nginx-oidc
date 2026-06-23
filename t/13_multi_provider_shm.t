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
