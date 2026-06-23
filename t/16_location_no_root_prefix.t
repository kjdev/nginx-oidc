use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== no root prefix: internal /_oidc_http_fetch is still found at config time
# A server that configures the internal /_oidc_http_fetch location and only
# exact locations, WITHOUT a root prefix "location /". The static location tree
# is then built so that node names retain their leading '/', which the previous
# implementation could not match because it stripped the leading '/' from the
# search name. The result was a spurious startup failure:
#   emerg: OIDC module requires internal location "/_oidc_http_fetch" ...
# This test asserts nginx starts (no emerg) and serves an auth_oidc-off
# location; it does not need the stub IdP because the authenticated location
# (/a) is never requested.
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    include $TEST_NGINX_CONF_DIR/test-provider-multi.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;

    location = /ping {
        auth_oidc off;
        return 200 "pong";
    }

    location = /a {
        auth_oidc multi_provider_a;
        return 200 "a";
    }
--- request
GET /ping
--- error_code: 200
--- response_body chomp
pong
--- no_error_log
[alert]
[crit]
[emerg]
