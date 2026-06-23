use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== store-memory-evict: re-authentication succeeds when the store is at capacity
# Drive many sequential logins against a memory store whose max entry count
# (memory_max_size 32) is small enough to fill after a few completed logins.
# Once full, every new login must evict something. The active authentication's
# state/nonce/code_verifier have the earliest expiration of all entries, so an
# expiration-ordered eviction would drop the just-created state and the
# callback would fail with 401. LRU eviction keeps the in-flight entries and
# evicts idle older sessions instead, so every login keeps succeeding.
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-evict.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /run-evict {
        auth_oidc off;
        content_by_lua_block {
            local oidc = require "oidc_test"
            local http = require "resty.http"

            local total = 15
            local ok = 0

            for i = 1, total do
                local httpc = http.new()
                local res = oidc.full_flow(httpc)
                if res and res.status == 200 and res.body
                    and res.body:find("user id is user-identifier", 1, true)
                then
                    ok = ok + 1
                end
            end

            ngx.status = 200
            ngx.say("logins_ok:" .. ok .. " total:" .. total)
        }
    }
--- request
GET /run-evict
--- timeout: 120
--- error_code: 200
--- response_body
logins_ok:15 total:15
