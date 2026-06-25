use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== store-memory-cleanup: cleanup_expired reclaims head-side expired entries
# Regression guard for the full-queue scan in cleanup_expired().
#
# The LRU queue is ordered by recency of use, not by expiration. A bounded
# tail scan (the pre-fix behaviour, last 128 nodes) cannot reach expired
# entries that sit near the LRU head. This test creates far more than 128
# pre-auth entries, lets them all expire, triggers a single deterministic
# cleanup, then asserts every entry was reclaimed.
#
# With the full-queue scan the store drains to 0. If cleanup is ever reverted
# to a bounded tail scan, the head-side entries survive (count stays well above
# 0) and this test fails.
#
# Mechanics:
#  - The provider has no explicit session_store, so pre-auth entries, the
#    NULL-store cleanup and /status all share the default shared memory zone
#    (8MB, max 1024 entries: large enough to avoid eviction at ~200 entries).
#  - pre_auth_timeout 1 makes state/nonce/code_verifier/orig_uri expire in 1s.
#  - oidc_cleanup_interval 1000000 on "/" effectively disables the random
#    cleanup while entries are being created.
#  - /trigger-cleanup runs in verify mode (no entry creation) with
#    oidc_cleanup_interval 1, so a single request fires exactly one cleanup.
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-cleanup.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_provider;
    auth_oidc_mode require;
    oidc_cleanup_interval 1000000;
    include $TEST_NGINX_CONF_DIR/location-proxy.conf;

    location = /trigger-cleanup {
        # verify mode creates no pre-auth entries; the OIDC access-phase
        # handler still runs the cleanup. A content_by_lua body (content phase)
        # is used instead of "return" so the access phase is not bypassed.
        auth_oidc test_provider;
        auth_oidc_mode verify;
        oidc_cleanup_interval 1;
        content_by_lua_block { ngx.exit(204) }
    }

    location = /oidc_status {
        auth_oidc off;
        oidc_status;
    }

    location = /run-cleanup {
        auth_oidc off;
        content_by_lua_block {
            local http = require "resty.http"
            local app_url = "http://127.0.0.1:1984"

            -- Create many pre-auth entries via interrupted logins. Each GET /
            -- (no cookie) redirects to the authorize endpoint and stores
            -- state/nonce/code_verifier/orig_uri (4 entries) under a fresh
            -- session id. 50 logins => ~200 entries (> 128).
            local logins = 50
            for i = 1, logins do
                local httpc = http.new()
                httpc:request_uri(app_url .. "/", { follow_redirects = false })
            end

            local function state_entries()
                local httpc = http.new()
                local res = httpc:request_uri(app_url .. "/oidc_status")
                if not res then return nil end
                return tonumber(res.body:match("State/Nonce entries: (%d+)"))
            end

            local before = state_entries()

            -- Let every pre-auth entry expire (pre_auth_timeout 1s).
            ngx.sleep(2)

            -- Fire exactly one cleanup (verify mode creates no new entries).
            local httpc = http.new()
            httpc:request_uri(app_url .. "/trigger-cleanup")

            local after = state_entries()

            ngx.status = 200
            ngx.say("meaningful:" .. tostring(before ~= nil and before > 128))
            ngx.say("after:" .. tostring(after))
        }
    }
--- request
GET /run-cleanup
--- timeout: 120
--- error_code: 200
--- response_body
meaningful:true
after:0
