use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== discovery non-200: client receives 502 instead of a closed connection
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;$TEST_NGINX_CONF_DIR/../lib/?.lua;;";
    oidc_session_store memory_store {
        type memory;
        size 10m;
        ttl 3600;
    }
    oidc_provider test_provider {
        issuer "http://127.0.0.1:8888/no-such-issuer";
        client_id "test";
        client_secret "b028e7a42bbb072acf09ed342e760627";
        redirect_uri "http://127.0.0.1:1984/oidc_callback";
        session_store memory_store;
    }
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    location /_oidc_http_fetch {
        internal;
        auth_oidc off;
        proxy_bind 127.0.0.1;
        proxy_pass $oidc_fetch_url;
        proxy_method $oidc_fetch_method;
        proxy_set_header Content-Type $oidc_fetch_content_type;
        proxy_set_header Content-Length $oidc_fetch_content_length;
        proxy_set_header Host $proxy_host;
        proxy_set_header Accept-Encoding "";
        proxy_pass_request_body on;
        proxy_max_temp_file_size 0;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        subrequest_output_buffer_size 200k;
    }
    auth_oidc test_provider;
    location = /protected {
        content_by_lua_block { ngx.say("ok") }
    }
--- request
GET /protected
--- error_code: 502
--- error_log
oidc_module: metadata fetch failed for provider
