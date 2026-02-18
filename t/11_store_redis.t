use Test::Nginx::Socket::Lua 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== redis
--- skip_eval
1: {
  use IO::Socket::INET;
  my $s = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => 6379,
    Timeout  => 0.1,
  );
  if ($s) {
    close $s;
    undef;
  } else {
    "Redis (6379) is not listening";
  }
}
--- init
system "redis-cli flushall"
--- http_config
    lua_package_path "$TEST_NGINX_LUA_DIR/?.lua;;";
    lua_shared_dict cookie_dict 1m;
    include $TEST_NGINX_CONF_DIR/test-provider-redis.conf;
    include $TEST_NGINX_CONF_DIR/server-app.conf;
    include $TEST_NGINX_CONF_DIR/stub-idp.conf;
--- config
    include $TEST_NGINX_CONF_DIR/location-fetch.conf;
    auth_oidc test_redis_provider;
    include $TEST_NGINX_CONF_DIR/location-test.conf;
--- request
GET /test
--- error_code: 200
--- response_body_like
authenticate:1
id-token:.*
access-token:.*
userinfo:\{.*\}
user id is user-identifier
user email is test\@example\.com
user algorithm is RS256
