# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv

FROM nginx:alpine AS nginx

# [builder]
FROM nginx AS builder

WORKDIR /build
RUN --mount=type=cache,target=/var/cache/apk sh -ex <<'EOS'
apk upgrade
apk add \
  curl \
  gcc \
  gd-dev \
  geoip-dev \
  hiredis-dev \
  jansson-dev \
  libxslt-dev \
  linux-headers \
  make \
  musl-dev \
  nginx \
  openssl-dev \
  pcre-dev \
  perl-dev \
  zlib-dev
nginx_version=$(nginx -v 2>&1 | sed 's/^[^0-9]*//')
curl -sL -o nginx-${nginx_version}.tar.gz https://nginx.org/download/nginx-${nginx_version}.tar.gz
tar -xf nginx-${nginx_version}.tar.gz
mv nginx-${nginx_version} nginx
EOS

COPY config /build/
COPY src/ /build/src/

WORKDIR /build/nginx
RUN sh -ex <<'EOS'
opt=$(nginx -V 2>&1 | tail -1 | sed -e 's/configure arguments://' -e 's| --add-dynamic-module=[^ ]*||g')
with_cc_opt=$(echo "${opt}" | grep -e "--with-cc-opt='[^']*'" -o | sed -e "s/^--with-cc-opt='//" -e "s/'$//")
with_ld_opt=$(echo "${opt}" | grep -e "--with-ld-opt='[^']*'" -o | sed -e "s/^--with-ld-opt='//" -e "s/'$//")
opt=$(echo "${opt}" | sed -e "s|--with-cc-opt='[^']*'||" -e "s|--with-ld-opt='[^']*'||" -e 's/--without-engine//')
./configure \
  ${opt} \
  --with-cc-opt="${with_cc_opt} -DNGX_HTTP_HEADERS" \
  --with-ld-opt="${with_ld_opt}" \
  --add-dynamic-module=..
make
cp objs/ngx_http_oidc_module.so /usr/lib/nginx/modules/
EOS

# [nginx]
FROM nginx AS module

RUN --mount=type=cache,target=/var/cache/apk sh -ex <<'EOS'
apk upgrade
apk add \
  hiredis \
  jansson
# load module: ngx_http_oidc_module.so
sed -i '/events {/i load_module "/usr/lib/nginx/modules/ngx_http_oidc_module.so";' /etc/nginx/nginx.conf
EOS

COPY --from=builder /usr/lib/nginx/modules/ngx_http_oidc_module.so /usr/lib/nginx/modules/ngx_http_oidc_module.so

COPY --chmod=644 <<'EOS' /etc/nginx/oidc_http_fetch.conf
location /_oidc_http_fetch {
    internal;
    resolver 8.8.8.8 valid=300s;
    resolver_timeout 10s;
    auth_oidc off;

    proxy_pass $oidc_fetch_url;
    proxy_method $oidc_fetch_method;
    proxy_set_header Content-Type $oidc_fetch_content_type;
    proxy_set_header Content-Length $oidc_fetch_content_length;
    proxy_set_header Authorization $oidc_fetch_bearer;

    proxy_set_header Host $proxy_host;
    proxy_set_header Accept-Encoding "";
    proxy_pass_request_body on;
    proxy_max_temp_file_size 0;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    proxy_ssl_server_name on;
    proxy_ssl_name $proxy_host;

    proxy_connect_timeout 30s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;

    subrequest_output_buffer_size 200k;
}
EOS

# [google] Example
FROM module AS google

COPY --chmod=644 <<'EOS' /etc/nginx/templates/default.conf.template
upstream app {
    zone app 64k;
    server 127.0.0.1:8081;
}

server {
    listen 8081;
    default_type text/plain;
    charset utf-8;
    location / {
        return 200 "authenticate\nid-token:$http_x_id_token\naccess-token:$http_x_access_token\nuserinfo:$http_x_userinfo\nuser id is $http_x_user_id\nuser email is $http_x_user_email\nuser picture is $http_x_user_picture\n";
    }
}

oidc_session_store memory_store {
    type memory;
    size 10m;
    ttl 3600;
}

oidc_provider google {
    issuer "https://accounts.google.com";
    client_id "${NGINX_GOOGLE_CLIENT_ID}";
    client_secret "${NGINX_GOOGLE_CLIENT_SECRET}";
    session_store memory_store;
    redirect_uri "${NGINX_GOOGLE_REDIRECT_URI}";
    scopes openid email profile;
    userinfo on;
    logout_uri "/logout";
    post_logout_uri "${NGINX_GOOGLE_POST_LOGOUT}";
}

server {
    server_name ${NGINX_GOOGLE_SERVER_NAME};
    listen ${NGINX_GOOGLE_LISTEN_PORT};

    auth_oidc google;

    location / {
        proxy_pass http://app;
        proxy_set_header X-Id-Token $oidc_id_token;
        proxy_set_header X-Access-Token $oidc_access_token;
        proxy_set_header X-UserInfo $oidc_userinfo;
        proxy_set_header X-User-ID $oidc_claim_sub;
        proxy_set_header X-User-Email $oidc_claim_email;
        proxy_set_header X-User-Picture $oidc_claim_picture;
    }

    include /etc/nginx/oidc_http_fetch.conf;

    location = /public {
        auth_oidc off;
        default_type text/plain;
        return 200 "Public";
    }

    location = /oidc_status {
        auth_oidc off;
        oidc_status;
    }

    location = /favicon.ico {
      auth_oidc off;
      access_log off;
      log_not_found off;
      return 200;
    }
}
EOS

ENV NGINX_GOOGLE_CLIENT_ID= \
    NGINX_GOOGLE_CLIENT_SECRET= \
    NGINX_GOOGLE_REDIRECT_URI= \
    NGINX_GOOGLE_POST_LOGOUT=/public \
    NGINX_GOOGLE_SERVER_NAME=localhost \
    NGINX_GOOGLE_LISTEN_PORT=80
