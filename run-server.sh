#!/bin/sh

#build Nginx with OIDC module first
/bin/sh -c /build_ngx_openidc.sh

#start  nginx
/usr/local/nginx/sbin/nginx -p /usr/local/nginx/conf/ -c /usr/local/nginx/conf/nginx.conf

