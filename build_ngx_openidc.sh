cd ./dependencies/nginx-1.8.0
./configure --prefix=/opt/nginx-1.8.0	\
	--add-module=../../ \
  --without-http_charset_module  \
  --without-http_ssi_module        \
  --without-http_userid_module      \
  --without-http_access_module       \
  --without-http_auth_basic_module   \
  --without-http_autoindex_module    \
  --without-http_geo_module          \
  --without-http_map_module          \
  --without-http_split_clients_module \
  --without-http_referer_module      \
  --without-http_fastcgi_module      \
  --without-http_uwsgi_module        \
  --without-http_scgi_module         \
  --without-http_memcached_module    \
  --without-http_limit_conn_module   \
  --without-http_limit_req_module    \
  --without-http_empty_gif_module    \
  --without-http_browser_module      \
  --without-http_upstream_ip_hash_module \
  --without-http_upstream_least_conn_module \
  --without-http_upstream_keepalive_module \
  --without-mail_pop3_module  \
  --without-mail_imap_module   \
  --without-mail_smtp_module   \
  --with-pcre=../pcre-8.01 \
  --with-http_ssl_module  
make
sudo make install

