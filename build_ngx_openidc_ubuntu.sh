#! /bin/bash
# untar nginx
# you can download and use whichever nginx version you want
cp -rf src/config.ubuntu src/config
wget 'http://nginx.org/download/nginx-1.14.0.tar.gz'
tar -zxvf nginx-1.14.0.tar.gz
cd nginx-1.14.0
./configure --add-module=/src --with-http_ssl_module  
make
make install

