#! /bin/bash
# untar nginx
cp -rf src/config.ubuntu src/config
tar -zxvf nginx-1.8.0.tar.gz
cd nginx-1.8.0
./configure --add-module=/src --with-http_ssl_module  
make
make install

