# ngx-openidc
Nginx module for openid connect relying party.

# build
``````
env GIT_SSL_NO_VERIFY=true git clone https://github.dowjones.net/identity-systems/ngx-openidc.git
cd ngx-openidc
cd dependencies
tar -zxvf nginx-1.8.0.tar.gz
tar -zxvf pcre-8.01.tar.gz
cd ..
./build_ngx_openidc.sh