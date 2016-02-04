cd ./dependencies/nginx-1.8.0
./configure --prefix=/opt/nginx-1.8.0	\
	--add-module=../../ \
  --with-http_ssl_module  
make
sudo make install

