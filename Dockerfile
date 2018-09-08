FROM centos:centos7
MAINTAINER http://www.centos.org
LABEL Vendor="CentOS"
LABEL License=GPLv2
LABEL Version=2.4.6-31

#RUN	yum -y update
#RUN	yum -y install epel-release

RUN yum -y install unzip wget tar gcc gcc-c++ git make apr-util-devel curl-devel
RUN yum -y install libuuid-devel && yum -y install openssl-devel && yum -y install pcre-devel

EXPOSE 80
EXPOSE 443

WORKDIR /
# test config
COPY test-conf/nginx.conf /usr/local/nginx/conf/
COPY test-conf/oidc-config.xml /usr/local/nginx/conf/

# copy success


# copy oidc source and nginx source to docker for compilation
COPY src /src

# copy scripts
ADD *.sh /

# make it executable
RUN chmod -v +x /*.sh

CMD ["/run-server.sh", "-DFOREGROUND"]