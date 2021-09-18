#!/usr/bin/env bash

set -o nounset
set -o errexit

pushd "$(dirname $(readlink -f ${0}))" > /dev/null
BIN=${PWD}/bin
mkdir -p ${BIN}/{tmp,lib} || :

function configure
{
  cd nginx-1.18.0 && \
  ./configure \
    --add-module=../plugin \
    --build=custom-build \
    --with-cc-opt='-Wno-pointer-to-int-cast' \
    --with-ld-opt="-Wl,-z,origin,-rpath='\$\$ORIGIN/lib'" \
    --with-debug \
    --builddir=${BIN} \
    --prefix=${BIN} \
    --sbin-path=${BIN} \
    --conf-path=${BIN}/conf/nginx.conf \
    --pid-path=${BIN}/nginx.pid \
    --lock-path=${BIN}/lock \
    --modules-path=${BIN}/modules \
    --error-log-path=${BIN}/error.log \
    --http-log-path=${BIN}/access.log \
    --http-client-body-temp-path=${BIN}/tmp/client_body \
    --http-proxy-temp-path=${BIN}/tmp/proxy \
    --http-fastcgi-temp-path=${BIN}/tmp/fastcgi \
    --http-uwsgi-temp-path=${BIN}/tmp/uwsgi \
    --http-scgi-temp-path=${BIN}/tmp/scgi \
    --user=$(id -u) \
    --group=$(id -g) \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_stub_status_module \
    --without-http_rewrite_module \
    --without-http_gzip_module
    # --with-http_gzip_static_module
  cp -r ./conf ${BIN}
  cp -r ./html ${BIN}
}

function ngx
{
  pushd "$(dirname $(readlink -f ${0}))/nginx-1.18.0" > /dev/null
  make
}

function helper
{
  plugin/build_helper.sh
  cp plugin/bin/* ${BIN}/lib
}

function run
{
  ${BIN}/nginx -g "daemon off;"
}

function hup
{
  kill -s HUP $(cat ${BIN}//nginx.pid)
}

if [ $# -eq 0 ]
then
  helper
  configure
  ngx
else
  "$@"
fi