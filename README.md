# Nginx plugin

HTTP module for Nginx that uses libcurl.
It drives libcurl's multi_socket interface with Nginx's event loop.


```sh
# download nginx and build-tools
sudo dnf install -y --setopt=install_weak_deps=False \
  gcc binutils make wget openssl-devel pcre-devel zlib-devel
  # pcre-devel for ngx_http_rewrite_module
  # zlib-devel for ngx_http_gzip_static_module
wget https://nginx.org/download/nginx-1.18.0.tar.gz
tar zxf nginx-1.18.0.tar.gz

# plugin's curl-dependency
sudo dnf install libcurl-devel
```

```sh
# configure, build, run
./build.sh configure
./build.sh build
./build.sh run
```

Example location configuration in Nginx.conf:

```
location /api {
    api_enable;
}
```
