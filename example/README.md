Use example
===========

Running
-------

``` sh
$ docker run \
    --rm -p 8888:80 \
    -v ./default.conf:/etc/nginx/http.d/default.conf \
    -v ./images/sunrise.jpg:/var/lib/nginx/html/sunrise.jpg \
    -v ./images/firefox.png:/var/lib/nginx/html/firefox.png \
    ghcr.io/kjdev/nginx-thumbhash
```

Accessing
---------

### thumbhash_render


``` sh
$ curl --head localhost:8888/thumbhash/1QcSHQRnh493V4dIh4eXh1h4kJUI
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 1893
```

### thumbhash_filter

``` sh
$ : jpg
$ curl --head localhost:8888/sunrise.jpg
HTTP/1.1 200 OK
Content-Type: image/jpeg
Content-Length: 2539
$ : thumbhash
$ curl --head 'localhost:8888/sunrise.jpg?thumbhash'
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 1864
```
