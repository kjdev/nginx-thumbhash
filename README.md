nginx-thumbhash
===============

[ThumbHash]: https://github.com/evanw/thumbhash

This nginx module implements the [ThumbHash][] image placeholder generation
algorithm invented by Evan Wallace.

Installation
------------

### Build install

``` sh
$ : "clone repository"
$ git clone https://github.com/kjdev/nginx-thumbhash
$ cd nginx-thumbhash
$ : "get nginx source"
$ NGINX_VERSION=1.x.x # specify nginx version
$ wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
$ tar -zxf nginx-${NGINX_VERSION}.tar.gz
$ cd nginx-${NGINX_VERSION}
$ : "build module"
$ ./configure --add-dynamic-module=../
$ make && make install
```

### Docker

``` sh
$ docker build -t nginx-thumbhash .
$ : "app.conf: Create nginx configuration"
$ docker run -p 80:80 -v $PWD/app.conf:/etc/nginx/http.d/default.conf nginx-thumbhash
```

> Github package: ghcr.io/kjdev/nginx-thumbhash


Configuration
-------------

### Example

```
location ~ ^/thumbhash/(?<data>.+)$ {
  thumbhash_render $data base64=url;
}

location ~ ".(jpe?g|png|gif)$" {
  thumbhash_filter;
}
```

### Directives

```
Syntax: thumbhash_render <string> [base64=standard|url] [width=<size>] [height=<size>]
Default: -
Context: location
```

Generates and renders a ThumbHash image from the specified string.

The option `base64` parameter sets the encoding of the string.
(default value is `standard`)

The optional `width` parameter sets the width of the generated image.

The option `height` parameter sets the width of the generated image.

> If neither width nor height is specified, or both are set to 0,
> the image will be generated with a base size of 32 pt.
>
> If either width or height is set to 0, a non-zero value
> will be used as the base size

```
Syntax: thumbhash_filter [query=<string>] [width=<size>] [height=<size>];
Default: -
Context: location
```

Set to respond with ThumbHash processed images.

The optional `query` parameter sets the query string that determines whether
ThumbHash processing is performed.
(default value is `thumbhash`)

If the query string does not match this value,
no ThumbHash processing will be performed.

The optional `width` parameter sets the width of the generated image.

The option `height` parameter sets the width of the generated image.

> If neither width nor height is specified, or both are set to 0,
> the image will be generated with a base size of 32 pt.
>
> If either width or height is set to 0, a non-zero value
> will be used as the base size