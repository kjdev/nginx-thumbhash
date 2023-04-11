use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== jpg file
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter;
}
--- request eval
[
  "GET /sunrise.jpg",
  "GET /sunrise.jpg?thumbhash"
]
--- response_headers eval
[
  "Content-Type: image/jpeg\nContent-Length: 2539",
  "Content-Type: image/png\nContent-Length: 1864"
]
--- error_code eval
[
  200,
  200
]

=== png file
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- http_config
types { image/png png; }
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter;
}
--- request eval
[
  "GET /sunset.png",
  "GET /sunset.png?thumbhash"
]
--- response_headers eval
[
  "Content-Type: image/png\nContent-Length: 12825",
  "Content-Type: image/png\nContent-Length: 1882"
]
--- error_code eval
[
  200,
  200
]

=== gif file
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter;
}
--- request eval
[
  "GET /street.gif",
  "GET /street.gif?thumbhash"
]
--- response_headers eval
[
  "Content-Type: image/gif\nContent-Length: 8463",
  "Content-Type: image/png\nContent-Length: 1561"
]
--- error_code eval
[
  200,
  200
]

=== with width and height
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter width=64 height=32;
}
--- request
GET /sunrise.jpg?thumbhash
--- response_headers
Content-Type: image/png
--- error_code: 200

=== with query
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter;
}
location /hash {
  rewrite ^/hash/(.+)$ /$1 break;
  thumbhash_filter query=encode;
}
--- request eval
[
  "GET /sunrise.jpg",
  "GET /sunrise.jpg?thumbhash",
  "GET /sunrise.jpg?encode",
  "GET /hash/sunrise.jpg",
  "GET /hash/sunrise.jpg?thumbhash",
  "GET /hash/sunrise.jpg?encode",
]
--- response_headers eval
[
  "Content-Type: image/jpeg\nContent-Length: 2539",
  "Content-Type: image/png\nContent-Length: 1864",
  "Content-Type: image/jpeg\nContent-Length: 2539",
  "Content-Type: image/jpeg\nContent-Length: 2539",
  "Content-Type: image/jpeg\nContent-Length: 2539",
  "Content-Type: image/png\nContent-Length: 1864"
]
--- error_code eval
[
  200,
  200,
  200,
  200,
  200,
  200
]

=== re-access
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter;
}
--- request eval
[
  "GET /sunrise.jpg?thumbhash",
  "GET /sunrise.jpg",
  "GET /sunrise.jpg?thumbhash",
]
--- response_headers eval
[
  "Content-Type: image/png\nContent-Length: 1864",
  "Content-Type: image/jpeg\nContent-Length: 2539",
  "Content-Type: image/png\nContent-Length: 1864"
]
--- error_code eval
[
  200,
  200,
  200
]

=== invalid content type
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_filter;
}
--- request eval
[
  "GET /example.txt",
  "GET /example.txt?thumbhash",
]
--- response_headers eval
[
  "Content-Type: text/plain",
  "Content-Type: text/html"
]
--- error_code eval
[
  200,
  415
]
