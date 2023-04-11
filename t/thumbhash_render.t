use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== base64 standard
--- config
location = / {
  thumbhash_render "1QcSHQRnh493V4dIh4eXh1h4kJUI";
}
--- request
GET /
--- response_headers
Content-Type: image/png
--- error_code: 200

=== base64 urldecode
--- config
location = / {
  thumbhash_render "3OcRJYB4d3h_iIeHeEh3eIhw-j3A" base64=url;
}
--- request
GET /
--- response_headers
Content-Type: image/png
--- error_code: 200

=== with width and height
--- config
location = / {
  thumbhash_render "HBkSHYSIeHiPiHh8eJd4eTN0EEQG" width=64 height=32;
}
--- request
GET /
--- response_headers
Content-Type: image/png
--- error_code: 200

=== re-access
--- config
location = / {
  thumbhash_render "2fcZFIB3iId/h3iJh4aIYJ2V8g";
}
--- request eval
[
  "GET /",
  "GET /"
]
--- response_headers eval
[
  "Content-Type: image/png",
  "Content-Type: image/png"
]
--- error_code eval
[
  200,
  200
]

=== variable setting
--- config
set $data "3PcNNYSFeXh/d3eld0iHZoZgVwh2";
location = / {
  thumbhash_render $data;
}
--- request
GET /
--- response_headers
Content-Type: image/png
--- error_code: 200

=== invalid
--- config
location = / {
  thumbhash_render "example";
}
--- request
GET /
--- error_code: 415

=== cleanup
--- init
unlink glob($ENV{TEST_NGINX_HTML_DIR} . '/*_thumbhash.png')
--- config
location / {
  return 200;
}
--- request
GET /
--- error_code: 200
