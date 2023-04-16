use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== server config
--- config
thumbhash_temp_path /var/tmp;
location = / {
  thumbhash_render "1QcSHQRnh493V4dIh4eXh1h4kJUI";
}
--- request
GET /
--- response_headers
Content-Type: image/png
--- error_code: 200

=== location config
--- config
root $TEST_NGINX_HTML_DIR;
location / {
  thumbhash_temp_path /var/tmp;
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
