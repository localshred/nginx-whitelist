# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => 2 * blocks();

run_tests();

__DATA__

=== TEST 1: get request
--- config
    location / {
      whitelist_
    }
--- request
    GET /
--- error_code: 200