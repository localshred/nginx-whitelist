# vi:filetype=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => 2 * blocks();

run_tests();

__DATA__

=== TEST 1: whitelist compiled but not used
<<<<<<< HEAD
--- config
		location /nowhitelist {
			index index.html;
		}
--- request
    GET /nowhitelist
--- response_body
=======
--- request
    GET /
--- error_code: 200
>>>>>>> added more logging
