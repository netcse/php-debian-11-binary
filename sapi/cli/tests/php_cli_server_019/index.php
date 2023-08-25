<?php header('Bar-Foo: Foo');
var_dump(getallheaders());
var_dump(apache_request_headers());
var_dump(apache_response_headers()); ?>