--TEST--
oci8.default_prefetch ini option
--EXTENSIONS--
oci8
--SKIPIF--
<?php
require_once 'skipifconnectfailure.inc';
?>
--INI--
oci8.default_prefetch=100
--FILE--
<?php

require __DIR__.'/connect.inc';

// Initialize

$stmtarray = array(
    "drop table default_prefetch2_tab",
    "create table default_prefetch2_tab (id number, value number)",
    "insert into default_prefetch2_tab (id, value) values (1,1)",
    "insert into default_prefetch2_tab (id, value) values (1,1)",
    "insert into default_prefetch2_tab (id, value) values (1,1)",
);

oci8_test_sql_execute($c, $stmtarray);

// Run Test

$select_sql = "select * from default_prefetch2_tab";

if (!($s = oci_parse($c, $select_sql))) {
    die("oci_parse(select) failed!\n");
}

var_dump(oci_set_prefetch($s, 10));

if (!oci_execute($s)) {
    die("oci_execute(select) failed!\n");
}

var_dump(oci_fetch($s));
var_dump(oci_num_rows($s));

// Cleanup

$stmtarray = array(
    "drop table default_prefetch2_tab"
);

oci8_test_sql_execute($c, $stmtarray);

echo "Done\n";
?>
--EXPECT--
bool(true)
bool(true)
int(1)
Done
