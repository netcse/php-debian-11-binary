--TEST--
Bug #47243 (Crash on exit with ZTS mode)
--EXTENSIONS--
oci8
--SKIPIF--
<?php
require_once 'skipifconnectfailure.inc';
$target_dbs = array('oracledb' => true, 'timesten' => false);  // test runs on these DBs
require __DIR__.'/skipif.inc';
?>
--FILE--
<?php

require __DIR__.'/connect.inc';

// Run Test

$s = oci_parse($c, "select cursor(select dummy from dual) from dual");
oci_execute($s);
oci_fetch_all($s, $r);

// With explicit free and close
oci_free_statement($s);
oci_close($c);

?>
===DONE===
--EXPECT--
===DONE===
