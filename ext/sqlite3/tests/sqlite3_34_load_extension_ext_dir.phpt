--TEST--
SQLite3::loadExtension with disabled extensions
--CREDITS--
Jelle Lampaert
#Belgian Testfest 2009
--EXTENSIONS--
sqlite3
--SKIPIF--
<?php
if (!method_exists('SQLite3', 'loadExtension')) {
    die("skip if SQLITE_OMIT_LOAD_EXTENSION defined");
}
?>
--FILE--
<?php

$db = new SQLite3(':memory:');

try {
  $db->loadExtension("");
} catch (Extension $ex) {
  var_dump($ex->getMessage());
}

?>
--EXPECTF--
Warning: SQLite3::loadExtension(): SQLite Extensions are disabled in %s on line %d
