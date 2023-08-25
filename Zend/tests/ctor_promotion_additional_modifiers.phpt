--TEST--
Constructor promotion only permits visibility modifiers
--FILE--
<?php

class Test {
    public function __construct(public static $x) {}
}

?>
--EXPECTF--
Fatal error: Cannot use the static modifier on a promoted property in %s on line %d
