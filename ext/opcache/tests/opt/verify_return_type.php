<?php

class Test1 {
    final public function getIntOrFloat(int $i): int|float {
        return $i;
    }
    final public function getInt(): int {
        return $this->getIntOrFloat();
    }
}

class Test2 {
    public function getInt(): int {
        return 42;
    }
    public function getInt2(): int {
        return $this->getInt();
    }
    public function getIntOrFloat(int $i): int|float {
        return $i;
    }
    public function getInt3(int $i): int {
        // Should not elide return type check. Test2::getIntOrFloat() returns only int,
        // but a child method may return int|float.
        return $this->getIntOrFloat($i);
    }
}

class Test3 {
    private function getBool() {
        return true;
    }

    private function getBool2(): bool {
        return $this->getBool();
    }
}

function getClassUnion(): stdClass|FooBar {
    return new stdClass;
}

function getClassIntersection(): Traversable&Countable {
    return new ArrayObject;
}

?>
