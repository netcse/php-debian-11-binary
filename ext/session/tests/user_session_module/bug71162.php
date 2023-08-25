<?php
class MySessionHandler extends SessionHandler implements SessionUpdateTimestampHandlerInterface
{
    public function open($path, $sessname): bool {
        return TRUE;
    }

    public function close(): bool {
        return TRUE;
    }

    public function read($sessid): string|false {
        return '';
    }

    public function write($sessid, $sessdata): bool {
        echo __FUNCTION__, PHP_EOL;
        return TRUE;
    }

    public function destroy($sessid): bool {
        return TRUE;
    }

    public function gc($maxlifetime): int|false {
        return TRUE;
    }

    public function create_sid(): string {
        return sha1(random_bytes(32));
    }

    public function validateId($sid): bool {
        return TRUE;
    }

    public function updateTimestamp($sessid, $sessdata): bool {
        echo __FUNCTION__, PHP_EOL;
        return TRUE;
    }
}

ob_start();
$handler = new MySessionHandler();
session_set_save_handler($handler);

session_id(sha1(''));
var_dump(session_id());
var_dump(session_start(['lazy_write'=>1]));
session_commit();

session_id(sha1(''));
var_dump(session_id());
var_dump(session_start(['lazy_write'=>1]));
session_commit();

session_id(sha1(''));
var_dump(session_id());
var_dump(session_start(['lazy_write'=>0]));
session_commit();
?>
