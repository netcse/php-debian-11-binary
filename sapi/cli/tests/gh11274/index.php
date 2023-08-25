<?php $uri = $_SERVER['REQUEST_URI'];
if (isset($_GET["desired_status"]) && $uri[strlen($uri) - 1] !== '/') {
    $desired_status = (int) $_GET["desired_status"];
    http_response_code($desired_status);
    header("Location: $uri/");
    exit;
}

echo "method: ", $_SERVER['REQUEST_METHOD'], "; body: ", file_get_contents('php://input'), "\n"; ?>