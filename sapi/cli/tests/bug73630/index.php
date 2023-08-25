<?php var_dump(strncmp($_SERVER['REQUEST_URI'], "/overflow.php", strlen("/overflow.php")));
var_dump(strlen($_SERVER['QUERY_STRING'])); ?>