<?php set_exception_handler(function () { echo 'goodbye'; });
throw new Exception; ?>