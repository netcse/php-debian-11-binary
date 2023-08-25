<?php $fsize = 1000;
$chunksize = 99;
$chunks = floor($fsize / $chunksize); // 10 chunks * 99 bytes
$lastchunksize = $fsize - $chunksize * $chunks; // 1 chunk * 10 bytes

header("Content-Length: " . $fsize);
flush();
for ($chunk = 1; $chunk <= $chunks; $chunk++) {
    echo str_repeat('x', $chunksize);
    @ob_flush();
    usleep(50 * 1000);
}

echo str_repeat('x', $lastchunksize); ?>