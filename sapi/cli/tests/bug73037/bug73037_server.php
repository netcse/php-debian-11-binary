<?php $s = new SoapServer(NULL, array('uri' => 'http://here'));
$s->setObject(new stdclass());
$s->handle(); ?>