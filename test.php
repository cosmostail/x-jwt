<?php

require ("vendor/autoload.php");

$xJwt = new XJWT\Token();
$token = $xJwt->setPayload(["fox1" => "roger, roger", "fox2" => "收到, 收到"])
              ->encrypt('alias/pineapple', false);

echo $token . "\n";

$xJwt = new XJWT\Token();
print_r($xJwt->decrypt($token, false));