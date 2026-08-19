<?php
// Server-side CBOR fuzzer
// Run: php cbor-fuzz-server.php

if (!defined('__TYPECHO_ROOT_DIR__')) {
    define('__TYPECHO_ROOT_DIR__', dirname(__DIR__));
}

require_once dirname(__DIR__) . '/WebAuthn.php';

$testVectors = json_decode(file_get_contents(__DIR__ . '/cbor-vectors.json'), true);

foreach ($testVectors as $tv) {
    $name = $tv['name'];
    $data = base64_decode($tv['data_b64']);
    echo "[*] $name: ";
    try {
        WebAuthn::parseAttestationObject($data, 'example.com');
        echo "ACCEPTED\n";
    } catch (\Throwable $e) {
        echo "REJECTED: " . $e->getMessage() . "\n";
    }
}
