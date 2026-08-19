<?php
/**
 * Local verification of WebAuthn attestation fixes.
 * Tests that forged attestations are now rejected and legitimate ones pass.
 */
define('__TYPECHO_ROOT_DIR__', dirname(__DIR__));
require_once dirname(__DIR__) . '/WebAuthn.php';

use TypechoPlugin\PassKey\WebAuthn;

putenv('OPENSSL_CONF=' . dirname(__DIR__) . '/openssl-minimal.cnf');
$configArgs = ['config' => dirname(__DIR__) . '/openssl-minimal.cnf'];

// ─── CBOR helpers ───
function cborInt(int $v): string {
    if ($v >= 0) {
        if ($v < 24) return chr(0x00 + $v);
        if ($v < 256) return "\x18" . chr($v);
        if ($v < 65536) return "\x19" . pack('n', $v);
        return "\x1a" . pack('N', $v);
    }
    $n = -1 - $v;
    if ($n < 24) return chr(0x20 + $n);
    if ($n < 256) return "\x38" . chr($n);
    return "\x39" . pack('n', $n);
}
function cborBytes(string $d): string {
    $l = strlen($d);
    if ($l < 24) return chr(0x40 + $l) . $d;
    if ($l < 256) return "\x58" . chr($l) . $d;
    return "\x59" . pack('n', $l) . $d;
}
function cborText(string $d): string {
    $l = strlen($d);
    if ($l < 24) return chr(0x60 + $l) . $d;
    if ($l < 256) return "\x78" . chr($l) . $d;
    return "\x79" . pack('n', $l) . $d;
}
function cborMap(array $items): string {
    $c = count($items);
    $out = $c < 24 ? chr(0xa0 + $c) : "\xb8" . chr($c);
    foreach ($items as $k => $v) $out .= (is_int($k) ? cborInt($k) : cborText((string)$k)) . $v;
    return $out;
}

function genKey() {
    $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => $GLOBALS['configArgs']['config']]);
    $details = openssl_pkey_get_details($kp);
    openssl_pkey_export($kp, $pem, null, $GLOBALS['configArgs']);
    return [$kp, $pem, $details['ec']['x'], $details['ec']['y']];
}

function coseKey(string $x, string $y): string {
    return cborMap([1 => cborInt(2), 3 => cborInt(-7), -1 => cborInt(1), -2 => cborBytes($x), -3 => cborBytes($y)]);
}

function buildAuthData(string $rpId, string $credId, string $cosePub): string {
    return hash('sha256', $rpId, true) . chr(0x45) . pack('N', 1)
        . str_repeat("\x00", 16) . pack('n', strlen($credId)) . $credId . $cosePub;
}

function makeSelfSignedCert($keyPair) {
    $dn = ['commonName' => 'Test Root CA', 'organizationName' => 'PassKeyTest'];
    $csr = openssl_csr_new($dn, $keyPair, $GLOBALS['configArgs']);
    if ($csr === false) return '';
    $cert = openssl_csr_sign($csr, null, $keyPair, 365, $GLOBALS['configArgs']);
    openssl_x509_export($cert, $pem);
    $der = '';
    $lines = explode("\n", $pem);
    foreach ($lines as $ln) {
        $ln = trim($ln);
        if ($ln === '' || strpos($ln, '-----') === 0) continue;
        $der .= base64_decode($ln);
    }
    return $der;
}

$rpId = 'localhost';
$clientDataHash = hash('sha256', '{"type":"webauthn.create"}', true);

// Authenticator keypair (the "device" credential key)
[$authKp, $authPem, $ax, $ay] = genKey();
$credId = random_bytes(16);
$cosePub = coseKey($ax, $ay);
$authData = buildAuthData($rpId, $credId, $cosePub);

// Attestation certificate keypair
[$attKp, $attPem, , ] = genKey();
$attCertDer = makeSelfSignedCert($attKp);

$results = [];
function run(string $name, string $attObj, string $policy, bool $expectThrow): void {
    try {
        WebAuthn::parseAttestationObject($attObj, $GLOBALS['rpId'], $GLOBALS['clientDataHash'], $policy);
        $ok = $expectThrow ? false : true;
        $msg = $expectThrow ? 'X should have thrown but passed!' : 'PASS';
    } catch (\Throwable $e) {
        $ok = $expectThrow ? true : false;
        $msg = $expectThrow ? "PASS (rejected: {$e->getMessage()})" : "X threw: {$e->getMessage()}";
    }
    $GLOBALS['results'][] = ($ok ? '[OK]   ' : '[FAIL] ') . $name . ' — ' . $msg;
}

// Case 1: legitimate 'none' with empty attStmt → PASS
$noneAtt = cborMap(['fmt' => cborText('none'), 'attStmt' => cborMap([]), 'authData' => cborBytes($authData)]);
run('none, empty attStmt (legit)', $noneAtt, 'none', false);

// Case 2: forged 'none' with non-empty attStmt → REJECT
$noneAttBad = cborMap(['fmt' => cborText('none'), 'attStmt' => cborMap(['evil' => cborText('x')]), 'authData' => cborBytes($authData)]);
run('none with hidden attStmt (forged)', $noneAttBad, 'none', true);

// Case 3: forged packed with random signature → REJECT
$sigRandom = random_bytes(64);
$packedForged = cborMap([
    'fmt' => cborText('packed'),
    'attStmt' => cborMap(['alg' => cborInt(-7), 'sig' => cborBytes($sigRandom), 'x5c' => cborMap([0 => cborBytes($attCertDer)])]),
    'authData' => cborBytes($authData),
]);
run('packed with random sig (forged)', $packedForged, 'none', true);

// Case 4: legitimate packed signed by cert key → PASS
$sig = '';
openssl_sign($authData . $clientDataHash, $sig, $attPem, OPENSSL_ALGO_SHA256);
$packedLegit = cborMap([
    'fmt' => cborText('packed'),
    'attStmt' => cborMap(['alg' => cborInt(-7), 'sig' => cborBytes($sig), 'x5c' => cborMap([0 => cborBytes($attCertDer)])]),
    'authData' => cborBytes($authData),
]);
run('packed with valid sig + self-signed cert (legit)', $packedLegit, 'none', false);

// Case 5: policy 'required' with 'none' format → REJECT
run('policy=required + none format', $noneAtt, 'required', true);

// Case 6: policy 'required' with valid packed → PASS
run('policy=required + valid packed', $packedLegit, 'required', false);

// Case 7: packed self-attestation (signed by credential key, no x5c) → PASS (spec allows)
$sigSelf = '';
openssl_sign($authData . $clientDataHash, $sigSelf, $authPem, OPENSSL_ALGO_SHA256);
$packedSelf = cborMap([
    'fmt' => cborText('packed'),
    'attStmt' => cborMap(['alg' => cborInt(-7), 'sig' => cborBytes($sigSelf)]),
    'authData' => cborBytes($authData),
]);
run('packed self-attestation (cred key signs)', $packedSelf, 'none', false);

// Case 8: forged packed claiming another cert in chain (mismatch) → REJECT
[$attKp2, $attPem2, , ] = genKey();
$sig2 = '';
openssl_sign($authData . $clientDataHash, $sig2, $attPem2, OPENSSL_ALGO_SHA256); // sig by key2
$packedMismatch = cborMap([
    'fmt' => cborText('packed'),
    'attStmt' => cborMap(['alg' => cborInt(-7), 'sig' => cborBytes($sig2), 'x5c' => cborMap([0 => cborBytes($attCertDer)])]),
    'authData' => cborBytes($authData),
]);
run('packed sig by different key than cert (forged)', $packedMismatch, 'none', true);

echo "=== Attestation verification tests ===\n\n";
foreach ($results as $r) echo "$r\n";
$fails = count(array_filter($results, fn($r) => strpos($r, '[FAIL]') === 0));
echo "\n" . (count($results) - $fails) . "/" . count($results) . " passed, $fails failed\n";
exit($fails > 0 ? 1 : 0);
