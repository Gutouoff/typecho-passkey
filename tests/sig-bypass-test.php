<?php
/**
 * Signature Verification Bypass Tests
 * 
 * Run on the server: php sig-bypass-test.php
 * Tests WebAuthn::verifyAssertionSignature() with edge cases.
 */

if (!defined('__TYPECHO_ROOT_DIR__')) {
    define('__TYPECHO_ROOT_DIR__', dirname(__DIR__));
}

require_once dirname(__DIR__) . '/WebAuthn.php';

use TypechoPlugin\PassKey\WebAuthn;

echo "=== SIGNATURE VERIFICATION BYPASS TESTS ===\n\n";

$passCount = 0;
$failCount = 0;

function test_assert(string $name, callable $fn): void {
    global $passCount, $failCount;
    echo "[*] $name: ";
    try {
        $fn();
        echo "PASS\n";
        $passCount++;
    } catch (\Throwable $e) {
        echo "FAIL: " . $e->getMessage() . "\n";
        $failCount++;
    }
}

function check(bool $condition, string $message): void {
    if (!$condition) {
        throw new \RuntimeException($message);
    }
}

// Generate a real P-256 key pair for testing
echo "[*] Generating test EC key pair...\n";
putenv('OPENSSL_CONF=' . dirname(__DIR__) . '/openssl-minimal.cnf');
$keyConfig = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1', 'config' => dirname(__DIR__) . '/openssl-minimal.cnf'];
$keyPair = openssl_pkey_new($keyConfig);
if ($keyPair === false) {
    die("Failed to generate key: " . openssl_error_string() . "\n");
}
$details = openssl_pkey_get_details($keyPair);
echo "    Key type: {$details['type']}, bits: {$details['bits']}\n";

// Get DER public key
$publicKeyDer = base64_decode(str_replace(
    ["-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n", "\n"],
    '',
    $details['key']
));

// Create valid test data
$authenticatorData = random_bytes(37);
$authenticatorData[32] = chr(0x05); // UP + UV flags
$clientDataJson = '{"type":"webauthn.get","challenge":"' . b64url(random_bytes(32)) . '","origin":"https://example.com"}';
$signedData = $authenticatorData . hash('sha256', $clientDataJson, true);

// Generate a valid signature
openssl_sign($signedData, $validSignature, $keyPair, OPENSSL_ALGO_SHA256);

echo "    Valid signature created (" . strlen($validSignature) . " bytes)\n\n";

// ─── Test 1: Valid signature ──────────────────────────────────
test_assert('Valid signature', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === true, 'Valid signature should verify');
});

// ─── Test 2: Empty public key ─────────────────────────────────
test_assert('Empty public key', function () use ($authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature('', -7, $authenticatorData, $clientDataJson, $validSignature);
    check($result === false, 'Empty key should fail');
});

// ─── Test 3: All-zeros public key ─────────────────────────────
test_assert('All-zeros public key', function () use ($authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        str_repeat("\x00", 91), -7, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === false, 'Zero key should fail');
});

// ─── Test 4: Algorithm mismatch (EC key with RS256) ───────────
test_assert('Algorithm mismatch (EC key + RS256)', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -257, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === false, 'Algorithm mismatch should fail');
});

// ─── Test 5: Tampered authenticator data ──────────────────────
test_assert('Tampered authenticator data', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $tampered = $authenticatorData;
    $tampered[0] = chr(ord($tampered[0]) ^ 0x01);
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $tampered, $clientDataJson, $validSignature
    );
    check($result === false, 'Tampered auth data should fail');
});

// ─── Test 6: Tampered client data ─────────────────────────────
test_assert('Tampered client data', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $tampered = str_replace('webauthn.get', 'webauthn.create', $clientDataJson);
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $authenticatorData, $tampered, $validSignature
    );
    check($result === false, 'Tampered client data should fail');
});

// ─── Test 7: Tampered signature ───────────────────────────────
test_assert('Tampered signature', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $tampered = $validSignature;
    $tampered[0] = chr(ord($tampered[0]) ^ 0x01);
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $authenticatorData, $clientDataJson, $tampered
    );
    check($result === false, 'Tampered signature should fail');
});

// ─── Test 8: Empty signature ──────────────────────────────────
test_assert('Empty signature', function () use ($publicKeyDer, $authenticatorData, $clientDataJson) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $authenticatorData, $clientDataJson, ''
    );
    check($result === false, 'Empty signature should fail');
});

// ─── Test 9: Malformed DER public key ─────────────────────────
test_assert('Malformed DER (random bytes)', function () use ($authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        random_bytes(128), -7, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === false, 'Malformed DER should fail');
});

// ─── Test 10: RSA key with ES256 algorithm ────────────────────
test_assert('RSA key with ES256 algorithm', function () use ($authenticatorData, $clientDataJson) {
    $rsaKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048, 'config' => dirname(__DIR__) . '/openssl-minimal.cnf']);
    $rsaDetails = openssl_pkey_get_details($rsaKey);
    $rsaDer = base64_decode(str_replace(
        ["-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n", "\n"], '', $rsaDetails['key']
    ));
    $result = WebAuthn::verifyAssertionSignature(
        $rsaDer, -7, $authenticatorData, $clientDataJson, random_bytes(64)
    );
    check($result === false, 'RSA key with ES256 should fail');
    if (is_resource($rsaKey)) openssl_free_key($rsaKey);
});

// ─── Test 11: Invalid algorithm (0) ───────────────────────────
test_assert('Invalid algorithm constant (0)', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, 0, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === false, 'Invalid algorithm should fail');
});

// ─── Test 12: DER with trailing bytes ─────────────────────────
// OpenSSL tolerates trailing bytes after the ASN.1 structure, so the
// signature still verifies against the same key.  This is NOT a
// vulnerability — the key itself is unchanged.
test_assert('DER with trailing bytes (still valid key)', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer . "\x00\x00\x00", -7, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === true, 'Trailing bytes should not invalidate the key');
});

// ─── Test 13: Null byte signature ─────────────────────────────
test_assert('Null byte signature', function () use ($publicKeyDer, $authenticatorData, $clientDataJson) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $authenticatorData, $clientDataJson, "\x00"
    );
    check($result === false, 'Null byte signature should fail');
});

// ─── Test 14: Very long inputs ────────────────────────────────
test_assert('Oversized inputs (100KB)', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7,
        str_repeat("\x00", 102400),
        $clientDataJson,
        $validSignature
    );
    check($result === false, 'Oversized auth data should fail');

    $result2 = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7,
        $authenticatorData,
        str_repeat('A', 102400),
        $validSignature
    );
    check($result2 === false, 'Oversized client data should fail');

    $result3 = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7,
        $authenticatorData,
        $clientDataJson,
        str_repeat("\x00", 10240)
    );
    check($result3 === false, 'Oversized signature should fail');
});

// ─── Test 15: Empty authenticator data ────────────────────────
test_assert('Empty authenticator data', function () use ($publicKeyDer, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, '', $clientDataJson, $validSignature
    );
    check($result === false, 'Empty auth data should fail');
});

// ─── Test 16: Empty client data ───────────────────────────────
test_assert('Empty client data', function () use ($publicKeyDer, $authenticatorData, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $authenticatorData, '', $validSignature
    );
    check($result === false, 'Empty client data should fail');
});

// ─── Test 17: Valid ED25519 signature (not supported) ─────────
test_assert('ED25519 algorithm (-8, not supported)', function () use ($publicKeyDer, $authenticatorData, $clientDataJson, $validSignature) {
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -8, $authenticatorData, $clientDataJson, $validSignature
    );
    check($result === false, 'ED25519 should not be supported');
});

// ─── Test 18: Verify with different authenticator data ────────
test_assert('Cross-credential signature (should fail)', function () use ($publicKeyDer, $clientDataJson, $validSignature) {
    // Sign with different authenticator data
    $wrongAuthData = random_bytes(37);
    $wrongAuthData[32] = chr(0x05);
    $result = WebAuthn::verifyAssertionSignature(
        $publicKeyDer, -7, $wrongAuthData, $clientDataJson, $validSignature
    );
    check($result === false, 'Cross-credential signature should fail');
});

// ─────────────────────────────────────────────────────────────────
echo "\n" . str_repeat('=', 60) . "\n";
echo "RESULTS: $passCount passed, $failCount failed\n";
echo str_repeat('=', 60) . "\n";

if ($failCount > 0) {
    echo "⚠ SOME TESTS FAILED — potential vulnerabilities detected!\n";
    exit(1);
} else {
    echo "✓ All tests passed — signature verification is robust\n";
}

function b64url(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
