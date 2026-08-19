<?php

namespace TypechoPlugin\PassKey;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class WebAuthn
{
    private const MAX_CBOR_DEPTH = 8;
    private const MAX_CBOR_COLLECTION_ITEMS = 64;
    private const MAX_CBOR_STRING_BYTES = 65535;
    private const MAX_CREDENTIAL_ID_BYTES = 1024;
    private const MAX_DER_PUBLIC_KEY_BYTES = 4096;
    private const MAX_RSA_MODULUS_BYTES = 512;
    private const MAX_RSA_EXPONENT_BYTES = 8;

    private const SUPPORTED_ATTESTATION_FORMATS = ['none', 'packed', 'fido-u2f'];
    private const SUPPORTED_ALGORITHMS = [-7, -257];

    // ─── Public API ───────────────────────────────────────────

    public static function parseAssertionAuthenticatorData(string $authenticatorData): array
    {
        return self::parseAuthenticatorData($authenticatorData, false);
    }

    public static function parseAttestationObject(string $attestationObject, string $expectedRpId, string $clientDataHash = '', string $policy = 'none'): array
    {
        $offset = 0;
        $decoded = self::decodeCborItem($attestationObject, $offset, 0);

        if ($offset !== strlen($attestationObject) || !is_array($decoded)) {
            throw new \RuntimeException('Invalid attestationObject');
        }

        $format = isset($decoded['fmt']) && is_string($decoded['fmt']) ? $decoded['fmt'] : '';
        $authenticatorData = isset($decoded['authData']) && is_string($decoded['authData']) ? $decoded['authData'] : '';
        $attStmt = isset($decoded['attStmt']) && is_array($decoded['attStmt']) ? $decoded['attStmt'] : [];
        if ($format === '' || $authenticatorData === '') {
            throw new \RuntimeException('Attestation payload is incomplete');
        }

        self::assertSupportedAttestationFormat($format);

        $parsedAuthData = self::parseAuthenticatorData($authenticatorData, true);
        $expectedRpIdHash = hash('sha256', $expectedRpId, true);
        if (!hash_equals($expectedRpIdHash, $parsedAuthData['rp_id_hash'])) {
            throw new \RuntimeException('RP ID hash mismatch');
        }

        $credentialPublicKey = self::decodeCborBytes($parsedAuthData['credential_public_key_cose']);
        $algorithm = self::getCredentialAlgorithm($credentialPublicKey);
        self::assertKeyTypeMatchesAlgorithm($credentialPublicKey, $algorithm);

        $publicKeyDer = self::cosePublicKeyToDer($credentialPublicKey);
        if ($publicKeyDer === '' || strlen($publicKeyDer) > self::MAX_DER_PUBLIC_KEY_BYTES) {
            throw new \RuntimeException('Credential public key is too large');
        }

        // ─── Attestation authenticity verification ──────────────
        // 'none' 是 WebAuthn 规范允许的无证明格式，但我们必须保证
        // 其 attStmt 为空，防止攻击者在声明的 none 中夹带伪造数据。
        // 'packed' / 'fido-u2f' 需要验证签名（及证书链完整性），
        // 避免"声称是真实认证器"却完全没有证明。策略见 verifyAttestationPolicy()。
        self::verifyAttestationPolicy($format, $policy);
        self::verifyAttestationStatement($format, $attStmt, $authenticatorData, $clientDataHash, $parsedAuthData, $credentialPublicKey);

        return [
            'format' => $format,
            'flags' => $parsedAuthData['flags'],
            'sign_count' => $parsedAuthData['sign_count'],
            'credential_id' => $parsedAuthData['credential_id'],
            'credential_public_key_der' => $publicKeyDer,
            'algorithm' => $algorithm,
        ];
    }

    public static function verifyAssertionSignature(
        string $publicKeyDer,
        int $algorithm,
        string $authenticatorData,
        string $clientDataJson,
        string $signature
    ): bool {
        $pem = self::publicKeyDerToPem($publicKeyDer);
        if ($pem === '') {
            return false;
        }

        $publicKey = openssl_pkey_get_public($pem);
        if ($publicKey === false) {
            return false;
        }

        try {
            $details = openssl_pkey_get_details($publicKey);
            if (!is_array($details) || !isset($details['type'])) {
                return false;
            }

            if (!self::doesOpenSslKeyMatchAlgorithm((int) $details['type'], $algorithm)) {
                return false;
            }

            $openSslAlgorithm = self::resolveOpenSslAlgorithm($algorithm);
            if ($openSslAlgorithm === null) {
                return false;
            }

            $signedData = $authenticatorData . hash('sha256', $clientDataJson, true);
            $verified = openssl_verify($signedData, $signature, $publicKey, $openSslAlgorithm);

            return $verified === 1;
        } finally {
            // PHP 8.0+ deprecates openssl_free_key; the object is freed by GC.
            if (is_resource($publicKey)) {
                openssl_free_key($publicKey);
            }
        }
    }

    // ─── Authenticator Data Parsing ───────────────────────────

    private static function parseAuthenticatorData(string $authenticatorData, bool $requireAttestedCredentialData): array
    {
        if (strlen($authenticatorData) < 37) {
            throw new \RuntimeException('Authenticator data is too short');
        }

        $signCountData = unpack('Nsign_count', substr($authenticatorData, 33, 4));
        if (!is_array($signCountData) || !isset($signCountData['sign_count'])) {
            throw new \RuntimeException('Authenticator sign count is invalid');
        }

        $result = [
            'rp_id_hash' => substr($authenticatorData, 0, 32),
            'flags' => ord($authenticatorData[32]),
            'sign_count' => (int) $signCountData['sign_count'],
        ];

        if (!$requireAttestedCredentialData) {
            return $result;
        }

        if (($result['flags'] & 0x40) !== 0x40) {
            throw new \RuntimeException('Attested credential data flag is missing');
        }

        $offset = 37;
        if (strlen($authenticatorData) < $offset + 18) {
            throw new \RuntimeException('Attested credential data is incomplete');
        }

        // Skip AAGUID (16 bytes)
        $offset += 16;

        $credentialLengthData = unpack('nlength', substr($authenticatorData, $offset, 2));
        if (!is_array($credentialLengthData) || !isset($credentialLengthData['length'])) {
            throw new \RuntimeException('Credential ID length is invalid');
        }

        $offset += 2;
        $credentialLength = (int) $credentialLengthData['length'];
        if ($credentialLength <= 0 || $credentialLength > self::MAX_CREDENTIAL_ID_BYTES) {
            throw new \RuntimeException('Credential ID length exceeds the limit');
        }

        if (strlen($authenticatorData) < $offset + $credentialLength) {
            throw new \RuntimeException('Credential ID data is incomplete');
        }

        $credentialId = substr($authenticatorData, $offset, $credentialLength);
        $offset += $credentialLength;

        $publicKeyStart = $offset;
        self::decodeCborItem($authenticatorData, $offset, 0);
        $credentialPublicKeyBytes = substr($authenticatorData, $publicKeyStart, $offset - $publicKeyStart);
        if ($credentialPublicKeyBytes === '') {
            throw new \RuntimeException('Credential public key is missing');
        }

        // Skip extension data if present
        if (($result['flags'] & 0x80) === 0x80) {
            self::decodeCborItem($authenticatorData, $offset, 0);
        }

        if ($offset !== strlen($authenticatorData)) {
            throw new \RuntimeException('Authenticator data contains trailing bytes');
        }

        $result['credential_id'] = $credentialId;
        $result['credential_public_key_cose'] = $credentialPublicKeyBytes;

        return $result;
    }

    // ─── Attestation Format Validation ────────────────────────

    private static function assertSupportedAttestationFormat(string $format): void
    {
        if (!in_array($format, self::SUPPORTED_ATTESTATION_FORMATS, true)) {
            throw new \RuntimeException('Only fmt="none", "packed", or "fido-u2f" attestation is accepted');
        }
    }

    // ─── Attestation Authenticity Verification ────────────────

    /**
     * Enforce the configured attestation policy.
     *
     * Policy values:
     *  - 'none'     (default, compatible): accept none/packed/fido-u2f,
     *                but each format is still structurally verified.
     *  - 'preferred': like 'none', but registrations are encouraged to
     *                provide verifiable (packed/fido-u2f) attestation.
     *  - 'required' : only packed/fido-u2f attestation is accepted and it
     *                must pass signature / certificate-chain verification.
     */
    private static function verifyAttestationPolicy(string $format, string $policy): void
    {
        $policy = strtolower(trim($policy));
        if ($policy === 'required' && $format === 'none') {
            throw new \RuntimeException('Attestation with a verifiable format is required by policy');
        }

        if (!in_array($policy, ['none', 'preferred', 'required'], true)) {
            throw new \RuntimeException('Invalid attestation policy');
        }
    }

    /**
     * Verify the attestation statement for the given format.
     */
    private static function verifyAttestationStatement(
        string $format,
        array $attStmt,
        string $authenticatorData,
        string $clientDataHash,
        array $parsedAuthData,
        array $credentialPublicKey
    ): void {
        if ($clientDataHash === '') {
            throw new \RuntimeException('Client data hash is missing for attestation verification');
        }

        if ($format === 'none') {
            // 'none' must carry an empty attStmt — no hidden payload is allowed.
            if (count($attStmt) > 0) {
                throw new \RuntimeException('Invalid "none" attestation statement');
            }
            return;
        }

        if ($format === 'packed') {
            if (!self::verifyPackedAttestation($attStmt, $authenticatorData, $clientDataHash, $credentialPublicKey)) {
                throw new \RuntimeException('Packed attestation verification failed');
            }
            return;
        }

        if ($format === 'fido-u2f') {
            if (!self::verifyU2fAttestation($attStmt, $authenticatorData, $clientDataHash, $parsedAuthData, $credentialPublicKey)) {
                throw new \RuntimeException('FIDO U2F attestation verification failed');
            }
            return;
        }

        throw new \RuntimeException('Unsupported attestation format');
    }

    private static function verifyPackedAttestation(array $attStmt, string $authenticatorData, string $clientDataHash, array $credentialPublicKey): bool
    {
        $alg = isset($attStmt['alg']) ? (int) $attStmt['alg'] : 0;
        $sig = isset($attStmt['sig']) && is_string($attStmt['sig']) ? $attStmt['sig'] : '';
        if (!in_array($alg, self::SUPPORTED_ALGORITHMS, true) || $sig === '') {
            return false;
        }

        $signedData = $authenticatorData . $clientDataHash;
        $openSslAlgo = self::resolveOpenSslAlgorithm($alg);
        if ($openSslAlgo === null) {
            return false;
        }

        $x5c = isset($attStmt['x5c']) && is_array($attStmt['x5c']) ? $attStmt['x5c'] : [];

        if (count($x5c) > 0) {
            // Certificate-based attestation: verify signature with leaf cert,
            // and verify the certificate chain is at least self-consistent.
            $leafPem = self::certDerToPem((string) $x5c[0]);
            $publicKey = @openssl_pkey_get_public($leafPem);
            if ($publicKey === false) {
                return false;
            }

            $verified = @openssl_verify($signedData, $sig, $publicKey, $openSslAlgo);
            self::freeKey($publicKey);

            return $verified === 1 && self::verifyCertificateChain($x5c);
        }

        // Self attestation (no x5c): the signature must be produced by the
        // credential's own key. This proves possession but not provenance.
        $publicKeyPem = self::publicKeyDerToPem(self::cosePublicKeyToDer($credentialPublicKey));
        $publicKey = @openssl_pkey_get_public($publicKeyPem);
        if ($publicKey === false) {
            return false;
        }

        $verified = @openssl_verify($signedData, $sig, $publicKey, $openSslAlgo);
        self::freeKey($publicKey);

        return $verified === 1;
    }

    private static function verifyU2fAttestation(array $attStmt, string $authenticatorData, string $clientDataHash, array $parsedAuthData, array $credentialPublicKey): bool
    {
        $sig = isset($attStmt['sig']) && is_string($attStmt['sig']) ? $attStmt['sig'] : '';
        $x5c = isset($attStmt['x5c']) && is_array($attStmt['x5c']) ? $attStmt['x5c'] : [];
        if ($sig === '' || count($x5c) === 0) {
            return false;
        }

        $coordinates = self::extractEcCoordinates($credentialPublicKey);
        if ($coordinates === null) {
            return false;
        }
        [$x, $y] = $coordinates;
        $u2fPublicKey = "\x04" . $x . $y;

        $rpIdHash = substr($authenticatorData, 0, 32);
        $credentialId = (string) ($parsedAuthData['credential_id'] ?? '');
        if ($credentialId === '') {
            return false;
        }

        // U2F signature input: 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
        $signedData = "\x00" . $rpIdHash . $clientDataHash . $credentialId . $u2fPublicKey;

        $leafPem = self::certDerToPem((string) $x5c[0]);
        $publicKey = @openssl_pkey_get_public($leafPem);
        if ($publicKey === false) {
            return false;
        }

        $verified = @openssl_verify($signedData, $sig, $publicKey, OPENSSL_ALGO_SHA256);
        self::freeKey($publicKey);

        return $verified === 1 && self::verifyCertificateChain($x5c);
    }

    /**
     * Verify the x5c certificate chain: every certificate must be signed by
     * the next one in the list. The final certificate is accepted as-is
     * (real attestation chains often omit the root), so we only reject
     * broken / mismatched chains — the leaf signature check is the
     * authoritative gate against forgery.
     */
    private static function verifyCertificateChain(array $x5c): bool
    {
        $count = count($x5c);
        if ($count === 0) {
            return false;
        }

        for ($i = 0; $i < $count - 1; $i++) {
            $certPem = self::certDerToPem((string) $x5c[$i]);
            $signerPem = self::certDerToPem((string) $x5c[$i + 1]);
            if ($certPem === '' || $signerPem === '') {
                return false;
            }

            $cert = @openssl_x509_read($certPem);
            $signer = @openssl_x509_read($signerPem);
            if ($cert === false || $signer === false) {
                return false;
            }

            // The leaf/intermediate must be issued by the next cert in the list.
            if (openssl_x509_verify($cert, $signer) !== 1) {
                return false;
            }
        }

        return true;
    }

    private static function extractEcCoordinates(array $credentialPublicKey): ?array
    {
        $keyType = isset($credentialPublicKey[1]) ? (int) $credentialPublicKey[1] : 0;
        $curve = isset($credentialPublicKey[-1]) ? (int) $credentialPublicKey[-1] : 0;
        $x = isset($credentialPublicKey[-2]) && is_string($credentialPublicKey[-2]) ? $credentialPublicKey[-2] : '';
        $y = isset($credentialPublicKey[-3]) && is_string($credentialPublicKey[-3]) ? $credentialPublicKey[-3] : '';

        if ($keyType !== 2 || $curve !== 1 || strlen($x) !== 32 || strlen($y) !== 32) {
            return null;
        }

        return [$x, $y];
    }

    private static function certDerToPem(string $der): string
    {
        if ($der === '') {
            return '';
        }

        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    private static function freeKey($key): void
    {
        if (is_resource($key)) {
            openssl_free_key($key);
        }
    }

    // ─── Credential Algorithm Handling ────────────────────────

    private static function getCredentialAlgorithm(array $credentialPublicKey): int
    {
        $algorithm = isset($credentialPublicKey[3]) ? (int) $credentialPublicKey[3] : 0;
        if (!in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new \RuntimeException('Unsupported credential algorithm');
        }

        return $algorithm;
    }

    private static function assertKeyTypeMatchesAlgorithm(array $credentialPublicKey, int $algorithm): void
    {
        $keyType = isset($credentialPublicKey[1]) ? (int) $credentialPublicKey[1] : 0;

        $valid = ($keyType === 2 && $algorithm === -7)   // EC2 + ES256
              || ($keyType === 3 && $algorithm === -257); // RSA + RS256

        if (!$valid) {
            throw new \RuntimeException('Credential key type does not match its algorithm');
        }
    }

    private static function doesOpenSslKeyMatchAlgorithm(int $keyType, int $algorithm): bool
    {
        if ($algorithm === -7) {
            return defined('OPENSSL_KEYTYPE_EC') && $keyType === OPENSSL_KEYTYPE_EC;
        }

        if ($algorithm === -257) {
            return $keyType === OPENSSL_KEYTYPE_RSA;
        }

        return false;
    }

    private static function resolveOpenSslAlgorithm(int $algorithm): ?int
    {
        if (in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            return OPENSSL_ALGO_SHA256;
        }

        return null;
    }

    // ─── COSE → DER Public Key Conversion ─────────────────────

    private static function cosePublicKeyToDer(array $credentialPublicKey): string
    {
        $keyType = isset($credentialPublicKey[1]) ? (int) $credentialPublicKey[1] : 0;

        if ($keyType === 2) {
            return self::encodeEcPublicKey($credentialPublicKey);
        }

        if ($keyType === 3) {
            return self::encodeRsaPublicKey($credentialPublicKey);
        }

        throw new \RuntimeException('Unsupported credential key type');
    }

    private static function encodeEcPublicKey(array $credentialPublicKey): string
    {
        $curve = isset($credentialPublicKey[-1]) ? (int) $credentialPublicKey[-1] : 0;
        $x = isset($credentialPublicKey[-2]) && is_string($credentialPublicKey[-2]) ? $credentialPublicKey[-2] : '';
        $y = isset($credentialPublicKey[-3]) && is_string($credentialPublicKey[-3]) ? $credentialPublicKey[-3] : '';

        if ($curve !== 1 || strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \RuntimeException('Only P-256 EC public keys are supported');
        }

        $algorithmIdentifier = self::derEncodeSequence(
            self::derEncodeObjectIdentifier('1.2.840.10045.2.1')
            . self::derEncodeObjectIdentifier('1.2.840.10045.3.1.7')
        );
        $subjectPublicKey = self::derEncodeBitString("\x04" . $x . $y);

        return self::derEncodeSequence($algorithmIdentifier . $subjectPublicKey);
    }

    private static function encodeRsaPublicKey(array $credentialPublicKey): string
    {
        $modulus = isset($credentialPublicKey[-1]) && is_string($credentialPublicKey[-1]) ? $credentialPublicKey[-1] : '';
        $exponent = isset($credentialPublicKey[-2]) && is_string($credentialPublicKey[-2]) ? $credentialPublicKey[-2] : '';

        if ($modulus === '' || $exponent === '') {
            throw new \RuntimeException('RSA public key parameters are missing');
        }

        if (strlen($modulus) > self::MAX_RSA_MODULUS_BYTES || strlen($exponent) > self::MAX_RSA_EXPONENT_BYTES) {
            throw new \RuntimeException('RSA public key parameters exceed the limit');
        }

        $rsaPublicKey = self::derEncodeSequence(
            self::derEncodeInteger($modulus)
            . self::derEncodeInteger($exponent)
        );
        $algorithmIdentifier = self::derEncodeSequence(
            self::derEncodeObjectIdentifier('1.2.840.113549.1.1.1')
            . self::derEncodeNull()
        );

        return self::derEncodeSequence($algorithmIdentifier . self::derEncodeBitString($rsaPublicKey));
    }

    // ─── PEM Encoding ─────────────────────────────────────────

    private static function publicKeyDerToPem(string $derBinary): string
    {
        if ($derBinary === '') {
            return '';
        }

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($derBinary), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    // ─── CBOR Decoder ─────────────────────────────────────────

    private static function decodeCborBytes(string $data): array
    {
        $offset = 0;
        $decoded = self::decodeCborItem($data, $offset, 0);
        if ($offset !== strlen($data) || !is_array($decoded)) {
            throw new \RuntimeException('Invalid CBOR data');
        }

        return $decoded;
    }

    private static function decodeCborItem(string $data, int &$offset, int $depth)
    {
        if ($depth > self::MAX_CBOR_DEPTH) {
            throw new \RuntimeException('CBOR nesting is too deep');
        }

        if ($offset >= strlen($data)) {
            throw new \RuntimeException('Unexpected end of CBOR data');
        }

        $initialByte = ord($data[$offset++]);
        $majorType = $initialByte >> 5;
        $additionalInfo = $initialByte & 0x1f;

        if ($additionalInfo === 31) {
            throw new \RuntimeException('Indefinite-length CBOR is not supported');
        }

        switch ($majorType) {
            case 0: // unsigned integer
                return self::decodeCborLength($data, $offset, $additionalInfo);
            case 1: // negative integer
                return -1 - self::decodeCborLength($data, $offset, $additionalInfo);
            case 2: // byte string
                $length = self::decodeCborLength($data, $offset, $additionalInfo);
                self::assertCborStringLength($length);
                return self::readBytes($data, $offset, $length);
            case 3: // text string
                $length = self::decodeCborLength($data, $offset, $additionalInfo);
                self::assertCborStringLength($length);
                return self::readBytes($data, $offset, $length);
            case 4: // array
                $length = self::decodeCborLength($data, $offset, $additionalInfo);
                self::assertCollectionLength($length);
                $result = [];
                for ($i = 0; $i < $length; $i++) {
                    $result[] = self::decodeCborItem($data, $offset, $depth + 1);
                }
                return $result;
            case 5: // map
                $length = self::decodeCborLength($data, $offset, $additionalInfo);
                self::assertCollectionLength($length);
                $result = [];
                for ($i = 0; $i < $length; $i++) {
                    $key = self::decodeCborItem($data, $offset, $depth + 1);
                    if (!is_int($key) && !is_string($key)) {
                        throw new \RuntimeException('CBOR map key type is invalid');
                    }
                    $result[$key] = self::decodeCborItem($data, $offset, $depth + 1);
                }
                return $result;
            case 6: // tagged item
                self::decodeCborLength($data, $offset, $additionalInfo);
                return self::decodeCborItem($data, $offset, $depth + 1);
            case 7: // simple/float
                return self::decodeSimpleValue($data, $offset, $additionalInfo);
            default:
                throw new \RuntimeException('Unsupported CBOR major type');
        }
    }

    private static function decodeSimpleValue(string $data, int &$offset, int $additionalInfo)
    {
        switch ($additionalInfo) {
            case 20:
                return false;
            case 21:
                return true;
            case 22: // null
            case 23: // undefined
                return null;
            case 24: // 1-byte simple value
                self::readBytes($data, $offset, 1);
                return null;
            case 25: // 2-byte float (IEEE 754 half-precision) — skipped
                self::readBytes($data, $offset, 2);
                return null;
            case 26: // 4-byte float (IEEE 754 single-precision)
                $bytes = self::readBytes($data, $offset, 4);
                $value = unpack('Gvalue', $bytes);
                return is_array($value) && isset($value['value']) ? (float) $value['value'] : null;
            case 27: // 8-byte float (IEEE 754 double-precision)
                $bytes = self::readBytes($data, $offset, 8);
                $value = unpack('Evalue', $bytes);
                return is_array($value) && isset($value['value']) ? (float) $value['value'] : null;
            default:
                throw new \RuntimeException('Unsupported CBOR simple value');
        }
    }

    private static function decodeCborLength(string $data, int &$offset, int $additionalInfo): int
    {
        if ($additionalInfo < 24) {
            return $additionalInfo;
        }

        if ($additionalInfo === 24) {
            return ord(self::readBytes($data, $offset, 1));
        }

        if ($additionalInfo === 25) {
            $value = unpack('nvalue', self::readBytes($data, $offset, 2));
            return (int) $value['value'];
        }

        if ($additionalInfo === 26) {
            $value = unpack('Nvalue', self::readBytes($data, $offset, 4));
            return (int) $value['value'];
        }

        if ($additionalInfo === 27) {
            $parts = unpack('Nhigh/Nlow', self::readBytes($data, $offset, 8));
            $high = (int) ($parts['high'] ?? 0);
            $low = (int) ($parts['low'] ?? 0);

            if (PHP_INT_SIZE < 8) {
                if ($high > 0) {
                    throw new \RuntimeException('64-bit CBOR integers are not supported on 32-bit PHP');
                }
                return $low;
            }

            if ($high > 0x7fffffff) {
                throw new \RuntimeException('CBOR integer exceeds the supported range');
            }

            return ($high << 32) | $low;
        }

        throw new \RuntimeException('Unsupported CBOR length encoding');
    }

    // ─── Buffer Helpers ───────────────────────────────────────

    private static function readBytes(string $data, int &$offset, int $length): string
    {
        if ($length < 0 || strlen($data) < $offset + $length) {
            throw new \RuntimeException('CBOR data length is out of bounds');
        }

        $value = substr($data, $offset, $length);
        $offset += $length;
        return $value;
    }

    private static function assertCborStringLength(int $length): void
    {
        if ($length < 0 || $length > self::MAX_CBOR_STRING_BYTES) {
            throw new \RuntimeException('CBOR string length exceeds the limit');
        }
    }

    private static function assertCollectionLength(int $length): void
    {
        if ($length < 0 || $length > self::MAX_CBOR_COLLECTION_ITEMS) {
            throw new \RuntimeException('CBOR collection length exceeds the limit');
        }
    }

    // ─── DER Encoding Helpers ─────────────────────────────────

    private static function derEncodeSequence(string $value): string
    {
        return "\x30" . self::derEncodeLength(strlen($value)) . $value;
    }

    private static function derEncodeInteger(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }

        // Ensure positive integer: if high bit is set, prepend 0x00
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return "\x02" . self::derEncodeLength(strlen($value)) . $value;
    }

    private static function derEncodeBitString(string $value): string
    {
        return "\x03" . self::derEncodeLength(strlen($value) + 1) . "\x00" . $value;
    }

    private static function derEncodeNull(): string
    {
        return "\x05\x00";
    }

    private static function derEncodeObjectIdentifier(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));
        if (count($parts) < 2) {
            throw new \RuntimeException('OID is invalid');
        }

        $encoded = chr((40 * $parts[0]) + $parts[1]);
        for ($i = 2, $count = count($parts); $i < $count; $i++) {
            $encoded .= self::encodeOidPart($parts[$i]);
        }

        return "\x06" . self::derEncodeLength(strlen($encoded)) . $encoded;
    }

    private static function encodeOidPart(int $value): string
    {
        if ($value < 0) {
            throw new \RuntimeException('OID node is invalid');
        }

        $result = chr($value & 0x7f);
        $value >>= 7;
        while ($value > 0) {
            $result = chr(($value & 0x7f) | 0x80) . $result;
            $value >>= 7;
        }

        return $result;
    }

    private static function derEncodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $encoded = '';
        while ($length > 0) {
            $encoded = chr($length & 0xff) . $encoded;
            $length >>= 8;
        }

        return chr(0x80 | strlen($encoded)) . $encoded;
    }
}
