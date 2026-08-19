<?php

namespace TypechoPlugin\PassKey;

use Typecho\Common;
use Typecho\Db;
use Typecho\Widget;
use Widget\ActionInterface;
use Widget\Options;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

require_once __DIR__ . '/WebAuthn.php';
require_once __DIR__ . '/Model.php';

class Action extends Widget implements ActionInterface
{
    private const REGISTER_CHALLENGE_SESSION_KEY = '__passkey_register_challenge';
    private const CHALLENGE_TTL = 180;
    private const LOGIN_EXPIRE = 2592000;

    private const MAX_JSON_BODY_BYTES = 131072;
    private const MAX_CHALLENGE_TOKEN_BYTES = 4096;
    private const MAX_CREDENTIAL_ID_BYTES = 1024;
    private const MAX_CLIENT_DATA_BYTES = 4096;
    private const MAX_AUTHENTICATOR_DATA_BYTES = 8192;
    private const MAX_SIGNATURE_BYTES = 4096;
    private const MAX_ATTESTATION_OBJECT_BYTES = 65536;
    private const MAX_PUBLIC_KEY_BYTES = 4096;
    private const NONCE_STORAGE_PREFIX = 'pkn_';
    private const NONCE_CLEANUP_PROBABILITY = 10;
    private const SUPPORTED_ALGORITHMS = [-7, -257];

    /**
     * @var Db
     */
    private $db;

    /**
     * @var Options|null
     */
    private $cachedOptions;

    public function __construct($request, $response, $params = null)
    {
        parent::__construct($request, $response, $params);
        $this->db = Db::get();
    }

    // ─── Route Dispatch ───────────────────────────────────────

    public function action()
    {
        $this->response->setContentType('application/json');

        switch ($this->request->getPathinfo()) {
            case '/passkey/challenge':
                $this->issueLoginChallenge();
                return;
            case '/passkey/verify':
                $this->verifyPasskey();
                return;
            case '/passkey/register/options':
                $this->issueRegistrationOptions();
                return;
            case '/passkey/register/finish':
                $this->finishRegistration();
                return;
            default:
                $this->sendJson(false, '请求路径无效', null, 404);
        }
    }

    // ─── Login Challenge ──────────────────────────────────────

    private function issueLoginChallenge(): void
    {
        if (!$this->request->isPost()) {
            $this->sendJson(false, '请求方法不允许', null, 405);
        }

        try {
            $this->enforceRateLimit('challenge');
            $this->assertSameOriginRequest();
            $payload = $this->createChallengePayload();
            $challengeToken = $this->encodeChallengeToken($payload);

            $this->sendJson(true, '获取成功', [
                'challenge' => $payload['challenge'],
                'challengeToken' => $challengeToken,
                'rpId' => $payload['rp_id'],
                'timeout' => 60000,
            ]);
        } catch (\Throwable $e) {
            $this->sendJson(false, '获取挑战参数失败', null, 400);
        }
    }

    // ─── Registration Options ─────────────────────────────────

    private function issueRegistrationOptions(): void
    {
        if (!$this->request->isPost()) {
            $this->sendJson(false, '请求方法不允许', null, 405);
        }

        try {
            $this->enforceRateLimit('register_options');
            $this->assertSameOriginRequest();
            $user = $this->requireLoggedInUser();
            $payload = $this->createChallengePayload($user['uid']);
            $userHandle = $this->buildUserHandle($user['uid']);

            $this->storeChallengePayload(self::REGISTER_CHALLENGE_SESSION_KEY, $payload + [
                'uid' => $user['uid'],
                'user_handle' => $this->base64UrlEncode($userHandle),
            ]);

            $excludeCredentials = [];
            foreach (Model::getCurrentUserPasskeys() as $item) {
                $credentialId = trim((string) ($item['credential_id'] ?? ''));
                if ($credentialId === '') {
                    continue;
                }

                $credentialBytes = $this->base64UrlDecode($credentialId);
                if ($credentialBytes === '' || strlen($credentialBytes) > self::MAX_CREDENTIAL_ID_BYTES) {
                    continue;
                }

                $excludeCredentials[] = [
                    'type' => 'public-key',
                    'id' => $credentialId,
                ];
            }

            $displayName = trim((string) ($user['screenName'] !== '' ? $user['screenName'] : $user['name']));
            $this->sendJson(true, '获取成功', [
                'challenge' => $payload['challenge'],
                'rp' => [
                    'name' => (string) $this->getSiteOptions()->title,
                    'id' => $payload['rp_id'],
                ],
                'user' => [
                    'id' => $this->base64UrlEncode($userHandle),
                    'name' => (string) $user['name'],
                    'displayName' => $displayName,
                ],
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => -7],
                    ['type' => 'public-key', 'alg' => -257],
                ],
                'timeout' => 60000,
                'attestation' => $this->getPluginConfigValue('attestationPolicy', 'none') === 'required' ? 'direct' : 'none',
                'authenticatorSelection' => [
                    'residentKey' => 'required',
                    'requireResidentKey' => true,
                    'userVerification' => 'required',
                ],
                'extensions' => [
                    'credProps' => true,
                ],
                'excludeCredentials' => $excludeCredentials,
            ]);
        } catch (\Throwable $e) {
            $this->sendJson(false, $e->getMessage(), null, 400);
        }
    }

    // ─── Registration Completion ──────────────────────────────

    private function finishRegistration(): void
    {
        if (!$this->request->isPost()) {
            $this->sendJson(false, '请求方法不允许', null, 405);
        }

        try {
            $this->enforceRateLimit('register_finish');
            $this->assertSameOriginRequest();
            $user = $this->requireLoggedInUser();
            $data = $this->decodeJsonBody();

            $name = trim((string) ($data['name'] ?? ''));
            if ($name === '' || Common::strLen($name) > 64) {
                throw new \RuntimeException('名称长度必须在 1 到 64 个字符之间');
            }

            $credential = is_array($data['credential'] ?? null) ? $data['credential'] : [];
            $response = is_array($credential['response'] ?? null) ? $credential['response'] : [];

            if (($credential['type'] ?? '') !== 'public-key') {
                throw new \RuntimeException('凭据类型无效');
            }

            $rawId = $this->decodeBinaryField($credential['rawId'] ?? null, 'rawId', self::MAX_CREDENTIAL_ID_BYTES);
            $credentialId = $this->normalizeCredentialId($rawId, (string) ($credential['id'] ?? ''));
            $clientDataJson = $this->decodeBinaryField($response['clientDataJSON'] ?? null, 'clientDataJSON', self::MAX_CLIENT_DATA_BYTES);
            $attestationObject = $this->decodeBinaryField($response['attestationObject'] ?? null, 'attestationObject', self::MAX_ATTESTATION_OBJECT_BYTES);

            $challengePayload = $this->takeChallengeFromSession(self::REGISTER_CHALLENGE_SESSION_KEY, $user['uid']);
            $this->validateClientData($clientDataJson, 'webauthn.create', $challengePayload);

            $clientDataHash = hash('sha256', $clientDataJson, true);
            $attestation = WebAuthn::parseAttestationObject(
                $attestationObject,
                (string) $challengePayload['rp_id'],
                $clientDataHash,
                $this->getPluginConfigValue('attestationPolicy', 'none')
            );
            if (($attestation['flags'] & 0x01) !== 0x01) {
                throw new \RuntimeException('缺少用户在场标记');
            }

            if (($attestation['flags'] & 0x04) !== 0x04) {
                throw new \RuntimeException('需要用户验证');
            }

            if (!hash_equals($rawId, (string) $attestation['credential_id'])) {
                throw new \RuntimeException('通行密钥标识不匹配');
            }

            $expectedUserHandle = $this->base64UrlDecode((string) ($challengePayload['user_handle'] ?? ''));
            if ($expectedUserHandle === '' || !hash_equals($expectedUserHandle, $this->buildUserHandle($user['uid']))) {
                throw new \RuntimeException('注册挑战参数无效');
            }

            $publicKeyDer = (string) ($attestation['credential_public_key_der'] ?? '');
            if ($publicKeyDer === '' || strlen($publicKeyDer) > self::MAX_PUBLIC_KEY_BYTES) {
                throw new \RuntimeException('通行密钥公钥无效');
            }

            Model::saveVerifiedCredential(
                $user['uid'],
                $credentialId,
                $name,
                $this->base64UrlEncode($publicKeyDer),
                (int) $attestation['algorithm'],
                (int) $attestation['sign_count']
            );

            @error_log(
                sprintf(
                    '[PassKey][audit] passkey bound | uid=%d name=%s cred=%s fmt=%s alg=%d ip=%s',
                    (int) $user['uid'],
                    $name,
                    $this->base64UrlEncode($rawId),
                    (string) ($attestation['format'] ?? '?'),
                    (int) ($attestation['algorithm'] ?? 0),
                    (string) $this->request->getIp()
                ),
                0
            );

            $this->sendJson(true, '绑定成功');
        } catch (\Throwable $e) {
            $this->sendJson(false, $e->getMessage(), null, 400);
        }
    }

    // ─── Login Verification ───────────────────────────────────

    private function verifyPasskey(): void
    {
        if (!$this->request->isPost()) {
            $this->sendJson(false, '请求方法不允许', null, 405);
        }

        try {
            $this->enforceRateLimit('verify');
            $this->assertSameOriginRequest();
            $data = $this->decodeJsonBody();

            $credential = is_array($data['credential'] ?? null) ? $data['credential'] : [];
            $response = is_array($credential['response'] ?? null) ? $credential['response'] : [];
            if (($credential['type'] ?? '') !== 'public-key') {
                throw new \RuntimeException('凭据类型无效');
            }

            $rawId = $this->decodeBinaryField($credential['rawId'] ?? null, 'rawId', self::MAX_CREDENTIAL_ID_BYTES);
            $credentialId = $this->normalizeCredentialId($rawId, (string) ($credential['id'] ?? ''));
            $authenticatorData = $this->decodeBinaryField($response['authenticatorData'] ?? null, 'authenticatorData', self::MAX_AUTHENTICATOR_DATA_BYTES);
            $clientDataJson = $this->decodeBinaryField($response['clientDataJSON'] ?? null, 'clientDataJSON', self::MAX_CLIENT_DATA_BYTES);
            $signature = $this->decodeBinaryField($response['signature'] ?? null, 'signature', self::MAX_SIGNATURE_BYTES);
            $userHandle = $this->decodeOptionalBinaryField($response['userHandle'] ?? null, 'userHandle', 256);

            $challengePayload = $this->takeChallengeFromToken($data['challengeToken'] ?? null);
            $this->validateClientData($clientDataJson, 'webauthn.get', $challengePayload);

            $parsedAuthData = WebAuthn::parseAssertionAuthenticatorData($authenticatorData);
            $expectedRpIdHash = hash('sha256', (string) $challengePayload['rp_id'], true);
            if (!hash_equals($expectedRpIdHash, $parsedAuthData['rp_id_hash'])) {
                throw new \RuntimeException('RP ID 哈希不匹配');
            }

            if (($parsedAuthData['flags'] & 0x01) !== 0x01) {
                throw new \RuntimeException('缺少用户在场标记');
            }

            if (($parsedAuthData['flags'] & 0x04) !== 0x04) {
                throw new \RuntimeException('需要用户验证');
            }

            $ownerAndData = Model::findPasskeyOwnerAndDataByCredentialId($credentialId);
            if (!is_array($ownerAndData) || empty($ownerAndData['uid']) || empty($ownerAndData['passkey'])) {
                throw new \RuntimeException('未找到对应的通行密钥');
            }

            $storedPasskey = (array) $ownerAndData['passkey'];
            $storedPublicKey = $this->decodeBinaryField($storedPasskey['public_key'] ?? null, 'storedPublicKey', self::MAX_PUBLIC_KEY_BYTES);
            $storedAlgorithm = isset($storedPasskey['algorithm']) ? (int) $storedPasskey['algorithm'] : 0;
            if (!in_array($storedAlgorithm, self::SUPPORTED_ALGORITHMS, true)) {
                throw new \RuntimeException('已保存的通行密钥算法无效');
            }

            if (!WebAuthn::verifyAssertionSignature($storedPublicKey, $storedAlgorithm, $authenticatorData, $clientDataJson, $signature)) {
                throw new \RuntimeException('签名校验失败');
            }

            $uid = (int) $ownerAndData['uid'];
            if ($userHandle !== '' && !hash_equals($userHandle, $this->buildUserHandle($uid))) {
                throw new \RuntimeException('用户标识不匹配');
            }

            // Sign count verification: prevent cloned authenticators
            $storedSignCount = max(0, (int) ($storedPasskey['sign_count'] ?? 0));
            $currentSignCount = max(0, (int) $parsedAuthData['sign_count']);
            if ($storedSignCount > 0 && $currentSignCount > 0 && $currentSignCount <= $storedSignCount) {
                throw new \RuntimeException('签名计数器异常回退');
            }

            if ($currentSignCount > $storedSignCount) {
                Model::updateCredentialSignCount($uid, $credentialId, $currentSignCount);
            }

            $userWidget = \Widget\User::alloc();
            if (!$userWidget->simpleLogin($uid, false, self::LOGIN_EXPIRE)) {
                throw new \RuntimeException('登录状态写入失败');
            }

            if (session_status() === PHP_SESSION_ACTIVE) {
                session_regenerate_id(true);
            }

            @error_log(
                sprintf(
                    '[PassKey][audit] passkey login | uid=%d cred=%s ip=%s',
                    $uid,
                    $this->base64UrlEncode($rawId),
                    (string) $this->request->getIp()
                ),
                0
            );

            $this->sendJson(true, '登录成功', ['redirect' => Model::getAdminRedirectUrl()]);
        } catch (\Throwable $e) {
            $this->sendJson(false, '通行密钥验证失败', null, 401);
        }
    }

    // ─── User Authentication ──────────────────────────────────

    private function requireLoggedInUser(): array
    {
        $user = \Widget\User::alloc();
        if (!$user->hasLogin()) {
            throw new \RuntimeException('请先登录');
        }

        return [
            'uid' => (int) $user->uid,
            'name' => (string) $user->name,
            'screenName' => (string) $user->screenName,
        ];
    }

    // ─── Challenge Payload ────────────────────────────────────

    private function createChallengePayload(int $uid = 0): array
    {
        try {
            $challenge = $this->base64UrlEncode(random_bytes(32));
        } catch (\Throwable $e) {
            throw new \RuntimeException('生成挑战参数失败');
        }

        return [
            'challenge' => $challenge,
            'rp_id' => $this->getRpId(),
            'origin' => $this->getExpectedOrigin(),
            'uid' => $uid,
            'expires_at' => time() + self::CHALLENGE_TTL,
            'jti' => $this->base64UrlEncode(random_bytes(16)),
        ];
    }

    // ─── Challenge Token (HMAC-Signed) ────────────────────────

    private function encodeChallengeToken(array $payload): string
    {
        $tokenPayload = json_encode([
            'type' => 'login',
            'challenge' => (string) ($payload['challenge'] ?? ''),
            'origin' => (string) ($payload['origin'] ?? ''),
            'rp_id' => (string) ($payload['rp_id'] ?? ''),
            'expires_at' => (int) ($payload['expires_at'] ?? 0),
            'jti' => (string) ($payload['jti'] ?? ''),
        ], JSON_UNESCAPED_SLASHES);

        if (!is_string($tokenPayload) || $tokenPayload === '') {
            throw new \RuntimeException('编码挑战令牌失败');
        }

        $encodedPayload = $this->base64UrlEncode($tokenPayload);
        $signature = hash_hmac('sha256', $encodedPayload, $this->getChallengeSigningKey(), true);

        return $encodedPayload . '.' . $this->base64UrlEncode($signature);
    }

    private function takeChallengeFromToken($token): array
    {
        if (!is_string($token)) {
            throw new \RuntimeException('缺少挑战令牌');
        }

        $token = trim($token);
        if ($token === '') {
            throw new \RuntimeException('缺少挑战令牌');
        }

        if (strlen($token) > self::MAX_CHALLENGE_TOKEN_BYTES) {
            throw new \RuntimeException('挑战令牌长度超出限制');
        }

        $parts = explode('.', $token, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \RuntimeException('挑战令牌无效');
        }

        $encodedPayload = $parts[0];
        $encodedSignature = $parts[1];
        $expectedSignature = $this->base64UrlEncode(
            hash_hmac('sha256', $encodedPayload, $this->getChallengeSigningKey(), true)
        );

        if (!hash_equals($expectedSignature, $encodedSignature)) {
            throw new \RuntimeException('挑战令牌签名无效');
        }

        $payloadJson = $this->base64UrlDecode($encodedPayload);
        if ($payloadJson === '') {
            throw new \RuntimeException('挑战令牌内容无效');
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload) || ($payload['type'] ?? '') !== 'login') {
            throw new \RuntimeException('挑战令牌内容无效');
        }

        $expiresAt = (int) ($payload['expires_at'] ?? 0);
        if ($expiresAt < time()) {
            throw new \RuntimeException('挑战令牌已过期');
        }

        $challenge = trim((string) ($payload['challenge'] ?? ''));
        $origin = trim((string) ($payload['origin'] ?? ''));
        $rpId = trim((string) ($payload['rp_id'] ?? ''));
        if ($challenge === '' || $origin === '' || $rpId === '') {
            throw new \RuntimeException('挑战令牌内容无效');
        }

        $jti = trim((string) ($payload['jti'] ?? ''));
        if ($jti === '') {
            throw new \RuntimeException('挑战令牌无效');
        }

        $this->consumeNonce($jti);

        return [
            'challenge' => $challenge,
            'origin' => $origin,
            'rp_id' => $rpId,
            'uid' => 0,
            'user_handle' => '',
        ];
    }

    // ─── Session-based Challenge (Registration) ───────────────

    private function storeChallengePayload(string $sessionKey, array $payload): void
    {
        $this->startSession();
        $_SESSION[$sessionKey] = $payload;
    }

    private function takeChallengeFromSession(string $sessionKey, int $expectedUid = 0): array
    {
        $this->startSession();

        $challengePayload = $_SESSION[$sessionKey] ?? null;
        unset($_SESSION[$sessionKey]);

        if (!is_array($challengePayload)) {
            throw new \RuntimeException('缺少挑战参数');
        }

        $expiresAt = (int) ($challengePayload['expires_at'] ?? 0);
        if ($expiresAt < time()) {
            throw new \RuntimeException('挑战参数已过期');
        }

        if ($expectedUid > 0 && (int) ($challengePayload['uid'] ?? 0) !== $expectedUid) {
            throw new \RuntimeException('挑战参数与当前用户不匹配');
        }

        $challenge = trim((string) ($challengePayload['challenge'] ?? ''));
        $origin = trim((string) ($challengePayload['origin'] ?? ''));
        $rpId = trim((string) ($challengePayload['rp_id'] ?? ''));
        if ($challenge === '' || $origin === '' || $rpId === '') {
            throw new \RuntimeException('挑战参数无效');
        }

        return [
            'challenge' => $challenge,
            'origin' => $origin,
            'rp_id' => $rpId,
            'uid' => (int) ($challengePayload['uid'] ?? 0),
            'user_handle' => (string) ($challengePayload['user_handle'] ?? ''),
        ];
    }

    // ─── Client Data Validation ───────────────────────────────

    private function validateClientData(string $clientDataJson, string $expectedType, array $challengePayload): void
    {
        $clientData = json_decode($clientDataJson, true);
        if (!is_array($clientData)) {
            throw new \RuntimeException('客户端数据无效');
        }

        if (($clientData['type'] ?? '') !== $expectedType) {
            throw new \RuntimeException('客户端数据类型不匹配');
        }

        $clientChallenge = $this->decodeBinaryField($clientData['challenge'] ?? null, 'challenge', 256);
        $serverChallenge = $this->decodeBinaryField((string) $challengePayload['challenge'], 'challenge', 256);
        if (!hash_equals($serverChallenge, $clientChallenge)) {
            throw new \RuntimeException('挑战参数不匹配');
        }

        $clientOrigin = trim((string) ($clientData['origin'] ?? ''));
        $expectedOrigin = trim((string) ($challengePayload['origin'] ?? ''));
        if ($clientOrigin === '' || !$this->isSameOrigin($clientOrigin, $expectedOrigin)) {
            throw new \RuntimeException('来源不匹配');
        }

        if (array_key_exists('crossOrigin', $clientData) && $clientData['crossOrigin'] !== false) {
            throw new \RuntimeException('不允许跨域使用通行密钥');
        }
    }

    // ─── Credential ID Helpers ────────────────────────────────

    private function normalizeCredentialId(string $rawId, string $credentialId): string
    {
        $normalized = $this->base64UrlEncode($rawId);
        $credentialId = trim($credentialId);
        if ($credentialId !== '' && !hash_equals($normalized, $credentialId)) {
            throw new \RuntimeException('通行密钥标识不匹配');
        }

        return $normalized;
    }

    private function buildUserHandle(int $uid): string
    {
        return hash('sha256', rtrim((string) $this->getSiteOptions()->siteUrl, '/') . '|' . $uid, true);
    }

    // ─── Signing Key ──────────────────────────────────────────

    private function getChallengeSigningKey(): string
    {
        $secret = trim((string) $this->getSiteOptions()->secret);
        if ($secret === '') {
            throw new \RuntimeException('请先配置站点密钥');
        }

        return hash('sha256', 'PassKey|challenge|' . $secret, true);
    }

    // ─── Session Management ───────────────────────────────────

    private function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');

        $secure = $this->request->isSecure();
        $path = '/';

        if (PHP_VERSION_ID >= 70300) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => $path,
                'secure' => $secure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        } else {
            session_set_cookie_params(0, $path, '', $secure, true);
        }

        session_start();
    }

    // ─── Binary Field Decoding ────────────────────────────────

    private function decodeBinaryField($value, string $fieldName, int $maxBytes): string
    {
        $fieldLabel = $this->getFieldLabel($fieldName);

        if (is_string($value)) {
            $value = trim($value);
            if ($value === '') {
                throw new \RuntimeException($fieldLabel . '不能为空');
            }

            $decoded = $this->base64UrlDecode($value);
            if ($decoded === '') {
                throw new \RuntimeException($fieldLabel . '编码无效');
            }

            if (strlen($decoded) > $maxBytes) {
                throw new \RuntimeException($fieldLabel . '长度超出限制');
            }

            return $decoded;
        }

        if (!is_array($value)) {
            throw new \RuntimeException($fieldLabel . '类型无效');
        }

        $buffer = '';
        foreach ($value as $byte) {
            if (!is_numeric($byte)) {
                throw new \RuntimeException($fieldLabel . '内容无效');
            }

            $intByte = (int) $byte;
            if ($intByte < 0 || $intByte > 255) {
                throw new \RuntimeException($fieldLabel . '内容无效');
            }

            $buffer .= chr($intByte);
            if (strlen($buffer) > $maxBytes) {
                throw new \RuntimeException($fieldLabel . '长度超出限制');
            }
        }

        if ($buffer === '') {
            throw new \RuntimeException($fieldLabel . '不能为空');
        }

        return $buffer;
    }

    private function decodeOptionalBinaryField($value, string $fieldName, int $maxBytes): string
    {
        if ($value === null || $value === '') {
            return '';
        }

        return $this->decodeBinaryField($value, $fieldName, $maxBytes);
    }

    // ─── Base64URL Codec ──────────────────────────────────────

    private function base64UrlDecode(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $base64 = strtr($value, '-_', '+/');
        $padding = strlen($base64) % 4;
        if ($padding !== 0) {
            $base64 .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            return '';
        }

        return $decoded;
    }

    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    // ─── Origin / RP ID ───────────────────────────────────────

    private function assertSameOriginRequest(): void
    {
        $expectedOrigin = $this->getExpectedOrigin();
        if ($expectedOrigin === '') {
            throw new \RuntimeException('无法确定预期来源');
        }

        $this->warnIfSiteUrlMisconfigured();

        $originHeader = trim((string) $this->request->getHeader('Origin', ''));
        if ($originHeader !== '') {
            if (!$this->isSameOrigin($originHeader, $expectedOrigin)) {
                throw new \RuntimeException('来源校验失败');
            }
            return;
        }

        $referer = trim((string) $this->request->getReferer());
        if ($referer === '' || !$this->isSameOrigin($referer, $expectedOrigin)) {
            throw new \RuntimeException('来源页校验失败');
        }
    }

    private function getExpectedOrigin(): string
    {
        $parts = $this->getConfiguredSiteUrlParts();
        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        $port = isset($parts['port']) ? (int) $parts['port'] : null;

        if ($host === '') {
            return '';
        }

        $origin = $scheme . '://' . $host;
        if ($port !== null && $port > 0 && !$this->isDefaultPort($scheme, $port)) {
            $origin .= ':' . $port;
        }

        return $origin;
    }

    private function getRpId(): string
    {
        $parts = $this->getConfiguredSiteUrlParts();
        $host = strtolower((string) $parts['host']);
        if ($host === '') {
            throw new \RuntimeException('站点标识不可用');
        }

        return $host;
    }

    private function getConfiguredSiteUrlParts(): array
    {
        $siteUrl = trim((string) $this->getSiteOptions()->siteUrl);
        $parts = parse_url($siteUrl);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new \RuntimeException('站点地址必须包含协议和域名');
        }

        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \RuntimeException('站点地址必须使用 http 或 https');
        }

        return $parts;
    }

    // ─── Options (Cached) ─────────────────────────────────────

    private function getSiteOptions(): Options
    {
        if ($this->cachedOptions === null) {
            $this->cachedOptions = Options::alloc();
        }

        return $this->cachedOptions;
    }

    // ─── Plugin Config / Rate Limiting ────────────────────────

    /**
     * Read a PassKey plugin config value (cached inside the options object).
     */
    private function getPluginConfigValue(string $key, $default = null)
    {
        try {
            $config = (array) $this->getSiteOptions()->plugin('PassKey');
            return array_key_exists($key, $config) ? $config[$key] : $default;
        } catch (\Throwable $e) {
            return $default;
        }
    }

    private function isRateLimitEnabled(): bool
    {
        return (string) $this->getPluginConfigValue('rateLimitEnabled', '1') !== '0';
    }

    /**
     * Lightweight per-IP / per-scope sliding-window rate limiting backed by
     * temp files (avoids the varchar(32) constraint on options.name).
     *
     * @throws \RuntimeException when the limit is exceeded
     */
    private function enforceRateLimit(string $scope): void
    {
        if (!$this->isRateLimitEnabled()) {
            return;
        }

        $ip = trim((string) $this->request->getIp());
        if ($ip === '') {
            $ip = 'unknown';
        }

        $window = (int) max(1, (int) $this->getPluginConfigValue('rateLimitWindow', 60));
        $max = (int) max(1, (int) $this->getPluginConfigValue('rateLimitMax', 30));
        $file = sys_get_temp_dir() . '/passkey_rl_' . md5(__FILE__ . '|' . $scope . '|' . $ip) . '.json';
        $now = time();

        $data = ['count' => 0, 'window' => $now];
        if (is_file($file)) {
            $raw = @file_get_contents($file);
            $parsed = json_decode((string) $raw, true);
            if (is_array($parsed)) {
                $data = $parsed;
                if ((int) ($data['window'] ?? 0) < $now - $window) {
                    $data = ['count' => 0, 'window' => $now];
                }
            }
        }

        $data['count'] = (int) ($data['count'] ?? 0) + 1;
        @file_put_contents($file, json_encode($data));

        if ($data['count'] > $max) {
            throw new \RuntimeException('操作过于频繁，请稍后再试');
        }
    }

    /**
     * Detect a misconfigured siteUrl (e.g. left as http://localhost:8080)
     * and surface it clearly instead of silently failing origin checks.
     */
    private function warnIfSiteUrlMisconfigured(): void
    {
        try {
            $expected = $this->getExpectedOrigin();
            $hostHeader = strtolower(trim((string) $this->request->getServer('HTTP_HOST')));
            if ($expected === '' || $hostHeader === '') {
                return;
            }

            $expectedParts = parse_url($expected);
            $expectedHost = strtolower((string) ($expectedParts['host'] ?? ''));
            $requestHost = $hostHeader;

            $isLocalhostPlaceholder = in_array($expectedHost, ['localhost', '127.0.0.1', '::1'], true);
            if ($isLocalhostPlaceholder && $expectedHost !== $requestHost) {
                @error_log(
                    '[PassKey] siteUrl 仍为 localhost/127.0.0.1（' . $expected
                    . '），与实际访问域名 ' . $requestHost . ' 不一致。'
                    . '请到 设置→基本 将站点地址改为实际域名，否则通行密钥登录/绑定会被来源校验拒绝。',
                    0
                );
            }
        } catch (\Throwable $e) {
            // 诊断信息不应影响主流程
        }
    }

    // ─── Field Labels ─────────────────────────────────────────

    private function getFieldLabel(string $fieldName): string
    {
        $labels = [
            'rawId' => '凭据 ID',
            'clientDataJSON' => '客户端数据',
            'attestationObject' => '注册凭据数据',
            'authenticatorData' => '认证器数据',
            'signature' => '签名',
            'userHandle' => '用户标识',
            'storedPublicKey' => '已保存的公钥',
            'challenge' => '挑战参数',
        ];

        return $labels[$fieldName] ?? $fieldName;
    }

    // ─── Origin Comparison ────────────────────────────────────

    private function isSameOrigin(string $targetUrl, string $expectedOrigin): bool
    {
        $targetParts = parse_url($targetUrl);
        $expectedParts = parse_url($expectedOrigin);
        if (!is_array($targetParts) || !is_array($expectedParts)) {
            return false;
        }

        $targetScheme = strtolower((string) ($targetParts['scheme'] ?? ''));
        $targetHost = strtolower((string) ($targetParts['host'] ?? ''));
        $targetPort = isset($targetParts['port']) ? (int) $targetParts['port'] : ($targetScheme === 'https' ? 443 : 80);

        $expectedScheme = strtolower((string) ($expectedParts['scheme'] ?? ''));
        $expectedHost = strtolower((string) ($expectedParts['host'] ?? ''));
        $expectedPort = isset($expectedParts['port']) ? (int) $expectedParts['port'] : ($expectedScheme === 'https' ? 443 : 80);

        return $targetScheme === $expectedScheme
            && $targetHost === $expectedHost
            && $targetPort === $expectedPort;
    }

    private function isDefaultPort(string $scheme, int $port): bool
    {
        if ($scheme === 'https' && $port === 443) {
            return true;
        }

        return $scheme === 'http' && $port === 80;
    }

    // ─── JSON Body Decoding ───────────────────────────────────

    private function decodeJsonBody(): array
    {
        $raw = file_get_contents('php://input', false, null, 0, self::MAX_JSON_BODY_BYTES + 1);
        if (!is_string($raw) || $raw === '') {
            $this->sendJson(false, '请求体不能为空', null, 400);
        }

        if (strlen($raw) > self::MAX_JSON_BODY_BYTES) {
            $this->sendJson(false, '请求体过大', null, 413);
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $this->sendJson(false, 'JSON 请求体无效', null, 400);
        }

        return $data;
    }

    // ─── Nonce Replay Protection ──────────────────────────────
    //
    // Each nonce is stored as a separate row in table.options with
    // name = pkn_{hash} and user = 0.  This avoids the
    // read-modify-write race condition that a single serialized
    // array would have under concurrent requests.
    //
    // IMPORTANT: Typecho's options.name column is VARCHAR(32), so the
    // nonce name must stay within 32 characters (4 prefix + 28 hash).

    private function consumeNonce(string $jti): void
    {
        $this->cleanupExpiredNonces();

        $nonceName = self::NONCE_STORAGE_PREFIX . substr(hash('sha256', $jti), 0, 28);
        $expiresAt = time() + self::CHALLENGE_TTL;

        $db = $this->db;

        try {
            $db->query(
                $db->insert('table.options')
                    ->rows([
                        'name' => $nonceName,
                        'user' => 0,
                        'value' => (string) $expiresAt,
                    ])
            );
            // Insert succeeded — nonce is now consumed.
            return;
        } catch (\Throwable $e) {
            // Duplicate key — a row for this nonce already exists.
            // Fall through to check whether the existing row is stale.
        }

        $row = $db->fetchObject(
            $db->select('value')
                ->from('table.options')
                ->where('name = ? AND user = ?', $nonceName, 0)
        );

        if (!is_object($row) || !isset($row->value)) {
            throw new \RuntimeException('挑战令牌已使用');
        }

        $storedExpiresAt = (int) $row->value;
        $now = time();

        if ($storedExpiresAt > $now) {
            // Nonce is still valid — replay attack
            throw new \RuntimeException('挑战令牌已使用');
        }

        // Stale nonce — overwrite it with the new expiration.
        $db->query(
            $db->update('table.options')
                ->rows(['value' => (string) $expiresAt])
                ->where('name = ? AND user = ?', $nonceName, 0)
        );
    }

    private function cleanupExpiredNonces(): void
    {
        if (random_int(0, self::NONCE_CLEANUP_PROBABILITY - 1) !== 0) {
            return;
        }

        $db = $this->db;
        $now = time();

        // Fetch all nonce rows (bounded by CHALLENGE_TTL, so typically
        // only a few hundred at most on a busy site).
        $rows = $db->fetchAll(
            $db->select('name, value')
                ->from('table.options')
                ->where('name LIKE ? AND user = ?', self::NONCE_STORAGE_PREFIX . '%', 0)
        );

        if (!is_array($rows) || empty($rows)) {
            return;
        }

        foreach ($rows as $row) {
            $name = isset($row['name']) ? (string) $row['name'] : '';
            $expiresAt = isset($row['value']) ? (int) $row['value'] : 0;
            if ($name === '' || $expiresAt >= $now) {
                continue;
            }

            $db->query(
                $db->delete('table.options')
                    ->where('name = ? AND user = ?', $name, 0)
            );
        }
    }

    // ─── JSON Response ────────────────────────────────────────

    /**
     * Send a JSON response and terminate.
     *
     * @param bool  $success
     * @param string $message
     * @param mixed $data
     * @param int   $status  HTTP status code
     * @return never
     */
    private function sendJson(bool $success, string $message, $data = null, int $status = 200): void
    {
        $this->response->setStatus($status);
        $this->response->setContentType('application/json');
        $this->response->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
        $this->response->setHeader('Pragma', 'no-cache');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');

        $result = [
            'success' => $success,
            'message' => $message,
        ];

        if ($data !== null) {
            $result['data'] = $data;
        }

        if (function_exists('ob_get_level') && ob_get_level() > 0) {
            ob_clean();
        }

        echo json_encode($result);
        exit;
    }
}
