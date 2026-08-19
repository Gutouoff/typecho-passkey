<?php

namespace TypechoPlugin\PassKey;

use Typecho\Common;
use Typecho\Db;
use Typecho\Widget;
use Utils\Helper;
use Widget\Base\Options as BaseOptions;
use Widget\Notice;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Model
{
    private const PERSONAL_CONFIG_KEY = '_plugin:PassKey';
    private const USER_STORAGE_KEY = 'passkey_user_data';
    private const SETUP_STORAGE_KEY = 'passkey_setup';
    private const SETUP_USER = 0;
    private const CREDENTIAL_INDEX_KEY = 'credential_index_json';
    private const MAX_REMARK_CHARS = 64;
    private const MAX_CREDENTIAL_ID_LENGTH = 2048;
    private const MAX_PUBLIC_KEY_LENGTH = 8192;
    private const MAX_PASSKEYS_PER_USER = 32;
    private const SUPPORTED_ALGORITHMS = [-7, -257];

    /** @var bool */
    private static $storageReady = false;

    // ─── Template Rendering ───────────────────────────────────

    public static function renderTemplate(string $file, array $params = []): string
    {
        $path = __DIR__ . '/' . ltrim($file, '/');
        if (!is_file($path)) {
            return '';
        }

        $template = file_get_contents($path);
        if ($template === false || empty($params)) {
            return (string) $template;
        }

        return str_replace(array_keys($params), array_values($params), $template);
    }

    // ─── Personal Config Handling ─────────────────────────────

    public static function handlePersonalConfig($settings, $isSetup): void
    {
        self::ensureStorageReady();

        if ($isSetup) {
            self::ensurePersonalConfigStub();
            return;
        }

        $action = isset($settings['action']) ? (string) $settings['action'] : 'none';
        if ($action === '' || $action === 'none') {
            return;
        }

        if (!in_array($action, ['update', 'delete', 'unbind'], true)) {
            Notice::alloc()->set(_t('不支持的操作'), 'error');
            Helper::options()->response->goBack();
            return;
        }

        try {
            if ($action === 'update') {
                $updateId = trim((string) ($settings['update_credential_id'] ?? ''));
                $remark = trim((string) ($settings['remark'] ?? ''));
                self::updateCurrentUserCredentialMeta($updateId, $remark);
                Notice::alloc()->set(_t('通行密钥名称已更新'), 'success');
                Helper::options()->response->goBack();
                return;
            }

            if ($action === 'delete') {
                $removeId = trim((string) ($settings['remove_credential_id'] ?? ''));
                self::deleteCurrentUserCredential($removeId);
                Notice::alloc()->set(_t('通行密钥已解绑'), 'success');
                Helper::options()->response->goBack();
                return;
            }

            // unbind
            self::unbindCurrentUserCredentials();
            Notice::alloc()->set(_t('已移除全部通行密钥'), 'success');
            Helper::options()->response->goBack();
        } catch (\InvalidArgumentException $e) {
            Notice::alloc()->set($e->getMessage(), 'error');
            Helper::options()->response->goBack();
        }
    }

    // ─── User Config / Passkey Queries ────────────────────────

    /**
     * @return array|string
     */
    public static function getCurrentUserConfig($key = null)
    {
        self::ensureStorageReady();

        $config = self::getUserConfigByUid((int) Widget::widget('Widget_User')->uid);
        if ($key === null) {
            return $config;
        }

        return $config[$key] ?? '';
    }

    /**
     * @return array<int, array{credential_id: string, name: string, remark: string, public_key: string, algorithm: int, sign_count: int, created: int}>
     */
    public static function getCurrentUserPasskeys(): array
    {
        return self::parsePasskeysFromConfig(self::getCurrentUserConfig());
    }

    public static function findUserIdByCredentialId(string $credentialId): int
    {
        $found = self::findPasskeyOwnerAndDataByCredentialId($credentialId);
        return $found ? (int) $found['uid'] : 0;
    }

    /**
     * @return array{uid: int, passkey: array}|null
     */
    public static function findPasskeyOwnerAndDataByCredentialId(string $credentialId): ?array
    {
        self::ensureStorageReady();

        $credentialId = trim($credentialId);
        if ($credentialId === '' || strlen($credentialId) > self::MAX_CREDENTIAL_ID_LENGTH) {
            return null;
        }

        $uid = self::findIndexedUserIdByCredentialId($credentialId);
        if ($uid <= 0) {
            return null;
        }

        $config = self::getUserConfigByUid($uid);
        if (empty($config)) {
            self::removeCredentialIndexEntry($credentialId, $uid);
            return null;
        }

        $passkeys = self::parsePasskeysFromConfig($config);
        foreach ($passkeys as $item) {
            if (hash_equals((string) $item['credential_id'], $credentialId)) {
                return [
                    'uid' => $uid,
                    'passkey' => $item,
                ];
            }
        }

        // Stale index entry — clean up
        self::removeCredentialIndexEntry($credentialId, $uid);
        return null;
    }

    // ─── Admin URL ────────────────────────────────────────────

    public static function getAdminRedirectUrl(): string
    {
        $adminUrl = Common::url('admin/', Widget::widget('Widget_Options')->siteUrl);
        return str_replace('index.php/', '', $adminUrl);
    }

    // ─── Credential CRUD ──────────────────────────────────────

    public static function saveVerifiedCredential(
        int $uid,
        string $credentialId,
        string $remark,
        string $publicKey,
        int $algorithm,
        int $signCount = 0
    ): void {
        $credentialId = trim($credentialId);
        $remark = trim($remark);
        $publicKey = trim($publicKey);
        $signCount = max(0, $signCount);

        if ($uid <= 0) {
            throw new \InvalidArgumentException('用户无效');
        }

        if ($credentialId === '' || $publicKey === '') {
            throw new \InvalidArgumentException('通行密钥数据不完整');
        }

        if (strlen($credentialId) > self::MAX_CREDENTIAL_ID_LENGTH) {
            throw new \InvalidArgumentException('通行密钥标识长度超出限制');
        }

        if (strlen($publicKey) > self::MAX_PUBLIC_KEY_LENGTH) {
            throw new \InvalidArgumentException('通行密钥公钥长度超出限制');
        }

        if (Common::strLen($remark) > self::MAX_REMARK_CHARS) {
            throw new \InvalidArgumentException('名称不能超过 64 个字符');
        }

        if (!in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new \InvalidArgumentException('不支持的密钥算法');
        }

        $owner = self::findUserIdByCredentialId($credentialId);
        if ($owner > 0 && $owner !== $uid) {
            throw new \InvalidArgumentException('这把通行密钥已绑定到其他账号');
        }

        $config = self::getUserConfigByUid($uid);
        $passkeys = self::parsePasskeysFromConfig($config);
        $found = false;

        foreach ($passkeys as &$item) {
            if (!hash_equals((string) $item['credential_id'], $credentialId)) {
                continue;
            }

            $item['remark'] = $remark;
            $item['name'] = $remark !== '' ? $remark : '通行密钥';
            $item['public_key'] = $publicKey;
            $item['algorithm'] = $algorithm;
            $item['sign_count'] = $signCount;
            if (empty($item['created'])) {
                $item['created'] = time();
            }
            $found = true;
            break;
        }
        unset($item);

        if (!$found) {
            if (count($passkeys) >= self::MAX_PASSKEYS_PER_USER) {
                throw new \InvalidArgumentException('当前账号绑定的通行密钥数量已达上限');
            }

            $passkeys[] = [
                'credential_id' => $credentialId,
                'name' => $remark !== '' ? $remark : '通行密钥',
                'remark' => $remark,
                'public_key' => $publicKey,
                'algorithm' => $algorithm,
                'sign_count' => $signCount,
                'created' => time(),
            ];
        }

        self::saveUserPasskeys($uid, $passkeys);
        self::syncCredentialIndexForUser($uid, $passkeys);
    }

    public static function updateCurrentUserCredentialMeta(string $credentialId, string $remark): void
    {
        $credentialId = trim($credentialId);
        if ($credentialId === '') {
            throw new \InvalidArgumentException('通行密钥标识不能为空');
        }

        $remark = trim($remark);
        if (Common::strLen($remark) > self::MAX_REMARK_CHARS) {
            throw new \InvalidArgumentException('名称不能超过 64 个字符');
        }

        $passkeys = self::getCurrentUserPasskeys();
        $found = false;

        foreach ($passkeys as &$item) {
            if (hash_equals((string) $item['credential_id'], $credentialId)) {
                $item['remark'] = $remark;
                $item['name'] = $remark !== '' ? $remark : '通行密钥';
                $found = true;
                break;
            }
        }
        unset($item);

        if (!$found) {
            throw new \InvalidArgumentException('未找到这把通行密钥');
        }

        self::saveCurrentUserPasskeys($passkeys);
    }

    public static function updateCredentialSignCount(int $uid, string $credentialId, int $signCount): void
    {
        $credentialId = trim($credentialId);
        $signCount = max(0, $signCount);
        if ($uid <= 0 || $credentialId === '') {
            return;
        }

        $config = self::getUserConfigByUid($uid);
        if (empty($config)) {
            return;
        }

        $passkeys = self::parsePasskeysFromConfig($config);
        $changed = false;

        foreach ($passkeys as &$item) {
            if (!hash_equals((string) $item['credential_id'], $credentialId)) {
                continue;
            }

            if ((int) ($item['sign_count'] ?? 0) !== $signCount) {
                $item['sign_count'] = $signCount;
                $changed = true;
            }
            break;
        }
        unset($item);

        if ($changed) {
            self::saveUserPasskeys($uid, $passkeys);
        }
    }

    public static function deleteCurrentUserCredential(string $credentialId): void
    {
        $credentialId = trim($credentialId);
        if ($credentialId === '') {
            throw new \InvalidArgumentException('通行密钥标识不能为空');
        }

        $passkeys = self::getCurrentUserPasskeys();
        $filtered = [];
        $found = false;

        foreach ($passkeys as $item) {
            if (hash_equals((string) $item['credential_id'], $credentialId)) {
                $found = true;
                continue;
            }
            $filtered[] = $item;
        }

        if (!$found) {
            throw new \InvalidArgumentException('未找到这把通行密钥');
        }

        self::saveCurrentUserPasskeys($filtered);
        self::syncCredentialIndexForUser((int) Widget::widget('Widget_User')->uid, $filtered);
    }

    public static function unbindCurrentUserCredentials(): void
    {
        self::ensureStorageReady();

        $uid = (int) Widget::widget('Widget_User')->uid;
        BaseOptions::alloc()->delete(
            Db::get()->sql()->where('name = ? AND user = ?', self::USER_STORAGE_KEY, $uid)
        );

        self::syncCredentialIndexForUser($uid, []);
    }

    // ─── Storage Initialization ───────────────────────────────

    public static function ensureStorageReady(): void
    {
        if (self::$storageReady) {
            return;
        }

        self::$storageReady = true;
        self::migrateLegacyStorage();
        self::ensurePersonalConfigStub();
        self::ensureSetupRecord();
    }

    // ─── Private: Personal Config Stub ────────────────────────

    private static function ensurePersonalConfigStub(): void
    {
        $db = Db::get();
        $stubValue = serialize([
            self::CREDENTIAL_INDEX_KEY => '{}',
        ]);

        $stubExists = (int) $db->fetchObject(
            $db->select(['COUNT(*)' => 'num'])
                ->from('table.options')
                ->where('name = ? AND user = ?', self::PERSONAL_CONFIG_KEY, self::SETUP_USER)
        )->num;

        if ($stubExists > 0) {
            BaseOptions::alloc()->update(
                ['value' => $stubValue],
                $db->sql()->where('name = ? AND user = ?', self::PERSONAL_CONFIG_KEY, self::SETUP_USER)
            );
            return;
        }

        BaseOptions::alloc()->insert([
            'name' => self::PERSONAL_CONFIG_KEY,
            'value' => $stubValue,
            'user' => self::SETUP_USER,
        ]);
    }

    // ─── Private: Setup Record (Credential Index) ─────────────

    private static function ensureSetupRecord(): void
    {
        $db = Db::get();
        $exists = (int) $db->fetchObject(
            $db->select(['COUNT(*)' => 'num'])
                ->from('table.options')
                ->where('name = ? AND user = ?', self::SETUP_STORAGE_KEY, self::SETUP_USER)
        )->num;

        if ($exists > 0) {
            return;
        }

        BaseOptions::alloc()->insert([
            'name' => self::SETUP_STORAGE_KEY,
            'value' => serialize([
                self::CREDENTIAL_INDEX_KEY => '{}',
            ]),
            'user' => self::SETUP_USER,
        ]);
    }

    // ─── Private: User Passkey Persistence ────────────────────

    private static function saveCurrentUserPasskeys(array $passkeys): void
    {
        $uid = (int) Widget::widget('Widget_User')->uid;
        self::saveUserPasskeys($uid, $passkeys);
    }

    private static function saveUserPasskeys(int $uid, array $passkeys): void
    {
        self::ensureStorageReady();

        if ($uid <= 0) {
            return;
        }

        $passkeys = self::normalizePasskeys($passkeys);
        $json = json_encode($passkeys, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $first = $passkeys[0] ?? ['credential_id' => '', 'name' => '', 'created' => 0];

        $value = serialize([
            'passkeys_json' => $json ?: '[]',
            'credential_id' => (string) $first['credential_id'],
            'name' => (string) $first['name'],
            'created' => (int) $first['created'],
        ]);

        $db = Db::get();
        $exists = (int) $db->fetchObject(
            $db->select(['COUNT(*)' => 'num'])
                ->from('table.options')
                ->where('name = ? AND user = ?', self::USER_STORAGE_KEY, $uid)
        )->num;

        if ($exists > 0) {
            BaseOptions::alloc()->update(
                ['value' => $value],
                $db->sql()->where('name = ? AND user = ?', self::USER_STORAGE_KEY, $uid)
            );
        } else {
            BaseOptions::alloc()->insert([
                'name' => self::USER_STORAGE_KEY,
                'value' => $value,
                'user' => $uid,
            ]);
        }
    }

    // ─── Private: User Config Retrieval ───────────────────────

    private static function getUserConfigByUid(int $uid): array
    {
        self::ensureStorageReady();

        if ($uid <= 0) {
            return [];
        }

        $query = BaseOptions::alloc()->select()->where(
            'name = ? AND user = ?',
            self::USER_STORAGE_KEY,
            $uid
        );

        $result = Db::get()->fetchObject($query);
        if ($result === null) {
            return [];
        }

        return self::decodeConfigValue($result->value);
    }

    // ─── Private: Config Decoding ─────────────────────────────

    private static function decodeConfigValue(string $value): array
    {
        if ($value === '') {
            return [];
        }

        set_error_handler(static function () {
            return true;
        });

        try {
            $result = unserialize($value, ['allowed_classes' => false]);
            if (is_array($result)) {
                return $result;
            }
        } catch (\Throwable $e) {
            // Corrupt data — return empty
        } finally {
            restore_error_handler();
        }

        return [];
    }

    // ─── Private: Passkey Parsing ─────────────────────────────

    private static function parsePasskeysFromConfig(array $config): array
    {
        // Preferred: JSON blob
        $json = isset($config['passkeys_json']) ? (string) $config['passkeys_json'] : '';
        if ($json !== '') {
            $decoded = json_decode($json, true);
            if (is_array($decoded)) {
                return self::normalizePasskeys($decoded);
            }
        }

        // Legacy fallback: single credential stored in top-level fields
        if (!empty($config['credential_id'])) {
            $legacy = [
                [
                    'credential_id' => (string) $config['credential_id'],
                    'name' => !empty($config['name']) ? (string) $config['name'] : '通行密钥',
                    'remark' => !empty($config['name']) ? (string) $config['name'] : '',
                    'public_key' => '',
                    'algorithm' => 0,
                    'sign_count' => 0,
                    'created' => !empty($config['created']) ? (int) $config['created'] : time(),
                ],
            ];
            return self::normalizePasskeys($legacy);
        }

        return [];
    }

    // ─── Private: Credential Index ────────────────────────────

    private static function findIndexedUserIdByCredentialId(string $credentialId): int
    {
        $config = self::getSetupConfig();
        if (!array_key_exists(self::CREDENTIAL_INDEX_KEY, $config)) {
            $index = self::rebuildCredentialIndex();
            return (int) ($index[self::credentialIndexKey($credentialId)] ?? 0);
        }

        $index = self::getCredentialIndex();
        return (int) ($index[self::credentialIndexKey($credentialId)] ?? 0);
    }

    private static function removeCredentialIndexEntry(string $credentialId, int $expectedUid = 0): void
    {
        $credentialId = trim($credentialId);
        if ($credentialId === '') {
            return;
        }

        $index = self::getCredentialIndex();
        $key = self::credentialIndexKey($credentialId);
        if (!isset($index[$key])) {
            return;
        }

        if ($expectedUid > 0 && (int) $index[$key] !== $expectedUid) {
            return;
        }

        unset($index[$key]);
        self::saveCredentialIndex($index);
    }

    private static function rebuildCredentialIndex(): array
    {
        self::ensureStorageReady();

        $index = [];
        $rows = Db::get()->fetchAll(
            BaseOptions::alloc()->select()
                ->where('name = ?', self::USER_STORAGE_KEY)
                ->where('user > ?', 0)
        );

        foreach ($rows as $row) {
            $uid = (int) ($row['user'] ?? 0);
            if ($uid <= 0) {
                continue;
            }

            $config = self::decodeConfigValue($row['value']);
            if (empty($config)) {
                continue;
            }

            foreach (self::parsePasskeysFromConfig($config) as $item) {
                $credentialId = trim((string) ($item['credential_id'] ?? ''));
                if ($credentialId === '') {
                    continue;
                }

                $index[self::credentialIndexKey($credentialId)] = $uid;
            }
        }

        self::saveCredentialIndex($index);
        return $index;
    }

    private static function getCredentialIndex(): array
    {
        $config = self::getSetupConfig();
        $json = isset($config[self::CREDENTIAL_INDEX_KEY]) ? (string) $config[self::CREDENTIAL_INDEX_KEY] : '';
        if ($json === '') {
            return [];
        }

        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return [];
        }

        $index = [];
        foreach ($decoded as $key => $uid) {
            if (!is_string($key) || $key === '') {
                continue;
            }

            $intUid = (int) $uid;
            if ($intUid <= 0) {
                continue;
            }

            $index[$key] = $intUid;
        }

        return $index;
    }

    private static function saveCredentialIndex(array $index): void
    {
        ksort($index);

        $config = self::getSetupConfig();
        $config[self::CREDENTIAL_INDEX_KEY] = json_encode($index, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '{}';
        self::saveSetupConfig($config);
    }

    private static function syncCredentialIndexForUser(int $uid, array $passkeys): void
    {
        if ($uid <= 0) {
            return;
        }

        $index = self::getCredentialIndex();
        foreach ($index as $key => $ownerUid) {
            if ((int) $ownerUid === $uid) {
                unset($index[$key]);
            }
        }

        foreach (self::normalizePasskeys($passkeys) as $item) {
            $credentialId = trim((string) ($item['credential_id'] ?? ''));
            if ($credentialId === '') {
                continue;
            }

            $index[self::credentialIndexKey($credentialId)] = $uid;
        }

        self::saveCredentialIndex($index);
    }

    private static function credentialIndexKey(string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    // ─── Private: Setup Config Persistence ────────────────────

    private static function getSetupConfig(): array
    {
        self::ensureStorageReady();

        $query = BaseOptions::alloc()->select()->where(
            'name = ? AND user = ?',
            self::SETUP_STORAGE_KEY,
            self::SETUP_USER
        );

        $result = Db::get()->fetchObject($query);
        if ($result === null) {
            return [];
        }

        return self::decodeConfigValue($result->value);
    }

    private static function saveSetupConfig(array $config): void
    {
        self::ensureStorageReady();

        BaseOptions::alloc()->update(
            ['value' => serialize($config)],
            Db::get()->sql()->where('name = ? AND user = ?', self::SETUP_STORAGE_KEY, self::SETUP_USER)
        );
    }

    // ─── Private: Legacy Migration ────────────────────────────

    private static function migrateLegacyStorage(): void
    {
        $db = Db::get();

        // Migrate setup-level credential index
        $legacySetupRow = $db->fetchObject(
            BaseOptions::alloc()->select()->where(
                'name = ? AND user = ?',
                self::PERSONAL_CONFIG_KEY,
                self::SETUP_USER
            )
        );

        if ($legacySetupRow !== null) {
            $legacySetupConfig = self::decodeConfigValue($legacySetupRow->value);
            if (isset($legacySetupConfig[self::CREDENTIAL_INDEX_KEY])) {
                $setupExists = (int) $db->fetchObject(
                    $db->select(['COUNT(*)' => 'num'])
                        ->from('table.options')
                        ->where('name = ? AND user = ?', self::SETUP_STORAGE_KEY, self::SETUP_USER)
                )->num;

                if ($setupExists <= 0) {
                    BaseOptions::alloc()->insert([
                        'name' => self::SETUP_STORAGE_KEY,
                        'value' => serialize([
                            self::CREDENTIAL_INDEX_KEY => (string) $legacySetupConfig[self::CREDENTIAL_INDEX_KEY],
                        ]),
                        'user' => self::SETUP_USER,
                    ]);
                }
            }
        }

        // Migrate per-user passkey data
        $legacyUserRows = $db->fetchAll(
            BaseOptions::alloc()->select()
                ->where('name = ?', self::PERSONAL_CONFIG_KEY)
                ->where('user > ?', 0)
        );

        foreach ($legacyUserRows as $row) {
            $uid = (int) ($row['user'] ?? 0);
            $value = isset($row['value']) ? (string) $row['value'] : '';
            if ($uid <= 0 || $value === '') {
                continue;
            }

            $exists = (int) $db->fetchObject(
                $db->select(['COUNT(*)' => 'num'])
                    ->from('table.options')
                    ->where('name = ? AND user = ?', self::USER_STORAGE_KEY, $uid)
            )->num;

            if ($exists > 0) {
                continue;
            }

            BaseOptions::alloc()->insert([
                'name' => self::USER_STORAGE_KEY,
                'value' => $value,
                'user' => $uid,
            ]);
        }

        // Clean up legacy rows
        BaseOptions::alloc()->delete(
            $db->sql()->where('name = ? AND user > ?', self::PERSONAL_CONFIG_KEY, 0)
        );
    }

    // ─── Private: Passkey Normalization ───────────────────────

    private static function normalizePasskeys(array $passkeys): array
    {
        $result = [];
        $seen = [];

        foreach ($passkeys as $item) {
            if (!is_array($item)) {
                continue;
            }

            $credentialId = trim((string) ($item['credential_id'] ?? ''));
            if ($credentialId === '' || strlen($credentialId) > self::MAX_CREDENTIAL_ID_LENGTH || isset($seen[$credentialId])) {
                continue;
            }

            $seen[$credentialId] = true;
            $remark = trim((string) ($item['remark'] ?? ''));
            if ($remark === '') {
                $remark = trim((string) ($item['name'] ?? ''));
            }
            if (Common::strLen($remark) > self::MAX_REMARK_CHARS) {
                $remark = Common::subStr($remark, 0, self::MAX_REMARK_CHARS, '');
            }

            $publicKey = trim((string) ($item['public_key'] ?? ''));
            if ($publicKey !== '' && strlen($publicKey) > self::MAX_PUBLIC_KEY_LENGTH) {
                continue;
            }

            $algorithm = (int) ($item['algorithm'] ?? 0);
            if (!in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
                $algorithm = 0;
            }

            $result[] = [
                'credential_id' => $credentialId,
                'name' => $remark !== '' ? $remark : '通行密钥',
                'remark' => $remark,
                'public_key' => $publicKey,
                'algorithm' => $algorithm,
                'sign_count' => max(0, (int) ($item['sign_count'] ?? 0)),
                'created' => (int) ($item['created'] ?? time()),
            ];

            if (count($result) >= self::MAX_PASSKEYS_PER_USER) {
                break;
            }
        }

        usort($result, static function ($a, $b) {
            return (int) $b['created'] <=> (int) $a['created'];
        });

        return $result;
    }
}
