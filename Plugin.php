<?php

namespace TypechoPlugin\PassKey;

use Typecho\Common;
use Typecho\Plugin\Exception;
use Typecho\Plugin\PluginInterface;
use Typecho\Request;
use Typecho\Widget;
use Typecho\Widget\Helper\Form;
use Typecho\Widget\Helper\Form\Element\Hidden;
use Utils\Helper;
use Widget\Options;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

// Typecho 的插件自动加载器（TypechoPlugin\ 命名空间）在不同版本/环境下
// 并不总是可靠（尤其是 Linux 上目录名大小写敏感时）。这里在插件激活时
// 显式加载全部插件类，避免后续路由匹配时出现 "Class not found" 报错。
require_once __DIR__ . '/Model.php';
require_once __DIR__ . '/WebAuthn.php';
require_once __DIR__ . '/Action.php';

/**
 * 多用户 PassKey 认证插件，<a href="https://www.dbkuaizi.com/archives/passkey-plugin.html">使用帮助</a>
 *
 * @package PassKey
 * @author 两双筷子
 * @version 1.1.0
 * @link https://www.dbkuaizi.com
 * @since 1.2.0
 */
class Plugin implements PluginInterface
{
    private const PLUGIN_NAME = 'PassKey';
    private const ALLOW_DISABLE_KEY = 'allowDisable';

    private const VERIFY_ROUTE_NAME = 'passkey_verify';
    private const VERIFY_ROUTE_PATH = '/passkey/verify';
    private const CHALLENGE_ROUTE_NAME = 'passkey_challenge';
    private const CHALLENGE_ROUTE_PATH = '/passkey/challenge';
    private const REGISTER_OPTIONS_ROUTE_NAME = 'passkey_register_options';
    private const REGISTER_OPTIONS_ROUTE_PATH = '/passkey/register/options';
    private const REGISTER_FINISH_ROUTE_NAME = 'passkey_register_finish';
    private const REGISTER_FINISH_ROUTE_PATH = '/passkey/register/finish';

    private const ROUTE_MAP = [
        self::VERIFY_ROUTE_NAME => self::VERIFY_ROUTE_PATH,
        self::CHALLENGE_ROUTE_NAME => self::CHALLENGE_ROUTE_PATH,
        self::REGISTER_OPTIONS_ROUTE_NAME => self::REGISTER_OPTIONS_ROUTE_PATH,
        self::REGISTER_FINISH_ROUTE_NAME => self::REGISTER_FINISH_ROUTE_PATH,
    ];

    // ─── Plugin Lifecycle ─────────────────────────────────────

    /**
     * @throws Exception
     */
    public static function activate(): string
    {
        if (version_compare(Common::VERSION, '1.2.0', '<')) {
            throw new Exception('该插件要求 Typecho 1.2.0 及以上版本');
        }

        Model::ensureStorageReady();
        self::ensureRoutesRegistered();

        \Typecho\Plugin::factory('admin/footer.php')->end = [__CLASS__, 'loginInput'];
        return 'PassKey 插件已启用';
    }

    public static function deactivate(): void
    {
        $pluginConfig = Options::alloc()->plugin(self::PLUGIN_NAME);
        if (empty($pluginConfig->{self::ALLOW_DISABLE_KEY})) {
            throw new Exception('请先在插件设置中开启"允许禁用插件"，再执行禁用。');
        }

        foreach (self::ROUTE_MAP as $name => $path) {
            Helper::removeRoute($name);
        }
    }

    // ─── Plugin Config Page ───────────────────────────────────

    public static function config(Form $form): void
    {
        Model::ensureStorageReady();
        self::ensureRoutesRegistered();

        $attestationPolicy = new Form\Element\Select(
            'attestationPolicy',
            [
                'none' => _t('宽松（默认，兼容所有认证器）'),
                'preferred' => _t('优先可验证（packed/fido-u2f 通过验证，仍接受 none）'),
                'required' => _t('严格（仅接受通过验证的 packed/fido-u2f）'),
            ],
            'none',
            _t('Attestation 校验策略'),
            _t('宽松：none/packed/fido-u2f 均可绑定，但攻击者可用自签证书伪造 packed。'
                . '严格：仅接受通过签名与证书链验证的 packed/fido-u2f，可抵御绝大多数伪造注册。')
        );
        $form->addInput($attestationPolicy);

        $rateLimitEnabled = new Form\Element\Radio(
            'rateLimitEnabled',
            [1 => _t('启用'), 0 => _t('关闭')],
            '1',
            _t('接口速率限制'),
            _t('基于 IP 对 challenge / verify / register 接口做滑动窗口限流，防止自动化爆破与批量注册。')
        );
        $form->addInput($rateLimitEnabled);

        $allowDisable = new Form\Element\Radio(
            self::ALLOW_DISABLE_KEY,
            [1 => _t('允许禁用'), 0 => _t('禁止禁用')],
            '0',
            _t('是否允许禁用插件'),
            _t('禁用插件前请先确认，避免影响登录验证和个人设置页管理入口。')
        );
        $form->addInput($allowDisable);
    }

    // ─── Personal Config Page ─────────────────────────────────

    public static function personalConfig(Form $form): void
    {
        Model::ensureStorageReady();
        self::ensureRoutesRegistered();

        $config = Model::getCurrentUserConfig();
        $passkeys = Model::getCurrentUserPasskeys();
        $optionsBase = rtrim(Options::alloc()->index, '/');

        $listHtml = self::buildPasskeyListHtml($passkeys);

        $ui = Model::renderTemplate('personal.tpl', [
            '{passkeyListHtml}' => $listHtml,
            '{bindBtnText}' => '绑定通行密钥',
            '{registerOptionsUrlJson}' => json_encode($optionsBase . self::REGISTER_OPTIONS_ROUTE_PATH, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            '{registerFinishUrlJson}' => json_encode($optionsBase . self::REGISTER_FINISH_ROUTE_PATH, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            '{formId}' => self::PLUGIN_NAME,
        ]);

        $form->addInput(self::buildHtmlElement('passkey_ui', $ui));
        $form->addInput((new Hidden('action'))->value('none'));
        $form->addInput(new Hidden('update_credential_id'));
        $form->addInput(new Hidden('remark'));
        $form->addInput(new Hidden('remove_credential_id'));
        $form->addInput((new Hidden('credential_id'))->value((string) ($config['credential_id'] ?? '')));
        $form->addInput((new Hidden('public_key'))->value((string) ($config['public_key'] ?? '')));
        $form->addInput((new Hidden('sign_count'))->value((string) ($config['sign_count'] ?? '0')));
        $form->addInput((new Hidden('credential_index_json'))->value('{}'));
        $form->addInput((new Hidden('passkeys_json'))->value((string) ($config['passkeys_json'] ?? '[]')));
        $form->addInput((new Hidden('name'))->value((string) ($config['name'] ?? '')));
        $form->addInput((new Hidden('created'))->value((string) ($config['created'] ?? '0')));

        self::addLegacyConfigInputs($form, $config);
    }

    public static function personalConfigHandle($settings, $isSetup): void
    {
        Model::handlePersonalConfig($settings, $isSetup);
    }

    // ─── Login Page Injection ─────────────────────────────────

    public static function loginInput(): void
    {
        Model::ensureStorageReady();
        self::ensureRoutesRegistered();

        if (Widget::widget('Widget_User')->hasLogin()) {
            return;
        }

        if (strpos(Request::getInstance()->getRequestUri(), 'login.php') === false) {
            return;
        }

        $optionsBase = rtrim(Options::alloc()->index, '/');
        $verifyUrl = $optionsBase . self::VERIFY_ROUTE_PATH;
        $challengeUrl = $optionsBase . self::CHALLENGE_ROUTE_PATH;

        echo Model::renderTemplate('login-button.tpl', [
            '{verifyUrlJson}' => json_encode($verifyUrl, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            '{challengeUrlJson}' => json_encode($challengeUrl, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    }

    // ─── Private Helpers ──────────────────────────────────────

    private static function buildPasskeyListHtml(array $passkeys): string
    {
        if (empty($passkeys)) {
            return '<p class="description passkey-empty">暂无已绑定通行密钥</p>';
        }

        $html = '<div class="passkey-card-list">';
        foreach ($passkeys as $item) {
            $nameRaw = (string) ($item['remark'] ?? $item['name'] ?? '');
            $name = htmlspecialchars($nameRaw, ENT_QUOTES);
            if ($name === '') {
                $name = '（未填写）';
            }

            $created = date('Y-m-d H:i:s', (int) $item['created']);
            $id = htmlspecialchars((string) $item['credential_id'], ENT_QUOTES);
            $nameAttr = htmlspecialchars($nameRaw, ENT_QUOTES);

            $html .= '<article class="passkey-card">';
            $html .= '<div class="passkey-card-info">';
            $html .= '<p><span class="passkey-key">名称：</span><span>' . $name . '</span></p>';
            $html .= '<p><span class="passkey-key">绑定时间：</span><span>' . $created . '</span></p>';
            $html .= '</div>';
            $html .= '<div class="passkey-card-actions">';
            $html .= '<a href="#" class="passkey-text-action passkey-edit-btn" data-credential-id="' . $id . '" data-remark="' . $nameAttr . '">修改名称</a>';
            $html .= '<a href="#" class="passkey-text-action passkey-delete-btn" data-credential-id="' . $id . '">解绑</a>';
            $html .= '</div>';
            $html .= '</article>';
        }
        $html .= '</div>';

        return $html;
    }

    /**
     * Build a read-only HTML form element for embedding arbitrary HTML.
     */
    private static function buildHtmlElement(string $name, string $html): object
    {
        return new class($name, $html) extends \Typecho\Widget\Helper\Form\Element {
            /** @var string */
            private $htmlContent;

            public function __construct(string $name, string $html)
            {
                $this->htmlContent = $html;
                parent::__construct($name, null, null, null, null);
            }

            public function input(?string $name = null, ?array $options = null): ?\Typecho\Widget\Helper\Layout
            {
                $node = new \Typecho\Widget\Helper\Layout('div', ['class' => 'passkey-ui-root']);
                $node->html($this->htmlContent);
                $this->container($node);
                return $node;
            }

            protected function inputValue($value): void
            {
            }
        };
    }

    /**
     * Inject legacy config keys as hidden inputs so they survive form submissions.
     */
    private static function addLegacyConfigInputs(Form $form, array $config): void
    {
        $existingInputs = $form->getInputs();
        foreach ($config as $key => $value) {
            if (!is_string($key) || $key === '' || isset($existingInputs[$key])) {
                continue;
            }

            if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $key)) {
                continue;
            }

            if (is_array($value) || is_object($value)) {
                continue;
            }

            $form->addInput((new Hidden($key))->value((string) $value));
        }
    }

    /**
     * Ensure all plugin routes are registered.  Idempotent — skips routes that
     * already point to the correct widget and action.
     */
    private static function ensureRoutesRegistered(): void
    {
        $routingTable = Options::alloc()->routingTable;
        if (!is_array($routingTable)) {
            return;
        }

        // Typecho sometimes stores a numeric-keyed entry; remove it
        if (isset($routingTable[0])) {
            unset($routingTable[0]);
        }

        foreach (self::ROUTE_MAP as $name => $path) {
            $route = $routingTable[$name] ?? null;
            if (
                is_array($route)
                && ($route['url'] ?? '') === $path
                && ($route['widget'] ?? '') === Action::class
                && ($route['action'] ?? '') === 'action'
            ) {
                continue;
            }

            Helper::addRoute($name, $path, Action::class, 'action');
            $routingTable = Options::alloc()->routingTable;
            if (isset($routingTable[0])) {
                unset($routingTable[0]);
            }
        }
    }
}
