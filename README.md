# PassKey

Typecho 通行密钥（WebAuthn / Passkey）登录与管理插件。

## 功能

- 后台登录页支持通行密钥登录
- 个人设置页支持绑定、重命名、解绑通行密钥
- 服务端校验 `challenge`、`origin`、`rpId`、签名和 `signCount`
- 登录使用 Typecho 标准 `simpleLogin`，并补充 session 安全处理
- 非 HTTPS / 非安全上下文页面会直接提示不可用

## 环境要求

- Typecho >= 1.2.0
- 浏览器支持 WebAuthn / Passkey
- PHP 已启用 OpenSSL 扩展
- PHP 已启用 Session

## 使用说明

1. 系统设置中的站点地址必须填写为实际访问地址，并且包含协议和域名，例如 `https://blog.example.com`
2. 通行密钥仅支持安全上下文，正式环境请使用 HTTPS
3. 进入个人设置，点击“绑定通行密钥”
4. 按系统弹窗完成绑定
5. 登录页点击“通行密钥登录”完成验证

## 注意

- `siteUrl` 必须和你实际访问后台的域名一致
- 如果站点域名发生变化，已绑定的通行密钥通常需要重新绑定

## 安全加固（1.1.0 渗透测试修复）

本次安全审计修复了以下问题：

1. **Attestation 真实性验证**（核心）：原实现对 `none`/`packed`/`fido-u2f`
   只解析结构、不验证任何签名，攻击者可构造任意公钥注册成为后门。
   现已实现：
   - `none`：强制 `attStmt` 为空（禁止隐藏数据夹带）
   - `packed` / `fido-u2f`：验证签名确实由声明证书私钥签发 + 证书链一致性
   - 支持策略配置：`none`（宽松）/ `preferred` / `required`（仅接受验证通过的 packed/fido-u2f）
2. **接口速率限制**：`challenge` / `verify` / `register*` 基于 IP 的滑动窗口限流（默认 60s / 30 次），防自动化爆破与批量注册
3. **siteUrl 配置检测**：检测到站点地址仍为 localhost/127.0.0.1 且与实际域名不符时，写入明确警告日志
4. **审计日志**：每次绑定 / 登录记录 `[PassKey][audit]` 事件（uid、凭据、格式、IP）

> ⚠️ 残留风险说明：`attestation:'none'` 是 WebAuthn 规范允许的格式，
> 攻击者可利用合法的空 `attStmt` 注册自有密钥（无法用格式验证阻止）；
> 同理，无信任锚时无法完全阻止自建证书链。因此 attestation 验证是**深度防御**，
> 最有效的根本防线是：登录凭据安全 + 保持限流开启 + 检查审计日志。

## 插件设置项

| 配置 | 说明 | 默认 |
|------|------|------|
| `attestationPolicy` | Attestation 校验策略：none / preferred / required | `none` |
| `rateLimitEnabled` | 接口速率限制开关 | 启用 |
| `allowDisable` | 是否允许禁用插件 | 禁止 |

## 路由

- `POST /passkey/challenge` 获取登录 challenge
- `POST /passkey/verify` 提交通行密钥断言并登录
- `POST /passkey/register/options` 获取绑定参数
- `POST /passkey/register/finish` 完成绑定并保存凭据

## 存储

- 用户通行密钥数据保存在 `table.options` 的 `passkey_user_data`
- 凭据索引保存在 `table.options` 的 `passkey_setup`

## 1.1.0

- 完善 WebAuthn 注册、登录阶段的服务端校验
- 修复插件升级、禁用再启用后的兼容问题
- 优化存储结构，拆分用户数据和全局索引
- 登录和绑定提示统一改为中文
- 非 HTTPS 页面下增加更明确的使用提示
- 【安全】attestation 真实性验证（签名 + 证书链 + 策略）
- 【安全】接口速率限制、siteUrl 配置检测、审计日志
