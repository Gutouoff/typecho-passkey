<style>
#passkey-login-row {
    display: flex;
    gap: 8px;
    align-items: stretch;
}
#passkey-login-row > .btn {
    flex: 1;
    width: 100%;
    line-height: 40px;
    min-height: 40px;
    padding-top: 0;
    padding-bottom: 0;
}
@media (max-width: 575px) {
    #passkey-login-row {
        flex-direction: column;
        gap: 10px;
    }
    #passkey-login-row > .btn {
        width: 100%;
        line-height: 44px;
        min-height: 44px;
    }
}
</style>
<script>
(function () {
    var submitRow = document.querySelector('.typecho-login form p.submit');
    if (!submitRow || document.getElementById('passkey-login-btn')) return;

    var loginBtn = submitRow.querySelector('button[type="submit"]');
    if (!loginBtn) return;

    var row = document.createElement('div');
    row.id = 'passkey-login-row';

    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn-l w-100';
    button.id = 'passkey-login-btn';
    button.textContent = '通行密钥登录';

    var msg = document.createElement('p');
    msg.className = 'description';
    msg.style.marginTop = '8px';
    msg.id = 'passkey-login-msg';

    row.appendChild(loginBtn);
    row.appendChild(button);
    submitRow.insertBefore(row, submitRow.firstChild);
    submitRow.after(msg);

    function setMsg(text, isError) {
        msg.textContent = text || '';
        msg.style.color = isError ? '#c00' : '#666';
    }

    function isSecurePasskeyContext() {
        return !!window.isSecureContext;
    }

    function applyHttpsNotice() {
        if (isSecurePasskeyContext()) {
            return false;
        }

        button.disabled = true;
        setMsg('当前页面不是安全上下文，浏览器不会触发通行密钥验证。请先使用 HTTPS 打开页面。', true);
        return true;
    }

    function bytesToBase64Url(buffer) {
        var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer || []);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function base64UrlToBytes(value) {
        var normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
        while (normalized.length % 4 !== 0) {
            normalized += '=';
        }
        var binary = atob(normalized);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    async function fetchChallenge() {
        var response = await fetch({challengeUrlJson}, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });

        var result = null;
        try {
            result = await response.json();
        } catch (err) {
            result = null;
        }

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('登录接口不存在，请刷新页面后重试');
            }

            throw new Error((result && result.message) ? result.message : '无法获取登录验证参数');
        }

        if (!result || !result.success || !result.data || !result.data.challenge || !result.data.challengeToken) {
            throw new Error((result && result.message) ? result.message : '无法获取登录验证参数');
        }

        return result.data;
    }

    applyHttpsNotice();

    button.addEventListener('click', async function () {
        if (applyHttpsNotice()) {
            return;
        }

        if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
            setMsg('当前浏览器不支持通行密钥登录', true);
            return;
        }

        button.disabled = true;
        setMsg('请在系统弹窗中完成通行密钥验证...', false);

        try {
            var challengeOptions = await fetchChallenge();
            var credential = await navigator.credentials.get({
                publicKey: {
                    rpId: challengeOptions.rpId || window.location.hostname,
                    challenge: base64UrlToBytes(challengeOptions.challenge),
                    timeout: Number(challengeOptions.timeout || 60000),
                    userVerification: 'required'
                }
            });

            if (!credential || !credential.id) {
                throw new Error('未获取到有效凭据');
            }

            var payload = {
                challengeToken: challengeOptions.challengeToken,
                credential: {
                    id: credential.id,
                    type: credential.type || 'public-key',
                    rawId: bytesToBase64Url(credential.rawId),
                    response: {
                        authenticatorData: bytesToBase64Url(credential.response.authenticatorData),
                        clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
                        signature: bytesToBase64Url(credential.response.signature),
                        userHandle: credential.response.userHandle ? bytesToBase64Url(credential.response.userHandle) : ''
                    }
                }
            };

            var response = await fetch({verifyUrlJson}, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            var result = await response.json();
            if (result && result.success && result.data && result.data.redirect) {
                window.location.href = result.data.redirect;
                return;
            }

            setMsg((result && result.message) ? result.message : '通行密钥登录失败', true);
        } catch (e) {
            if (e && e.name === 'NotAllowedError') {
                setMsg('你已取消验证', true);
            } else {
                setMsg((e && e.message) ? e.message : '通行密钥登录失败', true);
            }
        } finally {
            button.disabled = false;
        }
    });
})();
</script>
