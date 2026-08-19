<style>
#{formId} p.submit,
#{formId} .typecho-option-submit {
    display: none !important;
}
[id^="typecho-option-item-passkey_ui-"] {
    margin: 0;
    padding: 0;
}
[id^="typecho-option-item-passkey_ui-"] > li {
    margin: 0;
    padding: 0;
}
[id^="typecho-option-item-passkey_ui-"] > li > .typecho-label {
    display: none;
    margin: 0;
    padding: 0;
    line-height: 0;
}
[id^="typecho-option-item-passkey_ui-"] > li > p.description {
    margin: 0;
}
#passkey-manager-ui {
    margin-top: 0;
    font-weight: 400;
}
#passkey-manager-ui .passkey-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 6px;
}
#passkey-manager-ui .passkey-toolbar-title {
    color: #666;
    line-height: 1.5;
    font-weight: 400;
}
#passkey-manager-ui .passkey-list-wrap {
    margin-top: 0;
}
#passkey-manager-ui .passkey-card-list {
    display: grid;
    gap: 6px;
}
#passkey-manager-ui .passkey-card {
    border: 1px solid #dcdcdc;
    border-radius: 2px;
    background: #fff;
    padding: 10px 12px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
}
#passkey-manager-ui .passkey-card-info p {
    margin: 0 0 4px 0;
    line-height: 1.5;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    font-weight: 400;
}
#passkey-manager-ui .passkey-card-info span {
    font-weight: 400;
}
#passkey-manager-ui .passkey-card-info p:last-child {
    margin-bottom: 0;
}
#passkey-manager-ui .passkey-key {
    color: #888;
    min-width: 64px;
}
#passkey-manager-ui .passkey-card-actions {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 4px;
    white-space: nowrap;
}
#passkey-manager-ui .passkey-text-action {
    color: #467b96;
    text-decoration: none;
    font-size: 13px;
    line-height: 1.4;
    font-weight: 400;
}
#passkey-manager-ui .passkey-text-action:hover {
    text-decoration: underline;
}
#passkey-manager-ui .passkey-text-action.is-disabled {
    color: #999;
    pointer-events: none;
    text-decoration: none;
}
#passkey-manager-ui .passkey-delete-btn {
    color: #c00;
}
#passkey-manager-ui .passkey-empty {
    margin: 2px 0 0;
}
#passkey-msg {
    margin-top: 6px;
}
@media (max-width: 575px) {
    #passkey-manager-ui .passkey-toolbar {
        align-items: flex-start;
    }
    #passkey-manager-ui .passkey-card {
        flex-direction: column;
    }
    #passkey-manager-ui .passkey-card-actions {
        width: 100%;
        flex-direction: row;
        justify-content: flex-end;
        gap: 10px;
    }
}
</style>
<div id="passkey-manager-ui">
    <div class="passkey-toolbar">
        <span class="passkey-toolbar-title">已绑定的通行密钥</span>
        <a href="#" class="passkey-text-action" id="passkey-bind-btn">{bindBtnText}</a>
    </div>
    <div class="passkey-list-wrap">{passkeyListHtml}</div>
    <p id="passkey-msg" class="description"></p>
</div>
<script>
(function () {
    var form = document.getElementById('{formId}');
    if (!form) return;

    var submitRow = form.querySelector('p.submit, .typecho-option-submit');
    if (submitRow) {
        submitRow.style.display = 'none';
    }

    var bindBtn = document.getElementById('passkey-bind-btn');
    var msg = document.getElementById('passkey-msg');

    function getField(name) {
        return form.querySelector('input[name="' + name + '"]');
    }

    function showMsg(text, isError) {
        if (!msg) return;
        msg.textContent = text || '';
        msg.style.color = isError ? '#c00' : '#666';
    }

    function setBindPending(pending) {
        if (!bindBtn) return;
        if (pending) {
            bindBtn.classList.add('is-disabled');
            bindBtn.setAttribute('aria-disabled', 'true');
        } else {
            bindBtn.classList.remove('is-disabled');
            bindBtn.setAttribute('aria-disabled', 'false');
        }
    }

    function isSecurePasskeyContext() {
        return !!window.isSecureContext;
    }

    function applyHttpsNotice() {
        if (isSecurePasskeyContext()) {
            return false;
        }

        setBindPending(true);
        showMsg('当前页面不是安全上下文，浏览器不会触发通行密钥绑定。请先使用 HTTPS 打开后台。', true);
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

    async function fetchJson(url, payload) {
        var response = await fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {})
        });

        var result = null;
        try {
            result = await response.json();
        } catch (err) {
            result = null;
        }

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('绑定接口不存在，请刷新后台页面后重试。');
            }

                throw new Error(result && result.message ? result.message : '请求失败');
        }

        if (!result || !result.success) {
            throw new Error(result && result.message ? result.message : '请求失败');
        }

        return result.data || {};
    }

    applyHttpsNotice();

    bindBtn && bindBtn.addEventListener('click', async function (e) {
        e.preventDefault();
        if (bindBtn.classList.contains('is-disabled')) {
            return;
        }

        if (applyHttpsNotice()) {
            return;
        }

        if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
            showMsg('当前浏览器不支持通行密钥。', true);
            return;
        }

        var name = prompt('请输入通行密钥名称：', '我的通行密钥');
        if (name === null) {
            return;
        }

        name = name.trim();
        if (!name) {
            showMsg('请输入名称。', true);
            return;
        }

        setBindPending(true);
        showMsg('请在系统弹窗中确认绑定。', false);

        try {
            var creationOptions = await fetchJson({registerOptionsUrlJson}, {});
            var publicKey = {
                challenge: base64UrlToBytes(creationOptions.challenge),
                rp: creationOptions.rp || {},
                user: {
                    id: base64UrlToBytes(creationOptions.user && creationOptions.user.id),
                    name: creationOptions.user && creationOptions.user.name ? creationOptions.user.name : '',
                    displayName: creationOptions.user && creationOptions.user.displayName
                        ? creationOptions.user.displayName
                        : (creationOptions.user && creationOptions.user.name ? creationOptions.user.name : '')
                },
                pubKeyCredParams: Array.isArray(creationOptions.pubKeyCredParams) ? creationOptions.pubKeyCredParams : [],
                timeout: Number(creationOptions.timeout || 60000),
                attestation: creationOptions.attestation || 'none',
                authenticatorSelection: creationOptions.authenticatorSelection || {
                    residentKey: 'required',
                    requireResidentKey: true,
                    userVerification: 'required'
                },
                extensions: creationOptions.extensions || {}
            };

            if (Array.isArray(creationOptions.excludeCredentials) && creationOptions.excludeCredentials.length) {
                publicKey.excludeCredentials = creationOptions.excludeCredentials.map(function (item) {
                    return {
                        type: item.type || 'public-key',
                        id: base64UrlToBytes(item.id)
                    };
                });
            }

            var credential = await navigator.credentials.create({ publicKey: publicKey });
            if (!credential || !credential.id || !credential.rawId) {
                throw new Error('未获取到有效凭据。');
            }

            if (!credential.response || !credential.response.attestationObject || !credential.response.clientDataJSON) {
                throw new Error('浏览器没有返回完整的凭据信息。');
            }

            await fetchJson({registerFinishUrlJson}, {
                name: name,
                credential: {
                    id: credential.id,
                    type: credential.type || 'public-key',
                    rawId: bytesToBase64Url(credential.rawId),
                    response: {
                        attestationObject: bytesToBase64Url(credential.response.attestationObject),
                        clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON)
                    }
                }
            });

            window.location.reload();
        } catch (err) {
            if (err && err.name === 'NotAllowedError') {
                showMsg('你已取消操作。', true);
            } else if (err && err.name === 'InvalidStateError') {
                showMsg('这把通行密钥已经绑定过了，请换一把新的，或先解绑旧的再绑定。', true);
            } else if (err && err.name === 'SecurityError') {
                showMsg('当前页面或域名不满足通行密钥要求，请确认你访问的是正确的 HTTPS 地址。', true);
            } else {
                showMsg((err && err.message) ? err.message : '绑定失败。', true);
            }
        } finally {
            setBindPending(false);
        }
    });

    document.addEventListener('click', function (e) {
        var target = e.target;
        if (target && target.matches && target.matches('a.passkey-text-action')) {
            e.preventDefault();
        }
        if (!target || !target.classList) {
            return;
        }

        if (target.classList.contains('passkey-edit-btn')) {
            var editId = target.getAttribute('data-credential-id') || '';
            var currentName = target.getAttribute('data-remark') || '';
            if (!editId) {
                showMsg('通行密钥标识无效。', true);
                return;
            }

            var newName = prompt('请输入新的通行密钥名称：', currentName);
            if (newName === null) {
                return;
            }

            newName = newName.trim();
            if (!newName) {
                showMsg('请输入名称。', true);
                return;
            }

            var updateActionInput = getField('action');
            var updateIdInput = getField('update_credential_id');
            var updateNameInput = getField('remark');
            if (!updateActionInput || !updateIdInput || !updateNameInput) {
                showMsg('表单字段缺失，请刷新页面后重试。', true);
                return;
            }

            updateActionInput.value = 'update';
            updateIdInput.value = editId;
            updateNameInput.value = newName;
            form.submit();
            return;
        }

        if (!target.classList.contains('passkey-delete-btn')) {
            return;
        }

        var credentialId = target.getAttribute('data-credential-id') || '';
        if (!credentialId) {
            showMsg('通行密钥标识无效。', true);
            return;
        }

        if (!confirm('确认解绑这把通行密钥吗？')) {
            return;
        }

        var actionInput = getField('action');
        var removeInput = getField('remove_credential_id');
        if (!actionInput || !removeInput) {
            showMsg('表单字段缺失，请刷新页面后重试。', true);
            return;
        }

        actionInput.value = 'delete';
        removeInput.value = credentialId;
        form.submit();
    });
})();
</script>
