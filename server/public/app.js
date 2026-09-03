const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

// Views
const appDownloadView = document.getElementById('appDownloadView');
const oauthErrorView = document.getElementById('oauthErrorView');
const loginView = document.getElementById('loginView');
const missingParamsList = document.getElementById('missingParamsList');
const displayClientId = document.getElementById('displayClientId');

// Login Form Elements
const btnRegister = document.getElementById('btnRegister');
const btnSignIn = document.getElementById('btnSignIn');
const btnQuickLogin = document.getElementById('btnQuickLogin');
const usernameInput = document.getElementById('username');
const statusBox = document.getElementById('statusBox');
const redirectContainer = document.getElementById('redirectContainer');
const redirectBtn = document.getElementById('redirectBtn');

// Parse URL Parameters (strict standard OAuth 2.0 / OIDC / PKCE parameters only)
const urlParams = new URLSearchParams(window.location.search);

const STANDARD_OAUTH_PARAMS = [
  'client_id',
  'redirect_uri',
  'scope',
  'code_challenge',
  'code_challenge_method',
  'response_type',
  'state',
];

const REQUIRED_PARAMS = [
  { key: 'client_id', label: 'client_id (クライアントID)' },
  { key: 'redirect_uri', label: 'redirect_uri (リダイレクト先URI)' },
  { key: 'scope', label: 'scope (認可スコープ: 例 openid profile)' },
  { key: 'code_challenge', label: 'code_challenge (PKCE チャレンジ値)' },
  { key: 'code_challenge_method', label: 'code_challenge_method (PKCE メソッド: S256)' },
];

/**
 * Validates request parameters and activates corresponding view
 */
function validateAndInit() {
  // Check if any standard OAuth parameter exists in query
  let hasAnyOAuthParam = false;
  for (const param of STANDARD_OAUTH_PARAMS) {
    if (urlParams.has(param)) {
      hasAnyOAuthParam = true;
      break;
    }
  }

  // Case 1: No OAuth params present -> Show App Download View
  if (!hasAnyOAuthParam) {
    appDownloadView.style.display = 'block';
    return;
  }

  // Case 2: Some OAuth params present -> Validate required params
  const missingParams = [];
  const statusItems = [];

  for (const { key, label } of REQUIRED_PARAMS) {
    const val = (urlParams.get(key) || '').trim();
    if (!val) {
      missingParams.push(key);
      statusItems.push({ key, label, ok: false, message: '未指定 (必須)' });
    } else {
      // Specific checks
      if (key === 'code_challenge_method' && val !== 'S256' && val !== 'plain') {
        missingParams.push(key);
        statusItems.push({ key, label, ok: false, message: `不正な値: ${val} (S256 を指定してください)` });
      } else {
        statusItems.push({ key, label, ok: true, value: val });
      }
    }
  }

  // Check response_type if provided
  if (urlParams.has('response_type')) {
    const respType = urlParams.get('response_type');
    if (respType !== 'code') {
      missingParams.push('response_type');
      statusItems.push({ key: 'response_type', label: 'response_type', ok: false, message: `不正な値: ${respType} (code のみ対応)` });
    }
  }

  // If there are missing or invalid params -> Show OAuth Error View
  if (missingParams.length > 0) {
    missingParamsList.innerHTML = '';
    statusItems.forEach(item => {
      const li = document.createElement('li');
      li.className = `param-item ${item.ok ? 'ok' : 'missing'}`;
      if (item.ok) {
        li.innerHTML = `<span>✓</span> <span><strong>${item.key}</strong>: ${escapeHtml(item.value)}</span>`;
      } else {
        li.innerHTML = `<span>✗</span> <span><strong>${item.key}</strong>: ${escapeHtml(item.message)}</span>`;
      }
      missingParamsList.appendChild(li);
    });

    oauthErrorView.style.display = 'block';
    return;
  }

  // Case 3: All required params are valid -> Show Login View
  const clientId = urlParams.get('client_id');
  displayClientId.textContent = clientId;
  loginView.style.display = 'block';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, (m) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[m]);
}

function showStatus(message, isSuccess = true) {
  statusBox.textContent = message;
  statusBox.className = 'status-box ' + (isSuccess ? 'status-success' : 'status-error');
}

function handleSuccessRedirect(code) {
  const redirectUri = urlParams.get('redirect_uri');
  const state = urlParams.get('state');

  // Build deep link redirect strictly using provided redirect_uri
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  if (state) {
    url.searchParams.set('state', state);
  }
  const deepLink = url.toString();

  showStatus(`認証成功！アプリへリダイレクト中...`, true);
  redirectBtn.href = deepLink;
  redirectContainer.style.display = 'block';

  // Trigger redirect
  setTimeout(() => {
    window.location.href = deepLink;
  }, 500);
}

function getOAuthContext() {
  return {
    client_id: urlParams.get('client_id'),
    redirect_uri: urlParams.get('redirect_uri'),
    scope: urlParams.get('scope'),
    code_challenge: urlParams.get('code_challenge'),
    code_challenge_method: urlParams.get('code_challenge_method'),
    state: urlParams.get('state') || undefined,
  };
}

// 1. Passkey Registration Flow
if (btnRegister) {
  btnRegister.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
      showStatus('ユーザー名を入力してください', false);
      return;
    }

    btnRegister.disabled = true;
    btnSignIn.disabled = true;
    if (btnQuickLogin) btnQuickLogin.disabled = true;
    showStatus('パスキー作成オプションを取得中...', true);

    try {
      // 1. Get creation options from server
      const optRes = await fetch('/api/passkey/register/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, displayName: username }),
      });

      if (!optRes.ok) {
        const err = await optRes.json();
        throw new Error(err.error || 'オプション取得失敗');
      }

      const { options } = await optRes.json();
      showStatus('端末の認証器でパスキーを作成してください...', true);

      // 2. Perform WebAuthn ceremony
      const regResponse = await startRegistration(options);

      showStatus('サーバーで検証中...', true);

      // 3. Send response with OAuth request context to server
      const oauthContext = getOAuthContext();
      const verifyRes = await fetch('/api/passkey/register/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          response: regResponse,
          username,
          ...oauthContext,
        }),
      });

      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.verified) {
        throw new Error(verifyData.error || '検証に失敗しました');
      }

      // 4. Redirect with auth code
      handleSuccessRedirect(verifyData.code);
    } catch (error) {
      console.error('Registration error:', error);
      showStatus(`エラー: ${error.message}`, false);
      btnRegister.disabled = false;
      btnSignIn.disabled = false;
      if (btnQuickLogin) btnQuickLogin.disabled = false;
    }
  });
}

// 2. Passkey Sign-In Flow
if (btnSignIn) {
  btnSignIn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();

    btnRegister.disabled = true;
    btnSignIn.disabled = true;
    if (btnQuickLogin) btnQuickLogin.disabled = true;
    showStatus('ログインオプションを取得中...', true);

    try {
      // 1. Get auth options
      const optRes = await fetch('/api/passkey/login/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username || undefined }),
      });

      if (!optRes.ok) {
        const err = await optRes.json();
        throw new Error(err.error || 'オプション取得失敗');
      }

      const { options } = await optRes.json();
      showStatus('パスキーで生体認証を行ってください...', true);

      // 2. WebAuthn ceremony
      const authResponse = await startAuthentication(options);

      showStatus('サーバーでログイン検証中...', true);

      // 3. Verify with OAuth request context
      const oauthContext = getOAuthContext();
      const verifyRes = await fetch('/api/passkey/login/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          response: authResponse,
          ...oauthContext,
        }),
      });

      const verifyData = await verifyRes.json();
      if (!verifyRes.ok || !verifyData.verified) {
        throw new Error(verifyData.error || '認証に失敗しました');
      }

      // 4. Redirect with code
      handleSuccessRedirect(verifyData.code);
    } catch (error) {
      console.error('Sign-in error:', error);
      showStatus(`エラー: ${error.message}`, false);
      btnRegister.disabled = false;
      btnSignIn.disabled = false;
      if (btnQuickLogin) btnQuickLogin.disabled = false;
    }
  });
}

// 3. Quick Login Flow (Emulator / Test)
if (btnQuickLogin) {
  btnQuickLogin.addEventListener('click', async () => {
    const username = usernameInput.value.trim() || 'test-user';
    btnQuickLogin.disabled = true;
    btnRegister.disabled = true;
    btnSignIn.disabled = true;
    showStatus('クイックログイン処理中...', true);

    try {
      const oauthContext = getOAuthContext();
      const res = await fetch('/api/passkey/quick-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          ...oauthContext,
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.verified) {
        throw new Error(data.error || 'クイックログイン失敗');
      }

      handleSuccessRedirect(data.code);
    } catch (err) {
      showStatus(`エラー: ${err.message}`, false);
      btnQuickLogin.disabled = false;
      btnRegister.disabled = false;
      btnSignIn.disabled = false;
    }
  });
}

// Initialize on page load
validateAndInit();
