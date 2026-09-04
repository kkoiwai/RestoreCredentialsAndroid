package com.example.restorecredentialspoc

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.example.restorecredentialspoc.theme.RestoreCredentialsPoCTheme
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : ComponentActivity() {

    private lateinit var tokenManager: TokenManager
    private lateinit var apiClient: ApiClient
    private lateinit var authTabManager: AuthTabManager
    private lateinit var restoreCredentialManager: RestoreCredentialManager

    private val _logs = mutableStateListOf<String>()
    private var _serverUrl = mutableStateOf("https://restore-credentials-poc-2gy33mqr2a-an.a.run.app")
    private var _session = mutableStateOf<SessionData?>(null)
    private var _isLoading = mutableStateOf(false)
    private var _statusMessage = mutableStateOf("未ログイン (Ready)")
    private var _protectedServiceMessage = mutableStateOf<String?>(null)
    private var _restoreKeyInfo = mutableStateOf<String?>(null)
    private var currentCodeVerifier: String? = null

    private fun addLog(message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        _logs.add(0, "[$time] $message")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tokenManager = TokenManager(this)
        apiClient = ApiClient()
        authTabManager = AuthTabManager(this)
        restoreCredentialManager = RestoreCredentialManager(this)

        _session.value = tokenManager.getSession()
        if (_session.value != null) {
            _statusMessage.value = "ログイン中: ${_session.value?.username}"
            addLog("既存セッション復元: ${_session.value?.username} (Access Token: ${_session.value?.accessToken?.take(15)}...)")
        } else {
            addLog("アプリ起動: 保存されたセッションはありません")
        }

        enableEdgeToEdge()
        setContent {
            RestoreCredentialsPoCTheme {
                Scaffold(
                    topBar = {
                        @OptIn(ExperimentalMaterial3Api::class)
                        TopAppBar(
                            title = {
                                Column {
                                    Text("Restore Credentials PoC", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                                    Text("${BuildConfig.APP_FLAVOR_LABEL} (${BuildConfig.APPLICATION_ID})", fontSize = 12.sp, color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f))
                                }
                            },
                            colors = TopAppBarDefaults.topAppBarColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer,
                                titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        )
                    }
                ) { innerPadding ->
                    PoCScreen(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        serverUrl = _serverUrl.value,
                        onServerUrlChange = { _serverUrl.value = it },
                        session = _session.value,
                        statusMessage = _statusMessage.value,
                        protectedServiceMessage = _protectedServiceMessage.value,
                        restoreKeyInfo = _restoreKeyInfo.value,
                        logs = _logs,
                        isLoading = _isLoading.value,
                        onSignInOidc = { startOidcSignIn() },
                        onCreateRestoreKey = { createRestoreKey() },
                        onCallProtectedService = { callProtectedService() },
                        onSimulateMigration = { simulateDeviceMigration() },
                        onRestoreSession = { restoreSession() },
                        onSignOut = { signOut() }
                    )
                }
            }
        }

        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val uri = intent?.data ?: return
        if (uri.scheme == "restoreapp" && uri.host == "auth-callback") {
            val code = uri.getQueryParameter("code")
            if (!code.isNullOrEmpty()) {
                addLog("Deep Link受信: code = ${code.take(12)}...")
                handleAuthCodeCallback(code)
            } else {
                val error = uri.getQueryParameter("error") ?: "不明なエラー"
                addLog("認証エラー: $error")
                _statusMessage.value = "認証失敗: $error"
            }
        }
    }

    /**
     * Step 1: Open AuthTab for OIDC Passkey sign-in
     */
    private fun startOidcSignIn() {
        val verifier = PkceUtil.generateCodeVerifier()
        val challenge = PkceUtil.generateCodeChallenge(verifier)
        currentCodeVerifier = verifier

        addLog("Step 1: AuthTabでOIDCログイン画面を開きます (PKCE S256保護, ${_serverUrl.value})")
        _statusMessage.value = "AuthTabでログイン中..."
        authTabManager.openAuthTab(_serverUrl.value, codeChallenge = challenge)
    }

    /**
     * Callback when returning from AuthTab with authorization code
     */
    private fun handleAuthCodeCallback(code: String) {
        lifecycleScope.launch {
            _isLoading.value = true
            _statusMessage.value = "トークン取得中..."
            addLog("認可コードをAccess Token / Refresh Tokenに交換します (PKCE検証)...")

            val tokenResult = apiClient.exchangeCodeForTokens(_serverUrl.value, code, currentCodeVerifier)
            tokenResult.onSuccess { tokens ->
                tokenManager.saveTokens(
                    accessToken = tokens.accessToken,
                    refreshToken = tokens.refreshToken,
                    userId = tokens.userId,
                    username = tokens.username
                )
                _session.value = tokenManager.getSession()
                _statusMessage.value = "ログイン成功: ${tokens.username}"
                addLog("トークン取得成功！ User: ${tokens.username}")
                addLog("Access Token: ${tokens.accessToken}")

                // Auto call mock service
                callProtectedService()

                // Auto register restore credential!
                createRestoreKey()
            }.onFailure { err ->
                addLog("トークン取得失敗: ${err.message}")
                _statusMessage.value = "トークン交換エラー"
            }
            _isLoading.value = false
        }
    }

    /**
     * Step 2: Create Restore Credential via CredentialManager
     */
    private fun createRestoreKey() {
        val currentSession = _session.value
        if (currentSession == null) {
            addLog("エラー: ログインしていません")
            return
        }

        lifecycleScope.launch {
            _isLoading.value = true
            addLog("Step 2: Restore Credentialの作成を開始します...")
            _statusMessage.value = "Restore Credential作成中..."

            // 1. Get creation challenge
            val optResult = apiClient.getRestoreRegistrationOptions(_serverUrl.value, currentSession.accessToken)
            optResult.onSuccess { optionsJson ->
                addLog("サーバーからRestore Key作成オプション取得成功")

                // 2. CredentialManager.createCredential
                val credResult = restoreCredentialManager.createRestoreCredential(optionsJson)
                credResult.onSuccess { responseJson ->
                    addLog("Google Play ServicesでRestore Key生成成功！")

                    // 3. Send response to server to verify and store
                    val verifyResult = apiClient.verifyRestoreRegistration(_serverUrl.value, currentSession.accessToken, responseJson)
                    verifyResult.onSuccess { v ->
                        val info = "Restore Key登録完了\nAAGUID: ${v.aaguid}\nBE (Backup Eligible): ${v.backupEligible}\nBS (Backup State): ${v.backupState}"
                        _restoreKeyInfo.value = info
                        tokenManager.saveRestoreKeyInfo(v.aaguid, v.backupEligible, v.backupState)
                        addLog("サーバー検証成功: AAGUID=${v.aaguid}, BE=${v.backupEligible}, BS=${v.backupState}")
                        _statusMessage.value = "Restore Credential登録完了！"
                    }.onFailure { err ->
                        addLog("サーバー検証失敗: ${err.message}")
                    }
                }.onFailure { err ->
                    addLog("CredentialManager Restore Key作成失敗: ${err.message}")
                }
            }.onFailure { err ->
                addLog("作成オプション取得失敗: ${err.message}")
            }
            _isLoading.value = false
        }
    }

    /**
     * Step 3: Call Protected Mock Service
     */
    private fun callProtectedService() {
        val currentSession = _session.value
        if (currentSession == null) {
            addLog("エラー: ログインしていません")
            return
        }

        lifecycleScope.launch {
            _isLoading.value = true
            addLog("Step 3: Access Tokenで保護されたサービスを呼び出します...")
            val result = apiClient.callProtectedService(_serverUrl.value, currentSession.accessToken)
            result.onSuccess { profile ->
                _protectedServiceMessage.value = "${profile.message}\n${profile.credentialsSummary}"
                addLog("サービス呼出成功: ${profile.message}")
                addLog("登録済鍵一覧:\n${profile.credentialsSummary.trimEnd()}")
            }.onFailure { err ->
                addLog("サービス呼出失敗: ${err.message}")
            }
            _isLoading.value = false
        }
    }

    /**
     * Step 4: Simulate Device Migration (wipes local app storage)
     */
    private fun simulateDeviceMigration() {
        tokenManager.clearLocalTokens()
        _session.value = null
        _protectedServiceMessage.value = null
        _restoreKeyInfo.value = null
        _statusMessage.value = "新端末移行シミュレーション: ローカル保存消去済"
        addLog("==================================================")
        addLog("Step 4: ローカル保存（Access/Refresh Token）を消去しました。")
        addLog("※Google Play Services内のRestore Keyは保持されています。")
        addLog("「5. Restore Credentialでセッション復旧」を押してください。")
        addLog("==================================================")
    }

    /**
     * Step 5: Restore Session via Restore Credential
     */
    private fun restoreSession() {
        lifecycleScope.launch {
            _isLoading.value = true
            addLog("==================================================")
            addLog("Step 5: Restore Credentialによるセッション復旧を開始...")
            _statusMessage.value = "Restore Credentialで復旧中..."

            // 1. Get challenge from server
            val challengeResult = apiClient.getRestoreChallenge(_serverUrl.value)
            challengeResult.onSuccess { challengeJson ->
                addLog("サーバーから復旧用Challenge取得成功")

                // 2. CredentialManager.getCredential with GetRestoreCredentialOption
                val getResult = restoreCredentialManager.getRestoreCredential(challengeJson)
                getResult.onSuccess { assertionJson ->
                    addLog("Google Play ServicesからRestore Credential取得成功！")

                    // 3. Exchange assertion at /api/auth/restore-session
                    val restoreResult = apiClient.restoreSession(_serverUrl.value, assertionJson)
                    restoreResult.onSuccess { tokens ->
                        tokenManager.saveTokens(
                            accessToken = tokens.accessToken,
                            refreshToken = tokens.refreshToken,
                            userId = tokens.userId,
                            username = tokens.username,
                            isRestored = true
                        )
                        tokenManager.saveRestoreKeyInfo(tokens.aaguid, tokens.backupEligible, tokens.backupState)
                        _session.value = tokenManager.getSession()
                        _statusMessage.value = "復旧完了！ (Restored: ${tokens.username})"

                        val aaguidInfo = "セッション復旧完了\nAAGUID: ${tokens.aaguid ?: "unknown"}\nBE: ${tokens.backupEligible}\nBS: ${tokens.backupState}"
                        _restoreKeyInfo.value = aaguidInfo

                        addLog("★ セッション復旧完了！ User: ${tokens.username}")
                        addLog("★ AAGUID: ${tokens.aaguid}, BE: ${tokens.backupEligible}, BS: ${tokens.backupState}")
                        addLog("★ 新規Access Token: ${tokens.accessToken}")

                        // Immediately verify calling protected service with the restored token!
                        callProtectedService()
                    }.onFailure { err ->
                        addLog("セッション復元API失敗: ${err.message}")
                        _statusMessage.value = "復元失敗: ${err.message}"
                    }
                }.onFailure { err ->
                    addLog("Restore Credential取得失敗: ${err.message}")
                    _statusMessage.value = "Restore Keyなし/取得失敗"
                }
            }.onFailure { err ->
                addLog("復旧Challenge取得失敗: ${err.message}")
            }
            _isLoading.value = false
        }
    }

    /**
     * Step 6: Sign Out & Revoke Restore Credential
     */
    private fun signOut() {
        lifecycleScope.launch {
            _isLoading.value = true
            addLog("Step 6: サインアウト処理開始...")

            // Clear Play Services restore key
            val clearResult = restoreCredentialManager.clearRestoreCredential()
            clearResult.onSuccess {
                addLog("CredentialManager.clearCredentialState(TYPE_CLEAR_RESTORE_CREDENTIAL) 実行完了")
            }.onFailure { err ->
                addLog("clearCredentialState警告: ${err.message}")
            }

            tokenManager.clearLocalTokens()
            _session.value = null
            _protectedServiceMessage.value = null
            _restoreKeyInfo.value = null
            _statusMessage.value = "サインアウト完了"
            addLog("サインアウト完了: ローカルセッション及びRestore Keyを削除しました。")
            _isLoading.value = false
        }
    }
}

@Composable
fun PoCScreen(
    modifier: Modifier = Modifier,
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    session: SessionData?,
    statusMessage: String,
    protectedServiceMessage: String?,
    restoreKeyInfo: String?,
    logs: List<String>,
    isLoading: Boolean,
    onSignInOidc: () -> Unit,
    onCreateRestoreKey: () -> Unit,
    onCallProtectedService: () -> Unit,
    onSimulateMigration: () -> Unit,
    onRestoreSession: () -> Unit,
    onSignOut: () -> Unit
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Server URL input
        item {
            OutlinedTextField(
                value = serverUrl,
                onValueChange = onServerUrlChange,
                label = { Text("Server URL (エミュレータは 10.0.2.2)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
        }

        // App Info Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFECEFF1))
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "📱 ${BuildConfig.APP_FLAVOR_LABEL}",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp
                    )
                    Text(
                        text = "Client ID: ${BuildConfig.CLIENT_ID} | Pkg: ${BuildConfig.APPLICATION_ID}",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Color.DarkGray
                    )
                }
            }
        }

        // Status Card
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (session != null) Color(0xFFE8F5E9) else Color(0xFFF5F5F5)
                )
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "ステータス: $statusMessage",
                        fontWeight = FontWeight.Bold,
                        color = if (session != null) Color(0xFF2E7D32) else Color(0xFF424242)
                    )
                    if (session != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "ユーザー: ${session.username} (ID: ${session.userId})",
                            fontSize = 13.sp
                        )
                        Text(
                            text = "Access Token: ${session.accessToken.take(20)}...",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color.Gray
                        )
                        if (session.isRestored) {
                            Text(
                                text = "★ Restore Credentialにより自動復旧されたセッション",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF1565C0)
                            )
                        }
                    }
                    if (restoreKeyInfo != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = Color(0xFFE3F2FD),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = restoreKeyInfo,
                                modifier = Modifier.padding(8.dp),
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFF0D47A1)
                            )
                        }
                    }
                    if (protectedServiceMessage != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = Color(0xFFFFF3E0),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = protectedServiceMessage,
                                modifier = Modifier.padding(8.dp),
                                fontSize = 12.sp,
                                color = Color(0xFFE65100)
                            )
                        }
                    }
                }
            }
        }

        // Action Buttons
        item {
            Text("検証アクション", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        }

        item {
            Button(
                onClick = onSignInOidc,
                enabled = !isLoading && session == null,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("🔑 1. OIDCログイン (AuthTab + パスキー)")
            }
        }

        item {
            Button(
                onClick = onCreateRestoreKey,
                enabled = !isLoading && session != null,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF00796B))
            ) {
                Text("🛡️ 2. Restore Credential再作成 (手動)")
            }
        }

        item {
            Button(
                onClick = onCallProtectedService,
                enabled = !isLoading && session != null,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF3F51B5))
            ) {
                Text("🌐 3. 保護サービス呼び出し (トークン利用)")
            }
        }

        item {
            Button(
                onClick = onSimulateMigration,
                enabled = !isLoading && session != null,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100))
            ) {
                Text("📱 4. 新端末移行シミュレーション (ローカル消去)")
            }
        }

        item {
            Button(
                onClick = onRestoreSession,
                enabled = !isLoading && session == null,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))
            ) {
                Text("⚡ 5. Restore Credentialで復旧 (Zero-Tap)")
            }
        }

        item {
            OutlinedButton(
                onClick = onSignOut,
                enabled = !isLoading,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFC62828))
            ) {
                Text("🚪 6. サインアウト (Restore Key削除)")
            }
        }

        // Live Log Output
        item {
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("実行ログ (Real-time Logs)", fontWeight = FontWeight.Bold, fontSize = 15.sp)
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                }
            }
        }

        items(logs) { log ->
            Text(
                text = log,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF212121), RoundedCornerShape(4.dp))
                    .padding(6.dp),
                color = when {
                    log.contains("★") || log.contains("成功") -> Color(0xFF81C784)
                    log.contains("エラー") || log.contains("失敗") -> Color(0xFFE57373)
                    log.contains("Step") -> Color(0xFF64B5F6)
                    else -> Color(0xFFE0E0E0)
                }
            )
        }
    }
}
