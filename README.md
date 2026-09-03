# Android Restore Credentials PoC

An end-to-end Proof of Concept (PoC) demonstrating **Android Credential Manager Restore Credentials** with **WebAuthn / Passkeys**, **OpenID Connect (OIDC) with PKCE (RFC 7636)**, and a **Google Cloud Run** backend.

---

## 🌟 Key Features

1. **Seamless Device Restore (Restore Credentials)**:
   - Registers a `restore_key` via Android's `CredentialManager.createCredential(CreateRestoreCredentialRequest)` backed by Google Play Services.
   - Silently restores user sessions on a new device using `CredentialManager.getCredential(GetRestoreCredentialOption)` without requiring user interaction (Zero-Tap / Single-Tap).
   - Validates AAGUID, Backup Eligibility (BE), and Backup State (BS) flags in authenticator data.
   - Clean revocation via `CredentialManager.clearCredentialState(TYPE_CLEAR_RESTORE_CREDENTIAL)`.

2. **OIDC & Passkey Authentication (AuthTab)**:
   - First-time sign-in powered by Passkeys in Chrome Custom Tabs / AuthTab.
   - Fully compliant with **RFC 7636 PKCE (S256)**, **RFC 6749 OAuth 2.0**, and **OpenID Connect Core 1.0**.
   - Strict parameter verification (`client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method`).
   - Dynamic 3-state UI:
     - **No OAuth parameters**: Displays app download portal with signed APK.
     - **Incomplete / invalid parameters**: Displays 400 Bad Request error view with detailed missing parameter diagnostics.
     - **Valid request**: Unlocks PKCE-protected Passkey registration & sign-in.

3. **Backend Server (Express & SimpleWebAuthn)**:
   - Built with Node.js & TypeScript using `@simplewebauthn/server`.
   - In-memory database storing users, passkeys, restore keys, challenges, and OAuth authorization codes.
   - Fully configurable via environment variables (`.env`).
   - Ready for Google Cloud Run deployment via included `deploy.sh` and `Dockerfile`.

---

## 📁 Repository Structure

```
RestoreCredentialsAndroid/
├── android/                     # Android Application (Jetpack Compose, Kotlin)
│   ├── app/
│   │   ├── build.gradle.kts
│   │   └── src/main/java/com/example/restorecredentialspoc/
│   │       ├── MainActivity.kt               # Main verification UI & lifecycle
│   │       ├── ApiClient.kt                  # REST API & Token exchange client
│   │       ├── AuthTabManager.kt             # OIDC AuthTab launcher with PKCE
│   │       ├── PkceUtil.kt                   # Cryptographic PKCE S256 generator
│   │       ├── RestoreCredentialManager.kt   # CredentialManager Restore API wrapper
│   │       └── TokenManager.kt               # SharedPreferences encrypted session store
│   ├── gradle/
│   └── build.gradle.kts
│
├── server/                      # Backend & Web UI (Node.js, Express, SimpleWebAuthn)
│   ├── public/                  # AuthTab Web UI & Static assets
│   │   ├── login.html           # 3-State OIDC Web UI (Download / Error / Login)
│   │   ├── app.js               # WebAuthn ceremony & parameter validation
│   │   ├── simplewebauthn-browser.min.js
│   │   └── RestoreCredentialsPoC.apk # Pre-built signed APK for instant testing
│   ├── src/
│   │   ├── config.ts            # Environment variables & origin validation
│   │   ├── db.ts                # In-memory session, credential & code storage
│   │   ├── index.ts             # Express server setup & routing
│   │   ├── oidc.ts              # OAuth2 / OIDC endpoints & PKCE verifier
│   │   ├── restore.ts           # Restore Credential registration & restoration
│   │   ├── webauthn.ts          # Passkey registration, login, & quick-login
│   │   ├── service.ts           # Bearer-protected mock API services
│   │   └── test-server.ts       # Automated unit test suite
│   ├── Dockerfile
│   ├── deploy.sh                # Google Cloud Run deployment script
│   ├── .env.example             # Environment variable template
│   └── package.json
│
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v20 or v22
- **Android Studio / Android SDK**: compileSdk 36, minSdk 28 (Android 9+)
  - Physical Android 15+ device or Emulator running Android 14+ with Google Play Services.

---

### Backend Server Setup

1. **Install Dependencies**:
   ```bash
   cd server
   npm install
   ```

2. **Configure Environment Variables**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` as needed:
   ```env
   PORT=8080
   RP_NAME=Restore Credentials PoC
   RP_ID=localhost
   CLIENT_ID=android-poc-client
   REDIRECT_URI=restoreapp://auth-callback
   ```

3. **Build & Run Tests**:
   ```bash
   npm run build
   npm test
   ```

4. **Start Development Server**:
   ```bash
   npm run dev
   ```
   Server will listen on `http://localhost:8080`.

---

### Google Cloud Run Deployment

Deploy directly to Google Cloud Run using the automated deployment script:

```bash
cd server
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

bash deploy.sh
```

The script builds the container using Cloud Build, deploys to Cloud Run, and automatically sets `RP_ID` and `ISSUER` based on the assigned Cloud Run URL.

---

### Android App Setup

1. **Open in Android Studio**:
   Open the `android/` directory in Android Studio.

2. **Server URL Configuration**:
   In `MainActivity.kt`, update `_serverUrl` to point to your server:
   - For Android Emulator: `http://10.0.2.2:8080`
   - For Cloud Run: `https://your-service-xxxx-an.a.run.app`

3. **Build & Run**:
   ```bash
   cd android
   ./gradlew assembleDebug
   ```
   Or install directly onto a connected device via Android Studio.

---

## 📱 Verification Scenarios

The Android app provides an interactive dashboard with 6 step-by-step verification actions:

1. **🔑 1. OIDCログイン (AuthTab + パスキー)**:
   - Opens the AuthTab with PKCE parameters (`code_challenge`, `code_challenge_method=S256`).
   - Prompts for Passkey creation or Quick Login.
   - Redirects via `restoreapp://auth-callback` and exchanges the code with `code_verifier` for Access & Refresh tokens.

2. **🛡️ 2. Restore Credential作成 (手動 / 自動)**:
   - Calls `/api/restore/register/options` and uses `CredentialManager.createCredential` to store a `restore_key` in Google Play Services.

3. **🌐 3. 保護サービス呼び出し (トークン利用)**:
   - Accesses `/api/service/profile` with Bearer token, displaying registered passkeys and restore keys with their AAGUID and BE/BS flags.

4. **📱 4. 新端末移行シミュレーション (ローカル消去)**:
   - Clears local app tokens and shared preferences while keeping the Restore Key intact inside Google Play Services.

5. **⚡ 5. Restore Credentialで復旧 (Zero-Tap)**:
   - Queries `CredentialManager.getCredential(GetRestoreCredentialOption)`.
   - Sends the assertion to `/api/auth/restore-session` to regain a valid session and new Access/Refresh tokens without re-authenticating.

6. **🚪 6. サインアウト (Restore Key削除)**:
   - Calls `CredentialManager.clearCredentialState(TYPE_CLEAR_RESTORE_CREDENTIAL)` to completely revoke the restore key from Google Play Services.

---

## 🔒 Security Specifications

- **PKCE Verification (RFC 7636)**: Authorization codes are bound to a `code_challenge` generated via SHA-256. Token exchange enforces mathematical validation of the `code_verifier`.
- **Client ID & Redirect URI Binding**: Token exchange ensures strict 1:1 match between the authorization request context and the token request.
- **Restore Key Origin Verification**: Ensures incoming assertion origins match authorized `android:apk-key-hash:<sha256-base64url>` fingerprints.

---

## 📄 License
MIT License
