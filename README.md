# Android Restore Credentials PoC & 実装・統合ガイド

Android Credential Manager の **Restore Credentials（資格情報の復元）** 機能を、**WebAuthn / Passkeys**、**PKCE 対応 OpenID Connect (OIDC)**、および **Google Cloud Run** バックエンドと統合したエンドツーエンドの検証用 PoC (Proof of Concept) およびアーキテクチャ設計ガイドです。

---

## 📚 既存 OIDC + パスキー環境への Restore Credentials 導入ガイド (Japanese)

すでに「**Web側でパスキー（WebAuthn）認証を実装済みの IdP**」を持ち、「**アプリは Custom Tabs (AuthTab) で Web ログイン画面を開き、Deep Link で認可コード (auth code) を持ち帰ってトークン交換している**」既存システムにおいて、Restore Credentials を新規導入する際の改修ポイントを「**アプリ拡張**」「**Web / IdP サーバー拡張**」「**DB 拡張**」の3つの観点から整理します。

```
【既存システム】
[Android App] --(AuthTab)--> [IdP Web (Passkey)] --(DeepLink: code)--> [Android App] --(POST /token)--> Access/Refresh Tokens

【Restore Credentials 追加後】
[Android App] --(初回ログイン完了時)-------------> [CredentialManager] (Restore Key 作成 & GMS 同期)
[新端末移行時]  --(Zero-Tap 復元)--------------> [IdP / Server] (Restore Key 署名検証 -> 新規トークン再発行)
```

---

### 1. アプリ拡張 (Mobile App Extensions)

アプリ側には、**初回ログイン完了時の鍵作成**、**新端末移行時の自動復旧**、および**サインアウト時の鍵破棄**の 3 つのライフサイクル処理を追加します。

#### ① ライブラリの追加
- `androidx.credentials:credentials:1.5.0` 以上（推奨: `1.7.0-alpha03` 等の最新安定/プレビュー版）
- `androidx.credentials:credentials-play-services-auth:1.5.0` 以上

#### ② ログイン完了時の Restore Key 自動生成（初回登録フロー）
- Deep Link 経由で受け取った認可コードを `/oauth/token` で Access Token / Refresh Token に交換し、セッションが確立した直後に実行します。
- サーバーから Restore Key 登録用の公開鍵作成オプション（`PublicKeyCredentialCreationOptionsJSON`）を取得。
- `CredentialManager.createCredential(context, CreateRestoreCredentialRequest(requestJson, isCloudBackupEnabled = true))` を呼び出します。
- **注意（`isCloudBackupEnabled = false` の位置づけ）**:
  - 端末に画面ロックがない場合や Google バックアップが未設定の場合、`E2eeUnavailableException`（エンドツーエンド暗号化利用不可）が発生します。
  - 公式ガイドには `isCloudBackupEnabled = false` でリトライするフォールバックが記載されていますが、**`false` で作成した鍵はクラウドバックアップの対象外となり、クラウド経由での新端末復元では取得できません**（※端末同士をケーブルやWi-Fiで直接つなぐ D2D 移行時のみ移行されます）。
  - そのため、「クラウド復元による自動ログイン」を要件とする一般的なアプリでは、E2EE 不可時にローカル鍵を作成してもクラウド復元は成功しないため、作成をスキップするか、ユーザーに画面ロックの設定を促す設計にするのが合理的です（D2D 移行もサポートしたい場合のみフォールバックを活用します）。
- 生成された Attestation レスポンスをサーバーへ送信して登録完了とします。
- ※ログインのたびに無駄な鍵生成を行わないよう、`has_synced_restore_credential` などのローカルフラグを設定します。

#### ③ 新端末初回起動時のサイレントセッション復旧（2-Tier 復元アーキテクチャ）
- **Tier 2（フォアグラウンド復元 - Launcher Activity）**:
  - アプリ起動時、ローカルストレージ（EncryptedSharedPreferences 等）にトークンが存在しない場合、バックエンドから復旧用チャレンジを取得。
  - `CredentialManager.getCredential(context, GetCredentialRequest(listOf(GetRestoreCredentialOption(challengeJson))))` を実行。
  - ユーザー確認ダイアログや生体認証は表示されず、**ダイアログなし（Zero-Tap）**で即座に `RestoreCredential` が取得されます。
  - 取得したアサーションをサーバーの `/api/auth/restore-session` へ送信し、新しい Access Token / Refresh Token を取得して自動ログイン状態に復帰します。
- **Tier 1（バックグラウンド復元 - BackupAgent）**:
  - `AndroidManifest.xml` で `android:allowBackup="true"` の場合、`BackupAgent.onRestoreFinished()` 内で上記復旧処理および FCM（プッシュ通知）トークンの再同期を同期実行 (`runBlocking`) することで、ユーザーが新端末でアプリを開く前から通知のバックグラウンド受信を再開できます。

#### ④ サインアウト時の鍵破棄
- アプリ内のログアウト処理で、ローカルのトークン消去に加えて、以下を必ず呼び出します：
  ```kotlin
  val clearRequest = ClearCredentialStateRequest(ClearCredentialStateRequest.TYPE_CLEAR_RESTORE_CREDENTIAL)
  credentialManager.clearCredentialState(clearRequest)
  ```
  ※引数なしの `clearCredentialState()` では Restore Credential は削除されないため、必ず `TYPE_CLEAR_RESTORE_CREDENTIAL` を指定します。

---

### 2. Web / IdP / サーバー拡張 (Web / IdP Server Extensions)

Web 側で既にパスキー（FIDO2/WebAuthn）をサポートしている場合、署名アルゴリズム（ES256 等）やチャレンジ検証エンジンは基本的に再利用できます。しかし、**標準 WebAuthn 仕様と Restore Credentials の動作差分（UP/UVフラグ）に対する重要な改修** が必要です。

#### ① WebAuthn 検証ロジックの改修：UP（ユーザー所在）および UV（ユーザー検証）チェックの要否比較とスキップ対応

WebAuthn 仕様と Restore Credentials の最大の違いは、**「ユーザーがその場に存在して物理操作を行ったか（UP: User Present）」** および **「生体認証・PIN 等のユーザー本人確認が行われたか（UV: User Verified）」** の扱いです。

##### 【UP / UV チェック要否の比較表】

| フラグ | 通常のパスキーログイン | Restore Credentials (セッション復元) | 復元時にスキップが必要な理由 |
|---|---|---|---|
| **UP (Bit 0)**<br>User Present<br>(ユーザーの所在・操作) | **検証必須 (MUST = 1)** | **検証スキップ（免除・許容）が必須**<br>*(UP=0 でも成功させる)* | W3C WebAuthn 仕様（7.2節 Step 13）では UP=1 が必須であり、多くのサーバーライブラリ（`@simplewebauthn/server` 等）はデフォルトで `if (!flags.up) throw Error` と判定します。<br>しかし Restore Credentials は、端末セットアップ中のバックグラウンド（Tier 1）やフォアグラウンドのサイレント起動（Tier 2）で動作し、物理操作を伴わないため、**OS/GMS から `UP=0` のアサーションが正規に返却される可能性**があります。<br>UP=1 を強制するとセッション復旧が全滅するため、Restore Key 検証時は **UP チェックのバイパスが必須**です。 |
| **UV (Bit 2)**<br>User Verified<br>(生体認証・PIN) | **検証必須 / 推奨 (1)** | **検証スキップ（UV=0 許容）が必須** | 端末移行時のゼロタップ（ダイアログなし）復元を実現するため、サーバー側で `requireUserVerification: false` を明示設定します。 |

##### 【実装上の具体策】
1. **ライブラリの検証バイパスオプションの活用 (例: SimpleWebAuthn)**:
   `verifyAuthenticationResponse` に `advancedFIDOConfig: { userVerification: 'discouraged' }` を渡すことで、ライブラリ内部の `!flags.up` 例外スロー処理を完全にバイパスできます。
2. **代替となるセキュリティ担保**:
   UP チェックをスキップする代わりに、以下の 2 点で安全性を担保します：
   - **公開鍵暗号署名の厳格検証**: 保存済み `restore_key` の公開鍵による `authData + clientDataHash` の電子署名検証。
   - **Android 署名証明書（APK Key Hash）の厳格検証**: `clientData.origin` が `assetlinks.json` に登録された正規アプリの SHA-256 フィンガープリントと完全一致することの検証。

#### ② エンドポイントの新設
1. **`POST /api/restore/register/options`**:
   - Access Token で認証されたユーザーに対し、Restore Key 作成用の `PublicKeyCredentialCreationOptionsJSON` を返却。
2. **`POST /api/restore/register/verify`**:
   - クライアントから送信された Attestation を検証し、DB へ `restore_key` として保存。
3. **`POST /api/restore/challenge`**:
   - セッション復旧用のアサーションチャレンジを発行。
4. **`POST /api/auth/restore-session`**:
   - 送信された WebAuthn アサーション（署名）を公開鍵で検証（UP/UV スキップ適用）。
   - 検証成功後、対象ユーザーに対して**認可スコープを継承した新しい Access Token と Refresh Token を直接発行・返却**。

#### ③ OAuth 認可スコープ (`scope`) およびクライアント (`client_id`) の管理
- **スコープのバインドと継承**:
  - OAuth 2.0 / OIDC の原則（最小権限の原則）に基づき、Restore Key 登録時に、そのセッションで認可されていた `scope`（例: `openid profile email`）および発行元 `client_id` を Restore Key レコードに紐付けて保持します。
  - 新端末でのセッション復元時（`/api/auth/restore-session`）には、紐付けられた `scope` と `client_id` を引き継いだ新規 Access Token を発行します。これにより、トークンの権限過剰付与や欠落を防ぎます。
- **パスキー管理 API のフィルタリング改修**:
  - ユーザー向けの設定画面 API（一覧取得 `GET /api/passkeys`、削除 `DELETE /api/passkeys/:id`）で `WHERE credential_type = 'passkey'` の絞り込みを行い、システム管理鍵である Restore Key を確実に除外（隠蔽）。
- **復旧エンドポイントでの型チェック**:
  - `/api/auth/restore-session` において、検証対象が `credential_type === 'restore_key'` であることをチェックし、通常のパスキーを用いた不正なセッション復旧を防止。

#### ④ OIDC ID トークン (`id_token`) 復元時の設計考慮事項（`acr`, `amr`, `auth_time` の是非）
OAuth の Access Token / Refresh Token だけでなく、OIDC の `id_token` も復元時に再発行すべきか、また再発行する場合に元のクレームを **Retain（そのまま引き継ぎ）してよいか** については、OIDC Core 1.0 仕様およびセキュリティ保証レベルの観点から慎重な設計が必要です。

1. **そもそも復元時（Restore Session）に `id_token` を発行すべきか？**
   - **推奨: 原則として復元時には `id_token` を発行しない（`access_token` と `refresh_token` のみを返却する）。**
   - **理由**: `id_token` は本来「その瞬間にエンドユーザーに対する対話型の認証セレモニーが行われたこと」を証明するアーティファクトです。Restore Credentials による復元は、OAuth 2.0 のリフレッシュトークン更新と同様に「**セッションの継続・再開 (Session Resumption)**」であり、ユーザー本人がその場で生体認証を行ったわけではありません。ユーザープロフィールが必要な場合は、発行された Access Token で `/userinfo` を呼び出すのが OIDC の標準的な思想です。

2. **アプリの都合で `id_token` も再発行する場合のクレーム設計（Retain の是非）**
   オフラインでのユーザー識別等でどうしても `id_token` を再発行する場合、元のクレームを単純に Retain することは**セキュリティ上および仕様上の問題**を引き起こします：

   - **`auth_time` (Authentication Time / loginat)**:
     - **オリジナルの認証時刻を Retain する場合**: 「ユーザーが実際に認証器（生体認証・パスキー）で本人確認を完了した過去の日時」を表すため、監査的には事実です。しかし、クライアントアプリやライブラリが `max_age` を検証している場合、過去の日時であるため即座にセッション期限切れと誤判定され、再ログインループに陥るリスクがあります。
     - **復元日時に更新する場合**: 期限切れは防げますが、ユーザーはその瞬間に認証操作を行っていないため、OIDC Core 仕様の「エンドユーザーが認証された時刻」という定義に反する（虚偽の時刻主張となる）リスクがあります。
     - **対応策**: 監査上はオリジナルの `auth_time` を保持しつつ、アプリ側で「Restore 経由のセッション復旧」であることを認識し、`max_age` 検証をスキップまたは緩和する設計にします。

   - **`amr` (Authentication Methods References - RFC 8176)**:
     - **結論: オリジナルの `amr` をそのまま Retain してはならない（虚偽の認証主張となる）。**
     - 初回 Web ログイン時の `amr` は `["passkey", "user", "pop"]`（パスキーかつ生体認証済み）などですが、Restore Credential による復元は `requireUserVerification: false`（生体認証なし、場合により UP=0）でサイレントに実行されます。
     - オリジナルの `amr` を引き継ぐと「新端末でユーザーが生体認証を行った」という虚偽の主張になり、セキュリティ監査に違反します。
     - **対応策**: 復元手法を明示する `amr`（例: `["hwk", "pop", "android_restore"]`。`user` 生体認証フラグは除外）へ必ず更新します。

   - **`acr` (Authentication Context Class Reference)**:
     - **結論: オリジナルの `acr` をそのまま Retain してはならない（ダウングレードまたは専用 ACR を付与）。**
     - パスキーによる生体認証付きログインは高保証レベル（例: NIST AAL2 や `urn:...:passkey-mfa`）を満たしますが、ゼロタップの Restore Credential は「端末の所持」のみを検証するものであるため、保証レベル（Assurance Level）が本質的に異なります。
     - 高保証 ACR を引き継ぐと、送金や個人情報変更などの機密 API が「生体認証を通過した」と誤認して重大なリスクを生みます。
     - **対応策**: 復元時は `acr` を端末復旧用のベースラインレベル（例: `urn:...:device-restore` 等）にダウングレードし、重要機能の実行時にはアプリ側で Step-up 認証（パスキー再認証）を要求します。

#### ⑤ Origin（オリジン）および証明書フィンガープリントの厳格検証
- Web ブラウザからのオリジンは `https://<rp_id>` ですが、Android の Credential Manager からのリクエストでは、以下の形式でオリジンが渡されます：
  $$\text{origin} = \texttt{android:apk-key-hash:} + \text{Base64URL}(\text{SHA-256(アプリ署名証明書)})$$
- サーバー側で `.well-known/assetlinks.json` に登録された正規の署名証明書（Release Keystore 等）の SHA-256 フィンガープリントと厳格に突合し、不正な再署名 APK や他アプリからの復元リクエストを確実にブロックします。

#### ⑥ 鍵のライフサイクル・孤立鍵（Orphaned Keys）対策
- アプリのアンインストールや端末設定でのデータ消去ではサーバーに通知が届きません。
- 新しい Restore Key 登録時に同一ユーザーの古い Restore Key を非活性化する、または有効期限（TTL）を設けて定期クリーンアップする仕組みをサーバー側に導入します。

---

### 3. DB 拡張 (Database Schema Extensions)

既存のパスキー用テーブル（`credentials` / `authenticators` 等）と **構造を統合・共有** できます。
パスキーと同様、Restore Credential も一意な `credential_id`（および公開鍵）を固有に持つため、`device_id` などの独自端末識別カラムを新たに追加する必要はありません。同一 `user_id` に対して複数の鍵レコード（1:N）が紐づくだけで、複数端末の利用も自然にサポートされます。

追加・拡張するカラムは以下の通りです：

| カラム名 | 型 | 用途・説明 |
|---|---|---|
| `credential_type` | `VARCHAR(32)` | `'passkey'`（通常のパスキー）または `'restore_key'`（復元専用鍵）を識別。<br>**最重要**: ユーザー向けのパスキー管理画面で Restore Key が表示・誤削除されないようフィルタリングに必須。 |
| `scope` | `VARCHAR(255)` | **OAuth 認可スコープ**（例: `openid profile email`）。<br>セッション復旧時に、元のセッションで付与されていた正規の認可スコープを正確に引き継いだ新規 Access Token を発行するために必須。 |
| `client_id` | `VARCHAR(128)` | クライアント識別子。発行元のアプリ（OAuth クライアント）を特定し、他アプリへの不整合なトークン発行を防止。 |
| `aaguid` | `CHAR(36)` | 認証器識別子。<br>・通常パスキー（GPM）: `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4`<br>・Restore Credential: `00000000-0000-0000-0000-000000000000`（実測値） |
| `backup_eligible` (BE) | `BOOLEAN` | バックアップ対象フラグ（Restore Credential では `true`）。 |
| `backup_state` (BS) | `BOOLEAN` | クラウドバックアップ同期状態（D2D 時は `false`、クラウド E2EE 同期時は `true`）。 |
| `auth_time` *(任意)* | `BIGINT` | 初回対話認証完了時刻（エポック秒）。復旧時に `id_token` を発行する場合、オリジナルの認証日時を追跡するために利用。 |
| `last_used_at` / `expires_at` | `TIMESTAMP` | 最終復旧利用日時および有効期限。古い孤立鍵のクリーンアップに利用。 |

---

### 4. 公式 Google ドキュメントリンク (Official Documentation)

- 📘 [Android Developers: Restore Credentials 実装ガイド](https://developer.android.com/identity/sign-in/restore-credentials-implementation)
- 🧪 [Android Developers: Restore Credentials テストガイド](https://developer.android.com/identity/sign-in/test-restore-credentials)
- 🔑 [Android Developers: Credential Manager 概要](https://developer.android.com/identity/sign-in/credential-manager)
- 🌐 [Google Developers: パスキー＆WebAuthn 開発者向けガイド](https://developers.google.com/identity/passkeys)

---
---

## 📚 Integration Guide: Adding Restore Credentials to Existing OIDC + Passkey Systems (English)

If your architecture already uses an **IdP with WebAuthn/Passkey support** where the **Android app performs Web login via Custom Tabs (AuthTab) and receives an authorization code via Deep Link**, this section outlines the required changes across the **Mobile App**, **Web / IdP Server**, and **Database**.

```
[Existing Flow]
[Android App] --(AuthTab)--> [IdP Web (Passkey)] --(DeepLink: code)--> [Android App] --(POST /token)--> Access/Refresh Tokens

[With Restore Credentials Added]
[Android App] --(After First Login)-----------> [CredentialManager] (Create Restore Key & Sync via GMS)
[New Device Setup] --(Zero-Tap Restoration)------> [IdP / Server] (Verify Restore Key Assertion -> Issue New Tokens)
```

---

### 1. Mobile App Extensions (Android Client)

Add three lifecycle hooks: **creation upon login**, **zero-tap restoration on new device setup**, and **revocation upon logout**.

#### 1.1 Dependencies
- `androidx.credentials:credentials:1.5.0` or higher (Recommended: `1.7.0-alpha03`+)
- `androidx.credentials:credentials-play-services-auth:1.5.0` or higher

#### 1.2 Automatic Restore Key Creation (Post-Login Hook)
- Triggered immediately after the authorization code is successfully exchanged for access/refresh tokens via `/oauth/token`.
- Fetch `PublicKeyCredentialCreationOptionsJSON` from the server.
- Call `CredentialManager.createCredential(context, CreateRestoreCredentialRequest(requestJson, isCloudBackupEnabled = true))`.
- **Note on `isCloudBackupEnabled = false`**:
  - If the device lacks a screen lock or Google cloud backup, an `E2eeUnavailableException` is thrown.
  - While Google's guide mentions falling back to `isCloudBackupEnabled = false`, **keys saved with `false` are NOT backed up to the cloud and cannot be restored during a cloud-based device restoration** (they only transfer during direct cable/Wi-Fi Device-to-Device migration).
  - Therefore, for apps whose primary requirement is seamless cloud restoration, creating a local-only key is ineffective for cloud restores. It is generally recommended to either skip key creation or prompt the user to enable a screen lock, unless direct cable D2D migration is explicitly targeted.
- Send the attestation response back to the server to complete registration.
- Store a local flag (`has_synced_restore_credential = true`) to prevent redundant creation on every subsequent app launch.

#### 1.3 Silent Session Restoration on New Devices (Two-Tier Architecture)
- **Tier 2 (Foreground Fallback - Launcher Activity)**:
  - If no stored tokens exist in local storage on launch, fetch an authentication challenge from `/api/restore/challenge`.
  - Invoke `CredentialManager.getCredential(context, GetCredentialRequest(listOf(GetRestoreCredentialOption(challengeJson))))`.
  - The OS returns a `RestoreCredential` **silently without any user prompts or biometric dialogs (Zero-Tap)**.
  - Send the assertion to `/api/auth/restore-session` to receive newly minted Access and Refresh Tokens.
- **Tier 1 (Background Primary - BackupAgent)**:
  - If `android:allowBackup="true"` is configured in `AndroidManifest.xml`, execute the restoration synchronously (`runBlocking`) inside `BackupAgent.onRestoreFinished()`. Re-register FCM notification tokens so background sync and push notifications resume before the user ever opens the app.

#### 1.4 Explicit Key Revocation on Sign-Out
- When the user signs out, revoke the restore key from Google Play Services:
  ```kotlin
  val clearRequest = ClearCredentialStateRequest(ClearCredentialStateRequest.TYPE_CLEAR_RESTORE_CREDENTIAL)
  credentialManager.clearCredentialState(clearRequest)
  ```
  *(Note: A default `clearCredentialState()` without a type parameter only clears non-restore credentials).*

---

### 2. Web / IdP / Server Extensions

Because your IdP already implements Passkeys (FIDO2/WebAuthn), cryptographic verification engines can largely be reused. However, **critical adaptations are required for the differences in User Presence (UP) and User Verification (UV) flags**.

#### 2.1 WebAuthn Verification Adjustments: UP (User Present) & UV (User Verified) Check Necessity & Bypass

The most fundamental architectural divergence between standard interactive Passkeys and Restore Credentials lies in how **User Presence (UP: Bit 0)** and **User Verification (UV: Bit 2)** are evaluated.

##### [Comparison Table: UP & UV Verification Necessity]

| Flag | Standard Interactive Passkey | Restore Credentials (Session Restoration) | Why Bypassing the Check is Required |
|---|---|---|---|
| **UP (Bit 0)**<br>User Present | **Mandatory (MUST = 1)** | **Bypass / Exemption is REQUIRED**<br>*(Must succeed even if UP = 0)* | W3C WebAuthn Level 2/3 (Section 7.2 Step 13) specifies that servers MUST verify that the UP bit is set. Standard FIDO2/WebAuthn libraries (such as `@simplewebauthn/server`) enforce this by default: `if (!flags.up) throw Error('User not present')`.<br>However, Restore Credentials operates silently in the background (Tier 1: `BackupAgent.onRestoreFinished()`) or during zero-tap startup (Tier 2) without physical interaction. Consequently, **assertions may legitimately return with `flags.up = 0` (User Absent)**.<br>Enforcing `UP=1` will cause valid restoration requests to fail completely; thus, bypassing the UP check for restore keys is mandatory. |
| **UV (Bit 2)**<br>User Verified | **Mandatory / Preferred (1)** | **Bypass (UV=0 allowed) is REQUIRED** | Zero-tap silent restoration bypasses biometric prompts; the server must configure `requireUserVerification: false`. |

##### [Implementation Guidance]
1. **Bypass Option in Libraries (e.g. SimpleWebAuthn)**:
   Providing `advancedFIDOConfig: { userVerification: 'discouraged' }` allows bypassing the internal `!flags.up` error throw.
2. **Compensating Controls**:
   When UP is relaxed, security assurance is guaranteed via:
   - **Cryptographic Signature Verification**: Validating the digital signature over `authData + clientDataHash` against the registered `restore_key` public key.
   - **Origin Certificate Fingerprint Matching**: Enforcing that `clientData.origin` matches authorized SHA-256 APK signing certificate hashes declared in `assetlinks.json`.

#### 2.2 New Dedicated Endpoints
1. **`POST /api/restore/register/options`**: Returns public key creation options for an authenticated user.
2. **`POST /api/restore/register/verify`**: Verifies the creation attestation and stores the `restore_key`.
3. **`POST /api/restore/challenge`**: Issues a challenge for session restoration.
4. **`POST /api/auth/restore-session`**: Verifies the assertion against the registered `restore_key` (with relaxed UP/UV checks) and directly issues new Access & Refresh tokens with inherited scopes.

#### 2.3 OAuth Scope & Client ID Management
- **Scope Binding & Inheritance**:
  - Following OAuth 2.0 / OIDC least privilege principles, the `scope` granted during the initial authorization code flow (e.g. `openid profile email`) and the app's `client_id` must be stored alongside the `restore_key`.
  - Upon session restoration via `/api/auth/restore-session`, the newly minted Access Token inherits this exact `scope` and `client_id`, preventing privilege escalation or missing claims.
- **Passkey Management API Filtering**:
  - In user-facing passkey management APIs (`GET /api/passkeys`, `DELETE /api/passkeys/:id`), add `WHERE credential_type = 'passkey'` to strictly filter out Restore Keys so users cannot view or accidentally delete them.
- **Restoration Endpoint Authorization**:
  - Ensure `/api/auth/restore-session` verifies that the matching record has `credential_type === 'restore_key'`, preventing regular passkeys from being misused as restore credentials.

#### 2.4 OIDC ID Token (`id_token`) Considerations (`acr`, `amr`, `auth_time` Semantics)
Whether an `id_token` should be re-issued upon session restoration—and whether original claims can be **retained**—requires careful consideration of OIDC Core 1.0 specifications and security assurance:

1. **Should an `id_token` be re-issued upon restoration?**
   - **Recommended: Do NOT issue an `id_token` during Restore Session (return only `access_token` and `refresh_token`).**
   - **Rationale**: An `id_token` is an assertion attesting that an interactive user authentication ceremony took place at a specific moment. Restore Credentials is a **Session Resumption / Continuity** mechanism (akin to a Refresh Token exchange), not a live user authentication event. If profile information is needed, clients should query `/userinfo` using the restored Access Token.

2. **Claim design if the app architecture requires an `id_token` (Can claims be retained?)**
   If an application strictly requires an `id_token`, retaining original claims verbatim is **inappropriate and misleading**:

   - **`auth_time` (Authentication Time / loginat)**:
     - **Retaining original timestamp**: Accurately reflects when the user completed interactive authentication. However, if the client verifies `max_age`, an old `auth_time` will immediately trigger session expiration and an unwanted login loop.
     - **Updating to restoration time**: Avoids expiration, but technically misrepresents the fact that no interactive user authentication occurred at that moment.
     - **Guidance**: Retain the original `auth_time` for audit fidelity, but configure the client application to bypass `max_age` checks for restore-resumed sessions.

   - **`amr` (Authentication Methods References - RFC 8176)**:
     - **Conclusion: Never retain original `amr` values (it constitutes a false authentication claim).**
     - Original login might have `amr: ["passkey", "user", "pop"]` (with biometric verification). Restore Credential executes silently with `userVerification: false` (and potentially `UP=0`).
     - Claiming `user` verification on a zero-tap restore is false.
     - **Guidance**: Explicitly set `amr` to reflect restoration (e.g. `["hwk", "pop", "android_restore"]`, omitting `user`).

   - **`acr` (Authentication Context Class Reference)**:
     - **Conclusion: Never retain high original `acr` values (downgrade or define dedicated restore ACR).**
     - Passkeys with biometrics satisfy high assurance levels (e.g. NIST AAL2). Zero-tap restore proves device possession, but not user presence.
     - Retaining high `acr` allows downstream sensitive APIs (e.g., money transfer) to wrongly assume active biometric verification occurred.
     - **Guidance**: Downgrade `acr` to a device-restore baseline (e.g. `urn:...:device-restore`) and enforce Step-Up re-authentication for high-risk operations.

#### 2.5 Strict Origin & Certificate Fingerprint Verification
- Android Credential Manager sends origins in the following format:
  $$\text{origin} = \texttt{android:apk-key-hash:} + \text{Base64URL}(\text{SHA-256(Signing Certificate)})$$
- The server must validate this value against authorized SHA-256 fingerprints declared in `.well-known/assetlinks.json` to block tampered or unauthorized APKs.

#### 2.6 Lifecycle & Orphaned Key Mitigation
- App uninstalls do not trigger server callbacks. Invalidate older restore keys upon registering a new key for the user, or implement server-side TTL expiration to clean up inactive keys.

---

### 3. Database Schema Extensions

Restore keys and Passkeys can share the same `credentials` table.
Just like standard Passkeys, Restore Credentials have unique `credential_id` values and public keys. There is no need to add a custom `device_id` column; mapping multiple credentials to a single `user_id` (1:N) naturally supports multiple devices and multiple keys.

The following columns should be added/maintained:

| Column | Type | Description |
|---|---|---|
| `credential_type` | `VARCHAR(32)` | `'passkey'` or `'restore_key'`. Crucial for filtering out restore keys from user-facing passkey management settings. |
| `scope` | `VARCHAR(255)` | **OAuth Authorized Scopes** (e.g. `openid profile email`). Essential for issuing new access tokens with the identical scope originally consented to by the user. |
| `client_id` | `VARCHAR(128)` | OAuth client identifier. Binds the restore key to the specific mobile application, preventing cross-client token issuance. |
| `aaguid` | `CHAR(36)` | Authenticator AAGUID (`00000000-0000-0000-0000-000000000000` for Restore Credentials). |
| `backup_eligible` (BE) | `BOOLEAN` | `true` for Restore Credentials. |
| `backup_state` (BS) | `BOOLEAN` | `false` when local/D2D only; `true` when synced via Google Cloud E2EE. |
| `auth_time` *(Optional)* | `BIGINT` | Epoch timestamp of original interactive authentication. Used if issuing an `id_token` upon restore. |
| `last_used_at` / `expires_at` | `TIMESTAMP` | Tracks usage and enables garbage collection of orphaned keys. |

---

### 4. 公式 Google ドキュメントリンク (Official Documentation)

- 📘 [Android Developers: Restore Credentials 実装ガイド](https://developer.android.com/identity/sign-in/restore-credentials-implementation)
- 🧪 [Android Developers: Test Restore Credentials Guide](https://developer.android.com/identity/sign-in/test-restore-credentials)
- 🔑 [Android Developers: Credential Manager 概要](https://developer.android.com/identity/sign-in/credential-manager)
- 🌐 [Google Developers: パスキー＆WebAuthn 開発者向けガイド](https://developers.google.com/identity/passkeys)

---
---

## 🌟 PoC Architecture & Live Verification Details

### GCP Cloud Run Live Deployment
- **Service URL**: `https://restore-credentials-poc-2gy33mqr2a-an.a.run.app`
- **RP_ID**: `restore-credentials-poc-2gy33mqr2a-an.a.run.app`
- **Region**: `asia-northeast1` (Tokyo)
- **GCP Project**: `passkey-example-book`
- **Signed APK Download**: [`/RestoreCredentialsPoC.apk`](https://restore-credentials-poc-2gy33mqr2a-an.a.run.app/RestoreCredentialsPoC.apk) or [`/download`](https://restore-credentials-poc-2gy33mqr2a-an.a.run.app/download)
- **Web UI**: [`/login.html`](https://restore-credentials-poc-2gy33mqr2a-an.a.run.app/login.html)
- **OpenID Configuration**: [`/.well-known/openid-configuration`](https://restore-credentials-poc-2gy33mqr2a-an.a.run.app/.well-known/openid-configuration)
- **Asset Links**: [`/.well-known/assetlinks.json`](https://restore-credentials-poc-2gy33mqr2a-an.a.run.app/.well-known/assetlinks.json)

---

## 📁 Repository Structure

```
RestoreCredentialsAndroid/
├── android/                     # Android Application (Jetpack Compose, Kotlin)
│   ├── app/
│   │   ├── build.gradle.kts     # Release signingConfig with poc-release.jks
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
│   │   ├── login.html           # 3-State OIDC Web UI & APK Download portal
│   │   ├── app.js               # WebAuthn ceremony & parameter validation
│   │   ├── simplewebauthn-browser.min.js
│   │   ├── RestoreCredentialsPoC.apk # Pre-built signed APK for instant testing
│   │   └── .well-known/
│   │       └── assetlinks.json  # Fingerprints for Release & Debug APKs
│   ├── src/
│   │   ├── config.ts            # Environment variables & strict fingerprint verification
│   │   ├── db.ts                # In-memory session, credential & code storage
│   │   ├── index.ts             # Express server setup & routing
│   │   ├── oidc.ts              # OAuth2 / OIDC endpoints & PKCE verifier
│   │   ├── restore.ts           # Restore Credential registration & restoration
│   │   ├── webauthn.ts          # Passkey registration, login, & quick-login
│   │   ├── authDataUtils.ts     # AAGUID and BE/BS flag extraction
│   │   └── service.ts           # Bearer-protected mock API services
│   ├── Dockerfile
│   ├── deploy.sh                # Google Cloud Run deployment script
│   └── package.json
│
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v20 or v22
- **Android SDK**: compileSdk 36, minSdk 28 (Android 9+)
  - Physical Android 9+ device or Emulator with Google Play Services.

### Local Server Setup
```bash
cd server
npm install
npm run build
npm start
```
Server will listen on `http://localhost:8080`.

### Google Cloud Run Deployment
```bash
cd server
bash deploy.sh
```

### Android App Setup
1. Open `android/` in Android Studio.
2. In `MainActivity.kt`, verify `_serverUrl` points to `https://restore-credentials-poc-2gy33mqr2a-an.a.run.app` or `http://10.0.2.2:8080`.
3. Run or install the app (`./gradlew assembleDebug` or `./gradlew assembleRelease`).

---

## 📱 Verification Steps in App

1. **🔑 1. OIDCログイン (AuthTab + パスキー)**: Custom Tabs で Web ログイン。認証後 Deep Link (`restoreapp://auth-callback`) で戻り、PKCE コード交換でトークン取得。
2. **🛡️ 2. Restore Credential作成**: トークン交換完了後、自動（または手動ボタン）で `CredentialManager.createCredential` を実行し、GMS に Restore Key を登録。
3. **🌐 3. 保護サービス呼び出し**: 発行された Access Token で `/api/service/profile` を呼び出し、登録済み Passkey / Restore Key の AAGUID や BE/BS フラグを確認。
4. **📱 4. 新端末移行シミュレーション**: アプリ内のトークンを消去し、新端末移行直後の状態を再現。
5. **⚡ 5. Restore Credentialで復旧 (Zero-Tap)**: `getRestoreCredential` をサイレント呼び出しし、ダイアログなしで新規トークンを再取得。
6. **🚪 6. サインアウト**: `clearCredentialState(TYPE_CLEAR_RESTORE_CREDENTIAL)` で GMS 内の Restore Key を抹消。

---

## 📄 License
MIT License
