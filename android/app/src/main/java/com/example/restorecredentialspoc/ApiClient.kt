package com.example.restorecredentialspoc

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

data class AuthTokenResult(
    val accessToken: String,
    val refreshToken: String,
    val userId: String,
    val username: String,
    val aaguid: String? = null,
    val backupEligible: Boolean? = null,
    val backupState: Boolean? = null
)

data class RestoreVerifyResult(
    val verified: Boolean,
    val credentialId: String,
    val aaguid: String,
    val backupEligible: Boolean,
    val backupState: Boolean
)

data class ProfileResult(
    val message: String,
    val username: String,
    val credentialsSummary: String
)

class ApiClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    /**
     * 1. Exchange OIDC authorization code for Access & Refresh tokens.
     */
    suspend fun exchangeCodeForTokens(baseUrl: String, code: String, codeVerifier: String? = null): Result<AuthTokenResult> = withContext(Dispatchers.IO) {
        try {
            val jsonBody = JSONObject().apply {
                put("grant_type", "authorization_code")
                put("code", code)
                put("client_id", BuildConfig.CLIENT_ID)
                put("redirect_uri", BuildConfig.REDIRECT_URI)
                if (!codeVerifier.isNullOrEmpty()) {
                    put("code_verifier", codeVerifier)
                }
            }

            val request = Request.Builder()
                .url("$baseUrl/oauth/token")
                .post(jsonBody.toString().toRequestBody(jsonMediaType))
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(IOException("Token exchange failed (${response.code}): $body"))
                }
                val json = JSONObject(body)
                val accessToken = json.getString("access_token")
                val refreshToken = json.optString("refresh_token", "")

                // Parse user from ID token or userinfo
                var userId = "user"
                var username = "user"
                if (json.has("id_token")) {
                    val idTokenParts = json.getString("id_token").split(".")
                    if (idTokenParts.size >= 2) {
                        val payload = String(android.util.Base64.decode(idTokenParts[1], android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING))
                        val payloadJson = JSONObject(payload)
                        userId = payloadJson.optString("sub", "user")
                        username = payloadJson.optString("preferred_username", "user")
                    }
                }

                Result.success(AuthTokenResult(accessToken, refreshToken, userId, username))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * 2. Get Creation Options JSON for CreateRestoreCredentialRequest.
     */
    suspend fun getRestoreRegistrationOptions(baseUrl: String, accessToken: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/restore/register/options")
                .addHeader("Authorization", "Bearer $accessToken")
                .post("{}".toRequestBody(jsonMediaType))
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(IOException("Get restore options failed (${response.code}): $body"))
                }
                val json = JSONObject(body)
                val optionsObj = json.getJSONObject("options")
                Result.success(optionsObj.toString())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * 3. Send CreateRestoreCredentialResponse.responseJson to server to verify & save restore key.
     */
    suspend fun verifyRestoreRegistration(baseUrl: String, accessToken: String, responseJson: String): Result<RestoreVerifyResult> = withContext(Dispatchers.IO) {
        try {
            val payload = JSONObject().apply {
                put("response", JSONObject(responseJson))
                put("client_id", BuildConfig.CLIENT_ID)
            }

            val request = Request.Builder()
                .url("$baseUrl/api/restore/register/verify")
                .addHeader("Authorization", "Bearer $accessToken")
                .post(payload.toString().toRequestBody(jsonMediaType))
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(IOException("Verify restore registration failed (${response.code}): $body"))
                }
                val json = JSONObject(body)
                val cred = json.getJSONObject("credential")
                val result = RestoreVerifyResult(
                    verified = json.getBoolean("verified"),
                    credentialId = cred.getString("id"),
                    aaguid = cred.getString("aaguid"),
                    backupEligible = cred.getBoolean("backupEligible"),
                    backupState = cred.getBoolean("backupState")
                )
                Result.success(result)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * 4. Get Challenge JSON for GetRestoreCredentialOption on new device.
     */
    suspend fun getRestoreChallenge(baseUrl: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/restore/challenge")
                .post("{}".toRequestBody(jsonMediaType))
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(IOException("Get restore challenge failed (${response.code}): $body"))
                }
                val json = JSONObject(body)
                val optionsObj = json.getJSONObject("options")
                Result.success(optionsObj.toString())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * 5. Exchange RestoreCredential assertion for fresh Access & Refresh Tokens.
     */
    suspend fun restoreSession(baseUrl: String, assertionJson: String): Result<AuthTokenResult> = withContext(Dispatchers.IO) {
        try {
            val payload = JSONObject().apply {
                put("client_id", BuildConfig.CLIENT_ID)
                put("assertion", JSONObject(assertionJson))
            }

            val request = Request.Builder()
                .url("$baseUrl/api/auth/restore-session")
                .post(payload.toString().toRequestBody(jsonMediaType))
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(IOException("Restore session failed (${response.code}): $body"))
                }
                val json = JSONObject(body)
                val user = json.getJSONObject("user")
                val restoreInfo = json.optJSONObject("restoreInfo")

                val result = AuthTokenResult(
                    accessToken = json.getString("access_token"),
                    refreshToken = json.optString("refresh_token", ""),
                    userId = user.getString("id"),
                    username = user.getString("username"),
                    aaguid = restoreInfo?.optString("aaguid"),
                    backupEligible = restoreInfo?.optBoolean("backupEligible"),
                    backupState = restoreInfo?.optBoolean("backupState")
                )
                Result.success(result)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * 6. Call Protected Mock Service with Bearer token.
     */
    suspend fun callProtectedService(baseUrl: String, accessToken: String): Result<ProfileResult> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$baseUrl/api/service/profile")
                .addHeader("Authorization", "Bearer $accessToken")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(IOException("Protected service call failed (${response.code}): $body"))
                }
                val json = JSONObject(body)
                val message = json.optString("message", "")
                val user = json.getJSONObject("user")
                val credentials = json.optJSONArray("credentials")

                val credSummary = StringBuilder()
                if (credentials != null) {
                    for (i in 0 until credentials.length()) {
                        val c = credentials.getJSONObject(i)
                        val type = c.getString("type")
                        val aaguid = c.optString("aaguid", "none")
                        val be = c.optBoolean("backupEligible", false)
                        val bs = c.optBoolean("backupState", false)
                        credSummary.append("• [$type] AAGUID: $aaguid (BE=$be, BS=$bs)\n")
                    }
                }

                Result.success(ProfileResult(message, user.getString("username"), credSummary.toString()))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
