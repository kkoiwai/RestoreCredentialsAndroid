package com.example.restorecredentialspoc

import android.content.Context
import android.content.SharedPreferences

data class SessionData(
    val accessToken: String,
    val refreshToken: String,
    val userId: String,
    val username: String,
    val passkeyAaguid: String? = null,
    val restoreKeyAaguid: String? = null,
    val isRestored: Boolean = false
)

class TokenManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("auth_session", Context.MODE_PRIVATE)

    fun saveTokens(
        accessToken: String,
        refreshToken: String,
        userId: String,
        username: String,
        isRestored: Boolean = false
    ) {
        prefs.edit()
            .putString("access_token", accessToken)
            .putString("refresh_token", refreshToken)
            .putString("user_id", userId)
            .putString("username", username)
            .putBoolean("is_restored", isRestored)
            .apply()
    }

    fun savePasskeyInfo(aaguid: String?, be: Boolean?, bs: Boolean?) {
        prefs.edit()
            .putString("passkey_aaguid", aaguid)
            .putBoolean("passkey_be", be ?: false)
            .putBoolean("passkey_bs", bs ?: false)
            .apply()
    }

    fun saveRestoreKeyInfo(aaguid: String?, be: Boolean?, bs: Boolean?) {
        prefs.edit()
            .putString("restore_aaguid", aaguid)
            .putBoolean("restore_be", be ?: false)
            .putBoolean("restore_bs", bs ?: false)
            .apply()
    }

    fun getSession(): SessionData? {
        val token = prefs.getString("access_token", null) ?: return null
        val refreshToken = prefs.getString("refresh_token", "") ?: ""
        val userId = prefs.getString("user_id", "") ?: ""
        val username = prefs.getString("username", "") ?: ""
        val passkeyAaguid = prefs.getString("passkey_aaguid", null)
        val restoreAaguid = prefs.getString("restore_aaguid", null)
        val isRestored = prefs.getBoolean("is_restored", false)

        return SessionData(
            accessToken = token,
            refreshToken = refreshToken,
            userId = userId,
            username = username,
            passkeyAaguid = passkeyAaguid,
            restoreKeyAaguid = restoreAaguid,
            isRestored = isRestored
        )
    }

    /**
     * Simulates device migration or app reinstall by clearing local SharedPreferences.
     * Note: This does NOT clear Google Play Services restore keys!
     */
    fun clearLocalTokens() {
        prefs.edit().clear().apply()
    }
}
