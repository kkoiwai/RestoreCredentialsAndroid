package com.example.restorecredentialspoc

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent

class AuthTabManager(private val context: Context) {

    /**
     * Opens the AuthTab / Custom Tab to perform OIDC authorization & Passkey registration/login.
     */
    fun openAuthTab(baseUrl: String, codeChallenge: String, state: String = "poc_state") {
        val authUrl = Uri.parse("$baseUrl/oauth/authorize")
            .buildUpon()
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", BuildConfig.CLIENT_ID)
            .appendQueryParameter("redirect_uri", BuildConfig.REDIRECT_URI)
            .appendQueryParameter("scope", "openid profile")
            .appendQueryParameter("code_challenge", codeChallenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .appendQueryParameter("state", state)
            .build()

        val customTabsIntent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()

        customTabsIntent.launchUrl(context, authUrl)
    }
}
