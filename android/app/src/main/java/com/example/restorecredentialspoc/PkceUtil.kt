package com.example.restorecredentialspoc

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

object PkceUtil {

    /**
     * Generates a cryptographically secure PKCE code_verifier (RFC 7636).
     * 32 random bytes -> 43 Base64URL characters (URL-safe, no wrap, no padding).
     */
    fun generateCodeVerifier(): String {
        val secureRandom = SecureRandom()
        val codeVerifierBytes = ByteArray(32)
        secureRandom.nextBytes(codeVerifierBytes)
        return Base64.encodeToString(
            codeVerifierBytes,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
    }

    /**
     * Generates a code_challenge using SHA-256 (S256) from the given code_verifier.
     */
    fun generateCodeChallenge(codeVerifier: String): String {
        val bytes = codeVerifier.toByteArray(Charsets.US_ASCII)
        val messageDigest = MessageDigest.getInstance("SHA-256")
        val digest = messageDigest.digest(bytes)
        return Base64.encodeToString(
            digest,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
    }
}
