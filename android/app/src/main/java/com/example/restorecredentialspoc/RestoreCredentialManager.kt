package com.example.restorecredentialspoc

import android.content.Context
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CreateRestoreCredentialRequest
import androidx.credentials.CreateRestoreCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetRestoreCredentialOption
import androidx.credentials.RestoreCredential
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException

class RestoreCredentialManager(private val context: Context) {
    private val credentialManager = CredentialManager.create(context)

    /**
     * Creates a restore credential using CredentialManager.
     * Takes WebAuthn PublicKeyCredentialCreationOptions JSON from relying party server.
     */
    suspend fun createRestoreCredential(creationOptionsJson: String): Result<String> {
        return try {
            try {
                // First try with cloud backup enabled
                val request = CreateRestoreCredentialRequest(
                    requestJson = creationOptionsJson,
                    isCloudBackupEnabled = true
                )
                val response = credentialManager.createCredential(context, request)
                if (response is CreateRestoreCredentialResponse) {
                    Result.success(response.responseJson)
                } else {
                    Result.failure(IllegalStateException("Unexpected response type: ${response.javaClass.name}"))
                }
            } catch (e: Exception) {
                // If cloud backup / E2EE is unavailable (e.g. emulator without Google Account),
                // fallback to local restore key (D2D migration mode)
                val fallbackRequest = CreateRestoreCredentialRequest(
                    requestJson = creationOptionsJson,
                    isCloudBackupEnabled = false
                )
                val fallbackResponse = credentialManager.createCredential(context, fallbackRequest)
                if (fallbackResponse is CreateRestoreCredentialResponse) {
                    Result.success(fallbackResponse.responseJson)
                } else {
                    Result.failure(IllegalStateException("Unexpected fallback response type: ${fallbackResponse.javaClass.name}"))
                }
            }
        } catch (e: CreateCredentialException) {
            Result.failure(e)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Retrieves the RestoreCredential from the device (zero-tap silent restore).
     * Takes WebAuthn PublicKeyCredentialRequestOptions JSON from relying party server.
     */
    suspend fun getRestoreCredential(authenticationJson: String): Result<String> {
        return try {
            val option = GetRestoreCredentialOption(authenticationJson)
            val request = GetCredentialRequest(listOf(option))
            val response = credentialManager.getCredential(context, request)

            if (response.credential is RestoreCredential) {
                val restoreCredential = response.credential as RestoreCredential
                Result.success(restoreCredential.authenticationResponseJson)
            } else {
                Result.failure(IllegalStateException("Retrieved credential is not of type RestoreCredential"))
            }
        } catch (e: GetCredentialException) {
            Result.failure(e)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Clears the restore credential state on sign out.
     */
    suspend fun clearRestoreCredential(): Result<Unit> {
        return try {
            val request = ClearCredentialStateRequest(ClearCredentialStateRequest.TYPE_CLEAR_RESTORE_CREDENTIAL)
            credentialManager.clearCredentialState(request)
            Result.success(Unit)
        } catch (e: ClearCredentialException) {
            Result.failure(e)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
