package com.freeq.model

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URL
import java.net.URLEncoder

/**
 * The signing key a DID uses to sign its messages, as returned by
 * `GET /api/v1/signing-keys/{did}`.
 */
data class SigningKeyInfo(
    val publicKey: String,
    val algorithm: String,
    val source: String,
) {
    /** Client-session keys mean the message was signed on the sender's own
     *  device — true non-repudiation, not the server vouching. */
    val sourceLabel: String
        get() = if (source == "client-session") "signed on their device" else "server-attested"
}

/**
 * Honest signature verification: asks the server to actually verify a message's
 * signature and to surface the sender's real signing key. Mirrors the iOS
 * VerifiedProofSheet / web MessageList flow against the same REST endpoints.
 * The answer is only ever what the server said — `SignatureVerdict` keeps the
 * distinction between a bad signature and one nobody could check.
 */
object VerificationService {

    /**
     * Ask whether one message's signature holds up. Settled answers are
     * remembered, so re-opening the sheet is instant and a mismatch stays
     * marked; a transient or failed check is asked again next time.
     */
    suspend fun verifyMessage(msgId: String): VerifyAnswer {
        SignatureVerdict.checked[msgId]?.let { return it }
        val answer = withContext(Dispatchers.IO) {
            try {
                val enc = URLEncoder.encode(msgId, "UTF-8")
                val url = URL("${ServerConfig.apiBaseUrl}/api/v1/verify/$enc")
                val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                    connectTimeout = 5000
                    readTimeout = 5000
                }
                val status = conn.responseCode
                val text = if (status in 200..299) {
                    conn.inputStream.bufferedReader().readText()
                } else {
                    null
                }
                SignatureVerdict.parse(status, text)
            } catch (_: Exception) {
                // A network failure says nothing about the signature.
                VerifyAnswer(VerifyOutcome.UNREACHABLE)
            }
        }
        SignatureVerdict.remember(msgId, answer)
        return answer
    }

    /** Fetch the signing key a DID publishes. null on any error. */
    suspend fun fetchSigningKey(did: String): SigningKeyInfo? = withContext(Dispatchers.IO) {
        try {
            val enc = URLEncoder.encode(did, "UTF-8")
            val url = URL("${ServerConfig.apiBaseUrl}/api/v1/signing-keys/$enc")
            val conn = url.openConnection().apply {
                connectTimeout = 5000
                readTimeout = 5000
            }
            val text = conn.getInputStream().bufferedReader().readText()
            val json = JSONObject(text)
            val pk = json.optString("public_key").takeIf { it.isNotEmpty() }
                ?: return@withContext null
            SigningKeyInfo(
                publicKey = pk,
                algorithm = json.optString("algorithm").takeIf { it.isNotEmpty() } ?: "ed25519",
                source = json.optString("source"),
            )
        } catch (_: Exception) {
            null
        }
    }
}
