package com.freeq.model

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.freeq.ffi.DeviceKeyStore
import com.freeq.ffi.EnrollOutcome
import com.freeq.ffi.EnrollResult
import com.freeq.ffi.Enrollment
import com.freeq.ffi.StoredDeviceKey
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * This device's signing key: where it is kept, and how it reaches the account.
 *
 * The key is one 32-byte seed that outlives a session, so messages from this
 * device keep signing with the same key and a reader can learn it once. It is
 * kept the way `brokerToken` is — in `securePrefs` — with one extra turn: the
 * seed is wrapped under an AES key that lives in the Android Keystore and
 * never leaves it, so the stored bytes are useless off this device.
 */
class AndroidDeviceKeyStore(private val prefs: SharedPreferences) : DeviceKeyStore {

    override fun load(): StoredDeviceKey? {
        val blob = prefs.getString(SEED, null) ?: return null
        val createdAt = prefs.getString(CREATED_AT, null) ?: return null
        // An unreadable seed is a key this device no longer has: say so and
        // let the SDK mint a fresh one rather than failing the connect.
        val seed = try {
            unwrap(blob)
        } catch (e: Exception) {
            android.util.Log.w("freeq.devicekey", "stored seed unreadable, minting a new key", e)
            return null
        }
        return StoredDeviceKey(seed, createdAt, prefs.getString(RECORD_URI, null))
    }

    override fun save(key: StoredDeviceKey) {
        val edit = prefs.edit()
            .putString(SEED, wrap(key.seed))
            .putString(CREATED_AT, key.createdAt)
        if (key.recordUri != null) edit.putString(RECORD_URI, key.recordUri) else edit.remove(RECORD_URI)
        edit.apply()
    }

    /** Whether the key this device holds is published to the account. */
    fun isPublished(): Boolean = prefs.getString(RECORD_URI, null) != null

    private fun wrap(seed: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val sealed = cipher.doFinal(seed)
        return b64(cipher.iv) + "." + b64(sealed)
    }

    private fun unwrap(blob: String): ByteArray {
        val (iv, sealed) = blob.split(".").let { unb64(it[0]) to unb64(it[1]) }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(sealed)
    }

    private fun wrappingKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return gen.generateKey()
    }

    private fun b64(bytes: ByteArray) = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    private fun unb64(text: String) = android.util.Base64.decode(text, android.util.Base64.NO_WRAP)

    private companion object {
        const val ALIAS = "freeq_device_key_wrap"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val SEED = "deviceKeySeed"
        const val CREATED_AT = "deviceKeyCreatedAt"
        const val RECORD_URI = "deviceKeyRecordUri"
    }
}

/**
 * Reading the broker's answer to a key record.
 *
 * Three outcomes, and the middle one is the only one that asks anything of the
 * user: the account will not take a write from this session, so the key stays
 * where it is and keeps signing until they sign in again.
 */
object EnrollAnswer {
    fun outcomeFor(status: Int): EnrollOutcome = when {
        status == 200 -> EnrollOutcome.PUBLISHED
        status in 401..403 -> EnrollOutcome.NEEDS_SIGN_IN
        else -> EnrollOutcome.FAILED
    }
}

/**
 * Publishing this device's key record through the broker, the one party that
 * holds the account's token. The SDK calls this off the connect path, so a
 * refusal never keeps the user out of the room.
 */
class BrokerEnrollment(
    private val brokerBase: () -> String,
    private val brokerToken: () -> String?,
) : Enrollment {

    override fun publish(recordJson: String, signerPublicKey: String): EnrollResult {
        val token = brokerToken()
            ?: return EnrollResult(EnrollOutcome.NEEDS_SIGN_IN, null, "no broker session")
        return try {
            val url = java.net.URL("${brokerBase()}/enroll")
            val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Content-Type", "application/json")
            }
            // The record goes out as the SDK serialized it. Its `bindingSig`
            // is over the record's own canonical form, so re-encoding it here
            // would only risk changing what was signed.
            val body = """{"broker_token":${JSONObject.quote(token)},"record":$recordJson,""" +
                """"signer_public_key":${JSONObject.quote(signerPublicKey)}}"""
            conn.outputStream.use { it.write(body.toByteArray()) }
            val status = conn.responseCode
            val outcome = EnrollAnswer.outcomeFor(status)
            if (outcome != EnrollOutcome.PUBLISHED) {
                return EnrollResult(outcome, null, "broker returned $status")
            }
            val text = conn.inputStream.bufferedReader().readText()
            val uri = JSONObject(text).optString("uri").takeIf { it.isNotEmpty() }
            EnrollResult(EnrollOutcome.PUBLISHED, uri, null)
        } catch (e: Exception) {
            // A network failure says nothing about the account's answer; the
            // SDK tries again on the next connect.
            EnrollResult(EnrollOutcome.FAILED, null, e.message)
        }
    }
}

/**
 * The one line the room is told when the key could not be published.
 *
 * Said once per session: the SDK re-offers the key on every connect, and a
 * repeated line would read as a new fault each time. Messages keep sending and
 * keep carrying that key — they just show the weaker mark.
 */
class SigningKeyNotice {
    private var told = false

    /** The line, the first time it is asked for; null after that. */
    fun line(): String? {
        if (told) return null
        told = true
        return LINE
    }

    fun forget() {
        told = false
    }

    companion object {
        const val LINE =
            "Security upgrade available: publish your key so others can verify messages from this device. Open Settings to publish it."
    }
}
