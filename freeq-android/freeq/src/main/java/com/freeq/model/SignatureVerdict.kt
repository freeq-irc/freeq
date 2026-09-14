package com.freeq.model

import androidx.compose.runtime.mutableStateMapOf
import com.freeq.ffi.KeyLayer
import com.freeq.ffi.VerdictState

/** The SDK's verdict, as it arrives over the FFI. Named here so this file can
 *  talk about it without colliding with the object below. */
typealias FfiVerdict = com.freeq.ffi.SignatureVerdict

/** How loudly a verdict is allowed to speak. Green only for sender proof; red
 *  only where a signature was found and did not hold; everything else is a
 *  quiet statement of fact. */
enum class VerdictTone { GOOD, BAD, QUIET }

/** One answer in two parts: what it is, and what it means for the reader. The
 *  line is the SDK's sentence for the state, which every freeq client shows;
 *  the heading and the tone are this client's. */
data class VerdictCopy(val heading: String, val line: String)

/**
 * What this client can say about a message's signature.
 *
 * The check is the SDK's own, made on the device: it rebuilds the signed
 * document from the line and looks the signer's key up in their identity
 * records, their DID document, or the server's key store. The verdict arrives
 * on the message, or shortly after it as a `Verdict` event, and this object
 * holds it so a row and the proof sheet read the same answer.
 *
 * The sentences come from `spec/verdict-model.json` through the SDK, so no
 * platform words its own.
 */
object SignatureVerdict {

    /** Verdicts by msgid, as the SDK settles them. Compose state, so a verdict
     *  that lands after the row was drawn appears without anything else
     *  forcing a recomposition. */
    val checked = mutableStateMapOf<String, FfiVerdict>()

    /** File what the SDK said about one line. */
    fun record(msgId: String?, verdict: FfiVerdict?) {
        if (msgId.isNullOrEmpty() || verdict == null) return
        checked[msgId] = verdict
    }

    /** The verdict on file for a message, if the SDK has given one. */
    fun of(msgId: String): FfiVerdict? = checked[msgId]

    fun tone(state: VerdictState): VerdictTone = when (state) {
        VerdictState.DEVICE -> VerdictTone.GOOD
        VerdictState.INVALID, VerdictState.RETIRED -> VerdictTone.BAD
        // A server vouch is quiet like every other not-proven state: valid is
        // not verified.
        VerdictState.SERVER, VerdictState.UNSIGNED,
        VerdictState.UNVERIFIABLE, VerdictState.PENDING -> VerdictTone.QUIET
    }

    /** The heading each state wears. The reader is asking one question — who
     *  vouches for this message — so the heading answers it and the sentence
     *  says what that means for them. */
    fun heading(state: VerdictState): String = when (state) {
        VerdictState.DEVICE -> "Signed"
        VerdictState.SERVER -> "Server Signed"
        VerdictState.UNSIGNED -> "Unsigned"
        VerdictState.UNVERIFIABLE -> "Signature Not Supported"
        VerdictState.INVALID, VerdictState.RETIRED -> "Signature Invalid"
        VerdictState.PENDING -> "Verification in Progress"
    }

    /** The answer for one verdict: this client's heading, the SDK's sentence. */
    fun copy(verdict: FfiVerdict): VerdictCopy =
        VerdictCopy(heading(verdict.state), verdict.sentence)

    /** Where the key was found, in the names the server's own answer uses. */
    fun keySource(verdict: FfiVerdict): String? = verdict.keySource

    /** The layer a device signature rests on, when it has one. */
    fun layer(verdict: FfiVerdict): KeyLayer? = verdict.layer
}
