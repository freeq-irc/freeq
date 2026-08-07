package com.freeq.model

import androidx.compose.runtime.mutableStateMapOf
import org.json.JSONObject

/**
 * What checking a message's signature can come back as.
 *
 * `UNVERIFIABLE` covers a signature from before the current canonical form, or
 * one made with a key the server does not hold, or a message nobody signed at
 * all. `INVALID` means the key the signature names was found and the signature
 * does not match it. `UNREACHABLE` means the check itself failed — network
 * down, proxy fault, server error — which is a fact about the network and not
 * a verdict about the message.
 */
enum class VerifyOutcome { DEVICE, SERVER, UNVERIFIABLE, INVALID, UNREACHABLE }

/** How loudly a verdict is allowed to speak. Green only after the server
 *  answered valid; red only after it answered invalid; everything else is a
 *  quiet statement of fact. */
enum class VerdictTone { GOOD, BAD, QUIET }

/**
 * A checked answer, with the one distinction inside `UNVERIFIABLE` that
 * changes what happens next: a signature naming a key this server simply
 * hasn't fetched yet is `transient` — answering the request is what starts the
 * fetch, so asking again shortly usually resolves it. Every other flavour is
 * final.
 */
data class VerifyAnswer(val outcome: VerifyOutcome, val transient: Boolean = false) {
    /** Sender proof only. A server signature is the server vouching for what
     *  it received — a valid fact, not a verification of the sender. */
    val isVerified: Boolean
        get() = outcome == VerifyOutcome.DEVICE

    val isInvalid: Boolean
        get() = outcome == VerifyOutcome.INVALID

    /** Whether this answer leaves a mark on the message row. Only a mismatch
     *  does, and only after the server said so — signing is the default state
     *  of a message and a default earns no ink. */
    val marksTheRow: Boolean
        get() = isInvalid
}

/**
 * Reading `GET /api/v1/verify/{msgid}`.
 *
 * Verification is an explicit request — the UI asks only when the user does —
 * and the answer says only what it can support. Kept pure and separate from
 * the fetch so each distinction is assertable. Mirrors the web client's
 * `verify-signature.ts`.
 */
object SignatureVerdict {

    /** Checked verdicts by msgid, observable so a row's mark appears without
     *  anything else forcing a recomposition. */
    val checked = mutableStateMapOf<String, VerifyAnswer>()

    fun parse(status: Int, body: String?): VerifyAnswer {
        if (status !in 200..299) {
            // A 4xx is the server answering "no record of that id" — a
            // can't-check. A 5xx means the check never happened.
            return VerifyAnswer(
                if (status < 500) VerifyOutcome.UNVERIFIABLE else VerifyOutcome.UNREACHABLE
            )
        }
        val v = try {
            JSONObject(body ?: "").optJSONObject("verification")
        } catch (_: Exception) {
            null
        } ?: return VerifyAnswer(VerifyOutcome.UNVERIFIABLE)

        val verifiedBy = v.optString("verified_by")
        // `verdict` is the server's three-way answer; fall back to the older
        // boolean for a server that predates it. An old server's `false` means
        // "could not confirm", which is not the same as "forged".
        val verdict = v.optString("verdict").takeIf { it.isNotEmpty() }
            ?: if (v.optBoolean("valid")) "valid" else "unverifiable"
        return when (verdict) {
            "valid" -> VerifyAnswer(
                if (verifiedBy == "client-session-key") VerifyOutcome.DEVICE
                else VerifyOutcome.SERVER
            )
            "invalid" -> VerifyAnswer(VerifyOutcome.INVALID)
            else -> VerifyAnswer(
                VerifyOutcome.UNVERIFIABLE,
                transient = verifiedBy == "unverifiable-unknown-key",
            )
        }
    }

    fun tone(outcome: VerifyOutcome): VerdictTone = when (outcome) {
        VerifyOutcome.DEVICE -> VerdictTone.GOOD
        VerifyOutcome.INVALID -> VerdictTone.BAD
        // A server vouch is quiet like every other not-proven state.
        VerifyOutcome.SERVER, VerifyOutcome.UNVERIFIABLE, VerifyOutcome.UNREACHABLE -> VerdictTone.QUIET
    }

    /** What the verdict says, in the sheet. */
    fun label(answer: VerifyAnswer): String = when (answer.outcome) {
        VerifyOutcome.DEVICE -> "Verified — signed on the sender's device."
        VerifyOutcome.SERVER -> "Valid server signature — the server vouches for what it received; the sender's own key did not sign it."
        VerifyOutcome.INVALID -> "Does not match its signing key — treat with suspicion."
        VerifyOutcome.UNVERIFIABLE ->
            if (answer.transient) "Fetching the signer's key — checking again shortly."
            else "Could not be checked — the server doesn't have what it needs to verify this one."
        VerifyOutcome.UNREACHABLE ->
            "The check didn't go through — nothing was determined. Close and try again."
    }

    /** A settled answer is the same every time it is asked; a transient or
     *  failed one deserves a fresh try. */
    fun worthCaching(answer: VerifyAnswer): Boolean =
        !answer.transient && answer.outcome != VerifyOutcome.UNREACHABLE

    fun remember(msgId: String, answer: VerifyAnswer) {
        if (worthCaching(answer)) checked[msgId] = answer
    }
}
