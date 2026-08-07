package com.freeq.model

/**
 * What this client can honestly say about who someone is.
 *
 * A claim about a person is not a claim about any message they sent — those
 * are different subjects and they never share a surface. This one answers only
 * the first.
 */
enum class IdentityClaim {
    /** A decentralized identifier the server bound at SASL and the AT Protocol
     *  resolves. This is the only claim that earns a mark. */
    AT_PROTOCOL,

    /** A key its holder issued to itself — real, and nothing on the AT
     *  Protocol stands behind it. Bots and guests sign this way. */
    SELF_ISSUED_KEY,

    /** Nothing assertable here: no identifier on file, or one this server
     *  learned from a peer rather than checked itself. */
    NONE;

    /** The mark IS the claim, so it appears exactly where the claim holds. */
    val showsMark: Boolean
        get() = this == AT_PROTOCOL
}

/**
 * The single rule behind every identity mark in the client. Kept here so the
 * message row, the profile card and the proof view cannot drift apart — the
 * defect that let a sender wear no mark on their message and a full
 * AT-Protocol seal in the sheet.
 */
object SenderIdentity {

    /**
     * @param did the server-bound identifier, never the freely-settable nick.
     * @param origin the peer that relayed this, when we did not see it first
     *   hand. Anything relayed is peer-vouched and claims nothing here.
     */
    fun claim(did: String?, origin: String?): IdentityClaim = when {
        origin != null -> IdentityClaim.NONE
        did.isNullOrBlank() -> IdentityClaim.NONE
        did.startsWith("did:key:") -> IdentityClaim.SELF_ISSUED_KEY
        else -> IdentityClaim.AT_PROTOCOL
    }
}
