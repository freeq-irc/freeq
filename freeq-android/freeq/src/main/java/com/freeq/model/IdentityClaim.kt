package com.freeq.model

/**
 * The identity-claim rule does not live here. Its states, precedence, and
 * every user-facing string come from the SDK (spec/identity-claims.json),
 * reached through the FFI's claimForMessage / claimForPerson /
 * claimForSender — the same rule, byte for byte, that the web client
 * renders. This file keeps only the app-side lookup plumbing that feeds it.
 */
enum class IdentityLookup {
    /** No ask has gone out, or the surface never asks. */
    NOT_ASKED,

    /** An ask is out and unanswered. */
    IN_FLIGHT,

    /** The answer came back and named no account. */
    NO_ACCOUNT,

    /** The answer named a DID this session, so the binding is live-known
     *  even when the person is in no roster right now. */
    ANSWERED_DID,
}

/**
 * What to call this person on a surface about them. Anyone we can name is
 * named; a message row always has a nick, so the empty fallback is
 * unreachable in practice.
 */
object SenderIdentity {
    fun title(displayName: String?, handle: String?, nick: String?): String =
        displayName?.takeIf { it.isNotBlank() }
            ?: handle?.takeIf { it.isNotBlank() }?.let { "@$it" }
            ?: nick?.takeIf { it.isNotBlank() }
            ?: ""
}
