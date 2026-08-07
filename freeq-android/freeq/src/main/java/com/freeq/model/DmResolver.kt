package com.freeq.model

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Who a bare nick actually is, learned before the first DM goes to them.
 *
 * A signature covers the venue it was written for, and a nick is not an
 * identity — the same letters can belong to someone else tomorrow. So the SDK
 * declines to sign a DM addressed to a bare nick, and a first message to a
 * stranger went out unsigned purely because nobody had asked who they were.
 * Asking is a WHOIS; the answer comes back as a `MemberDid` event.
 *
 * Asking must never cost the user their message. The wait is short, a peer
 * that stays silent gets the message at their nick exactly as before, no error
 * is shown, and the question is not asked twice in a session.
 *
 * Not thread-safe by design: every caller — the event handler and the send
 * path alike — runs on the main dispatcher.
 */
internal class DmResolver(
    private val nickToDid: (String) -> String?,
    private val askWhois: (String) -> Unit,
    private val timeoutMs: Long = WHOIS_TIMEOUT_MS,
) {
    private val asked = mutableSetOf<String>()
    private val waiting = mutableMapOf<String, CompletableDeferred<String>>()
    private val learnedDids = mutableMapOf<String, String>()

    /**
     * Ask about `target` now, without waiting — called when a DM thread is
     * opened, so the answer is usually in hand by the time anything is typed.
     */
    fun probe(target: String) {
        val nick = pendingNick(target) ?: return
        ask(nick)
    }

    /**
     * The venue to address `target` by: its DID where one can be learned in
     * time, otherwise `target` unchanged.
     */
    suspend fun resolve(target: String): String {
        val trimmed = target.trim()
        val nick = pendingNick(trimmed) ?: return known(trimmed) ?: trimmed
        // Asked once and never answered — don't make every later message pay
        // the wait for a peer whose server isn't going to tell us.
        if (nick in asked) return trimmed
        ask(nick)
        return withTimeoutOrNull(timeoutMs) { waiting[nick]?.await() } ?: trimmed
    }

    /** A nick↔DID binding arrived, from WHOIS or anything else that carries
     *  one. Releases whoever is waiting on it. */
    fun learned(nick: String, did: String) {
        val key = nick.trim().lowercase()
        if (key.isEmpty()) return
        learnedDids[key] = did
        waiting.remove(key)?.complete(did)
    }

    /** The lowercased nick that still needs looking up, or null when `target`
     *  is not a bare nick or its DID is already known. */
    private fun pendingNick(target: String): String? {
        val trimmed = target.trim()
        if (BufferRouter.classify(trimmed) != BufferRouter.Target.DM) return null
        if (DidDisplay.isDid(trimmed)) return null
        if (known(trimmed) != null) return null
        return trimmed.lowercase()
    }

    /** The DID on file for a target: what the app has bound, then what we
     *  learned by asking. */
    private fun known(target: String): String? =
        if (DidDisplay.isDid(target)) target
        else nickToDid(target) ?: learnedDids[target.lowercase()]

    private fun ask(nick: String) {
        if (!asked.add(nick)) return
        waiting[nick] = CompletableDeferred()
        askWhois(nick)
    }

    companion object {
        /** Long enough for a WHOIS round trip, short enough that a silent peer
         *  does not feel like a hung send. */
        const val WHOIS_TIMEOUT_MS = 2000L
    }
}
