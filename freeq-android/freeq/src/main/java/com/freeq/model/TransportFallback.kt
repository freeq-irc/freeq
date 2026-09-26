package com.freeq.model

/**
 * Pure decision logic for swapping IRC transport from WebSocket to plain
 * TCP after a failed connect. Lives outside AppState so it can be unit-
 * tested without instantiating an Android `ViewModel`.
 */
internal object TransportFallback {
    /** Should we swap from WS to TCP given the current Disconnected event?
     *
     *  Returns true when:
     *  - the disconnect reason names a WebSocket failure,
     *  - we haven't already swapped this attempt,
     *  - we have a saved session to fall back into,
     *  - and we know our nick.
     */
    fun shouldFallback(
        reason: String,
        transportFallbackUsed: Boolean,
        hasSavedSession: Boolean,
        nickIsEmpty: Boolean,
    ): Boolean = !transportFallbackUsed
            && reason.lowercase().contains("websocket")
            && hasSavedSession
            && !nickIsEmpty

    /** How the plain connection that replaces a failed WebSocket connects. */
    enum class Connect {
        /** A token no connect has sent yet. */
        WithUnsentToken,
        /** Ask the broker for a fresh one first, as `reconnectSavedSession` does. */
        FreshTokenFromBroker,
        /** A guest's connect, which carries no token. */
        WithoutToken,
    }

    /** The WebSocket attempt already took any token it had, and the server
     *  takes each token once: a signed-in session's plain connection gets a
     *  token of its own and never connects without one (it would register
     *  as a guest). */
    fun connect(signedIn: Boolean, unsentToken: String?): Connect = when {
        !signedIn -> Connect.WithoutToken
        unsentToken != null -> Connect.WithUnsentToken
        else -> Connect.FreshTokenFromBroker
    }
}
