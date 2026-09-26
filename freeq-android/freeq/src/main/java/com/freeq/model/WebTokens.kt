package com.freeq.model

/**
 * The web token the next connect sends. As the web's SDK
 * (freeq-sdk-js/src/client.ts, `skipBrokerRefresh`): a token is used for one
 * connect only. The server takes a token once (freeq-server/src/connection/
 * cap.rs), so a connect never offers one an earlier connect sent; a
 * reconnect with none in hand asks the broker for a fresh one.
 *
 * Lives outside AppState so the rule can be unit-tested without an Android
 * runtime.
 */
internal class WebTokens {
    /** A token handed over and not yet sent: the fresh sign-in's, or the
     *  broker's latest answer. */
    var pending: String? = null

    /** The broker answered with a fresh token for the next connect. */
    fun fromBroker(token: String) {
        pending = token
    }

    /** The token a reconnect may use without asking the broker: only one no
     *  connect has sent. Null means ask the broker. */
    fun forReconnect(): String? = pending

    /** The token this connect sends; it is gone once taken. */
    fun takeForConnect(): String? {
        val t = pending
        pending = null
        return t
    }
}
