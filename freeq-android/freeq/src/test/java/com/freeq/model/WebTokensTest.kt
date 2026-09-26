package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure-JVM tests for which web token a connect offers. As the web's SDK
 * (freeq-sdk-js/src/client.ts, `skipBrokerRefresh`): a token is used for one
 * connect only, and every other reconnect asks the broker for a fresh one.
 * The server takes a token once (freeq-server/src/connection/cap.rs).
 */
class WebTokensTest {

    @Test fun a_reconnect_never_offers_a_token_a_previous_connect_sent() {
        val t = WebTokens()
        t.fromBroker("A")
        assertEquals("A", t.takeForConnect())
        assertNull("the next reconnect asks the broker", t.forReconnect())
    }

    @Test fun the_first_connect_after_a_fresh_sign_in_uses_the_token_it_was_handed() {
        val t = WebTokens()
        t.pending = "signed-in"
        assertEquals("signed-in", t.forReconnect())
        assertEquals("signed-in", t.takeForConnect())
        assertNull(t.forReconnect())
    }

    @Test fun each_broker_answer_is_offered_to_one_connect() {
        val t = WebTokens()
        t.fromBroker("A")
        t.takeForConnect()
        t.fromBroker("B")
        assertEquals("B", t.forReconnect())
        assertEquals("B", t.takeForConnect())
        assertNull(t.forReconnect())
        assertNull(t.takeForConnect())
    }
}
