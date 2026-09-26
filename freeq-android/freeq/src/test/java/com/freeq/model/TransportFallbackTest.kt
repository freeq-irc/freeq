package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the WS→TCP fallback decider. No Android runtime
 * needed; the function under test takes plain primitives.
 */
class TransportFallbackTest {

    @Test fun fallback_when_reason_names_websocket_and_we_have_session() {
        assertTrue(TransportFallback.shouldFallback(
            reason = "WebSocket connect failed: handshake error",
            transportFallbackUsed = false,
            hasSavedSession = true,
            nickIsEmpty = false,
        ))
    }

    @Test fun reason_match_is_case_insensitive() {
        assertTrue(TransportFallback.shouldFallback(
            reason = "WEBSOCKET handshake closed",
            transportFallbackUsed = false,
            hasSavedSession = true,
            nickIsEmpty = false,
        ))
    }

    @Test fun no_fallback_when_already_swapped() {
        assertFalse(TransportFallback.shouldFallback(
            reason = "WebSocket connect failed",
            transportFallbackUsed = true,
            hasSavedSession = true,
            nickIsEmpty = false,
        ))
    }

    @Test fun no_fallback_when_reason_unrelated_to_websocket() {
        // E.g. a plain TCP read EOF — there's no point retrying as TCP again.
        assertFalse(TransportFallback.shouldFallback(
            reason = "EOF",
            transportFallbackUsed = false,
            hasSavedSession = true,
            nickIsEmpty = false,
        ))
    }

    @Test fun no_fallback_when_no_saved_session() {
        // Without saved creds we can't usefully reconnect at all.
        assertFalse(TransportFallback.shouldFallback(
            reason = "WebSocket failed",
            transportFallbackUsed = false,
            hasSavedSession = false,
            nickIsEmpty = false,
        ))
    }

    @Test fun no_fallback_when_nick_empty() {
        // No nick yet — we have nothing to send NICK with after reconnect.
        assertFalse(TransportFallback.shouldFallback(
            reason = "WebSocket failed",
            transportFallbackUsed = false,
            hasSavedSession = true,
            nickIsEmpty = true,
        ))
    }

    // ── How the plain-connection fallback connects ──

    @Test fun a_signed_in_fallback_asks_the_broker_for_a_fresh_token() {
        assertEquals(
            TransportFallback.Connect.FreshTokenFromBroker,
            TransportFallback.connect(signedIn = true, unsentToken = null),
        )
    }

    @Test fun a_signed_in_fallback_never_connects_without_a_token() {
        for (unsent in listOf(null, "t")) {
            assertNotEquals(
                TransportFallback.Connect.WithoutToken,
                TransportFallback.connect(signedIn = true, unsentToken = unsent),
            )
        }
    }

    @Test fun a_signed_in_fallback_holding_an_unsent_token_uses_it() {
        assertEquals(
            TransportFallback.Connect.WithUnsentToken,
            TransportFallback.connect(signedIn = true, unsentToken = "t"),
        )
    }

    @Test fun a_guest_fallback_connects_without_a_token() {
        assertEquals(
            TransportFallback.Connect.WithoutToken,
            TransportFallback.connect(signedIn = false, unsentToken = null),
        )
    }
}
