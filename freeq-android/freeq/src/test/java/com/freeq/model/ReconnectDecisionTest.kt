package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pure-JVM tests for the choice made when the app finds itself
 * disconnected: restore the account, reconnect the guest, or show the
 * connect screen.
 */
class ReconnectDecisionTest {

    @Test fun a_saved_session_is_reconnected() {
        assertEquals(
            ReconnectDecision.Action.ReconnectSavedSession,
            ReconnectDecision.decide(hasSavedSession = true, lastSessionWasGuest = false, savedNick = "alice"),
        )
    }

    @Test fun a_guest_with_a_nick_reconnects_as_a_guest() {
        assertEquals(
            ReconnectDecision.Action.ConnectAsGuest,
            ReconnectDecision.decide(hasSavedSession = false, lastSessionWasGuest = true, savedNick = "Guest123"),
        )
    }

    @Test fun a_guest_without_a_nick_does_nothing() {
        assertEquals(
            ReconnectDecision.Action.None,
            ReconnectDecision.decide(hasSavedSession = false, lastSessionWasGuest = true, savedNick = ""),
        )
    }

    @Test fun an_account_that_lost_its_token_does_not_become_a_guest() {
        assertEquals(
            ReconnectDecision.Action.None,
            ReconnectDecision.decide(hasSavedSession = false, lastSessionWasGuest = false, savedNick = "alice"),
        )
    }

    @Test fun a_missing_flag_does_nothing() {
        assertEquals(
            ReconnectDecision.Action.None,
            ReconnectDecision.decide(hasSavedSession = false, lastSessionWasGuest = null, savedNick = "alice"),
        )
    }
}
