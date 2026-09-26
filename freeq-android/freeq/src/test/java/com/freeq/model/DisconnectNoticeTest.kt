package com.freeq.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the "Disconnected: …" pop-up: once per drop, on the
 * first disconnect after the app was registered, not on each failed
 * reconnect attempt that follows.
 */
class DisconnectNoticeTest {

    @Test fun the_first_drop_after_registering_shows() {
        val n = DisconnectNotice()
        n.onRegistered()
        assertTrue(n.onDisconnected())
    }

    @Test fun the_failed_attempts_that_follow_do_not_show() {
        val n = DisconnectNotice()
        n.onRegistered()
        assertTrue(n.onDisconnected())
        assertFalse("second attempt", n.onDisconnected())
        assertFalse("third attempt", n.onDisconnected())
    }

    @Test fun after_registering_again_the_next_drop_shows_again() {
        val n = DisconnectNotice()
        n.onRegistered()
        n.onDisconnected()
        n.onDisconnected()
        n.onRegistered()
        assertTrue(n.onDisconnected())
        assertFalse(n.onDisconnected())
    }

    @Test fun failed_attempts_before_ever_registering_do_not_show() {
        val n = DisconnectNotice()
        assertFalse(n.onDisconnected())
        assertFalse(n.onDisconnected())
    }
}
