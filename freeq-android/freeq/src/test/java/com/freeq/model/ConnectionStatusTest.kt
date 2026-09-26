package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the status bar at the top of the main screen, against
 * the iPhone's `ConnectionStatusBanner` (freeq-ios/freeq/ContentView.swift):
 * its 4 s grace, its words, its icons and its "Sign in again".
 */
class ConnectionStatusTest {

    private fun bar(state: ConnectionState, network: Boolean = true, seconds: Int) =
        ConnectionStatus.bar(state, network, seconds)

    @Test fun registered_shows_nothing() {
        assertNull(bar(ConnectionState.Registered, seconds = 0))
        assertNull(bar(ConnectionState.Registered, seconds = 60))
        assertNull(bar(ConnectionState.Registered, network = false, seconds = 60))
    }

    @Test fun nothing_shows_for_the_first_4_seconds_of_a_drop() {
        for (state in listOf(ConnectionState.Disconnected, ConnectionState.Connecting, ConnectionState.Connected)) {
            for (s in 0..3) {
                assertNull("$state at $s s", bar(state, seconds = s))
                assertNull("$state offline at $s s", bar(state, network = false, seconds = s))
            }
        }
        assertTrue(bar(ConnectionState.Disconnected, seconds = 4) != null)
    }

    @Test fun disconnected_with_no_network_says_offline() {
        val b = bar(ConnectionState.Disconnected, network = false, seconds = 4)!!
        assertEquals("Offline — messages will sync when you reconnect", b.text)
        assertEquals(ConnectionStatus.Icon.Offline, b.icon)
        assertEquals(
            "Offline — messages will sync when you reconnect",
            bar(ConnectionState.Disconnected, network = false, seconds = 30)!!.text,
        )
    }

    @Test fun disconnected_with_a_network_says_signing_in_then_still_trying() {
        val early = bar(ConnectionState.Disconnected, seconds = 11)!!
        assertEquals("Signing in…", early.text)
        assertEquals(ConnectionStatus.Icon.Retry, early.icon)
        val late = bar(ConnectionState.Disconnected, seconds = 12)!!
        assertEquals("Still trying — network looks slow", late.text)
        assertEquals(ConnectionStatus.Icon.Retry, late.icon)
    }

    @Test fun connecting_says_signing_in_then_still_signing_in() {
        val early = bar(ConnectionState.Connecting, seconds = 4)!!
        assertEquals("Signing in…", early.text)
        assertEquals(ConnectionStatus.Icon.Spinner, early.icon)
        val late = bar(ConnectionState.Connecting, seconds = 12)!!
        assertEquals("Still signing in…", late.text)
        assertEquals(ConnectionStatus.Icon.Spinner, late.icon)
    }

    @Test fun connected_but_not_registered_says_almost_there() {
        val b = bar(ConnectionState.Connected, seconds = 5)!!
        assertEquals("Almost there…", b.text)
        assertEquals(ConnectionStatus.Icon.Spinner, b.icon)
    }

    /** The network only picks the offline words: a drop the network monitor
     *  never saw (a VPN keeps its network up) still shows the bar. */
    @Test fun a_drop_with_the_network_still_up_shows_the_bar() {
        assertEquals("Signing in…", bar(ConnectionState.Disconnected, network = true, seconds = 4)?.text)
    }

    @Test fun no_network_while_connecting_keeps_the_connecting_words() {
        val b = bar(ConnectionState.Connecting, network = false, seconds = 4)!!
        assertEquals("Signing in…", b.text)
        assertEquals(ConnectionStatus.Icon.Spinner, b.icon)
    }

    @Test fun sign_in_again_shows_after_20_seconds_not_connected() {
        assertFalse(bar(ConnectionState.Disconnected, seconds = 19)!!.signInAgain)
        assertTrue(bar(ConnectionState.Disconnected, seconds = 20)!!.signInAgain)
        assertTrue(bar(ConnectionState.Disconnected, network = false, seconds = 20)!!.signInAgain)
        assertFalse(bar(ConnectionState.Connecting, seconds = 19)!!.signInAgain)
        assertTrue(bar(ConnectionState.Connecting, seconds = 20)!!.signInAgain)
        assertFalse("connected is not stuck", bar(ConnectionState.Connected, seconds = 60)!!.signInAgain)
    }

    // ── Colour: danger when offline, warning otherwise (the iPhone's chat bar) ──

    @Test fun offline_is_danger() {
        assertEquals(ConnectionStatus.Tone.Danger, bar(ConnectionState.Disconnected, network = false, seconds = 4)!!.tone)
        assertEquals(ConnectionStatus.Tone.Danger, bar(ConnectionState.Connecting, network = false, seconds = 4)!!.tone)
    }

    @Test fun a_network_that_is_up_is_warning() {
        assertEquals(ConnectionStatus.Tone.Warning, bar(ConnectionState.Disconnected, seconds = 4)!!.tone)
        assertEquals(ConnectionStatus.Tone.Warning, bar(ConnectionState.Connecting, seconds = 30)!!.tone)
        assertEquals(ConnectionStatus.Tone.Warning, bar(ConnectionState.Connected, seconds = 4)!!.tone)
    }

    // ── DropTimer: the seconds the bar counts ──

    @Test fun a_launch_that_is_not_registered_counts_from_the_first_look() {
        val t = DropTimer()
        t.update(ConnectionState.Disconnected, nowMs = 1_000)
        assertEquals(0, t.secondsSinceDrop(1_000))
        assertEquals(4, t.secondsSinceDrop(5_000))
    }

    @Test fun registered_counts_nothing() {
        val t = DropTimer()
        t.update(ConnectionState.Registered, nowMs = 1_000)
        assertNull(t.secondsSinceDrop(9_000))
    }

    @Test fun attempts_within_one_drop_keep_counting() {
        val t = DropTimer()
        t.update(ConnectionState.Disconnected, nowMs = 0)
        t.update(ConnectionState.Connecting, nowMs = 3_000)
        t.update(ConnectionState.Disconnected, nowMs = 8_000)
        assertEquals(21, t.secondsSinceDrop(21_000))
    }

    @Test fun each_drop_re_arms_the_grace() {
        val t = DropTimer()
        t.update(ConnectionState.Disconnected, nowMs = 0)
        t.update(ConnectionState.Registered, nowMs = 30_000)
        assertNull(t.secondsSinceDrop(40_000))
        t.update(ConnectionState.Disconnected, nowMs = 100_000)
        assertEquals(0, t.secondsSinceDrop(100_000))
        assertEquals(3, t.secondsSinceDrop(103_999))
        assertNull(
            "a quick reconnect shows nothing",
            ConnectionStatus.bar(ConnectionState.Disconnected, true, t.secondsSinceDrop(103_999)!!),
        )
    }

    @Test fun a_clock_read_before_the_drop_counts_as_zero() {
        val t = DropTimer()
        t.update(ConnectionState.Disconnected, nowMs = 10_000)
        assertEquals(0, t.secondsSinceDrop(9_500))
    }
}
