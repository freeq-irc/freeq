package com.freeq.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the connection banner's state, fed the default-network
 * callback's events. Networks are plain strings here.
 */
class DefaultNetworkTrackerTest {

    @Test fun the_default_network_lost_with_no_replacement_is_not_connected() {
        val tracker = DefaultNetworkTracker<String>(initiallyConnected = true)
        tracker.onAvailable("wifi")
        tracker.onLost("wifi")
        assertFalse(tracker.isConnected)
    }

    @Test fun the_default_network_lost_then_a_new_default_is_connected() {
        val tracker = DefaultNetworkTracker<String>(initiallyConnected = true)
        tracker.onAvailable("wifi")
        tracker.onLost("wifi")
        tracker.onAvailable("lte")
        assertTrue(tracker.isConnected)
    }

    @Test fun a_late_loss_of_the_old_default_after_the_switch_stays_connected() {
        val tracker = DefaultNetworkTracker<String>(initiallyConnected = true)
        tracker.onAvailable("wifi")
        tracker.onAvailable("lte")
        tracker.onLost("wifi")
        assertTrue(tracker.isConnected)
    }

    @Test fun available_asks_for_a_reconnect() {
        val tracker = DefaultNetworkTracker<String>(initiallyConnected = false)
        assertTrue(tracker.onAvailable("wifi"))
        assertTrue(tracker.isConnected)
    }

    @Test fun available_asks_for_a_reconnect_without_a_seen_loss() {
        // A dozed process misses the loss; the reconnect is still asked for.
        val tracker = DefaultNetworkTracker<String>(initiallyConnected = true)
        tracker.onAvailable("wifi")
        assertTrue(tracker.onAvailable("wifi"))
    }

    @Test fun the_initial_state_holds_until_an_event() {
        assertFalse(DefaultNetworkTracker<String>(initiallyConnected = false).isConnected)
        assertTrue(DefaultNetworkTracker<String>(initiallyConnected = true).isConnected)
    }
}
