package com.freeq.model

/**
 * The "No network connection" banner's state, fed the events of a
 * default-network callback (the one network the device is using). A loss
 * counts only for the current default: when the default switches, a late
 * `onLost` for the old one does not clear the new one.
 *
 * Generic over the network type so it can be unit-tested without Android.
 */
internal class DefaultNetworkTracker<N>(initiallyConnected: Boolean) {
    var isConnected = initiallyConnected
        private set

    private var current: N? = null

    /**
     * A network became the default. Always asks for a reconnect (true):
     * a dozed process misses the loss, so on wake there may be none seen.
     */
    fun onAvailable(network: N): Boolean {
        current = network
        isConnected = true
        return true
    }

    /** A network was lost; only the current default's loss disconnects. */
    fun onLost(network: N) {
        if (current == null || current == network) {
            current = null
            isConnected = false
        }
    }
}
