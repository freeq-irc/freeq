package com.freeq.model

/**
 * Whether a DM named in the CHATHISTORY TARGETS reply should ask for its
 * history, given what the thread already holds.
 *
 * A DM has no join to replay it, and a connection that was down — the app
 * backgrounded, or killed and restored from the cache — missed whatever was
 * sent meanwhile. The server stored it, and TARGETS says when the thread last
 * moved; asking only for empty threads left that gap unfilled for good.
 *
 * Pure, so the rule can be tested without an Android runtime.
 */
internal object DmCatchUp {
    /**
     * [serverLastMs] is the TARGETS `time` tag, null when absent. Compared in
     * whole seconds: the server writes that tag second-precision.
     */
    fun shouldFetch(serverLastMs: Long?, held: List<ChatMessage>): Boolean {
        // Join/part lines and the like carry ids the server never minted, and
        // device time; only the server's own messages say how far we are.
        val newest = held.lastOrNull { !BufferCache.isLocallyMintedId(it.id) } ?: return true
        if (serverLastMs == null) return true
        return serverLastMs / 1000 > newest.timestamp.time / 1000
    }
}
