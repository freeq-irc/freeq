package com.freeq.model

/**
 * Whether opening a thread should ask the server for its history.
 *
 * A channel is rejoined on every connect and the server replays that
 * channel's task events with the JOIN, so its cards rebuild themselves. A DM
 * has no join to hang replay off: its task events arrive live, or inside a
 * history page, or never. Opening the thread is the closest thing a DM has to
 * a join, and once per session is enough — the page is the same page.
 *
 * Pure, so the rule can be tested without an Android runtime.
 */
internal object DmHistoryOnOpen {
    fun shouldFetch(name: String, authenticated: Boolean, alreadyAsked: Set<String>): Boolean {
        if (name.startsWith("#") || name.startsWith("&")) return false
        // The server serves DM history only to the identity it belongs to.
        if (!authenticated) return false
        return name.lowercase() !in alreadyAsked
    }
}
