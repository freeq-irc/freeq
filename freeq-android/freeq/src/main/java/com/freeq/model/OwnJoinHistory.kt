package com.freeq.model

/**
 * Whether this client's own JOIN of a channel asks for the channel's recent
 * history: on every own JOIN, as iOS does, since a channel the saved buffers
 * refilled after a reconnect still lacks what was said, edited and reacted to
 * while this device was away, and a server that reclaims the old session
 * sends JOIN with no history of its own. At most once per channel per
 * connection, so a JOIN repeated on one connection does not ask twice.
 *
 * Lives outside the event handler so the rule can be unit-tested without an
 * Android runtime.
 */
internal class OwnJoinHistory {
    private val asked = mutableSetOf<String>()

    /** Whether to ask for `channel`'s history on this own JOIN. */
    fun shouldAsk(channel: ChannelState): Boolean = asked.add(channel.name.lowercase())

    /** A new connection registered: every channel asks again. */
    fun newConnection() {
        asked.clear()
    }
}
