package com.freeq.model

/**
 * IRCv3 batches accumulate messages off the wire and flush them into a
 * channel buffer in one go. Two pieces of pure logic live here so the
 * CHATHISTORY backfill path can be unit-tested independently of
 * AppState's batch map and event-handler wiring.
 */

/** Messages buffered between BatchStart and BatchEnd, plus enough metadata
 *  to know which buffer they belong to and whether they're a CHATHISTORY
 *  reply (so the "no more history" flag can be set when an empty page
 *  comes back). */
data class BatchBuffer(
    val target: String,
    val batchType: String = "",
    val messages: MutableList<ChatMessage> = mutableListOf(),
)

internal object BatchFlush {
    /** Sort the buffered messages chronologically and append each to the
     *  channel via `appendIfNew` (which dedups + maintains order). */
    fun flushInto(buffer: BatchBuffer, channel: ChannelState) {
        buffer.messages
            .sortedWith(ChatMessage.replayOrder)
            .forEach { channel.appendIfNew(it) }
    }

    /** A CHATHISTORY batch that came back with zero messages means the
     *  channel has reached the start of its history; the caller should
     *  flip `hasMoreHistory.value = false` so the load-older button
     *  stops paging. Other batch types don't carry that signal. */
    fun isExhaustedHistory(buffer: BatchBuffer): Boolean =
        buffer.batchType == "chathistory" && buffer.messages.isEmpty()
}
