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

    /** An edit line inside a batch: onto the buffered original when the
     *  batch holds it, with the edit's text and reactions; else buffered as
     *  it came. */
    fun foldEdit(buffer: BatchBuffer, editTarget: String, edit: ChatMessage, text: String) {
        val idx = buffer.messages.indexOfFirst { it.id == editTarget }
        if (idx < 0) {
            buffer.messages.add(edit)
            return
        }
        val held = buffer.messages[idx]
        // Reactions attach to the msgid the user reacted to — usually the
        // latest edit id — so replay delivers them ON the edit row; merge them
        // or reactions on edited messages vanish every relaunch. (The id
        // deliberately stays the original's: the flush dedupe is id-only, and
        // re-keying would append a duplicate beside a held copy after an
        // offline-window edit. An edit-anchor merge at flush is the follow-up
        // that unlocks re-keying.)
        for ((emoji, nicks) in edit.reactions) {
            if (nicks.isNotEmpty()) held.reactions[emoji] = nicks
        }
        buffer.messages[idx] = held.copy(text = text, isEdited = true)
    }

    /** A CHATHISTORY batch that came back with zero messages means the
     *  channel has reached the start of its history; the caller should
     *  flip `hasMoreHistory.value = false` so the load-older button
     *  stops paging. Other batch types don't carry that signal. */
    fun isExhaustedHistory(buffer: BatchBuffer): Boolean =
        buffer.batchType == "chathistory" && buffer.messages.isEmpty()
}
