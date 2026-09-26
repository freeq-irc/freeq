package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Pure-JVM tests for what an own JOIN after a reconnect brings into a channel
 * the phone already holds: whether it asks for history (OwnJoinHistory), and
 * what the history batch then does to the held rows, through the same
 * BatchFlush steps the event handler runs.
 */
class RejoinHistoryTest {

    private fun msg(id: String, text: String, at: Long, from: String = "alice") = ChatMessage(
        id = id,
        from = from,
        text = text,
        isAction = false,
        timestamp = Date(at * 1000L),
    )

    /** A channel as the saved buffers refill it after a reconnect. */
    private fun heldChannel(): ChannelState {
        val ch = ChannelState("#naptest")
        ch.appendIfNew(msg("X", "before the edit", 1))
        ch.appendIfNew(msg("Z", "react to me", 2))
        return ch
    }

    @Test fun an_own_join_of_a_channel_that_holds_messages_asks_for_its_history() {
        assertTrue(OwnJoinHistory().shouldAsk(heldChannel()))
    }

    @Test fun an_own_join_of_an_empty_channel_asks_for_its_history() {
        assertTrue(OwnJoinHistory().shouldAsk(ChannelState("#naptest")))
    }

    @Test fun asks_once_per_channel_per_connection() {
        val history = OwnJoinHistory()
        val ch = heldChannel()
        assertTrue(history.shouldAsk(ch))
        assertFalse("a second JOIN on the same connection", history.shouldAsk(ch))
        assertTrue("another channel", history.shouldAsk(ChannelState("#other")))
        history.newConnection()
        assertTrue("the next connection asks again", history.shouldAsk(ch))
    }

    /**
     * The phone was away; meanwhile someone sent a line, edited a held one
     * and reacted to another. It reconnects, the saved buffers refill the
     * channel, and the server's reclaim sends JOIN with no history. What the
     * channel shows after the own JOIN is what the phone showed.
     */
    @Test fun a_rejoin_onto_a_held_channel_brings_new_lines_edits_and_reactions() {
        val ch = heldChannel()
        val history = OwnJoinHistory()
        history.newConnection()

        if (history.shouldAsk(ch)) {
            // The server's answer to CHATHISTORY LATEST: the original row,
            // its newest edit, the reacted row with its reactions, and the
            // line sent while away.
            val batch = BatchBuffer(target = "#naptest", batchType = "chathistory")
            batch.messages.add(msg("X", "before the edit", 1))
            BatchFlush.foldEdit(
                batch,
                editTarget = "X",
                edit = msg("Y", "after the edit", 3).copy(isEdited = true),
                text = "after the edit",
            )
            batch.messages.add(
                msg("Z", "react to me", 2).copy(
                    reactions = mutableMapOf("👍" to mutableSetOf("nap")),
                ),
            )
            batch.messages.add(msg("W", "sent while away", 4, from = "bob"))
            BatchFlush.flushInto(batch, ch)
        }

        val byId = ch.messages.associateBy { it.id }
        assertEquals("(a) the line sent while away", "sent while away", byId["W"]?.text)
        assertEquals("(b) the edit replaces the held text", "after the edit", byId["X"]?.text)
        assertTrue("(b) marked edited", byId["X"]?.isEdited == true)
        assertEquals(
            "(c) the reaction on the held row",
            setOf("nap"),
            byId["Z"]?.reactions?.get("👍"),
        )
        assertEquals("no row doubled", 3, ch.messages.size)
    }

    /**
     * The rejoin's `CHATHISTORY LATEST` page mostly repeats lines the channel
     * already holds. Those rows stay the same objects in the same order, so
     * the list on screen is not rebuilt or re-sorted under the reader; only
     * the new line is added, after them.
     */
    @Test fun a_replayed_page_of_held_lines_leaves_every_held_row_in_place() {
        val ch = ChannelState("#naptest")
        for (i in 1..5) ch.appendIfNew(msg("m$i", "line $i", i.toLong()))
        val before = ch.messages.toList()

        val batch = BatchBuffer(target = "#naptest", batchType = "chathistory")
        for (i in 1..5) batch.messages.add(msg("m$i", "line $i", i.toLong()))
        batch.messages.add(msg("m6", "sent while away", 6, from = "bob"))
        BatchFlush.flushInto(batch, ch)

        assertEquals(listOf("m1", "m2", "m3", "m4", "m5", "m6"), ch.messages.map { it.id })
        for (i in before.indices) {
            assertTrue("row ${before[i].id} is the same object", before[i] === ch.messages[i])
        }
    }
}
