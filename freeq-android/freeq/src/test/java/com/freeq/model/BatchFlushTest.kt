package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Tests for the IRCv3 batch flush — the path that backfills CHATHISTORY
 * scrollback into a channel. Sort order, dedup against existing channel
 * messages, and the empty-batch "no more history" signal are all covered.
 */
class BatchFlushTest {

    private fun msg(id: String, ts: Long, from: String = "alice", text: String = "hi") =
        ChatMessage(
            id = id,
            from = from,
            text = text,
            isAction = false,
            timestamp = Date(ts),
        )

    @Test fun flush_appends_messages_in_chronological_order() {
        val buf = BatchBuffer(
            target = "#test",
            messages = mutableListOf(msg("c", 300), msg("a", 100), msg("b", 200)),
        )
        val ch = ChannelState("#test")
        BatchFlush.flushInto(buf, ch)
        assertEquals(listOf("a", "b", "c"), ch.messages.map { it.id })
    }

    @Test fun flush_dedups_against_existing_channel_messages() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg("a", 100))
        ch.appendIfNew(msg("b", 200))

        val buf = BatchBuffer(
            target = "#test",
            messages = mutableListOf(msg("a", 100), msg("c", 300)),
        )
        BatchFlush.flushInto(buf, ch)
        assertEquals(listOf("a", "b", "c"), ch.messages.map { it.id })
    }

    @Test fun flush_interleaves_older_history_into_correct_position() {
        // CHATHISTORY backfill arrives AFTER the channel has new live
        // messages. The flush must still place older messages before
        // newer ones rather than dumping them at the tail.
        val ch = ChannelState("#test")
        ch.appendIfNew(msg("live-1", 1000))
        ch.appendIfNew(msg("live-2", 2000))

        val buf = BatchBuffer(
            target = "#test",
            batchType = "chathistory",
            messages = mutableListOf(msg("hist-1", 100), msg("hist-2", 500)),
        )
        BatchFlush.flushInto(buf, ch)
        assertEquals(
            listOf("hist-1", "hist-2", "live-1", "live-2"),
            ch.messages.map { it.id },
        )
    }

    @Test fun flush_orders_same_second_rows_by_msgid_in_both_input_orders() {
        // The server's replay time tag is second-precision, so an act offer
        // and its accept minted in the same second arrive with equal
        // timestamps. ULID order is mint order, so the offer must lead
        // whichever order the two were buffered in.
        val ts = 1_756_760_000_000
        val offer = msg("01M1FDM7HM4E9H8FPB7ND1DZKA", ts)
        val accept = msg("01M1FDM7HQ7Z9K2XR4V6TB0C3E", ts)

        for (buffered in listOf(listOf(offer, accept), listOf(accept, offer))) {
            val ch = ChannelState("#test")
            BatchFlush.flushInto(
                BatchBuffer(target = "#test", messages = buffered.toMutableList()),
                ch,
            )
            assertEquals(listOf(offer.id, accept.id), ch.messages.map { it.id })
        }
    }

    @Test fun isExhaustedHistory_true_for_empty_chathistory_batch() {
        val buf = BatchBuffer(target = "#test", batchType = "chathistory")
        assertTrue(BatchFlush.isExhaustedHistory(buf))
    }

    @Test fun isExhaustedHistory_false_when_chathistory_returned_messages() {
        val buf = BatchBuffer(
            target = "#test",
            batchType = "chathistory",
            messages = mutableListOf(msg("a", 100)),
        )
        assertFalse(BatchFlush.isExhaustedHistory(buf))
    }

    @Test fun isExhaustedHistory_false_for_non_chathistory_empty_batch() {
        // Other batch types (e.g. netjoin) being empty is just normal —
        // it must not trip the "end of history" flag.
        val buf = BatchBuffer(target = "#test", batchType = "netjoin")
        assertFalse(BatchFlush.isExhaustedHistory(buf))
    }

    @Test fun flush_of_empty_batch_is_a_no_op() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg("a", 100))
        val buf = BatchBuffer(target = "#test")
        BatchFlush.flushInto(buf, ch)
        assertEquals(listOf("a"), ch.messages.map { it.id })
    }
}
