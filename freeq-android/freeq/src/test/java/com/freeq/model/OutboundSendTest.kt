package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * What the compose bar turns typed text into.
 *
 * These used to be assertions about hand-built IRC lines, because edits and
 * replies were hand-built IRC lines. A raw line is never signed, so the wire
 * shape those tests pinned was precisely the thing that had to go; what
 * survives is the decision — which send this is, and what text it carries.
 */
class OutboundSendTest {
    private val target = "#freeq"

    @Test fun plain_text_is_a_plain_send() {
        assertEquals(
            OutboundSend.Plain(target, "hello"),
            ComposeSend.plan(target, "hello", editingId = null, replyToId = null),
        )
    }

    @Test fun an_edit_in_progress_wins() {
        assertEquals(
            OutboundSend.Edit(target, "01ABC", "fixed"),
            ComposeSend.plan(target, "fixed", editingId = "01ABC", replyToId = null),
        )
    }

    @Test fun a_reply_in_progress_is_a_reply() {
        assertEquals(
            OutboundSend.Reply(target, "01DEF", "answering"),
            ComposeSend.plan(target, "answering", editingId = null, replyToId = "01DEF"),
        )
    }

    @Test fun editing_beats_replying_when_both_are_pending() {
        // The compose bar shows one banner at a time, but both fields have
        // been left set before; editing is what the user is looking at.
        assertEquals(
            OutboundSend.Edit(target, "01ABC", "text"),
            ComposeSend.plan(target, "text", editingId = "01ABC", replyToId = "01DEF"),
        )
    }

    @Test fun carriage_returns_are_stripped_from_every_kind() {
        assertEquals(
            OutboundSend.Plain(target, "a\nb"),
            ComposeSend.plan(target, "a\r\nb", editingId = null, replyToId = null),
        )
        assertEquals(
            OutboundSend.Edit(target, "01ABC", "a\nb"),
            ComposeSend.plan(target, "a\r\nb", editingId = "01ABC", replyToId = null),
        )
    }

    @Test fun newlines_reach_the_sdk_intact() {
        // Multi-line edits and replies used to be escaped to a literal `\n`
        // and tagged `+freeq.at/multiline` here, because the line was built
        // here. The SDK owns that routing now — and it has to see the real
        // newlines to sign the body a receiver will actually assemble.
        val plan = ComposeSend.plan(target, "one\ntwo", editingId = "01ABC", replyToId = null)
        assertEquals(OutboundSend.Edit(target, "01ABC", "one\ntwo"), plan)
    }

    @Test fun empty_text_sends_nothing() {
        assertNull(ComposeSend.plan(target, "", editingId = null, replyToId = null))
        assertNull(ComposeSend.plan(target, "\r", editingId = "01ABC", replyToId = null))
    }
}
