package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The line a reaction actually puts on the wire.
 *
 * Un-reacting used to transmit nothing: the send path toggled local state and
 * only sent when the toggle *added*, so taking a reaction back updated this
 * device's screen and left it in place for everyone else. These assert the
 * outbound line, not just local state, because local state was never the part
 * that was broken.
 */
class ReactionOpTest {
    private val target = "#freeq"
    private val msgId = "01JABCDEF"
    private val emoji = "🔥"

    @Test fun reacting_sends_react() {
        assertEquals(
            "@+react=$emoji;+reply=$msgId TAGMSG $target",
            ReactionOp.line(target, msgId, emoji, alreadyReacted = false),
        )
    }

    @Test fun un_reacting_sends_unreact() {
        assertEquals(
            "@+freeq.at/unreact=$emoji;+reply=$msgId TAGMSG $target",
            ReactionOp.line(target, msgId, emoji, alreadyReacted = true),
        )
    }

    @Test fun the_two_ops_differ_only_in_the_tag() {
        // Same reply id and target either way — the server resolves the
        // message by that id, and it is the same message in both directions.
        val add = ReactionOp.line(target, msgId, emoji, alreadyReacted = false)
        val remove = ReactionOp.line(target, msgId, emoji, alreadyReacted = true)
        assertEquals(add.substringAfter(";"), remove.substringAfter(";"))
    }

    @Test fun a_dm_target_uses_the_same_shape() {
        assertEquals(
            "@+react=$emoji;+reply=$msgId TAGMSG bob",
            ReactionOp.line("bob", msgId, emoji, alreadyReacted = false),
        )
    }
}
