package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Which reaction op a tap resolves to.
 *
 * Un-reacting used to transmit nothing: the send path toggled local state and
 * only sent when the toggle *added*, so taking a reaction back updated this
 * device's screen and left it in place for everyone else. These assert the
 * outbound decision, not just local state, because local state was never the
 * part that was broken.
 *
 * They used to assert the TAGMSG line this object built. That line was raw, so
 * nothing signed it and no event id was ever filed for the reaction; the ops
 * go through the SDK's typed senders now and the line is not ours to write.
 */
class ReactionOpTest {
    private val target = "#freeq"
    private val msgId = "01JABCDEF"
    private val emoji = "🔥"

    @Test fun reacting_adds() {
        assertEquals(
            ReactionSend.Add(target, msgId, emoji),
            ReactionOp.plan(target, msgId, emoji, alreadyReacted = false),
        )
    }

    @Test fun un_reacting_removes() {
        assertEquals(
            ReactionSend.Remove(target, msgId, emoji),
            ReactionOp.plan(target, msgId, emoji, alreadyReacted = true),
        )
    }

    @Test fun the_two_ops_differ_only_in_direction() {
        // Same message and target either way — it is the same reaction being
        // put on and taken off.
        val add = ReactionOp.plan(target, msgId, emoji, alreadyReacted = false)
        val remove = ReactionOp.plan(target, msgId, emoji, alreadyReacted = true)
        assertEquals(add.target, remove.target)
        assertEquals(add.msgId, remove.msgId)
        assertEquals(add.emoji, remove.emoji)
    }

    @Test fun a_dm_target_uses_the_same_shape() {
        assertEquals(
            ReactionSend.Add("bob", msgId, emoji),
            ReactionOp.plan("bob", msgId, emoji, alreadyReacted = false),
        )
    }
}
