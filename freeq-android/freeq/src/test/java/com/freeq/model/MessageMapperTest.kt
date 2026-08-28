package com.freeq.model

import com.freeq.ffi.IrcMessage
import com.freeq.ffi.ReactionTally
import com.freeq.ffi.TagEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the FFI-IrcMessage → ChatMessage mapping.
 *
 * The signing badge silently regressed for months because nothing
 * exercised this plumbing — the FFI carried `isSigned` through but
 * the UI ChatMessage didn't have a field for it (commit 8869ca9).
 * These tests pin every wire field that needs to surface.
 */
class MessageMapperTest {

    private fun ircMsg(
        fromNick: String = "alice",
        target: String = "#freeq",
        text: String = "hello",
        msgid: String? = "01HX",
        replyTo: String? = null,
        replacesMsgid: String? = null,
        editOf: String? = null,
        batchId: String? = null,
        pinMsgid: String? = null,
        unpinMsgid: String? = null,
        isAction: Boolean = false,
        isSigned: Boolean = false,
        timestampMs: Long = 1_700_000_000_000L,
        account: String? = null,
        origin: String? = null,
        reactions: List<ReactionTally> = emptyList(),
        edited: Boolean = false,
        tags: List<TagEntry> = emptyList(),
    ) = IrcMessage(
        fromNick = fromNick,
        target = target,
        text = text,
        msgid = msgid,
        replyTo = replyTo,
        replacesMsgid = replacesMsgid,
        editOf = editOf,
        batchId = batchId,
        pinMsgid = pinMsgid,
        unpinMsgid = unpinMsgid,
        isAction = isAction,
        isSigned = isSigned,
        timestampMs = timestampMs,
        account = account,
        origin = origin,
        reactions = reactions,
        edited = edited,
        dmKey = null,
        coordination = null,
        tags = tags,
    )

    @Test fun preserves_basic_fields() {
        val out = MessageMapper.fromIrc(ircMsg(
            fromNick = "alice",
            text = "hello world",
            timestampMs = 1_700_000_000_000L,
        ))
        assertEquals("alice", out.from)
        assertEquals("hello world", out.text)
        assertEquals(1_700_000_000_000L, out.timestamp.time)
    }

    @Test fun preserves_msgid_when_present() {
        val out = MessageMapper.fromIrc(ircMsg(msgid = "01HXABC123"))
        assertEquals("01HXABC123", out.id)
    }

    @Test fun synthesizes_uuid_when_msgid_is_null() {
        val out = MessageMapper.fromIrc(ircMsg(msgid = null))
        assertNotNull(out.id)
        assertTrue(
            "synthesized id should be UUID-shaped",
            out.id.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
        )
    }

    @Test fun account_propagates() {
        // The sender's server-bound DID rides on the message itself. Without
        // it, a signature check on a row from someone who has since left the
        // channel has no identity to name — the member list is gone.
        assertEquals("did:plc:abc", MessageMapper.fromIrc(ircMsg(account = "did:plc:abc")).account)
        assertNull(MessageMapper.fromIrc(ircMsg(account = null)).account)
    }

    @Test fun isSigned_propagates() {
        // The signing-badge regression hid here: FFI had isSigned, our
        // ChatMessage ignored it. This test pins the bit end-to-end.
        assertTrue(MessageMapper.fromIrc(ircMsg(isSigned = true)).isSigned)
        assertFalse(MessageMapper.fromIrc(ircMsg(isSigned = false)).isSigned)
    }

    @Test fun origin_propagates() {
        // Federated provenance: the origin server name must surface so the UI
        // can render "via {origin}" and withhold the local verified/signed badges.
        assertEquals("zerosum", MessageMapper.fromIrc(ircMsg(origin = "zerosum")).origin)
        assertNull(MessageMapper.fromIrc(ircMsg(origin = null)).origin)
    }

    @Test fun isAction_propagates() {
        assertTrue(MessageMapper.fromIrc(ircMsg(isAction = true)).isAction)
        assertFalse(MessageMapper.fromIrc(ircMsg(isAction = false)).isAction)
    }

    @Test fun replyTo_propagates() {
        assertEquals("01HXABCPARENT", MessageMapper.fromIrc(ircMsg(replyTo = "01HXABCPARENT")).replyTo)
        assertNull(MessageMapper.fromIrc(ircMsg(replyTo = null)).replyTo)
    }

    @Test fun output_has_zero_reactions_and_unedited_undeleted() {
        val out = MessageMapper.fromIrc(ircMsg())
        assertTrue(out.reactions.isEmpty())
        assertFalse(out.isEdited)
        assertFalse(out.isDeleted)
    }

    @Test fun edited_flag_carries_through_from_the_server() {
        // Join replay collapses every revision into one row and sends no
        // `+draft/edit`, so the server's `+freeq.at/edited` (surfaced as
        // `edited`) is the only signal that a message was ever revised.
        // Without this a message edited before you arrived read as original.
        assertTrue(MessageMapper.fromIrc(ircMsg(edited = true)).isEdited)
        assertFalse(MessageMapper.fromIrc(ircMsg(edited = false)).isEdited)
    }

    @Test fun reactions_persisted_on_history_message_populate_into_chat_message() {
        // The persisted-reactions tag (+freeq.at/reactions) rides on
        // history-replay messages. Without this mapping, history msgs
        // arrive on-screen with no chips even though the FFI surfaced
        // the tallies. Pin every parsed tally end-to-end.
        val out = MessageMapper.fromIrc(ircMsg(reactions = listOf(
            ReactionTally(emoji = "👍", nicks = listOf("alice", "bob")),
            ReactionTally(emoji = "❤️", nicks = listOf("carol")),
        )))
        assertEquals(2, out.reactions.size)
        assertEquals(setOf("alice", "bob"), out.reactions["👍"])
        assertEquals(setOf("carol"), out.reactions["❤️"])
    }

    @Test fun empty_emoji_or_nicks_in_tally_are_dropped() {
        val out = MessageMapper.fromIrc(ircMsg(reactions = listOf(
            ReactionTally(emoji = "", nicks = listOf("alice")),
            ReactionTally(emoji = "🎉", nicks = emptyList()),
            ReactionTally(emoji = "👍", nicks = listOf("dave")),
        )))
        assertEquals(1, out.reactions.size)
        assertEquals(setOf("dave"), out.reactions["👍"])
    }
}
