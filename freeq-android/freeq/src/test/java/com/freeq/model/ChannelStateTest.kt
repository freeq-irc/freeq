package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Pure-JVM unit tests for `ChannelState`. The class only uses Compose
 * runtime (`mutableStateListOf` etc.) which works on the host JVM, so no
 * Robolectric or instrumented runtime is needed.
 *
 * Covers the hot ingest paths the IRC event handler calls into:
 * `appendIfNew`, `applyEdit`, `applyDelete`, `applyReaction`.
 */
class ChannelStateTest {

    // ── Task events and the lines beside them ──

    private val opener = "01JOPENER00000000000000000"

    private fun offer(ch: ChannelState) = ch.actTasks.record(
        ActEventInput(
            from = "poster", did = "did:plc:poster", kind = "handoff", verb = "offer",
            eventId = opener, taskId = opener,
            fields = mapOf("act-title" to "ship the release"),
        )
    )

    @Test fun a_companion_line_joins_the_event_it_was_written_beside() {
        val ch = ChannelState("#work")
        offer(ch)
        ch.appendIfNew(msg(id = "m1", from = "poster", text = "offered: ship the release")
            .copy(actRef = opener))

        assertEquals("m1", ch.actTasks.task(opener)!!.events[0].msgId)
    }

    @Test fun a_line_that_landed_first_joins_when_its_event_arrives() {
        val ch = ChannelState("#work")
        ch.appendIfNew(msg(id = "m1", from = "poster").copy(actRef = opener))
        offer(ch)
        ch.pairActCompanions()

        assertEquals("m1", ch.actTasks.task(opener)!!.events[0].msgId)
    }

    @Test fun a_paired_line_draws_a_card_of_its_own_event() {
        val ch = ChannelState("#work")
        offer(ch)
        ch.appendIfNew(msg(id = "m1", from = "poster").copy(actRef = opener))
        ch.recordActEvent(
            ActEventInput(
                from = "worker", did = "did:plc:worker", kind = "handoff", verb = "progress",
                eventId = "e2", taskId = opener, fields = mapOf("act-note" to "halfway"),
            )
        )
        ch.appendIfNew(msg(id = "m2", from = "worker").copy(actRef = opener))

        // One card per event, each headed by the verb its own event carried.
        assertEquals("offer", ch.actCards["m1"]!!.event.verb)
        assertEquals("progress", ch.actCards["m2"]!!.event.verb)
        assertEquals("ship the release", ch.actCards["m2"]!!.task.title)
    }

    @Test fun an_event_with_no_line_draws_no_card() {
        val ch = ChannelState("#work")
        offer(ch)

        assertTrue(ch.actCards.isEmpty())
    }

    @Test fun a_wire_message_becomes_a_card_through_the_mapper() {
        // The whole path a companion takes: the FFI message with the tags the
        // server put on the wire, through the mapper, into the channel, joined
        // to an event carrying the fields the SDK hands over.
        val ch = ChannelState("#work")
        ch.recordActEvent(
            ActEventInput(
                from = "actposter", did = "did:key:zPoster", kind = "handoff", verb = "offer",
                eventId = opener, taskId = opener,
                fields = mapOf(
                    "act" to "handoff",
                    "act-title" to "update the release notes",
                    "act-verb" to "offer",
                ),
            )
        )
        val wire = com.freeq.ffi.IrcMessage(
            fromNick = "actposter", target = "#work",
            text = "offered: update the release notes", msgid = "m1",
            replyTo = null, replacesMsgid = null, editOf = null, batchId = null,
            pinMsgid = null, unpinMsgid = null, isAction = false, isSigned = true,
            timestampMs = 1_700_000_000_000L, account = "did:key:zPoster", origin = null,
            reactions = emptyList(), edited = false, dmKey = null, coordination = null,
            tags = listOf(com.freeq.ffi.TagEntry("+freeq.at/ref", opener)),
        )
        ch.appendIfNew(MessageMapper.fromIrc(wire))

        val card = ch.actCards["m1"]
        assertNotNull("the companion line must draw a card", card)
        assertEquals("offered", ActVerbs.headline(card!!.event.verb))
        assertEquals("update the release notes", card.task.title)
    }

    @Test fun an_ordinary_line_joins_nothing() {
        val ch = ChannelState("#work")
        offer(ch)
        ch.appendIfNew(msg(id = "m1", from = "poster", text = "unrelated"))

        assertNull(ch.actTasks.task(opener)!!.events[0].msgId)
    }

    private fun msg(
        id: String = "m-${idCounter++}",
        from: String = "alice",
        text: String = "hello",
        timestamp: Date = Date(idCounter * 1000L),
        isSigned: Boolean = false,
    ) = ChatMessage(
        id = id,
        from = from,
        text = text,
        isAction = false,
        timestamp = timestamp,
        isSigned = isSigned,
    )

    private var idCounter = 0L

    // ── appendIfNew ──

    @Test fun appendIfNew_appends_new_message_in_order() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a", timestamp = Date(1)))
        ch.appendIfNew(msg(id = "b", timestamp = Date(2)))
        ch.appendIfNew(msg(id = "c", timestamp = Date(3)))
        assertEquals(listOf("a", "b", "c"), ch.messages.map { it.id })
    }

    @Test fun appendIfNew_dedups_by_id() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "x", text = "first"))
        ch.appendIfNew(msg(id = "x", text = "should-be-ignored"))
        assertEquals(1, ch.messages.size)
        assertEquals("first", ch.messages[0].text)
    }

    @Test fun appendIfNew_inserts_out_of_order_message_in_timestamp_position() {
        // History replay can deliver an older message after newer ones have
        // already been appended; the channel must keep messages in
        // chronological order so CHATHISTORY backfill renders cleanly.
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "newer", timestamp = Date(100)))
        ch.appendIfNew(msg(id = "newest", timestamp = Date(200)))
        ch.appendIfNew(msg(id = "older", timestamp = Date(50)))
        assertEquals(listOf("older", "newer", "newest"), ch.messages.map { it.id })
    }

    @Test fun appendIfNew_only_real_messages_update_lastActivityTime() {
        // System join/part messages have empty `from`; they must NOT bump
        // the "recent activity" indicator the chat-list uses for sorting.
        val ch = ChannelState("#test")
        val before = ch.lastActivityTime.value
        ch.appendIfNew(msg(id = "sys", from = "", timestamp = Date(1000)))
        assertEquals(before, ch.lastActivityTime.value)

        ch.appendIfNew(msg(id = "real", from = "alice", timestamp = Date(2000)))
        assertEquals(2000L, ch.lastActivityTime.value)
    }

    // ── applyEdit ──

    @Test fun applyEdit_updates_text_and_marks_edited() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a", text = "original"))
        ch.applyEdit(originalId = "a", newId = null, newText = "edited")
        assertEquals("edited", ch.messages[0].text)
        assertTrue(ch.messages[0].isEdited)
    }

    @Test fun applyEdit_registers_new_id_so_followup_dedup_works() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a", text = "v1"))
        ch.applyEdit(originalId = "a", newId = "a-edit-1", newText = "v2")
        // A re-delivery of the edit shouldn't append a duplicate.
        ch.appendIfNew(msg(id = "a-edit-1", text = "duplicate"))
        assertEquals(1, ch.messages.size)
    }

    @Test fun applyEdit_no_op_when_message_id_unknown() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a", text = "hi"))
        ch.applyEdit(originalId = "missing", newId = null, newText = "x")
        assertEquals("hi", ch.messages[0].text)
        assertFalse(ch.messages[0].isEdited)
    }

    // ── applyDelete ──

    @Test fun applyDelete_clears_text_and_sets_flag() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a", text = "private!"))
        ch.applyDelete("a")
        assertEquals("", ch.messages[0].text)
        assertTrue(ch.messages[0].isDeleted)
    }

    @Test fun applyDelete_no_op_when_message_id_unknown() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a", text = "hi"))
        ch.applyDelete("missing")
        assertEquals(1, ch.messages.size)
        assertFalse(ch.messages[0].isDeleted)
    }

    // ── reactions ──
    //
    // Two explicit ops, never a toggle. The sender's intent toggles (see
    // ReactionOpTest); what arrives on the wire is an add or a remove, and
    // applying one twice must not undo it.

    @Test fun addReaction_adds_first_reaction() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        assertEquals(setOf("alice"), ch.messages[0].reactions["\uD83D\uDC4D"])
    }

    @Test fun addReaction_is_idempotent_on_redelivery() {
        // A duplicated or re-delivered `+react` used to toggle the reaction
        // back off, silently removing something nobody took back.
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        assertEquals(setOf("alice"), ch.messages[0].reactions["\uD83D\uDC4D"])
    }

    @Test fun removeReaction_drops_the_emoji_when_nobody_is_left() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        ch.removeReaction("a", "\uD83D\uDC4D", "alice")
        assertNull(ch.messages[0].reactions["\uD83D\uDC4D"])
    }

    @Test fun removeReaction_keeps_other_users_on_the_same_emoji() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        ch.addReaction("a", "\uD83D\uDC4D", "bob")
        ch.removeReaction("a", "\uD83D\uDC4D", "alice")
        assertEquals(setOf("bob"), ch.messages[0].reactions["\uD83D\uDC4D"])
    }

    @Test fun removeReaction_for_someone_who_never_reacted_is_a_noop() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        ch.removeReaction("a", "\uD83D\uDC4D", "bob")
        assertEquals(setOf("alice"), ch.messages[0].reactions["\uD83D\uDC4D"])
    }

    @Test fun hasReaction_reports_whether_this_user_already_reacted() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        assertFalse(ch.hasReaction("a", "\uD83D\uDC4D", "alice"))
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        assertTrue(ch.hasReaction("a", "\uD83D\uDC4D", "alice"))
        assertFalse(ch.hasReaction("a", "\uD83D\uDC4D", "bob"))
    }

    @Test fun addReaction_replaces_message_object_so_compose_recomposes() {
        // A LazyColumn reading via mutableStateListOf only recomposes when
        // the element identity changes (data class .equals would otherwise
        // make pre-/post- look identical to Compose). Verify the message
        // reference is replaced, not mutated in place.
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        val before = ch.messages[0]
        ch.addReaction("a", "\uD83D\uDC4D", "alice")
        val after = ch.messages[0]
        assertNotNull(after.reactions["\uD83D\uDC4D"])
        // Different instance — the helper builds a new map.
        assertFalse(before === after)
    }

    @Test fun reactions_on_an_unknown_message_are_a_noop() {
        // Reacting to something this buffer doesn't hold must not create it.
        val ch = ChannelState("#test")
        ch.addReaction("missing", "\uD83D\uDC4D", "alice")
        ch.removeReaction("missing", "\uD83D\uDC4D", "alice")
        assertTrue(ch.messages.isEmpty())
        assertFalse(ch.hasReaction("missing", "\uD83D\uDC4D", "alice"))
    }

    // ── findMessage ──

    @Test fun findMessage_returns_index_when_present() {
        val ch = ChannelState("#test")
        ch.appendIfNew(msg(id = "a"))
        ch.appendIfNew(msg(id = "b"))
        ch.appendIfNew(msg(id = "c"))
        assertEquals(0, ch.findMessage("a"))
        assertEquals(2, ch.findMessage("c"))
    }

    @Test fun findMessage_returns_null_when_absent() {
        val ch = ChannelState("#test")
        assertNull(ch.findMessage("nope"))
    }

    // ── seedActivityFromTarget (CHATHISTORY TARGETS cold-launch ordering) ──

    private fun iso(ms: Long) = java.time.Instant.ofEpochMilli(ms).toString()

    @Test fun parseServerTimeMillis_round_trips_iso8601_utc() {
        assertEquals(1319042451620L, parseServerTimeMillis("2011-10-19T16:40:51.620Z"))
        assertEquals(123456789L, parseServerTimeMillis(iso(123456789L)))
    }

    @Test fun parseServerTimeMillis_returns_null_for_blank_or_garbage() {
        assertNull(parseServerTimeMillis(null))
        assertNull(parseServerTimeMillis(""))
        assertNull(parseServerTimeMillis("   "))
        assertNull(parseServerTimeMillis("not-a-timestamp"))
        assertNull(parseServerTimeMillis("2011-10-19 16:40:51")) // no T / no zone
    }

    @Test fun seedActivityFromTarget_seeds_fresh_buffer_unconditionally() {
        // A buffer just minted by getOrCreateDM has no messages and
        // lastActivityTime == 0L; without this it would sort to the bottom
        // of the chat list until per-DM history backfilled.
        val ch = ChannelState("alice")
        ch.seedActivityFromTarget(iso(5_000L))
        assertEquals(5_000L, ch.lastActivityTime.value)
    }

    @Test fun seedActivityFromTarget_does_not_regress_in_session_activity() {
        // Buffer already has a live message newer than the server's
        // historical TARGETS timestamp; seeding must not move it backward.
        val ch = ChannelState("alice")
        ch.appendIfNew(msg(id = "live", from = "alice", timestamp = Date(9_000L)))
        assertEquals(9_000L, ch.lastActivityTime.value)
        ch.seedActivityFromTarget(iso(3_000L))
        assertEquals(9_000L, ch.lastActivityTime.value)
    }

    @Test fun seedActivityFromTarget_moves_forward_when_server_time_newer() {
        val ch = ChannelState("alice")
        ch.appendIfNew(msg(id = "old", from = "alice", timestamp = Date(2_000L)))
        ch.seedActivityFromTarget(iso(8_000L))
        assertEquals(8_000L, ch.lastActivityTime.value)
    }

    @Test fun seedActivityFromTarget_is_noop_on_blank_or_garbage() {
        val ch = ChannelState("alice")
        ch.seedActivityFromTarget(null)
        ch.seedActivityFromTarget("")
        ch.seedActivityFromTarget("garbage")
        assertEquals(0L, ch.lastActivityTime.value)
    }
}
