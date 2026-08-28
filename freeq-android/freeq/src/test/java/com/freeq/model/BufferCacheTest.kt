package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.Date
import java.util.UUID

/**
 * On-disk buffer cache: the snapshot rules, the JSON round trip, and the
 * interaction with `appendIfNew` when replayed history overlaps what was
 * restored.
 */
class BufferCacheTest {

    @get:Rule val tmp = TemporaryFolder()

    private fun msg(
        id: String,
        from: String = "alice",
        text: String = "hello",
        at: Long = 1_000L,
    ) = ChatMessage(
        id = id,
        from = from,
        text = text,
        isAction = false,
        timestamp = Date(at),
    )

    private fun channel(name: String, vararg messages: ChatMessage): ChannelState {
        val ch = ChannelState(name)
        messages.forEach { ch.appendIfNew(it) }
        return ch
    }

    @Test fun a_cached_companion_keeps_the_task_it_names() {
        // Dedup on replay is by id, so a cached line shadows the copy history
        // sends back: whatever it lost on the way to disk it never gets back,
        // and a companion that lost its task can never draw its card.
        val line = msg(id = "01LINE", text = "offered: ship the release")
            .copy(actRef = "01JOPENER00000000000000000")
        val back = BufferCache.decode(
            BufferCache.encode(listOf(CachedBuffer("#work", isDM = false, topic = null, messages = listOf(line))))
        )!!

        assertEquals("01JOPENER00000000000000000", back[0].messages[0].actRef)
    }

    // ── snapshot ──

    @Test fun snapshot_marks_channels_and_dms_by_name() {
        val buffers = BufferCache.snapshot(
            listOf(channel("#freeq", msg("01A")), channel("bob", msg("01B")))
        )
        assertEquals(listOf(false, true), buffers.map { it.isDM })
        assertEquals(listOf("#freeq", "bob"), buffers.map { it.name })
    }

    @Test fun snapshot_keeps_the_tail_at_the_cap() {
        val ch = ChannelState("#freeq")
        for (i in 1..60) ch.appendIfNew(msg(id = "01%02d".format(i), at = i * 1000L))
        val cached = BufferCache.snapshot(listOf(ch)).single()
        assertEquals(BufferCache.MAX_MESSAGES_PER_BUFFER, cached.messages.size)
        assertEquals("0111", cached.messages.first().id) // 60 - 50 + 1
        assertEquals("0160", cached.messages.last().id)
    }

    @Test fun snapshot_excludes_locally_minted_ids() {
        // Join/part notices and any message the server never gave a msgid
        // get a random UUID, which replay cannot dedup against.
        val ch = channel(
            "#freeq",
            msg("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            msg(UUID.randomUUID().toString(), from = "", text = "bob left"),
        )
        val cached = BufferCache.snapshot(listOf(ch)).single()
        assertEquals(listOf("01ARZ3NDEKTSV4RRFFQ69G5FAV"), cached.messages.map { it.id })
    }

    @Test fun snapshot_caps_after_excluding_unpersistable_messages() {
        val ch = ChannelState("#freeq")
        for (i in 1..60) {
            ch.appendIfNew(msg(id = "01%02d".format(i), at = i * 2000L))
            ch.appendIfNew(msg(id = UUID.randomUUID().toString(), from = "", at = i * 2000L + 1))
        }
        val cached = BufferCache.snapshot(listOf(ch)).single()
        assertEquals(BufferCache.MAX_MESSAGES_PER_BUFFER, cached.messages.size)
        assertTrue(cached.messages.none { BufferCache.isLocallyMintedId(it.id) })
    }

    @Test fun snapshot_carries_the_topic_and_drops_an_empty_one() {
        val withTopic = channel("#freeq", msg("01A")).apply { topic.value = "hi" }
        val without = channel("#other", msg("01B"))
        val cached = BufferCache.snapshot(listOf(withTopic, without))
        assertEquals("hi", cached[0].topic)
        assertNull(cached[1].topic)
    }

    // ── round trip ──

    @Test fun round_trip_preserves_buffer_and_message_fields() {
        val original = ChatMessage(
            id = "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            from = "alice",
            text = "hey there",
            isAction = true,
            timestamp = Date(1_700_000_000_000L),
            replyTo = "01PARENT",
            isEdited = true,
            isDeleted = false,
            isSigned = true,
            account = "did:plc:alice",
            origin = "peer.example",
            reactions = mutableMapOf("🎉" to mutableSetOf("bob", "carol")),
        )
        val ch = channel("#freeq", original).apply { topic.value = "the topic" }

        val restored = BufferCache.decode(BufferCache.encode(BufferCache.snapshot(listOf(ch))))!!
        val buf = restored.single()
        assertEquals("#freeq", buf.name)
        assertFalse(buf.isDM)
        assertEquals("the topic", buf.topic)

        val m = buf.messages.single()
        assertEquals(original.id, m.id)
        assertEquals(original.from, m.from)
        assertEquals(original.text, m.text)
        assertEquals(original.isAction, m.isAction)
        assertEquals(original.timestamp, m.timestamp)
        assertEquals(original.replyTo, m.replyTo)
        assertEquals(original.isEdited, m.isEdited)
        assertEquals(original.isSigned, m.isSigned)
        assertEquals(original.account, m.account)
        assertEquals(original.origin, m.origin)
        assertEquals(mapOf("🎉" to setOf("bob", "carol")), m.reactions)
    }

    @Test fun round_trip_preserves_a_deleted_message() {
        val ch = channel("#freeq", msg("01A").copy(isDeleted = true, text = ""))
        val restored = BufferCache.decode(BufferCache.encode(BufferCache.snapshot(listOf(ch))))!!
        assertTrue(restored.single().messages.single().isDeleted)
    }

    @Test fun round_trip_preserves_a_dm_buffer() {
        val restored = BufferCache.decode(
            BufferCache.encode(BufferCache.snapshot(listOf(channel("did:plc:abc", msg("01A")))))
        )!!
        assertTrue(restored.single().isDM)
        assertEquals("did:plc:abc", restored.single().name)
    }

    // ── display label for DID-keyed threads ──

    @Test fun snapshot_captures_the_resolved_label_for_a_did_keyed_buffer() {
        val snap = BufferCache.snapshot(listOf(channel("did:key:z6Mkabc", msg("01A")))) { key ->
            if (key == "did:key:z6Mkabc") "echo-bot" else key
        }
        assertEquals("echo-bot", snap.single().displayName)
    }

    @Test fun snapshot_stores_no_label_when_the_resolver_has_no_name() {
        // Resolver falls back to the key itself or its compacted form:
        // nothing worth persisting — the compacted form is recomputable.
        val identity = BufferCache.snapshot(listOf(channel("did:key:z6Mkabc", msg("01A"))))
        assertNull(identity.single().displayName)
        val compacted = BufferCache.snapshot(listOf(channel("did:key:z6Mkabc", msg("01A")))) {
            DidDisplay.shorten(it)
        }
        assertNull(compacted.single().displayName)
        val plainNick = BufferCache.snapshot(listOf(channel("guest123", msg("01A")))) { it }
        assertNull(plainNick.single().displayName)
    }

    @Test fun round_trip_preserves_the_display_label() {
        val restored = BufferCache.decode(
            BufferCache.encode(
                BufferCache.snapshot(listOf(channel("did:key:z6Mkabc", msg("01A")))) { "echo-bot" }
            )
        )!!
        assertEquals("echo-bot", restored.single().displayName)
    }

    @Test fun a_version_one_cache_is_discarded_not_migrated() {
        val v1 = """{"version":1,"buffers":[{"name":"did:key:z6Mkabc","isDM":true,"messages":[]}]}"""
        assertNull(BufferCache.decode(v1))
    }

    // ── version + damage ──

    @Test fun version_mismatch_decodes_to_null() {
        val stale = """{"version":${BufferCache.VERSION + 1},"buffers":[]}"""
        assertNull(BufferCache.decode(stale))
    }

    @Test fun malformed_json_decodes_to_null() {
        assertNull(BufferCache.decode("not json at all"))
        assertNull(BufferCache.decode(""))
    }

    // ── file IO ──

    @Test fun save_then_load_returns_the_buffers() {
        val dir = tmp.newFolder()
        BufferCache.save(dir, BufferCache.snapshot(listOf(channel("#freeq", msg("01A")))))
        val loaded = BufferCache.load(dir)!!
        assertEquals("#freeq", loaded.single().name)
        assertEquals("01A", loaded.single().messages.single().id)
    }

    @Test fun load_returns_null_when_nothing_was_saved() {
        assertNull(BufferCache.load(tmp.newFolder()))
    }

    @Test fun clear_removes_the_cache() {
        val dir = tmp.newFolder()
        BufferCache.save(dir, BufferCache.snapshot(listOf(channel("#freeq", msg("01A")))))
        BufferCache.clear(dir)
        assertNull(BufferCache.load(dir))
    }

    @Test fun a_stale_version_on_disk_loads_as_nothing() {
        val dir = tmp.newFolder()
        BufferCache.save(dir, BufferCache.snapshot(listOf(channel("#freeq", msg("01A")))))
        dir.resolve(BufferCache.FILE_NAME)
            .writeText("""{"version":${BufferCache.VERSION + 1},"buffers":[]}""")
        assertNull(BufferCache.load(dir))
    }

    // ── replay overlap ──

    @Test fun replayed_history_does_not_duplicate_restored_messages() {
        val saved = channel("#freeq", msg("01A", text = "one"), msg("01B", text = "two", at = 2000))
        val cached = BufferCache.decode(BufferCache.encode(BufferCache.snapshot(listOf(saved))))!!

        // Cold launch: hydrate, then let CHATHISTORY replay the same window
        // plus one newer message.
        val fresh = ChannelState("#freeq")
        cached.single().messages.forEach { fresh.appendIfNew(it) }
        fresh.appendIfNew(msg("01A", text = "one"))
        fresh.appendIfNew(msg("01B", text = "two", at = 2000))
        fresh.appendIfNew(msg("01C", text = "three", at = 3000))

        assertEquals(listOf("01A", "01B", "01C"), fresh.messages.map { it.id })
    }

    // ── id classification ──

    @Test fun ulids_are_not_locally_minted() {
        assertFalse(BufferCache.isLocallyMintedId("01ARZ3NDEKTSV4RRFFQ69G5FAV"))
        assertTrue(BufferCache.isLocallyMintedId(UUID.randomUUID().toString()))
        assertTrue(BufferCache.isLocallyMintedId(UUID.randomUUID().toString().uppercase()))
    }
}
