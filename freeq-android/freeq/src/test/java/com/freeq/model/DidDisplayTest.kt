package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Pure-JVM tests for the DID-keyed DM helpers (DidDisplay): identity
 * syntax, display resolution, and the nick→DID thread merge. Mirrors the
 * behavioral spec of the web client's identity.ts / store merge.
 */
class DidDisplayTest {

    private var idCounter = 0
    private fun msg(
        id: String = "m-${idCounter++}",
        from: String = "alice",
        text: String = "hello",
        timestamp: Date = Date(idCounter * 1000L),
    ) = ChatMessage(
        id = id,
        from = from,
        text = text,
        isAction = false,
        timestamp = timestamp,
    )

    // ── isDid / shorten ──

    @Test
    fun isDid_recognizes_dids_and_rejects_nicks() {
        assertTrue(DidDisplay.isDid("did:plc:k2n3e2vsihf3farequ44t5j7"))
        assertTrue(DidDisplay.isDid("did:key:z6MkabcDEF"))
        assertFalse(DidDisplay.isDid("alice"))
        assertFalse(DidDisplay.isDid("did:"))
        assertFalse(DidDisplay.isDid("did:plc:"))
        assertFalse(DidDisplay.isDid("#did:plc:x"))
    }

    @Test
    fun shorten_compacts_long_dids_and_passes_nicks_through() {
        assertEquals("plc:k2n3…t5j7", DidDisplay.shorten("did:plc:k2n3e2vsihf3farequ44t5j7"))
        assertEquals("plc:short", DidDisplay.shorten("did:plc:short"))
        assertEquals("bob", DidDisplay.shorten("bob"))
    }

    // ── displayName resolution chain ──

    @Test
    fun displayName_passes_plain_nicks_through() {
        assertEquals("alice", DidDisplay.displayName("alice", emptyMap(), emptyMap()))
    }

    @Test
    fun displayName_prefers_display_binding_then_reverse_then_shortens() {
        val did = "did:plc:k2n3e2vsihf3farequ44t5j7"
        assertEquals(
            "zapnap",
            DidDisplay.displayName(did, mapOf(did to "zapnap"), emptyMap())
        )
        assertEquals(
            "zapnap",
            DidDisplay.displayName(did, emptyMap(), mapOf("zapnap" to did))
        )
        assertEquals("plc:k2n3…t5j7", DidDisplay.displayName(did, emptyMap(), emptyMap()))
    }

    // ── mergeDmBuffers ──

    private fun buffers(vararg names: String): MutableList<ChannelState> =
        names.map { ChannelState(it) }.toMutableList()

    @Test
    fun merge_rekeys_a_lone_nick_thread_to_the_did() {
        val bufs = buffers("zapnap")
        bufs[0].appendIfNew(msg(text = "HELLO"))
        val unread = mutableMapOf("zapnap" to 2)

        assertTrue(DidDisplay.mergeDmBuffers(bufs, unread, "zapnap", "did:plc:zap"))
        assertEquals(1, bufs.size)
        assertEquals("did:plc:zap", bufs[0].name)
        assertEquals("HELLO", bufs[0].messages.single().text)
        assertEquals(2, unread["did:plc:zap"])
        assertFalse(unread.containsKey("zapnap"))
    }

    @Test
    fun merge_folds_nick_thread_into_existing_did_thread_ordered_and_deduped() {
        val bufs = buffers("zapnap", "did:plc:zap")
        val early = msg(text = "HELLO", timestamp = Date(1000))
        val late = msg(text = "uhm hi", timestamp = Date(2000))
        bufs[0].appendIfNew(early)
        bufs[1].appendIfNew(late)
        bufs[1].appendIfNew(early) // pre-existing copy → dedupe by id
        val unread = mutableMapOf("zapnap" to 1, "did:plc:zap" to 1)

        assertTrue(DidDisplay.mergeDmBuffers(bufs, unread, "zapnap", "did:plc:zap"))
        assertEquals(1, bufs.size)
        assertEquals(listOf("HELLO", "uhm hi"), bufs[0].messages.map { it.text })
        assertEquals(2, unread["did:plc:zap"])
    }

    @Test
    fun merge_is_a_noop_without_a_nick_thread_or_for_non_dids() {
        val bufs = buffers("did:plc:zap")
        assertFalse(DidDisplay.mergeDmBuffers(bufs, mutableMapOf(), "ghost", "did:plc:zap"))
        assertFalse(DidDisplay.mergeDmBuffers(bufs, mutableMapOf(), "zapnap", "notadid"))
        assertEquals(1, bufs.size)
    }

    @Test
    fun merge_never_touches_channel_buffers() {
        // A channel named like a nick must be untouched: merge only scans
        // the DM buffer list handed to it — pass channels to prove no-op.
        val bufs = buffers("#zapnap")
        assertFalse(DidDisplay.mergeDmBuffers(bufs, mutableMapOf(), "#zapnap", "did:plc:zap"))
        assertEquals("#zapnap", bufs[0].name)
    }
}

class DmEchoTest {
    @org.junit.Test
    fun `self echo with nick target and did dmKey yields the binding`() {
        val b = DmEcho.recipientBinding(true, "coldbot", "did:key:z6MkPeer")
        org.junit.Assert.assertEquals("coldbot" to "did:key:z6MkPeer", b)
    }

    @org.junit.Test
    fun `no binding for incoming, channels, did targets, or nick==did`() {
        org.junit.Assert.assertNull(DmEcho.recipientBinding(false, "coldbot", "did:key:z6MkPeer"))
        org.junit.Assert.assertNull(DmEcho.recipientBinding(true, "#chan", "did:key:z6MkPeer"))
        org.junit.Assert.assertNull(DmEcho.recipientBinding(true, "did:key:z6MkPeer", "did:key:z6MkPeer"))
        org.junit.Assert.assertNull(DmEcho.recipientBinding(true, "coldbot", null))
        org.junit.Assert.assertNull(DmEcho.recipientBinding(true, "coldbot", "not-a-did"))
    }

    // ── canonicalDmKey ──

    @org.junit.Test
    fun `canonical dm key resolves a known nick to its did`() {
        val nickToDid = { n: String -> if (n == "echo-bot") "did:key:z6MkBot" else null }
        org.junit.Assert.assertEquals("did:key:z6MkBot", DidDisplay.canonicalDmKey("echo-bot", nickToDid))
        org.junit.Assert.assertEquals("did:key:z6MkBot", DidDisplay.canonicalDmKey("  echo-bot  ", nickToDid))
    }

    @org.junit.Test
    fun `canonical dm key passes dids through and keeps unknown nicks`() {
        val none = { _: String -> null }
        org.junit.Assert.assertEquals("did:plc:abc", DidDisplay.canonicalDmKey("did:plc:abc", none))
        org.junit.Assert.assertEquals("gamma", DidDisplay.canonicalDmKey("gamma", none))
    }
}
