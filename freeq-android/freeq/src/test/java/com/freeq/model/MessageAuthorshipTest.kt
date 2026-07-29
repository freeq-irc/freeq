package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Authorship gate for inbound edit/delete. Same matrix the other clients
 * pin: DID comparison wins when both sides are known, nick comparison is
 * the fallback, and an actor who is neither is refused — including a
 * channel op acting on someone else's message, which the server permits
 * but no client applies.
 */
class MessageAuthorshipTest {

    private fun bufferWith(id: String, from: String): ChannelState {
        val ch = ChannelState("#test")
        ch.appendIfNew(
            ChatMessage(
                id = id,
                from = from,
                text = "original",
                isAction = false,
                timestamp = Date(1000),
            )
        )
        return ch
    }

    private val noDids: (String) -> String? = { null }

    // ── nick fallback (no DIDs known) ──

    @Test fun author_matches_by_nick() {
        val ch = bufferWith("m1", "alice")
        assertTrue(
            MessageAuthorship.actorIsAuthor(ch, "m1", "alice", null, noDids)
        )
    }

    @Test fun nick_comparison_is_case_insensitive() {
        val ch = bufferWith("m1", "Alice")
        assertTrue(
            MessageAuthorship.actorIsAuthor(ch, "m1", "aLiCe", null, noDids)
        )
    }

    @Test fun non_author_nick_is_refused() {
        val ch = bufferWith("m1", "alice")
        assertFalse(
            MessageAuthorship.actorIsAuthor(ch, "m1", "mallory", null, noDids)
        )
    }

    // ── DID comparison wins over nick ──

    @Test fun matching_dids_pass_despite_different_nicks() {
        // Same identity, renamed mid-session: the DID is the authority.
        val ch = bufferWith("m1", "alice")
        val dids = mapOf("alice" to "did:plc:aaa")
        assertTrue(
            MessageAuthorship.actorIsAuthor(ch, "m1", "alice_", "did:plc:aaa") { dids[it.lowercase()] }
        )
    }

    @Test fun mismatched_dids_are_refused_despite_matching_nick() {
        // Nick collision / impersonation across a federated peer.
        val ch = bufferWith("m1", "alice")
        val dids = mapOf("alice" to "did:plc:aaa")
        assertFalse(
            MessageAuthorship.actorIsAuthor(ch, "m1", "alice", "did:plc:bbb") { dids[it.lowercase()] }
        )
    }

    @Test fun falls_back_to_nick_when_original_author_has_no_did() {
        val ch = bufferWith("m1", "alice")
        assertTrue(
            MessageAuthorship.actorIsAuthor(ch, "m1", "alice", "did:plc:aaa", noDids)
        )
    }

    @Test fun falls_back_to_nick_when_actor_has_no_account_tag() {
        val ch = bufferWith("m1", "alice")
        val dids = mapOf("alice" to "did:plc:aaa")
        assertFalse(
            MessageAuthorship.actorIsAuthor(ch, "m1", "mallory", null) { dids[it.lowercase()] }
        )
    }

    // ── missing original ──

    @Test fun unknown_original_passes() {
        // Nothing to apply to; the gate defers rather than guessing.
        val ch = bufferWith("m1", "alice")
        assertTrue(
            MessageAuthorship.actorIsAuthor(ch, "does-not-exist", "mallory", null, noDids)
        )
    }

    // ── op acting on someone else's message ──

    @Test fun op_deleting_another_users_message_is_refused() {
        val ch = bufferWith("m1", "alice")
        ch.members.add(MemberInfo(nick = "carol", isOp = true, isVoiced = false))
        assertFalse(
            MessageAuthorship.actorIsAuthor(ch, "m1", "carol", null, noDids)
        )
    }

    // ── applied through the buffer mutators ──

    @Test fun refused_delete_leaves_the_message_intact() {
        val ch = bufferWith("m1", "alice")
        if (MessageAuthorship.actorIsAuthor(ch, "m1", "mallory", null, noDids)) {
            ch.applyDelete("m1")
        }
        assertFalse(ch.messages[0].isDeleted)
        assertEquals("original", ch.messages[0].text)
    }

    @Test fun allowed_delete_marks_the_message_deleted() {
        val ch = bufferWith("m1", "alice")
        if (MessageAuthorship.actorIsAuthor(ch, "m1", "alice", null, noDids)) {
            ch.applyDelete("m1")
        }
        assertTrue(ch.messages[0].isDeleted)
    }

    @Test fun refused_edit_leaves_the_text_intact() {
        val ch = bufferWith("m1", "alice")
        if (MessageAuthorship.actorIsAuthor(ch, "m1", "mallory", null, noDids)) {
            ch.applyEdit("m1", "m2", "tampered")
        }
        assertEquals("original", ch.messages[0].text)
        assertFalse(ch.messages[0].isEdited)
    }

    @Test fun allowed_edit_rewrites_the_text() {
        val ch = bufferWith("m1", "alice")
        if (MessageAuthorship.actorIsAuthor(ch, "m1", "alice", null, noDids)) {
            ch.applyEdit("m1", "m2", "fixed typo")
        }
        assertEquals("fixed typo", ch.messages[0].text)
        assertTrue(ch.messages[0].isEdited)
    }
}
