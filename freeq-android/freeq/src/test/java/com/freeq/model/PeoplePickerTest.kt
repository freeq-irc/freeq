package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The New-message people picker (port of macOS NewDMSheet): known people
 * from shared channels + existing DM threads, live-filtered, prefix
 * matches first, with a free-form row for a name nobody matches.
 */
class PeoplePickerTest {

    private val nickToDid = { n: String ->
        when (n.lowercase()) {
            "echo-bot" -> "did:key:z6MkBot"
            "alice" -> "did:plc:alice"
            else -> null
        }
    }
    private val displayName = { key: String ->
        if (key == "did:key:z6MkBot") "echo-bot" else key
    }

    private fun build(
        members: List<String> = emptyList(),
        threads: List<String> = emptyList(),
    ) = PeoplePicker.candidates(
        memberNicks = members,
        dmThreads = threads,
        selfNick = "zapnap",
        nickToDid = nickToDid,
        displayName = displayName,
    )

    @Test fun channel_members_are_online_and_self_is_excluded() {
        val people = build(members = listOf("alice", "zapnap", "bob"))
        assertEquals(listOf("alice", "bob"), people.map { it.label })
        assertTrue(people.all { it.online })
    }

    @Test fun dm_threads_appear_with_resolved_names_and_offline() {
        val people = build(threads = listOf("did:key:z6MkBot", "gamma"))
        assertEquals(listOf("echo-bot", "gamma"), people.map { it.label })
        assertTrue(people.none { it.online })
        // Opening uses the thread key itself, not the label.
        assertEquals("did:key:z6MkBot", people.first { it.label == "echo-bot" }.key)
    }

    @Test fun a_person_in_both_sources_appears_once_online() {
        // echo-bot is in a shared channel AND has a DID-keyed thread.
        val people = build(members = listOf("echo-bot"), threads = listOf("did:key:z6MkBot"))
        assertEquals(1, people.size)
        assertTrue(people.single().online)
    }

    @Test fun filter_is_substring_with_prefix_matches_first() {
        val people = build(members = listOf("brainstorm", "alice", "storman"))
        val hits = PeoplePicker.filter(people, "stor")
        assertEquals(listOf("storman", "brainstorm"), hits.map { it.label })
    }

    @Test fun empty_query_lists_everyone_alphabetically() {
        val people = build(members = listOf("carol", "alice", "bob"))
        assertEquals(listOf("alice", "bob", "carol"), PeoplePicker.filter(people, " ").map { it.label })
    }

    @Test fun freeform_row_appears_only_for_unknown_names() {
        val people = build(members = listOf("alice"))
        assertEquals("gamma", PeoplePicker.freeform("gamma", people))
        assertNull(PeoplePicker.freeform("alice", people))   // exact match, any case
        assertNull(PeoplePicker.freeform("ALICE", people))
        assertNull(PeoplePicker.freeform("  ", people))
        assertNull(PeoplePicker.freeform("#chan", people))   // channels are not people
    }

    @Test fun did_input_never_offers_a_freeform_row_mislabel() {
        // Typing a full DID is allowed; it stays the key, not a "name".
        val people = build()
        assertEquals("did:plc:xyz", PeoplePicker.freeform("did:plc:xyz", people))
        assertFalse(people.any { it.key == "did:plc:xyz" })
    }
}
