package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/** Join/part/quit display policy: hidden by default, grouped, or all. */
class PresenceLinesTest {

    private var n = 0
    private fun sys(text: String) = ChatMessage(id = "s${n++}", from = "", text = text, isAction = false, timestamp = Date())
    private fun say(from: String, text: String) = ChatMessage(id = "m${n++}", from = from, text = text, isAction = false, timestamp = Date())

    @Test fun defaultsToHidden() {
        assertEquals(JoinPartDisplay.HIDDEN, JoinPartDisplay.fromKey(null))
        assertEquals(JoinPartDisplay.HIDDEN, JoinPartDisplay.fromKey("bogus"))
        assertEquals(JoinPartDisplay.GROUPED, JoinPartDisplay.fromKey("grouped"))
    }

    @Test fun recognisesPresenceButNotModeration() {
        assertTrue(PresenceLines.isPresence(sys("alice joined")))
        assertTrue(PresenceLines.isPresence(sys("alice left")))
        assertTrue(PresenceLines.isPresence(sys("alice quit")))
        assertTrue(PresenceLines.isPresence(sys("alice quit (Ping timeout: 120 seconds)")))
        assertFalse(PresenceLines.isPresence(sys("alice was kicked by bob (spam)")))
        assertFalse(PresenceLines.isPresence(say("alice", "bob joined")))
    }

    @Test fun hiddenDropsPresenceAndKeepsKicks() {
        val msgs = listOf(sys("alice joined"), say("bob", "hi"), sys("carol was kicked by bob (x)"), sys("dave quit"))
        val out = PresenceLines.apply(msgs, JoinPartDisplay.HIDDEN)
        assertEquals(listOf("hi", "carol was kicked by bob (x)"), out.map { it.text })
    }

    @Test fun allLeavesEverything() {
        val msgs = listOf(sys("alice joined"), sys("bob joined"))
        assertEquals(msgs, PresenceLines.apply(msgs, JoinPartDisplay.ALL))
    }

    @Test fun groupedFoldsRunsAndKeepsLoneLines() {
        val msgs = listOf(
            sys("alice joined"), sys("bob joined"), sys("carol left"),
            say("bob", "hi"),
            sys("dave joined"),
        )
        val out = PresenceLines.apply(msgs, JoinPartDisplay.GROUPED)
        assertEquals(listOf("alice, bob joined · carol left", "hi", "dave joined"), out.map { it.text })
        assertEquals(msgs[0].id, out[0].id)
    }

    @Test fun groupedSummarisesOnePersonsChurn() {
        val reconnect = listOf(sys("nap quit (bye)"), sys("nap joined"), sys("nap quit"), sys("nap joined"))
        assertEquals("nap reconnected 2×", PresenceLines.summary(reconnect))
        assertEquals("nap joined 2×", PresenceLines.summary(listOf(sys("nap joined"), sys("NAP joined"))))
    }

    @Test fun groupedTruncatesLongNameLists() {
        val run = listOf("a", "b", "c", "d", "e").map { sys("$it joined") }
        assertEquals("a, b, c and 2 more joined", PresenceLines.summary(run))
    }
}
