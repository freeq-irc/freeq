package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The word a card puts at its head. One row per verb, the same rows the web
 * client reads, so the same move is called the same thing on both.
 */
class ActVerbsTest {

    @Test fun every_verb_has_the_word_the_web_shows() {
        val expected = mapOf(
            "offer" to "offered",
            "accept" to "accepted",
            "decline" to "declined",
            "claim" to "claimed",
            "progress" to "in progress",
            "complete" to "completed",
            "fail" to "failed",
            "cancel" to "cancelled",
            "bid" to "bid",
            "award" to "awarded",
            "submit" to "submitted",
            "revise" to "revisions requested",
            "accept-work" to "accepted",
            "forfeit" to "forfeited",
            "confirm" to "confirmed",
            "expire" to "expired",
        )
        for ((verb, word) in expected) assertEquals(word, ActVerbs.headline(verb))
    }

    @Test fun a_verb_with_no_row_shows_itself() {
        // How a kind may add a move without this table having to be taught it.
        assertEquals("escalate", ActVerbs.headline("escalate"))
    }
}
