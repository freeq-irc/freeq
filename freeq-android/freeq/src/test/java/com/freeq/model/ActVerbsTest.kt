package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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

    @Test fun every_verb_has_the_glyph_the_web_shows() {
        val expected = mapOf(
            "offer" to "📋",
            "accept" to "👍",
            "decline" to "👎",
            "claim" to "✋",
            "progress" to "📌",
            "complete" to "🎉",
            "fail" to "❌",
            "cancel" to "🚫",
            "bid" to "💰",
            "award" to "🏆",
            "submit" to "📤",
            "revise" to "🔁",
            "accept-work" to "✅",
            "forfeit" to "🏳️",
        )
        for ((verb, glyph) in expected) assertEquals(glyph, ActVerbs.emoji(verb))
    }

    @Test fun a_verb_with_no_row_gets_the_pin() {
        // Same discipline as the word table: a kind may add a move without
        // this having to be taught it.
        assertEquals("📌", ActVerbs.emoji("escalate"))
        assertEquals("📌", ActVerbs.emoji(""))
    }

    @Test fun the_home_own_two_verbs_carry_the_glyphs_their_lines_open_with() {
        assertEquals("✔️", ActVerbs.emoji("confirm"))
        assertEquals("⌛", ActVerbs.emoji("expire"))
    }

    @Test fun an_opening_move_is_new_and_the_moves_onto_a_plate_are_in_progress() {
        assertEquals(ActRegister.NEW, ActVerbs.register("offer"))
        assertEquals(ActRegister.IN_PROGRESS, ActVerbs.register("award"))
        assertEquals(ActRegister.IN_PROGRESS, ActVerbs.register("claim"))
        assertEquals(ActRegister.IN_PROGRESS, ActVerbs.register("accept"))
    }

    @Test fun a_good_end_and_a_bad_one_each_have_a_register() {
        assertEquals(ActRegister.ENDED_WELL, ActVerbs.register("complete"))
        assertEquals(ActRegister.ENDED_WELL, ActVerbs.register("accept-work"))
        assertEquals(ActRegister.DID_NOT_END_WELL, ActVerbs.register("fail"))
        assertEquals(ActRegister.DID_NOT_END_WELL, ActVerbs.register("forfeit"))
        assertEquals(ActRegister.DID_NOT_END_WELL, ActVerbs.register("cancel"))
        assertEquals(ActRegister.DID_NOT_END_WELL, ActVerbs.register("decline"))
    }

    @Test fun the_verbs_a_home_signs_for_itself_have_no_register_so_they_cannot_card() {
        assertNull(ActVerbs.register("confirm"))
        assertNull(ActVerbs.register("expire"))
        assertNull(ActVerbs.register("auto-accept"))
    }
}
