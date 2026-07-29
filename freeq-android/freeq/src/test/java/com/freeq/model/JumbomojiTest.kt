package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Jumbomoji policy. The first six cases are the shared cross-client
 * contract — the same vectors the web and Apple clients pin — so all four
 * clients agree on what renders large. The rest cover segmentation edges
 * specific to this implementation.
 */
class JumbomojiTest {

    // ── shared cross-client vectors ──

    @Test fun sizes_one_to_three_largest_first() {
        assertEquals(48, Jumbomoji.size("🎉"))
        assertEquals(40, Jumbomoji.size("🎉🚀"))
        assertEquals(34, Jumbomoji.size("🎉🚀🔥"))
    }

    @Test fun ignores_whitespace_between_emoji() {
        assertEquals(40, Jumbomoji.size("🎉 🚀"))
        assertEquals(48, Jumbomoji.size("  🔥  "))
    }

    @Test fun zwj_and_modifiers_count_as_one() {
        assertTrue(Jumbomoji.isJumbomoji("👩‍💻"))
        assertTrue(Jumbomoji.isJumbomoji("👍🏽"))
        assertEquals(40, Jumbomoji.size("👩‍💻👨‍👩‍👧"))
    }

    @Test fun rejects_more_than_three() {
        assertNull(Jumbomoji.size("🎉🚀🔥💯"))
        assertFalse(Jumbomoji.isJumbomoji("😀😀😀😀😀"))
    }

    @Test fun rejects_mixed_text() {
        assertNull(Jumbomoji.size("nice 🎉"))
        assertNull(Jumbomoji.size("🎉!"))
        assertNull(Jumbomoji.size("lol"))
        assertNull(Jumbomoji.size("123"))
        assertNull(Jumbomoji.size("#"))
    }

    @Test fun rejects_empty_or_whitespace_only() {
        assertNull(Jumbomoji.size(""))
        assertNull(Jumbomoji.size("   "))
    }

    // ── segmentation edges ──

    @Test fun flags_are_one_grapheme() {
        assertEquals(48, Jumbomoji.size("🇺🇸"))
        assertEquals(40, Jumbomoji.size("🇺🇸🇯🇵"))
    }

    @Test fun variation_selector_sequences_are_emoji() {
        // ❤️ and ☺️ are text-presentation characters asking for emoji
        // presentation; without the selector they are ordinary symbols.
        assertEquals(48, Jumbomoji.size("❤️"))
        assertEquals(40, Jumbomoji.size("❤️☺️"))
    }

    @Test fun bare_text_presentation_symbols_are_not_jumbo() {
        assertNull(Jumbomoji.size("❤"))
        assertNull(Jumbomoji.size("☺"))
    }

    @Test fun bare_star_and_hash_are_not_jumbo() {
        assertNull(Jumbomoji.size("*"))
        assertNull(Jumbomoji.size("#"))
    }

    @Test fun keycap_sequences_are_one_emoji() {
        assertEquals(48, Jumbomoji.size("#️⃣"))
        assertEquals(40, Jumbomoji.size("1️⃣2️⃣"))
    }

    @Test fun newlines_count_as_whitespace() {
        assertEquals(40, Jumbomoji.size("🎉\n🚀"))
    }

    @Test fun combining_accents_are_not_emoji() {
        // Multi-scalar grapheme that has nothing emoji about it.
        assertNull(Jumbomoji.size("é"))
    }

    @Test fun emoji_mixed_with_a_digit_is_rejected() {
        assertNull(Jumbomoji.size("🎉2"))
    }
}
