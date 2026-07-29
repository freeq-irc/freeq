package com.freeq.model

import java.text.BreakIterator

/**
 * Jumbomoji: a message that is nothing but 1–3 emoji renders large. Shared
 * policy with the web and Apple clients so every client agrees on what is
 * "jumbo". Pure JVM — no Android framework types — so it is unit-testable.
 */
internal object Jumbomoji {

    /**
     * Font size in sp for a jumbo message, or null if it isn't one.
     * 1 emoji → 48, 2 → 40, 3 → 34. Anything with letters, digits or
     * punctuation, and anything over three emoji, is a normal message.
     */
    fun size(text: String): Int? {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return null
        var count = 0
        for (grapheme in graphemes(trimmed)) {
            if (grapheme.isBlank()) continue // spaces between emoji are fine
            if (!isEmojiGrapheme(grapheme)) return null
            count += 1
            if (count > 3) return null
        }
        return when (count) {
            1 -> 48
            2 -> 40
            3 -> 34
            else -> null
        }
    }

    fun isJumbomoji(text: String): Boolean = size(text) != null

    /**
     * Grapheme clusters, so a ZWJ sequence, a skin-tone modifier, a flag or
     * a keycap counts as one unit. `java.text.BreakIterator` rather than
     * `android.icu` — the ICU classes are stubbed out of the unit-test
     * classpath, and the tests are the cross-client parity contract.
     */
    private fun graphemes(text: String): List<String> {
        val it = BreakIterator.getCharacterInstance()
        it.setText(text)
        val out = mutableListOf<String>()
        var start = it.first()
        var end = it.next()
        while (end != BreakIterator.DONE) {
            out.add(text.substring(start, end))
            start = end
            end = it.next()
        }
        return out
    }

    /**
     * A cluster is emoji when it carries emoji presentation by default, or
     * when a variation selector explicitly asks for it (❤️, ☺️, 1️⃣ — bare
     * ❤ and ☺ are ordinary symbols and stay small). Digits, `#` and `*` are
     * emoji-adjacent but never render as emoji alone, and fall out of this
     * because none of them has default emoji presentation.
     */
    private fun isEmojiGrapheme(grapheme: String): Boolean {
        var i = 0
        var sawVariationSelector = false
        while (i < grapheme.length) {
            val cp = grapheme.codePointAt(i)
            if (isEmojiPresentation(cp)) return true
            if (cp == EMOJI_VARIATION_SELECTOR) sawVariationSelector = true
            i += Character.charCount(cp)
        }
        return sawVariationSelector
    }

    private const val EMOJI_VARIATION_SELECTOR = 0xFE0F

    private fun isEmojiPresentation(cp: Int): Boolean {
        var lo = 0
        var hi = EMOJI_PRESENTATION_RANGES.size / 2 - 1
        while (lo <= hi) {
            val mid = (lo + hi) / 2
            val start = EMOJI_PRESENTATION_RANGES[mid * 2]
            val end = EMOJI_PRESENTATION_RANGES[mid * 2 + 1]
            when {
                cp < start -> hi = mid - 1
                cp > end -> lo = mid + 1
                else -> return true
            }
        }
        return false
    }

    /**
     * Unicode `Emoji_Presentation` code points as sorted (start, end) pairs
     * — the characters that render as emoji without a variation selector.
     * `Character.isEmojiPresentation` needs API 35, well above this app's
     * minimum, so the property is carried here instead. Regenerate from the
     * Unicode data when adopting a newer emoji revision; until then, newly
     * assigned emoji simply render at normal size.
     */
    private val EMOJI_PRESENTATION_RANGES = intArrayOf(
        0x231A, 0x231B, 0x23E9, 0x23EC, 0x23F0, 0x23F0, 0x23F3, 0x23F3,
        0x25FD, 0x25FE, 0x2614, 0x2615, 0x2648, 0x2653, 0x267F, 0x267F,
        0x2693, 0x2693, 0x26A1, 0x26A1, 0x26AA, 0x26AB, 0x26BD, 0x26BE,
        0x26C4, 0x26C5, 0x26CE, 0x26CE, 0x26D4, 0x26D4, 0x26EA, 0x26EA,
        0x26F2, 0x26F3, 0x26F5, 0x26F5, 0x26FA, 0x26FA, 0x26FD, 0x26FD,
        0x2705, 0x2705, 0x270A, 0x270B, 0x2728, 0x2728, 0x274C, 0x274C,
        0x274E, 0x274E, 0x2753, 0x2755, 0x2757, 0x2757, 0x2795, 0x2797,
        0x27B0, 0x27B0, 0x27BF, 0x27BF, 0x2B1B, 0x2B1C, 0x2B50, 0x2B50,
        0x2B55, 0x2B55, 0x1F004, 0x1F004, 0x1F0CF, 0x1F0CF, 0x1F18E, 0x1F18E,
        0x1F191, 0x1F19A, 0x1F1E6, 0x1F1FF, 0x1F201, 0x1F201,
        0x1F21A, 0x1F21A, 0x1F22F, 0x1F22F, 0x1F232, 0x1F236,
        0x1F238, 0x1F23A, 0x1F250, 0x1F251, 0x1F300, 0x1F320,
        0x1F32D, 0x1F335, 0x1F337, 0x1F37C, 0x1F37E, 0x1F393,
        0x1F3A0, 0x1F3CA, 0x1F3CF, 0x1F3D3, 0x1F3E0, 0x1F3F0,
        0x1F3F4, 0x1F3F4, 0x1F3F8, 0x1F43E, 0x1F440, 0x1F440,
        0x1F442, 0x1F4FC, 0x1F4FF, 0x1F53D, 0x1F54B, 0x1F54E,
        0x1F550, 0x1F567, 0x1F57A, 0x1F57A, 0x1F595, 0x1F596,
        0x1F5A4, 0x1F5A4, 0x1F5FB, 0x1F64F, 0x1F680, 0x1F6C5,
        0x1F6CC, 0x1F6CC, 0x1F6D0, 0x1F6D2, 0x1F6D5, 0x1F6D8,
        0x1F6DC, 0x1F6DF, 0x1F6EB, 0x1F6EC, 0x1F6F4, 0x1F6FC,
        0x1F7E0, 0x1F7EB, 0x1F7F0, 0x1F7F0, 0x1F90C, 0x1F93A,
        0x1F93C, 0x1F945, 0x1F947, 0x1F9FF, 0x1FA70, 0x1FA7C,
        0x1FA80, 0x1FA8A, 0x1FA8E, 0x1FAC6, 0x1FAC8, 0x1FAC8,
        0x1FACD, 0x1FADC, 0x1FADF, 0x1FAEA, 0x1FAEF, 0x1FAF8,
    )
}
