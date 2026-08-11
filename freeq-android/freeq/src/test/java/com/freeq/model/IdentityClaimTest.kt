package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The identity-claim rule itself is not tested here: it lives in the SDK,
 * pinned by the executable vectors in spec/identity-claims.json, and this
 * client only renders what the FFI hands it. What remains app-owned in this
 * file's old territory is the naming helper.
 */
class IdentityClaimTest {

    @Test fun a_display_name_wins_over_everything() {
        assertEquals("Nap", SenderIdentity.title("Nap", "zapnap.bsky.social", "zapnap"))
    }

    @Test fun a_handle_wears_its_at_sign() {
        assertEquals("@zapnap.bsky.social", SenderIdentity.title(null, "zapnap.bsky.social", "zapnap"))
    }

    @Test fun a_bare_nick_is_a_fine_name() {
        assertEquals("zapnap", SenderIdentity.title("", "  ", "zapnap"))
    }

    @Test fun nothing_at_all_names_nobody_rather_than_inventing_a_phrase() {
        // "Unidentified sender" was deleted by ruling: a message row always
        // has a nick, so the phrase was unreachable and said nothing.
        assertEquals("", SenderIdentity.title(null, null, ""))
    }
}
