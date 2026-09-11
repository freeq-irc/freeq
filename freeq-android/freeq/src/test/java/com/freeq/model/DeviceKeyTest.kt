package com.freeq.model

import com.freeq.ffi.EnrollOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * What the account's answer to this device's key means.
 *
 * Only one of the three outcomes asks anything of the user, and even that one
 * changes nothing about the session: the key stays where it is and keeps
 * signing every message, and the room hears about it once rather than on every
 * reconnect.
 */
class DeviceKeyTest {

    @Test fun a_refusal_asks_for_a_sign_in_and_tells_the_room_once() {
        // The account declining to take the write is the one outcome the user
        // can do something about.
        assertEquals(EnrollOutcome.NEEDS_SIGN_IN, EnrollAnswer.outcomeFor(401))
        assertEquals(EnrollOutcome.NEEDS_SIGN_IN, EnrollAnswer.outcomeFor(402))
        assertEquals(EnrollOutcome.NEEDS_SIGN_IN, EnrollAnswer.outcomeFor(403))

        // Nothing here touches the connection: the only thing a refusal
        // produces is the line, and only the first time.
        val notice = SigningKeyNotice()
        assertEquals(SigningKeyNotice.LINE, notice.line())
        assertNull(notice.line())
        assertNull(notice.line())
    }

    @Test fun the_line_names_the_one_thing_left_to_do() {
        assertEquals(
            "Your signing key is not published to your account yet. Open Settings to publish it.",
            SigningKeyNotice.LINE,
        )
    }

    @Test fun a_write_that_landed_is_published_and_every_fault_is_a_failure() {
        assertEquals(EnrollOutcome.PUBLISHED, EnrollAnswer.outcomeFor(200))
        // A fault at the broker or the PDS is not the user's to fix, so it
        // says nothing to them; the SDK offers the key again next connect.
        for (status in listOf(400, 404, 500, 502, 504)) {
            assertEquals("$status", EnrollOutcome.FAILED, EnrollAnswer.outcomeFor(status))
        }
    }
}
