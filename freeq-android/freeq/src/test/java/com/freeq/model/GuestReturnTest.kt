package com.freeq.model

import com.freeq.model.GuestReturn.Outcome
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pure-JVM tests for a signed-in session that registers as a guest: it signs
 * out on any connect, the first included; a guest's own session is unchanged.
 */
class GuestReturnTest {
    private val did = "did:plc:abc"

    @Test fun a_guest_return_after_registering_as_the_account_signs_out() {
        assertEquals(Outcome.Registered, GuestReturn.onRegistered(did, "zapnap"))
        assertEquals(Outcome.SignOut, GuestReturn.onRegistered(did, "Guest88894"))
    }

    @Test fun the_account_registering_again_carries_on() {
        GuestReturn.onRegistered(did, "zapnap")
        assertEquals(Outcome.Registered, GuestReturn.onRegistered(did, "zapnap"))
    }

    @Test fun a_guest_session_is_unchanged() {
        assertEquals(Outcome.Registered, GuestReturn.onRegistered(null, "Guest1"))
        assertEquals(Outcome.Registered, GuestReturn.onRegistered(null, "Guest2"))
    }

    @Test fun a_signed_in_first_registration_under_a_guest_nick_signs_out() {
        assertEquals(Outcome.SignOut, GuestReturn.onRegistered(did, "Guest5"))
    }
}
