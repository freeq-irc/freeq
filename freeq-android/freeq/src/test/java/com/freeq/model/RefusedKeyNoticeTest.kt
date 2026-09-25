package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure-JVM tests for the notice a server sends when it refuses this
 * device's signing key (FAIL MSGSIG KEY_RETIRED or KEY_EXPIRED), and what
 * follows from it.
 */
class RefusedKeyNoticeTest {

    @Test fun refusal_shows_the_sentence_clears_the_login_and_does_not_reconnect() {
        val parsed = RefusedKeyNotice.parse(
            "MSGSIG KEY_RETIRED This device was signed out from another device. Sign in again to continue."
        )
        assertEquals("This device was signed out from another device. Sign in again to continue.", parsed?.line)
        assertEquals(true, parsed?.clearsSavedLogin)
        assertEquals(false, parsed?.schedulesReconnect)
    }

    @Test fun expiry_shows_its_own_sentence_clears_the_login_and_does_not_reconnect() {
        val parsed = RefusedKeyNotice.parse(
            "MSGSIG KEY_EXPIRED This device's signing key has expired. Sign in again to continue."
        )
        assertEquals("This device's signing key has expired. Sign in again to continue.", parsed?.line)
        assertEquals(true, parsed?.clearsSavedLogin)
        assertEquals(false, parsed?.schedulesReconnect)
    }

    @Test fun ignores_other_notices() {
        assertNull(RefusedKeyNotice.parse("MSGSIG INVALID_KEY Expected 32-byte key"))
        assertNull(RefusedKeyNotice.parse("CHATHISTORY INVALID_TARGET gnap Unknown target"))
        assertNull(RefusedKeyNotice.parse(""))
    }
}
