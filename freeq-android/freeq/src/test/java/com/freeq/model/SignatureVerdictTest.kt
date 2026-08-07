package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Reading the server's answer about a signature.
 *
 * The distinctions here are the whole point. "We couldn't check this" and
 * "this doesn't check out" are different facts and only one of them is an
 * accusation; a check that never reached the server is a fact about the
 * network and says nothing about the message at all. Collapsing any of them
 * into the others puts a warning on messages nobody impugned.
 */
class SignatureVerdictTest {

    private fun answer(status: Int, body: String?) = SignatureVerdict.parse(status, body)

    @Test fun a_device_signature_is_verified_on_the_senders_own_hardware() {
        val a = answer(200, """{"verification":{"verdict":"valid","verified_by":"client-session-key"}}""")
        assertEquals(VerifyOutcome.DEVICE, a.outcome)
        assertTrue(a.isVerified)
        assertFalse(a.transient)
    }

    @Test fun a_server_signature_is_a_vouch_not_a_verification() {
        // Valid is not verified: the server vouching for what it received is a
        // fact about the server, not proof from the sender.
        val a = answer(200, """{"verification":{"verdict":"valid","verified_by":"server-key"}}""")
        assertEquals(VerifyOutcome.SERVER, a.outcome)
        assertFalse(a.isVerified)
    }

    @Test fun a_mismatch_is_the_one_accusation() {
        val a = answer(200, """{"verification":{"verdict":"invalid","verified_by":"client-session-key"}}""")
        assertEquals(VerifyOutcome.INVALID, a.outcome)
        assertFalse(a.isVerified)
        assertTrue(a.isInvalid)
    }

    @Test fun an_unknown_key_is_a_cant_check_that_a_retry_can_outrun() {
        // Answering the request is what starts the server fetching the key,
        // so asking again shortly usually resolves this one.
        val a = answer(200, """{"verification":{"verdict":"unverifiable","verified_by":"unverifiable-unknown-key"}}""")
        assertEquals(VerifyOutcome.UNVERIFIABLE, a.outcome)
        assertTrue(a.transient)
    }

    @Test fun other_cant_checks_are_final() {
        val a = answer(200, """{"verification":{"verdict":"unverifiable","verified_by":"unverifiable-retired-format"}}""")
        assertEquals(VerifyOutcome.UNVERIFIABLE, a.outcome)
        assertFalse(a.transient)
    }

    @Test fun an_unsigned_message_is_a_fact_not_a_warning() {
        // Guests sign nothing. There is no verification object at all.
        val a = answer(200, """{"msgid":"01ABC"}""")
        assertEquals(VerifyOutcome.UNVERIFIABLE, a.outcome)
        assertFalse(a.isInvalid)
    }

    @Test fun an_older_servers_boolean_false_is_not_an_accusation() {
        // Before the three-way verdict, `valid:false` meant "could not
        // confirm". Reading it as "forged" would put a red mark on messages
        // nobody impugned.
        val a = answer(200, """{"verification":{"valid":false,"verified_by":"none"}}""")
        assertEquals(VerifyOutcome.UNVERIFIABLE, a.outcome)
    }

    @Test fun an_older_servers_boolean_true_still_verifies() {
        val a = answer(200, """{"verification":{"valid":true,"verified_by":"client-session-key"}}""")
        assertEquals(VerifyOutcome.DEVICE, a.outcome)
    }

    @Test fun no_record_of_that_id_is_a_cant_check() {
        assertEquals(VerifyOutcome.UNVERIFIABLE, answer(404, null).outcome)
    }

    @Test fun a_server_fault_means_the_check_never_happened() {
        // Saying "could not be checked here" would claim the server looked.
        assertEquals(VerifyOutcome.UNREACHABLE, answer(500, null).outcome)
        assertEquals(VerifyOutcome.UNREACHABLE, answer(502, null).outcome)
    }

    @Test fun unreadable_body_from_an_ok_response_is_a_cant_check() {
        assertEquals(VerifyOutcome.UNVERIFIABLE, answer(200, "not json at all").outcome)
    }

    @Test fun only_sender_proof_gets_the_success_tone() {
        assertEquals(VerdictTone.GOOD, SignatureVerdict.tone(VerifyOutcome.DEVICE))
        assertEquals(VerdictTone.QUIET, SignatureVerdict.tone(VerifyOutcome.SERVER))
        assertEquals(VerdictTone.BAD, SignatureVerdict.tone(VerifyOutcome.INVALID))
        assertEquals(VerdictTone.QUIET, SignatureVerdict.tone(VerifyOutcome.UNVERIFIABLE))
        assertEquals(VerdictTone.QUIET, SignatureVerdict.tone(VerifyOutcome.UNREACHABLE))
    }

    @Test fun a_server_vouch_never_wears_the_verified_headline() {
        val device = SignatureVerdict.label(VerifyAnswer(VerifyOutcome.DEVICE))
        val server = SignatureVerdict.label(VerifyAnswer(VerifyOutcome.SERVER))
        assertTrue(device.startsWith("Verified"))
        assertFalse(server.startsWith("Verified"))
        assertTrue(server.contains("vouches"))
    }

    @Test fun only_a_mismatch_marks_the_message_row() {
        // The row is silent unless a check came back an accusation. Signing is
        // the default state of a message and earns no ink.
        assertTrue(VerifyAnswer(VerifyOutcome.INVALID).marksTheRow)
        for (o in VerifyOutcome.entries.filter { it != VerifyOutcome.INVALID }) {
            assertFalse("$o must not mark the row", VerifyAnswer(o).marksTheRow)
        }
    }

    @Test fun a_settled_answer_is_worth_remembering_and_an_unsettled_one_is_not() {
        // Re-asking a settled question gets the same answer; re-asking a
        // transient or failed one can land a real verdict.
        assertTrue(SignatureVerdict.worthCaching(VerifyAnswer(VerifyOutcome.DEVICE)))
        assertTrue(SignatureVerdict.worthCaching(VerifyAnswer(VerifyOutcome.INVALID)))
        assertTrue(SignatureVerdict.worthCaching(VerifyAnswer(VerifyOutcome.UNVERIFIABLE)))
        assertFalse(
            SignatureVerdict.worthCaching(VerifyAnswer(VerifyOutcome.UNVERIFIABLE, transient = true))
        )
        assertFalse(SignatureVerdict.worthCaching(VerifyAnswer(VerifyOutcome.UNREACHABLE)))
    }
}
