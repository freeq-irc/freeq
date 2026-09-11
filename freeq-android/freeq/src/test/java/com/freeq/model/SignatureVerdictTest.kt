package com.freeq.model

import com.freeq.ffi.KeyLayer
import com.freeq.ffi.VerdictState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a verdict is allowed to claim, and the words it wears.
 *
 * The check itself is the SDK's and its own vectors cover it. What this pins
 * is the app's side: every state shows the SDK's sentence unaltered, only
 * sender proof is spoken about in green, and only a signature that was found
 * and did not hold leaves a mark on a message nobody impugned.
 */
class SignatureVerdictTest {

    private fun verdict(
        state: VerdictState,
        sentence: String = "the sentence the SDK gave",
        layer: KeyLayer? = null,
        kid: String? = "kid",
        keySource: String? = null,
    ) = FfiVerdict(state, layer, kid, keySource, sentence)

    @Test fun every_state_shows_the_sentence_the_sdk_gave_it() {
        // The words live in spec/verdict-model.json and reach this client
        // through the FFI, so no platform words its own and no state is left
        // without one.
        for (state in VerdictState.entries) {
            val v = verdict(state, sentence = "sentence for $state")
            assertEquals("sentence for $state", SignatureVerdict.copy(v).line)
        }
    }

    @Test fun the_layer_a_device_signature_rests_on_rides_along() {
        val vouched = verdict(
            VerdictState.DEVICE,
            sentence = "Signed on the sender’s device. Key vouched for by their server.",
            layer = KeyLayer.VOUCHED,
        )
        assertEquals(KeyLayer.VOUCHED, SignatureVerdict.layer(vouched))
        assertEquals(
            "Signed on the sender’s device. Key vouched for by their server.",
            SignatureVerdict.copy(vouched).line,
        )
    }

    @Test fun every_answer_says_what_it_is_and_what_it_means() {
        for (state in VerdictState.entries) {
            val copy = SignatureVerdict.copy(verdict(state))
            assertTrue("$state", copy.heading.isNotBlank())
            assertTrue("$state", copy.line.isNotBlank())
            // The heading is the answer, not a restatement of the line.
            assertFalse("$state", copy.heading == copy.line)
        }
    }

    @Test fun only_sender_proof_gets_the_success_tone() {
        assertEquals(VerdictTone.GOOD, SignatureVerdict.tone(VerdictState.DEVICE))
        assertEquals("Verified", SignatureVerdict.heading(VerdictState.DEVICE))
        // Valid is not verified: the server vouching for what it received is a
        // fact about the server, not proof from the sender.
        assertEquals(VerdictTone.QUIET, SignatureVerdict.tone(VerdictState.SERVER))
        assertFalse(SignatureVerdict.heading(VerdictState.SERVER).contains("Verified"))
        for (state in listOf(VerdictState.INVALID, VerdictState.RETIRED)) {
            assertEquals("$state", VerdictTone.BAD, SignatureVerdict.tone(state))
        }
        for (state in listOf(
            VerdictState.UNSIGNED, VerdictState.UNVERIFIABLE, VerdictState.PENDING,
        )) {
            assertEquals("$state", VerdictTone.QUIET, SignatureVerdict.tone(state))
        }
    }

    @Test fun only_a_signature_that_did_not_hold_marks_the_row() {
        // Signing is the default state of a message and a default earns no
        // ink; a signature made after its key was retired is an invalid one.
        assertTrue(SignatureVerdict.marksTheRow(VerdictState.INVALID))
        assertTrue(SignatureVerdict.marksTheRow(VerdictState.RETIRED))
        val quiet = VerdictState.entries
            .filter { it != VerdictState.INVALID && it != VerdictState.RETIRED }
        for (state in quiet) {
            assertFalse("$state must not mark the row", SignatureVerdict.marksTheRow(state))
        }
    }

    @Test fun a_verdict_that_settles_late_replaces_the_pending_one() {
        SignatureVerdict.checked.clear()
        SignatureVerdict.record("01MSG", verdict(VerdictState.PENDING))
        assertEquals(VerdictState.PENDING, SignatureVerdict.of("01MSG")?.state)
        SignatureVerdict.record("01MSG", verdict(VerdictState.DEVICE))
        assertEquals(VerdictState.DEVICE, SignatureVerdict.of("01MSG")?.state)
    }

    @Test fun a_line_with_no_id_and_a_message_with_no_verdict_file_nothing() {
        SignatureVerdict.checked.clear()
        SignatureVerdict.record("", verdict(VerdictState.DEVICE))
        SignatureVerdict.record("01MSG", null)
        assertNull(SignatureVerdict.of("01MSG"))
        assertTrue(SignatureVerdict.checked.isEmpty())
    }
}
