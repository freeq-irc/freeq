package com.freeq.model

import com.freeq.ffi.KeyLayer
import com.freeq.ffi.VerdictState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the signature mark a message row wears for each verdict,
 * and for when a row that would group starts its own header because of it.
 */
class RowSignatureMarkTest {

    private fun verdict(state: VerdictState, layer: KeyLayer? = null) =
        FfiVerdict(state, layer, "kid", null, "the sentence the SDK gave")

    @Test fun a_published_device_key_wears_the_lock_at_full_strength() {
        assertEquals(
            RowSignatureMark.Lock(1f),
            RowSignatureMark.of(verdict(VerdictState.DEVICE, KeyLayer.PUBLISHED)),
        )
    }

    @Test fun a_vouched_device_key_wears_the_lock_at_30_percent() {
        assertEquals(
            RowSignatureMark.Lock(0.3f),
            RowSignatureMark.of(verdict(VerdictState.DEVICE, KeyLayer.VOUCHED)),
        )
    }

    @Test fun a_failed_or_retired_signature_wears_the_warning() {
        assertEquals(RowSignatureMark.Warning, RowSignatureMark.of(verdict(VerdictState.INVALID)))
        assertEquals(RowSignatureMark.Warning, RowSignatureMark.of(verdict(VerdictState.RETIRED)))
    }

    @Test fun every_other_state_and_no_verdict_wear_nothing() {
        for (state in listOf(
            VerdictState.SERVER, VerdictState.UNSIGNED,
            VerdictState.UNVERIFIABLE, VerdictState.PENDING,
        )) {
            assertNull("$state must not mark the row", RowSignatureMark.of(verdict(state)))
        }
        assertNull(RowSignatureMark.of(null))
    }

    // ── Grouping by the row mark ──

    private val published = verdict(VerdictState.DEVICE, KeyLayer.PUBLISHED)
    private val vouched = verdict(VerdictState.DEVICE, KeyLayer.VOUCHED)
    private val invalid = verdict(VerdictState.INVALID)
    private val server = verdict(VerdictState.SERVER)
    private val pending = verdict(VerdictState.PENDING)

    private fun startsHeader(header: FfiVerdict?, row: FfiVerdict?) =
        RowSignatureMark.startsHeader(RowSignatureMark.settled(header), RowSignatureMark.settled(row))

    @Test fun a_row_with_the_same_mark_as_its_header_groups() {
        assertFalse(startsHeader(published, published))
    }

    @Test fun full_lock_then_dim_lock_starts_a_header() {
        assertTrue(startsHeader(published, vouched))
    }

    @Test fun lock_then_warning_starts_a_header() {
        assertTrue(startsHeader(published, invalid))
    }

    @Test fun lock_then_no_mark_starts_a_header() {
        assertTrue(startsHeader(published, server))
    }

    @Test fun a_row_whose_check_is_pending_groups() {
        assertFalse(startsHeader(published, pending))
        assertFalse(startsHeader(published, null))
    }

    @Test fun a_pending_row_starts_a_header_when_its_verdict_settles_different() {
        assertFalse(startsHeader(published, pending))
        assertTrue(startsHeader(published, invalid))
    }

    @Test fun a_pending_row_stays_grouped_when_its_verdict_settles_the_same() {
        assertFalse(startsHeader(published, pending))
        assertFalse(startsHeader(published, published))
    }

    @Test fun the_settled_mark_is_null_only_while_pending_or_with_no_verdict() {
        assertNull(RowSignatureMark.settled(pending))
        assertNull(RowSignatureMark.settled(null))
        assertEquals(RowSignatureMark.Settled(null), RowSignatureMark.settled(server))
        assertEquals(RowSignatureMark.Settled(RowSignatureMark.Warning), RowSignatureMark.settled(invalid))
    }
}
