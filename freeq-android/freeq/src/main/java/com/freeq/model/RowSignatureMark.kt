package com.freeq.model

import com.freeq.ffi.KeyLayer
import com.freeq.ffi.VerdictState

/**
 * The signature mark a message row wears, decided from the row's verdict.
 *
 * Lives outside the view so the rule can be unit-tested without an Android
 * runtime; the row only applies it. Mirrors the iOS and macOS
 * `RowSignatureMark`.
 */
internal object RowSignatureMark {
    sealed interface Mark

    /** The sender's own device signed: a lock at [alpha], full when the key is
     *  published in their account, 30% while only their server vouches. */
    data class Lock(val alpha: Float) : Mark

    /** The signature failed, or was made after its key was retired. */
    object Warning : Mark

    /** The lock's alpha while only the sender's server vouches for the key. */
    const val VOUCHED_ALPHA = 0.3f

    /** The mark for a verdict; null with no verdict and for every state that
     *  shows nothing: server-signed, unsigned, unverifiable, still checking. */
    fun of(verdict: FfiVerdict?): Mark? {
        if (verdict == null) return null
        return when (verdict.state) {
            VerdictState.DEVICE ->
                Lock(if (verdict.layer == KeyLayer.PUBLISHED) 1f else VOUCHED_ALPHA)
            VerdictState.INVALID, VerdictState.RETIRED -> Warning
            VerdictState.SERVER, VerdictState.UNSIGNED,
            VerdictState.UNVERIFIABLE, VerdictState.PENDING -> null
        }
    }

    /** A row's mark once its check has answered; [mark] is null for a verdict
     *  that shows nothing. */
    data class Settled(val mark: Mark?)

    /** The settled mark for a verdict; null with no verdict or while pending. */
    fun settled(verdict: FfiVerdict?): Settled? =
        if (verdict == null || verdict.state == VerdictState.PENDING) null else Settled(of(verdict))

    /** Whether a row that would group under its header starts its own header
     *  instead: only when both marks have settled and differ. Null is pending,
     *  and a pending mark matches. */
    fun startsHeader(header: Settled?, row: Settled?): Boolean =
        header != null && row != null && header != row
}
