package com.freeq.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * Whether a DM the TARGETS reply names asks for its history.
 *
 * Asking only for empty threads meant a thread restored from the cache, or
 * one held across a background drop, never got what was sent while the
 * connection was down — the server had it, the app never asked.
 */
class DmCatchUpTest {

    private fun msg(id: String, at: Long) = ChatMessage(
        id = id,
        from = "peer",
        text = "hi",
        isAction = false,
        timestamp = Date(at),
    )

    private val ulid = "01M4JTYNAENCPWQ3TVRAXGPKR9"

    @Test fun an_empty_thread_asks() {
        assertTrue(DmCatchUp.shouldFetch(5_000L, emptyList()))
    }

    @Test fun a_thread_behind_the_server_asks() {
        // The gap: the server's newest is newer than anything held.
        assertTrue(DmCatchUp.shouldFetch(9_000L, listOf(msg(ulid, 5_000L))))
    }

    @Test fun a_thread_level_with_the_server_does_not() {
        assertFalse(DmCatchUp.shouldFetch(5_000L, listOf(msg(ulid, 5_000L))))
    }

    @Test fun the_same_second_is_level() {
        // The TARGETS time is second-precision; a live row may carry device
        // milliseconds in the same second.
        assertFalse(DmCatchUp.shouldFetch(5_000L, listOf(msg(ulid, 5_400L))))
    }

    @Test fun locally_minted_rows_do_not_count_as_caught_up() {
        // A join line stamped with device time after the gap says nothing
        // about what the server holds.
        val held = listOf(msg(ulid, 5_000L), msg("123e4567-e89b-12d3-a456-426614174000", 20_000L))
        assertTrue(DmCatchUp.shouldFetch(9_000L, held))
    }

    @Test fun a_thread_holding_only_local_rows_asks() {
        assertTrue(DmCatchUp.shouldFetch(9_000L, listOf(msg("123e4567-e89b-12d3-a456-426614174000", 20_000L))))
    }

    @Test fun no_server_time_asks() {
        // Nothing to compare against: a refetch costs a page, a gap costs messages.
        assertTrue(DmCatchUp.shouldFetch(null, listOf(msg(ulid, 5_000L))))
    }
}
