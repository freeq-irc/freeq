package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * What a channel remembers about the work done in it: one task per opener,
 * every move on it kept in the order it arrived, and each move joined to the
 * line its sender wrote beside it.
 */
class ActTaskStoreTest {

    private val opener = "01JOPENER00000000000000000"
    private val poster = "did:plc:poster"
    private val worker = "did:plc:worker"

    /** One task event as the bridge hands it over. */
    private fun ev(
        from: String = "poster",
        did: String? = poster,
        verb: String = "offer",
        eventId: String = opener,
        taskId: String = opener,
        fields: Map<String, String> = mapOf("act" to "handoff", "act-verb" to "offer", "act-title" to "ship the release"),
        kind: String = "handoff",
    ) = ActEventInput(
        from = from, did = did, kind = kind, verb = verb,
        eventId = eventId, taskId = taskId, fields = fields,
    )

    /** A later move on the task the opener above opened. */
    private fun move(
        verb: String,
        eventId: String,
        extra: Map<String, String> = emptyMap(),
        who: String = "worker",
        did: String? = worker,
    ) = ev(
        from = who, did = did, verb = verb, eventId = eventId,
        fields = mapOf("act" to "handoff", "act-verb" to verb, "act-id" to opener) + extra,
    )

    /** A companion line as replay hands it back: the nick as it was sent, and
     *  the sender's DID under the server's `account` tag. */
    private fun line(
        id: String, from: String, ref: String,
        account: String? = null, at: Long = 0L,
    ) = ActLine(id = id, from = from, account = account, timestampMs = at, ref = ref)

    /** The id an event minted at that moment carries: a ULID, time first. */
    private fun idAt(ms: Long): String {
        val crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        var left = ms
        var time = ""
        repeat(10) {
            time = crockford[(left % 32).toInt()] + time
            left /= 32
        }
        return time + "ZZZZZZZZZZZZZZZZ"
    }

    // ── The task map ──

    @Test fun an_opener_opens_a_task_keyed_by_its_own_event_id() {
        val store = ActTaskStore()
        store.record(ev())
        val task = store.task(opener)!!
        assertEquals(opener, task.taskId)
        assertEquals("handoff", task.kind)
        assertEquals("ship the release", task.title)
        assertEquals(poster, task.offerer)
        assertEquals("offer", task.verb)
        assertEquals(1, task.events.size)
    }

    @Test fun a_directed_offer_names_who_holds_it() {
        val store = ActTaskStore()
        store.record(ev(fields = mapOf("act-title" to "ship the release", "act-to" to worker)))
        assertEquals(worker, store.task(opener)!!.assignee)
    }

    @Test fun each_later_verb_becomes_the_latest_and_appends_to_the_list() {
        val store = ActTaskStore()
        store.record(ev())
        store.record(move("claim", "e2"))
        store.record(move("progress", "e3", mapOf("act-note" to "halfway")))

        val task = store.task(opener)!!
        assertEquals("progress", task.verb)
        assertEquals("halfway", task.note)
        assertEquals(worker, task.assignee)
        assertEquals(listOf(opener, "e2", "e3"), task.events.map { it.eventId })
        assertEquals(listOf("offer", "claim", "progress"), task.events.map { it.verb })
    }

    @Test fun each_context_link_is_kept_with_the_hash_its_signature_covers() {
        val store = ActTaskStore()
        store.record(ev())
        store.record(move("progress", "e2", mapOf("act-ctx" to "https://x/1", "act-ctx-h" to "sha256:aa")))
        store.record(move("complete", "e3", mapOf("act-ctx" to "https://x/2", "act-ctx-h" to "sha256:bb")))

        assertEquals(
            listOf(ActCtxLink("https://x/1", "sha256:aa"), ActCtxLink("https://x/2", "sha256:bb")),
            store.task(opener)!!.ctx,
        )
    }

    @Test fun an_award_hands_the_task_to_the_bidder_whose_bid_it_names() {
        val store = ActTaskStore()
        store.record(ev())
        store.record(move("bid", "bid-1", who = "worker", did = worker))
        store.record(move("award", "e3", mapOf("act-accepts" to "bid-1"), who = "poster", did = poster))

        assertEquals(worker, store.task(opener)!!.assignee)
    }

    @Test fun a_replayed_event_changes_nothing() {
        val store = ActTaskStore()
        store.record(ev())
        store.record(move("progress", "e2", mapOf("act-note" to "halfway")))
        val before = store.task(opener)!!

        assertNull(store.record(move("progress", "e2", mapOf("act-note" to "halfway"))))
        assertEquals(before, store.task(opener)!!)
        assertEquals(2, store.task(opener)!!.events.size)
    }

    // ── Companion lines ──

    @Test fun each_event_joins_the_line_its_sender_wrote_beside_it() {
        val store = ActTaskStore()
        store.record(ev())
        store.record(move("claim", "e2"))
        store.pair(listOf(line("m1", "poster", opener), line("m2", "worker", opener)))

        assertEquals(listOf("m1", "m2"), store.task(opener)!!.events.map { it.msgId })
    }

    @Test fun a_line_that_arrived_first_joins_the_event_that_follows_it() {
        val store = ActTaskStore()
        val lines = listOf(line("m1", "poster", opener))
        store.pair(lines)
        store.record(ev())
        store.pair(lines)

        assertEquals("m1", store.task(opener)!!.events[0].msgId)
    }

    @Test fun they_join_by_did_when_the_two_sides_spell_the_nick_differently() {
        // Replay hands the event back under the lowercased nick the server
        // holds and the line under the nick as it was sent.
        val store = ActTaskStore()
        store.record(ev(from = "taskbot", did = poster))
        store.pair(listOf(line("m1", "TaskBot", opener, account = poster)))

        assertEquals("m1", store.task(opener)!!.events[0].msgId)
    }

    @Test fun they_join_by_nick_case_aside_when_neither_side_carries_a_did() {
        val store = ActTaskStore()
        store.record(ev(from = "taskbot", did = null))
        store.pair(listOf(line("m1", "TaskBot", opener)))

        assertEquals("m1", store.task(opener)!!.events[0].msgId)
    }

    @Test fun a_line_never_joins_a_different_sender() {
        val store = ActTaskStore()
        store.record(ev(from = "poster", did = poster))
        store.pair(listOf(line("m1", "worker", opener, account = worker)))

        assertNull(store.task(opener)!!.events[0].msgId)
    }

    @Test fun each_line_takes_the_event_nearest_it_in_time_not_the_next_in_order() {
        // The lines and the task events replay as two windows that truncate
        // independently: here the opener's line fell outside its window.
        val store = ActTaskStore()
        val t0 = 1_755_000_000_000L
        val at = listOf(t0, t0 + 60_000, t0 + 120_000, t0 + 180_000)
        val ids = at.map { idAt(it) }
        store.record(ev(from = "worker", did = worker, eventId = ids[0], taskId = ids[0]))
        for ((i, verb) in listOf("claim", "progress", "complete").withIndex()) {
            store.record(
                ev(
                    from = "worker", did = worker, verb = verb,
                    eventId = ids[i + 1], taskId = ids[0],
                    fields = mapOf("act" to "handoff", "act-verb" to verb, "act-id" to ids[0]),
                )
            )
        }
        store.pair(listOf("claim", "progress", "complete").mapIndexed { i, verb ->
            line("m-$verb", "worker", ids[0], account = worker, at = at[i + 1])
        })

        assertEquals(
            listOf(null, "m-claim", "m-progress", "m-complete"),
            store.task(ids[0])!!.events.map { it.msgId },
        )
    }

    @Test fun a_pairing_survives_the_same_line_arriving_again() {
        val store = ActTaskStore()
        store.record(ev())
        val first = line("m1", "poster", opener)
        store.pair(listOf(first))
        store.record(move("progress", "e2", who = "poster", did = poster))
        store.pair(listOf(first))

        val events = store.task(opener)!!.events
        assertEquals("m1", events[0].msgId)
        assertNull(events[1].msgId)
    }

    // ── The two events that write no line of their own ──

    @Test fun a_confirm_tells_the_room_what_the_home_confirmed() {
        val store = ActTaskStore()
        store.record(ev())
        store.record(move("claim", "e2", who = "worker", did = worker))
        val line = store.record(
            move("confirm", "e3", mapOf("act-subject" to "e2"), who = "acceptance", did = null)
        )

        assertEquals("confirmed: worker's claim on ship the release", line)
    }

    @Test fun a_confirm_says_nothing_about_a_move_it_does_not_hold() {
        val store = ActTaskStore()
        store.record(ev())

        assertNull(
            store.record(move("confirm", "e3", mapOf("act-subject" to "never-seen"), who = "acceptance", did = null))
        )
    }

    @Test fun an_expiry_says_the_task_expired() {
        val store = ActTaskStore()
        store.record(ev())

        assertEquals("ship the release expired", store.record(move("expire", "e2", who = "acceptance", did = null)))
    }

    @Test fun an_expiry_says_nothing_when_no_title_is_held() {
        // The opener falls out of the replay window before the events that
        // follow it do, so there is no title to name and nothing to say.
        val store = ActTaskStore()

        assertNull(store.record(move("expire", "e2", who = "acceptance", did = null)))
    }

    // ── When an event was made ──

    @Test fun an_event_carries_the_moment_it_was_minted() {
        // The system lines are dated by this: a receipt handed back on join is
        // old news, and saying "now" would file it under the newest thing said.
        val at = 1_755_000_000_000L
        assertEquals(at, actEventTimeMs(idAt(at)))
    }

    @Test fun an_id_the_server_never_minted_carries_no_time() {
        assertNull(actEventTimeMs("e2"))
        assertNull(actEventTimeMs("UUUUUUUUUU" + "ZZZZZZZZZZZZZZZZ"))
    }

    @Test fun every_other_verb_is_left_to_its_card() {
        val store = ActTaskStore()
        store.record(ev())
        assertNull(store.record(move("claim", "e2")))
        assertNull(store.record(move("complete", "e3")))
    }
}
