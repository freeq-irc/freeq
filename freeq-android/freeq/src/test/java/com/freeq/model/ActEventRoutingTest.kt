package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Which buffer an act event lands in.
 *
 * The task decides, not the sender. The SDK keys a DM event by the non-self
 * end, so a receipt the home signs for itself arrives naming a thread with the
 * *server* — filing it there puts a `confirmed:` line in a thread named after
 * the server and leaves the participants' thread without it. The same rule the
 * web client (`actEventBuffer`) and the macOS client (`ActEventRouting.buffer`)
 * already read.
 */
class ActEventRoutingTest {

    private val opener = "01JOPENER00000000000000000"
    private val unheld = "01JUNHELD00000000000000000"
    private val server = "did:web:irc.example"
    private val poster = "did:plc:poster"

    @Test fun an_event_files_into_the_thread_already_holding_its_task() {
        // The receipt names the server as its sender, so the SDK can only key
        // it by the server. The task is what says where it belongs.
        assertEquals(
            poster,
            ActEventRouting.buffer(
                venue = server, taskId = opener, eventId = "01JRECEIPT",
                bufferHoldingTask = poster, hasBuffer = { false }),
        )
    }

    @Test fun an_opener_opens_its_own_thread() {
        // An opener names no earlier task, which is what makes it the opener.
        assertEquals(
            poster,
            ActEventRouting.buffer(
                venue = poster, taskId = opener, eventId = opener,
                bufferHoldingTask = null, hasBuffer = { false }),
        )
    }

    @Test fun a_move_on_an_unheld_task_files_into_the_senders_existing_thread() {
        assertEquals(
            poster,
            ActEventRouting.buffer(
                venue = poster, taskId = unheld, eventId = "01JPROGRESS",
                bufferHoldingTask = null, hasBuffer = { it == poster }),
        )
    }

    @Test fun a_move_on_an_unheld_task_from_a_stranger_creates_nothing() {
        // The silence an unheld receipt has always had, rather than a thread
        // conjured for one line that can say nothing.
        assertNull(
            ActEventRouting.buffer(
                venue = "did:plc:stranger", taskId = unheld, eventId = "01JPROGRESS",
                bufferHoldingTask = null, hasBuffer = { false }),
        )
    }

    @Test fun a_channel_event_stays_in_its_channel() {
        assertEquals(
            "#work",
            ActEventRouting.buffer(
                venue = "#work", taskId = opener, eventId = opener,
                bufferHoldingTask = null, hasBuffer = { false }),
        )
        assertEquals(
            "#work",
            ActEventRouting.buffer(
                venue = "#work", taskId = opener, eventId = "01JRECEIPT",
                bufferHoldingTask = "#work", hasBuffer = { it == "#work" }),
        )
    }

    @Test fun a_home_signed_dm_confirm_lands_in_the_thread_holding_the_task() {
        // End to end over the store: the DM holds the task, the receipt
        // arrives keyed by the server, and its system line is the one the
        // participants' thread shows.
        val store = ActTaskStore()
        store.record(
            ActEventInput(
                from = "actdmcards", did = poster, kind = "handoff", verb = "offer",
                eventId = opener, taskId = opener,
                fields = mapOf("act" to "handoff", "act-verb" to "offer", "act-title" to "tidy the DM inbox"),
            )
        )
        store.record(
            ActEventInput(
                from = "actdmcards", did = poster, kind = "handoff", verb = "cancel",
                eventId = "e2", taskId = opener,
                fields = mapOf("act" to "handoff", "act-verb" to "cancel", "act-id" to opener),
            )
        )

        // The receipt's venue is the server; the buffer holding the task wins.
        assertEquals(
            poster,
            ActEventRouting.buffer(
                venue = server, taskId = opener, eventId = "e3",
                bufferHoldingTask = poster, hasBuffer = { false }),
        )
        assertEquals(
            "confirmed: \"tidy the DM inbox\" — cancel by actdmcards",
            store.record(
                ActEventInput(
                    from = "irc.example", did = server, kind = "handoff", verb = "confirm",
                    eventId = "e3", taskId = opener,
                    fields = mapOf("act-id" to opener, "act-subject" to "e2"),
                )
            ),
        )
    }
}
