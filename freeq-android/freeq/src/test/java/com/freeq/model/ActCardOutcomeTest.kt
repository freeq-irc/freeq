package com.freeq.model

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Date

/**
 * What the reader ends up looking at, from the layers that actually run: the
 * buffer cache, the replay batch, event recording, and pairing. The per-layer
 * tests each pass on their own and still let a wrong transcript through — the
 * offer and accept cards landed on each other's lines — so this is the
 * order's regression net and they are not.
 *
 * The fixture is the live channel's shape. The offer and its accept are
 * minted 195ms apart inside one second; each companion line goes out a few ms
 * into the NEXT second and replays under that second's `.000` stamp. The
 * later event is then nearer to both lines (37ms against 232ms), which is
 * what let the accept take the offer's line.
 */
class ActCardOutcomeTest {

    private val worker = "did:key:z6MkWorker"
    private val home = "did:web:irc.zerosum.org"
    private val second = 1_756_760_000_000L

    private fun ulid(ms: Long, tail: String): String {
        val crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        var left = ms
        var time = ""
        for (i in 0 until 10) {
            time = crockford[(left % 32).toInt()] + time
            left /= 32
        }
        return time + tail
    }

    private val offerEventId = ulid(second + 768, "ZZZZZZZZZZZZZZZZ")
    private val acceptEventId = ulid(second + 963, "ZZZZZZZZZZZZZZZZ")
    private val confirmEventId = ulid(second + 3_000, "ZZZZZZZZZZZZZZZZ")
    private val offerLineId = ulid(second + 1_002, "AAAAAAAAAAAAAAAA")
    private val acceptLineId = ulid(second + 1_005, "BBBBBBBBBBBBBBBB")

    /** Both companion lines replay under the truncated stamp of the second
     *  they were sent in — the same value for both. */
    private val replayedLineStamp = Date(second + 1_000)

    private fun companion(id: String, text: String) = ChatMessage(
        id = id, from = "worker", text = text, isAction = false,
        timestamp = replayedLineStamp, account = worker, actRef = offerEventId,
    )

    private fun retired(id: String, eventType: String, text: String) = ChatMessage(
        id = id, from = "oldbot", text = text, isAction = false,
        timestamp = Date(second + 2_000),
        coordination = com.freeq.ffi.CoordinationEvent(
            eventType = eventType, taskId = "TASK001", phase = null,
            evidenceType = null, reference = null, payload = null,
        ),
    )

    private fun offerEvent() = ActEventInput(
        from = "worker", did = worker, kind = "handoff", verb = "offer",
        eventId = offerEventId, taskId = offerEventId,
        fields = mapOf("act" to "handoff", "act-verb" to "offer",
            "act-title" to "ship the release", "act-to" to worker),
    )

    private fun acceptEvent() = ActEventInput(
        from = "worker", did = worker, kind = "handoff", verb = "accept",
        eventId = acceptEventId, taskId = offerEventId,
        fields = mapOf("act" to "handoff", "act-verb" to "accept", "act-id" to offerEventId),
    )

    private fun confirmEvent() = ActEventInput(
        from = "irc.zerosum.org", did = home, kind = "handoff", verb = "confirm",
        eventId = confirmEventId, taskId = offerEventId,
        fields = mapOf("act" to "handoff", "act-verb" to "confirm",
            "act-id" to offerEventId, "act-subject" to acceptEventId),
    )

    /** The rows a previous session left in buffers.json, through the real
     *  encode/decode: the two companion lines, stored inverted. */
    private fun cached(): List<ChatMessage> {
        val stored = listOf(
            companion(acceptLineId, "accepted: ship the release"),
            companion(offerLineId, "offered: ship the release"),
        )
        return BufferCache.decode(
            BufferCache.encode(
                listOf(CachedBuffer("#actrepoint", isDM = false, topic = null, messages = stored))
            )
        )!!.single().messages
    }

    /** The transcript as the reader sees it, row by row. */
    private fun transcript(ch: ChannelState): List<String> = ch.messages.map { m ->
        val card = ch.actCards[m.id]
        val coord = m.coordination
        when {
            card != null -> "card:${card.event.verb}"
            // Every event-tagged message is a card, whatever its type says.
            coord != null -> "card:${coord.eventType}"
            m.from.isEmpty() -> "system"
            else -> "text"
        }
    }

    private fun run(eventsFirst: Boolean, cachedRows: List<ChatMessage>): ChannelState {
        val ch = ChannelState("#actrepoint")
        cachedRows.forEach { ch.appendIfNew(it) }

        val record = {
            ch.recordActEvent(offerEvent())
            ch.recordActEvent(acceptEvent())
            ch.recordActEvent(confirmEvent())?.let { line ->
                ch.appendIfNew(ChatMessage(
                    id = "$confirmEventId-line", from = "", text = line,
                    isAction = false, timestamp = Date(second + 3_000),
                ))
            }
            Unit
        }

        val deliver = {
            // The replay batch, deliberately out of wire order.
            val buf = BatchBuffer(
                target = "#actrepoint",
                batchType = "chathistory",
                messages = mutableListOf(
                    retired(ulid(second + 2_000, "DDDDDDDDDDDDDDDD"), "task_request",
                        "📋 New task: something the old family sent"),
                    companion(acceptLineId, "accepted: ship the release"),
                    retired(ulid(second + 2_100, "EEEEEEEEEEEEEEEE"), "task_complete",
                        "✅ Task complete: something the old family sent"),
                    companion(offerLineId, "offered: ship the release"),
                ),
            )
            BatchFlush.flushInto(buf, ch)
        }

        if (eventsFirst) { record(); deliver() } else { deliver(); record() }
        ch.pairActCompanions()
        return ch
    }

    @Test fun the_transcript_reads_the_same_whichever_side_lands_first() {
        val rows = cached()
        for (eventsFirst in listOf(true, false)) {
            assertEquals(
                "eventsFirst=$eventsFirst",
                listOf("card:offer", "card:accept", "card:task_request", "card:task_complete", "system"),
                transcript(run(eventsFirst, rows)),
            )
        }
    }

    @Test fun each_card_lands_on_its_own_senders_line() {
        val rows = cached()
        for (eventsFirst in listOf(true, false)) {
            val ch = run(eventsFirst, rows)
            assertEquals("eventsFirst=$eventsFirst", "offer", ch.actCards[offerLineId]?.event?.verb)
            assertEquals("eventsFirst=$eventsFirst", "accept", ch.actCards[acceptLineId]?.event?.verb)
        }
    }

    @Test fun the_cache_hands_back_the_two_lines_in_mint_order() {
        assertEquals(listOf(offerLineId, acceptLineId), cached().map { it.id })
    }

    @Test fun the_cache_keeps_the_task_each_line_names() {
        assertEquals(listOf(offerEventId, offerEventId), cached().map { it.actRef })
    }
}
