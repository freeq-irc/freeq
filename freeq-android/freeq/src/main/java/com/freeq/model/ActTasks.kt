package com.freeq.model

/** A link an event carried as context, with the hash its signature covers. */
data class ActCtxLink(val url: String, val hash: String? = null)

/** One move on a task, in the order it arrived. */
data class ActTaskEvent(
    val eventId: String,
    val verb: String,
    val from: String,
    val did: String? = null,
    /** Every `act-` tag of the event, keyed as the SDK hands them over — so a
     *  note reads as `act-note` and the kind itself as `act`. */
    val fields: Map<String, String> = emptyMap(),
    /** The companion line's msgid, once it has arrived. The home's own
     *  `confirm` and `expire` send no companion and keep none. */
    val msgId: String? = null,
)

/** A task as this channel has seen it, keyed by its opener's event id. */
data class ActTask(
    val taskId: String,
    val kind: String,
    val title: String,
    /** Who opened it, and who holds it — `act-to` on a directed offer, else
     *  whoever claimed it or was awarded it. */
    val offerer: String? = null,
    val assignee: String? = null,
    /** The latest move made on it, and the latest note anyone attached. */
    val verb: String,
    val note: String? = null,
    val ctx: List<ActCtxLink> = emptyList(),
    val events: List<ActTaskEvent> = emptyList(),
)

/** A task event and the task it belongs to, as one card draws them. */
data class ActCard(val task: ActTask, val event: ActTaskEvent)

/** What the bridge hands over from `FreeqEvent.Act`. */
data class ActEventInput(
    val from: String,
    val did: String?,
    val kind: String,
    val verb: String,
    val eventId: String,
    val taskId: String,
    val fields: Map<String, String>,
)

/**
 * A line that named a task, as a candidate for the card an event draws.
 *
 * `ref` is the `+freeq.at/ref` the companion carries: the only thing joining
 * a line to the work it is about. `account` is the sender's DID when the
 * server named one on the line.
 */
data class ActLine(
    val id: String,
    val from: String,
    val account: String?,
    val timestampMs: Long,
    val ref: String,
)

/**
 * The tasks one channel has seen.
 *
 * Fed live and by replay, and deduped by event id: the same event arrives up
 * to three times — our own echo, the replay a channel hands a joiner, and the
 * history that joiner asks for next — and the second and third change nothing.
 */
class ActTaskStore {
    private val byId = LinkedHashMap<String, ActTask>()

    val tasks: Map<String, ActTask> get() = byId

    fun task(taskId: String): ActTask? = byId[taskId]

    /**
     * File one event, and return the line the room is told about it — which
     * only the home's own `confirm` and `expire` have, every other verb being
     * read on a card. Null for a verb that writes its own line, for one that
     * has nothing left to name, and for an event already held.
     */
    fun record(ev: ActEventInput): String? {
        val prior = byId[ev.taskId]
        if (prior != null && prior.events.any { it.eventId == ev.eventId }) return null

        val events = (prior?.events ?: emptyList()) + ActTaskEvent(
            eventId = ev.eventId,
            verb = ev.verb,
            from = ev.from,
            did = ev.did,
            fields = ev.fields,
        )
        val ctx = ev.fields["act-ctx"]
        val task = ActTask(
            taskId = ev.taskId,
            kind = ev.kind.ifEmpty { prior?.kind ?: "" },
            title = ev.fields["act-title"] ?: prior?.title ?: "",
            // An opener names no other task, so its own id is the task's —
            // which is what makes it the opener, and its sender the offerer.
            offerer = if (ev.eventId == ev.taskId) (ev.did ?: ev.from) else prior?.offerer,
            assignee = assignee(prior, ev, events),
            verb = ev.verb,
            note = ev.fields["act-note"] ?: prior?.note,
            ctx = if (ctx != null) {
                (prior?.ctx ?: emptyList()) + ActCtxLink(ctx, ev.fields["act-ctx-h"])
            } else {
                prior?.ctx ?: emptyList()
            },
            events = events,
        )
        byId[ev.taskId] = task
        return systemLine(task, ev)
    }

    /**
     * Join each event to the companion line carrying its prose.
     *
     * The companion names only the task, never the event, so the two are
     * matched by their sender and then by how close in time they are: a
     * joiner is handed the lines and the task events as two windows that
     * truncate independently, so a line missing from its window must leave
     * its event unpaired rather than shift every later line onto the wrong
     * event. Either side can land first, so this runs from both, and never
     * re-pairs what it has already paired: the message list is capped, and an
     * evicted companion must not shift its successors.
     */
    fun pair(lines: List<ActLine>) {
        if (byId.isEmpty() || lines.isEmpty()) return
        val claimed = byId.values.flatMapTo(mutableSetOf()) { task ->
            task.events.mapNotNull { it.msgId }
        }
        val free = LinkedHashMap<String, MutableList<ActLine>>()
        for (line in lines) {
            if (line.id in claimed || line.ref !in byId) continue
            free.getOrPut(line.ref) { mutableListOf() }.add(line)
        }
        if (free.isEmpty()) return

        for ((id, task) in byId.entries.toList()) {
            val candidates = free[id] ?: continue
            // Every line each unpaired event could take, nearest in time
            // first, and in arrival order where neither side dates itself.
            val near = mutableListOf<Triple<Int, Int, Double>>()
            task.events.forEachIndexed events@{ evIdx, ev ->
                if (ev.msgId != null) return@events
                val at = actEventTimeMs(ev.eventId)
                candidates.forEachIndexed lines@{ lineIdx, line ->
                    if (!sameSender(ev, line)) return@lines
                    val gap = if (at != null) {
                        Math.abs(line.timestampMs - at).toDouble()
                    } else {
                        Double.POSITIVE_INFINITY
                    }
                    near.add(Triple(evIdx, lineIdx, gap))
                }
            }
            near.sortWith(compareBy({ it.third }, { it.first }, { it.second }))
            val pairedTo = mutableMapOf<Int, String>()
            val used = mutableSetOf<Int>()
            for ((evIdx, lineIdx, _) in near) {
                if (evIdx in pairedTo || lineIdx in used) continue
                pairedTo[evIdx] = candidates[lineIdx].id
                used.add(lineIdx)
            }
            if (pairedTo.isEmpty()) continue
            byId[id] = task.copy(
                events = task.events.mapIndexed { evIdx, ev ->
                    pairedTo[evIdx]?.let { ev.copy(msgId = it) } ?: ev
                },
            )
        }
    }

    /**
     * Whether a line was written by the sender an event names: the DID when
     * both sides carry one, the nick otherwise — case aside, since replay
     * hands back the event under the lowercased nick the server holds and the
     * line under the nick as it was sent.
     */
    private fun sameSender(ev: ActTaskEvent, line: ActLine): Boolean {
        if (ev.did != null && line.account != null) return ev.did == line.account
        return ev.from.equals(line.from, ignoreCase = true)
    }

    /**
     * What the room is told about an event that wrote no line of its own.
     *
     * The home signs `confirm` and `expire` itself and sends no companion, so
     * these two are the only events the reader hears about as a system line
     * rather than a card.
     */
    private fun systemLine(task: ActTask, ev: ActEventInput): String? {
        // Both lines name the task by its title, which only the opener
        // carries, and the opener falls out of the replay window before the
        // events that follow it do — so with no title held there is nothing
        // to name, and nothing said.
        val title = task.title
        if (title.isEmpty()) return null
        return when (ev.verb) {
            // The receipt carries only the id of the move it confirms, so the
            // move's sender and its raw verb are read off that event — and
            // with no such event held there is nothing to name, and nothing
            // to say.
            "confirm" -> {
                val subject = task.events.firstOrNull { it.eventId == ev.fields["act-subject"] }
                subject?.let { "confirmed: ${it.from}'s ${it.verb} on $title" }
            }
            "expire" -> "$title expired"
            else -> null
        }
    }

    /** Who holds the task after this move: named outright on a directed
     *  offer, taken by whoever claims or accepts it, and on an award the
     *  bidder whose bid was chosen — `act-accepts` names the bid, not the
     *  bidder. */
    private fun assignee(
        prior: ActTask?,
        ev: ActEventInput,
        events: List<ActTaskEvent>,
    ): String? = when (ev.verb) {
        "offer" -> ev.fields["act-to"] ?: prior?.assignee
        "claim", "accept" -> ev.did ?: ev.from
        "award" -> events.firstOrNull { it.eventId == ev.fields["act-accepts"] }
            ?.let { it.did ?: it.from } ?: prior?.assignee
        else -> prior?.assignee
    }
}

private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

/**
 * When an event was minted, off the ULID it is named by — the only time an
 * event carries. Null for an id that is not a ULID, so ids the server never
 * minted (a test's, a peer's own spelling) fall back to arrival order.
 */
fun actEventTimeMs(eventId: String): Long? {
    if (eventId.length != 26) return null
    var ms = 0L
    for (c in eventId.take(10)) {
        val digit = CROCKFORD.indexOf(c)
        if (digit < 0) return null
        ms = ms * 32 + digit
    }
    return ms
}
