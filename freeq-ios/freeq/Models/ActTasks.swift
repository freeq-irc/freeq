import Foundation

/// A link an event carried as context, with the hash its signature covers.
struct ActCtxLink: Equatable {
    var url: String
    var hash: String?
}

/// One move on a task, in the order it arrived.
struct ActTaskEvent: Equatable {
    var eventId: String
    var verb: String
    var from: String
    var did: String?
    /// Every `act-` tag of the event, keyed as the SDK hands them over — so a
    /// note reads as `act-note` and the kind itself as `act`.
    var fields: [String: String] = [:]
    /// The companion line's msgid, once it has arrived. The home's own
    /// `confirm` and `expire` send no companion and keep none.
    var msgId: String?
}

/// A task as this channel has seen it, keyed by its opener's event id.
struct ActTask: Equatable {
    var taskId: String
    var kind: String
    var title: String
    /// Who opened it, and who holds it — `act-to` on a directed offer, else
    /// whoever claimed it or was awarded it.
    var offerer: String?
    var assignee: String?
    /// The latest move made on it, and the latest note anyone attached.
    var verb: String
    var note: String?
    var ctx: [ActCtxLink] = []
    var events: [ActTaskEvent] = []
}

/// The cards either side of one, by the msgid of the line each is drawn on.
struct ActNeighbours: Equatable {
    var prev: String?
    var next: String?
}

/// The cards either side of this one.
///
/// A task's cards are its events in the order they were made, minus the two
/// the home signs for itself: those write no companion line, so there is no
/// card to land on. Absent at each end, which is what stops a link being
/// offered there — and absent entirely for an event whose own line has not
/// arrived, since it has no card of its own to navigate from.
func actCardNeighbours(task: ActTask, event: ActTaskEvent) -> ActNeighbours {
    let cards = task.events.filter { $0.msgId != nil }
    guard let i = cards.firstIndex(where: { $0.eventId == event.eventId }) else {
        return ActNeighbours()
    }
    return ActNeighbours(
        prev: i > 0 ? cards[i - 1].msgId : nil,
        next: i + 1 < cards.count ? cards[i + 1].msgId : nil)
}

/// A task event and the task it belongs to, as one card draws them.
struct ActCard: Equatable {
    var task: ActTask
    var event: ActTaskEvent
}

/// What the bridge hands over from `FreeqEvent.act`.
struct ActEventInput {
    var from: String
    var did: String?
    var kind: String
    var verb: String
    var eventId: String
    var taskId: String
    var fields: [String: String]
}

/// A line that named a task, as a candidate for the card an event draws.
///
/// `ref` is the `+freeq.at/ref` the companion carries: the only thing joining
/// a line to the work it is about. `account` is the sender's DID when the
/// server named one on the line.
struct ActLine {
    var id: String
    var from: String
    var account: String?
    var timestampMs: Int64
    var ref: String
}

/// The tasks one channel has seen.
///
/// Fed live and by replay, and deduped by event id: the same event arrives up
/// to three times — our own echo, the replay a channel hands a joiner, and the
/// history that joiner asks for next — and the second and third change nothing.
final class ActTaskStore {
    private(set) var tasks: [String: ActTask] = [:]

    func task(_ taskId: String) -> ActTask? { tasks[taskId] }

    /// File one event, and return the line the room is told about it — which
    /// only the home's own `confirm` and `expire` have, every other verb being
    /// read on a card. Nil for a verb that writes its own line, for one that
    /// has nothing left to name, and for an event already held.
    @discardableResult
    func record(_ ev: ActEventInput) -> String? {
        let prior = tasks[ev.taskId]
        if let prior, prior.events.contains(where: { $0.eventId == ev.eventId }) { return nil }

        let events = (prior?.events ?? []) + [ActTaskEvent(
            eventId: ev.eventId, verb: ev.verb, from: ev.from, did: ev.did,
            fields: ev.fields, msgId: nil)]
        var ctx = prior?.ctx ?? []
        if let link = ev.fields["act-ctx"] {
            ctx.append(ActCtxLink(url: link, hash: ev.fields["act-ctx-h"]))
        }
        let task = ActTask(
            taskId: ev.taskId,
            kind: ev.kind.isEmpty ? (prior?.kind ?? "") : ev.kind,
            title: ev.fields["act-title"] ?? prior?.title ?? "",
            // An opener names no other task, so its own id is the task's —
            // which is what makes it the opener, and its sender the offerer.
            offerer: ev.eventId == ev.taskId ? (ev.did ?? ev.from) : prior?.offerer,
            assignee: Self.assignee(prior: prior, ev: ev, events: events),
            verb: ev.verb,
            note: ev.fields["act-note"] ?? prior?.note,
            ctx: ctx,
            events: events)
        tasks[ev.taskId] = task
        return Self.systemLine(task: task, ev: ev)
    }

    /// Join each event to the companion line carrying its prose.
    ///
    /// The companion names only the task, never the event, so the two are
    /// matched by their sender and then by how close in time they are: a
    /// joiner is handed the lines and the task events as two windows that
    /// truncate independently, so a line missing from its window must leave
    /// its event unpaired rather than shift every later line onto the wrong
    /// event. Either side can land first, so this runs from both, and never
    /// re-pairs what it has already paired: the message list is capped, and an
    /// evicted companion must not shift its successors.
    func pair(_ lines: [ActLine]) {
        if tasks.isEmpty || lines.isEmpty { return }
        var claimed = Set<String>()
        for task in tasks.values {
            for ev in task.events { if let id = ev.msgId { claimed.insert(id) } }
        }
        var free: [String: [ActLine]] = [:]
        for line in lines where !claimed.contains(line.id) && tasks[line.ref] != nil {
            free[line.ref, default: []].append(line)
        }
        if free.isEmpty { return }

        for (id, task) in Array(tasks) {
            guard let candidates = free[id] else { continue }
            // Every line each unpaired event could take, nearest in time
            // first, and in arrival order where neither side dates itself.
            var near: [(evIdx: Int, lineIdx: Int, gap: Double)] = []
            for (evIdx, ev) in task.events.enumerated() where ev.msgId == nil {
                let at = actEventTimeMs(ev.eventId)
                for (lineIdx, line) in candidates.enumerated() where Self.sameSender(ev, line) {
                    let gap = at.map { Double(abs(line.timestampMs - $0)) } ?? .infinity
                    near.append((evIdx, lineIdx, gap))
                }
            }
            near.sort {
                if $0.gap != $1.gap { return $0.gap < $1.gap }
                if $0.evIdx != $1.evIdx { return $0.evIdx < $1.evIdx }
                return $0.lineIdx < $1.lineIdx
            }
            var pairedTo: [Int: String] = [:]
            var used = Set<Int>()
            for cand in near {
                if pairedTo[cand.evIdx] != nil || used.contains(cand.lineIdx) { continue }
                pairedTo[cand.evIdx] = candidates[cand.lineIdx].id
                used.insert(cand.lineIdx)
            }
            if pairedTo.isEmpty { continue }
            var updated = task
            for (evIdx, msgId) in pairedTo { updated.events[evIdx].msgId = msgId }
            tasks[id] = updated
        }
    }

    /// Whether a line was written by the sender an event names: the DID when
    /// both sides carry one, the nick otherwise — case aside, since replay
    /// hands back the event under the lowercased nick the server holds and the
    /// line under the nick as it was sent.
    private static func sameSender(_ ev: ActTaskEvent, _ line: ActLine) -> Bool {
        if let did = ev.did, let account = line.account { return did == account }
        return ev.from.lowercased() == line.from.lowercased()
    }

    /// What the room is told about an event that wrote no line of its own.
    ///
    /// The home signs `confirm` and `expire` itself and sends no companion, so
    /// these two are the only events the reader hears about as a system line
    /// rather than a card. Each opens with its verb's glyph, off the same table
    /// a card reads, so a line and a card mark the same move the same way.
    private static func systemLine(task: ActTask, ev: ActEventInput) -> String? {
        // Both lines name the task by its title, which only the opener
        // carries, and the opener falls out of the replay window before the
        // events that follow it do — so with no title held there is nothing
        // to name, and nothing said.
        let title = task.title
        if title.isEmpty { return nil }
        switch ev.verb {
        // The receipt carries only the id of the move it confirms, so the
        // move's sender and its raw verb are read off that event — and with
        // no such event held there is nothing to name, and nothing to say.
        case "confirm":
            guard let subject = task.events.first(where: { $0.eventId == ev.fields["act-subject"] })
            else { return nil }
            return "\(ActVerbs.emoji("confirm")) confirmed: \"\(title)\" — \(subject.verb) by \(subject.from)"
        case "expire":
            return "\(ActVerbs.emoji("expire")) \(title) expired"
        default:
            return nil
        }
    }

    /// Who holds the task after this move: named outright on a directed
    /// offer, taken by whoever claims or accepts it, and on an award the
    /// bidder whose bid was chosen — `act-accepts` names the bid, not the
    /// bidder.
    private static func assignee(
        prior: ActTask?, ev: ActEventInput, events: [ActTaskEvent]
    ) -> String? {
        switch ev.verb {
        case "offer":
            return ev.fields["act-to"] ?? prior?.assignee
        case "claim", "accept":
            return ev.did ?? ev.from
        case "award":
            guard let bid = events.first(where: { $0.eventId == ev.fields["act-accepts"] })
            else { return prior?.assignee }
            return bid.did ?? bid.from
        default:
            return prior?.assignee
        }
    }
}

/// Which buffer an act event belongs in — the task decides, not the sender.
///
/// An event naming a task some thread already holds files there, whoever
/// signed it, so a receipt the server signs lands beside the moves it confirms
/// instead of in a thread named after the server, and a peer home's receipt in
/// a federated conversation lands there too. An opener names no earlier task
/// and opens its own thread, as before. Anything else naming a task nobody
/// holds goes to the sender's thread when we have one and nowhere when we do
/// not — the silence an unheld confirm has always had, rather than a thread
/// conjured for one line that can say nothing.
///
/// The web client's rule, kept in one testable place here.
enum ActEventRouting {
    static func buffer(
        venue: String,
        taskId: String,
        eventId: String,
        bufferHoldingTask: String?,
        hasBuffer: (String) -> Bool
    ) -> String? {
        if let bufferHoldingTask { return bufferHoldingTask }
        // An opener's task is its own event, which is what makes it the opener.
        if taskId == eventId { return venue }
        return hasBuffer(venue) ? venue : nil
    }
}

private let actCrockford = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

/// When an event was minted, off the ULID it is named by — the only time an
/// event carries. Nil for an id that is not a ULID, so ids the server never
/// minted (a test's, a peer's own spelling) fall back to arrival order.
func actEventTimeMs(_ eventId: String) -> Int64? {
    if eventId.count != 26 { return nil }
    var ms: Int64 = 0
    for c in eventId.prefix(10) {
        guard let digit = actCrockford.firstIndex(of: c) else { return nil }
        ms = ms * 32 + Int64(digit)
    }
    return ms
}
