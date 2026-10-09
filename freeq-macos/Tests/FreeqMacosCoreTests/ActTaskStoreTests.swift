import XCTest
@testable import FreeqMacosCore

/// What a channel remembers about the work done in it: one task per opener,
/// every move on it kept in the order it arrived, and each move joined to the
/// line its sender wrote beside it.
final class ActTaskStoreTests: XCTestCase {

    private let opener = "01JOPENER00000000000000000"
    private let poster = "did:plc:poster"
    private let worker = "did:plc:worker"

    /// One task event as the bridge hands it over.
    private func ev(
        from: String = "poster",
        did: String? = "did:plc:poster",
        verb: String = "offer",
        eventId: String? = nil,
        taskId: String? = nil,
        fields: [String: String]? = nil,
        kind: String = "handoff"
    ) -> ActEventInput {
        ActEventInput(
            from: from, did: did, kind: kind, verb: verb,
            eventId: eventId ?? opener, taskId: taskId ?? opener,
            fields: fields ?? ["act": "handoff", "act-verb": "offer", "act-title": "ship the release"])
    }

    /// A later move on the task the opener above opened.
    private func move(
        _ verb: String,
        _ eventId: String,
        _ extra: [String: String] = [:],
        who: String = "worker",
        did: String? = "did:plc:worker"
    ) -> ActEventInput {
        var fields = ["act": "handoff", "act-verb": verb, "act-id": opener]
        for (k, v) in extra { fields[k] = v }
        return ev(from: who, did: did, verb: verb, eventId: eventId, fields: fields)
    }

    /// A companion line as replay hands it back: the nick as it was sent, and
    /// the sender's DID under the server's `account` tag.
    private func line(
        _ id: String, _ from: String, _ ref: String,
        account: String? = nil, at: Int64 = 0
    ) -> ActLine {
        ActLine(id: id, from: from, account: account, timestampMs: at, ref: ref)
    }

    /// The id an event minted at that moment carries: a ULID, time first.
    private func idAt(_ ms: Int64) -> String {
        let crockford = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var left = ms
        var time = ""
        for _ in 0..<10 {
            time = String(crockford[Int(left % 32)]) + time
            left /= 32
        }
        return time + "ZZZZZZZZZZZZZZZZ"
    }

    // ── The task map ──

    func testAnOpenerOpensATaskKeyedByItsOwnEventId() {
        let store = ActTaskStore()
        _ = store.record(ev())
        let task = store.task(opener)!
        XCTAssertEqual(task.taskId, opener)
        XCTAssertEqual(task.kind, "handoff")
        XCTAssertEqual(task.title, "ship the release")
        XCTAssertEqual(task.offerer, poster)
        XCTAssertEqual(task.verb, "offer")
        XCTAssertEqual(task.events.count, 1)
    }

    func testADirectedOfferNamesWhoHoldsIt() {
        let store = ActTaskStore()
        _ = store.record(ev(fields: ["act-title": "ship the release", "act-to": worker]))
        XCTAssertEqual(store.task(opener)?.assignee, worker)
    }

    func testEachLaterVerbBecomesTheLatestAndAppendsToTheList() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("claim", "e2"))
        _ = store.record(move("progress", "e3", ["act-note": "halfway"]))

        let task = store.task(opener)!
        XCTAssertEqual(task.verb, "progress")
        XCTAssertEqual(task.note, "halfway")
        XCTAssertEqual(task.assignee, worker)
        XCTAssertEqual(task.events.map(\.eventId), [opener, "e2", "e3"])
        XCTAssertEqual(task.events.map(\.verb), ["offer", "claim", "progress"])
    }

    func testEachContextLinkIsKeptWithTheHashItsSignatureCovers() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("progress", "e2", ["act-ctx": "https://x/1", "act-ctx-h": "sha256:aa"]))
        _ = store.record(move("complete", "e3", ["act-ctx": "https://x/2", "act-ctx-h": "sha256:bb"]))

        XCTAssertEqual(
            store.task(opener)?.ctx,
            [ActCtxLink(url: "https://x/1", hash: "sha256:aa"),
             ActCtxLink(url: "https://x/2", hash: "sha256:bb")])
    }

    func testAnAwardHandsTheTaskToTheBidderWhoseBidItNames() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("bid", "bid-1", who: "worker", did: worker))
        _ = store.record(move("award", "e3", ["act-accepts": "bid-1"], who: "poster", did: poster))

        XCTAssertEqual(store.task(opener)?.assignee, worker)
    }

    func testAReplayedEventChangesNothing() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("progress", "e2", ["act-note": "halfway"]))
        let before = store.task(opener)!

        XCTAssertNil(store.record(move("progress", "e2", ["act-note": "halfway"])))
        XCTAssertEqual(store.task(opener), before)
        XCTAssertEqual(store.task(opener)?.events.count, 2)
    }

    // ── Companion lines ──

    func testEachEventJoinsTheLineItsSenderWroteBesideIt() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("claim", "e2"))
        store.pair([line("m1", "poster", opener), line("m2", "worker", opener)])

        XCTAssertEqual(store.task(opener)?.events.map(\.msgId), ["m1", "m2"])
    }

    func testALineThatArrivedFirstJoinsTheEventThatFollowsIt() {
        let store = ActTaskStore()
        let lines = [line("m1", "poster", opener)]
        store.pair(lines)
        _ = store.record(ev())
        store.pair(lines)

        XCTAssertEqual(store.task(opener)?.events[0].msgId, "m1")
    }

    func testTheyJoinByDidWhenTheTwoSidesSpellTheNickDifferently() {
        // Replay hands the event back under the lowercased nick the server
        // holds and the line under the nick as it was sent.
        let store = ActTaskStore()
        _ = store.record(ev(from: "taskbot", did: poster))
        store.pair([line("m1", "TaskBot", opener, account: poster)])

        XCTAssertEqual(store.task(opener)?.events[0].msgId, "m1")
    }

    func testTheyJoinByNickCaseAsideWhenNeitherSideCarriesADid() {
        let store = ActTaskStore()
        _ = store.record(ev(from: "taskbot", did: nil))
        store.pair([line("m1", "TaskBot", opener)])

        XCTAssertEqual(store.task(opener)?.events[0].msgId, "m1")
    }

    func testALineNeverJoinsADifferentSender() {
        let store = ActTaskStore()
        _ = store.record(ev(from: "poster", did: poster))
        store.pair([line("m1", "worker", opener, account: worker)])

        XCTAssertNil(store.task(opener)?.events[0].msgId)
    }

    func testALineOutsideTheWindowLeavesItsEventUnpaired() {
        // The lines and the task events replay as two windows that truncate
        // independently: here the opener's line fell outside its window, and
        // the first line is a minute from the opener, so no line stands
        // opposite it and every later event still gets its own.
        let store = ActTaskStore()
        let t0: Int64 = 1_755_000_000_000
        let at: [Int64] = [t0, t0 + 60_000, t0 + 120_000, t0 + 180_000]
        let ids = at.map { idAt($0) }
        _ = store.record(ev(from: "worker", did: worker, eventId: ids[0], taskId: ids[0]))
        for (i, verb) in ["claim", "progress", "complete"].enumerated() {
            _ = store.record(ev(
                from: "worker", did: worker, verb: verb,
                eventId: ids[i + 1], taskId: ids[0],
                fields: ["act": "handoff", "act-verb": verb, "act-id": ids[0]]))
        }
        store.pair(["claim", "progress", "complete"].enumerated().map { i, verb in
            line("m-\(verb)", "worker", ids[0], account: worker, at: at[i + 1])
        })

        XCTAssertEqual(
            store.task(ids[0])?.events.map(\.msgId),
            [nil, "m-claim", "m-progress", "m-complete"])
    }

    func testAPairingSurvivesTheSameLineArrivingAgain() {
        let store = ActTaskStore()
        _ = store.record(ev())
        let first = line("m1", "poster", opener)
        store.pair([first])
        _ = store.record(move("progress", "e2", who: "poster", did: poster))
        store.pair([first])

        let events = store.task(opener)!.events
        XCTAssertEqual(events[0].msgId, "m1")
        XCTAssertNil(events[1].msgId)
    }

    // ── The two events that write no line of their own ──

    func testAConfirmTellsTheRoomWhatTheHomeConfirmed() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("claim", "e2", who: "worker", did: worker))
        let line = store.record(
            move("confirm", "e3", ["act-subject": "e2"], who: "acceptance", did: nil))

        XCTAssertEqual(line, "✔️ confirmed: \"ship the release\" — claim by worker")
    }

    func testAConfirmSaysNothingAboutAMoveItDoesNotHold() {
        let store = ActTaskStore()
        _ = store.record(ev())

        XCTAssertNil(store.record(
            move("confirm", "e3", ["act-subject": "never-seen"], who: "acceptance", did: nil)))
    }

    func testAnExpirySaysTheTaskExpired() {
        let store = ActTaskStore()
        _ = store.record(ev())

        XCTAssertEqual(
            store.record(move("expire", "e2", who: "acceptance", did: nil)),
            "⌛ ship the release expired")
    }

    func testAnExpirySaysNothingWhenNoTitleIsHeld() {
        // The opener falls out of the replay window before the events that
        // follow it do, so there is no title to name and nothing to say.
        let store = ActTaskStore()

        XCTAssertNil(store.record(move("expire", "e2", who: "acceptance", did: nil)))
    }

    func testEveryOtherVerbIsLeftToItsCard() {
        let store = ActTaskStore()
        _ = store.record(ev())
        XCTAssertNil(store.record(move("claim", "e2")))
        XCTAssertNil(store.record(move("complete", "e3")))
    }

    // ── The cards either side of one ──

    private func paired(_ store: ActTaskStore, _ verbs: [String]) {
        // An opener and its follow-ups, each with the line its sender wrote.
        _ = store.record(ev())
        for (i, verb) in verbs.enumerated() { _ = store.record(move(verb, "e\(i + 2)")) }
        store.pair(
            [line("m1", "poster", opener, account: poster)]
                + verbs.enumerated().map { i, _ in
                    line("m\(i + 2)", "worker", opener, account: worker)
                })
    }

    func testTheFirstCardHasNoCardBeforeIt() {
        let store = ActTaskStore()
        paired(store, ["claim", "complete"])
        let task = store.task(opener)!

        let ends = actCardNeighbours(task: task, event: task.events[0])
        XCTAssertNil(ends.prev)
        XCTAssertEqual(ends.next, "m2")
    }

    func testACardInTheMiddleHasOneEitherSide() {
        let store = ActTaskStore()
        paired(store, ["claim", "complete"])
        let task = store.task(opener)!

        let ends = actCardNeighbours(task: task, event: task.events[1])
        XCTAssertEqual(ends.prev, "m1")
        XCTAssertEqual(ends.next, "m3")
    }

    func testTheLastCardHasNoCardAfterIt() {
        let store = ActTaskStore()
        paired(store, ["claim", "complete"])
        let task = store.task(opener)!

        let ends = actCardNeighbours(task: task, event: task.events[2])
        XCTAssertEqual(ends.prev, "m2")
        XCTAssertNil(ends.next)
    }

    func testTheTwoTheHomeSignsAreNotNeighbours() {
        // They write no companion line, so there is no card to land on: a
        // confirm between two moves must not be offered as either one's
        // neighbour, and has no neighbours of its own.
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("claim", "e2"))
        _ = store.record(move("confirm", "e3", ["act-subject": "e2"], who: "acceptance", did: nil))
        _ = store.record(move("complete", "e4"))
        store.pair([
            line("m1", "poster", opener, account: poster),
            line("m2", "worker", opener, account: worker),
            line("m4", "worker", opener, account: worker),
        ])
        let task = store.task(opener)!

        XCTAssertEqual(actCardNeighbours(task: task, event: task.events[1]).next, "m4")
        let receipt = actCardNeighbours(task: task, event: task.events[2])
        XCTAssertNil(receipt.prev)
        XCTAssertNil(receipt.next)
    }

    func testAnEventWhoseLineHasNotArrivedOffersNothing() {
        let store = ActTaskStore()
        _ = store.record(ev())
        _ = store.record(move("claim", "e2"))
        store.pair([line("m1", "poster", opener, account: poster)])
        let task = store.task(opener)!

        let unpaired = actCardNeighbours(task: task, event: task.events[1])
        XCTAssertNil(unpaired.prev)
        XCTAssertNil(unpaired.next)
    }

    // ── When an event was made ──

    func testAnEventCarriesTheMomentItWasMinted() {
        // The system lines are dated by this: a receipt handed back on join is
        // old news, and saying "now" would file it under the newest thing said.
        let at: Int64 = 1_755_000_000_000
        XCTAssertEqual(actEventTimeMs(idAt(at)), at)
    }

    func testAnIdTheServerNeverMintedCarriesNoTime() {
        XCTAssertNil(actEventTimeMs("e2"))
        XCTAssertNil(actEventTimeMs("UUUUUUUUUU" + "ZZZZZZZZZZZZZZZZ"))
    }

    // ── Which thread an event lands in ──

    func testAnEventFilesIntoTheThreadAlreadyHoldingItsTask() {
        // The receipt names the server as its sender, so the venue can only be
        // keyed by the server. The task is what says where it belongs.
        XCTAssertEqual(
            ActEventRouting.buffer(
                venue: "did:web:irc.example", taskId: opener, eventId: "01JRECEIPT",
                bufferHoldingTask: "did:plc:poster", hasBuffer: { _ in false }),
            "did:plc:poster")
    }

    func testAnOpenerOpensItsOwnThread() {
        XCTAssertEqual(
            ActEventRouting.buffer(
                venue: "did:plc:poster", taskId: opener, eventId: opener,
                bufferHoldingTask: nil, hasBuffer: { _ in false }),
            "did:plc:poster")
    }

    func testAMoveOnATaskNobodyHoldsFilesIntoTheSendersExistingThread() {
        XCTAssertEqual(
            ActEventRouting.buffer(
                venue: "did:plc:poster", taskId: "01JUNHELD", eventId: "01JPROGRESS",
                bufferHoldingTask: nil, hasBuffer: { $0 == "did:plc:poster" }),
            "did:plc:poster")
    }

    func testAMoveOnATaskNobodyHoldsFromSomeoneWeHaveNoThreadWithCreatesNothing() {
        XCTAssertNil(
            ActEventRouting.buffer(
                venue: "did:plc:stranger", taskId: "01JUNHELD", eventId: "01JPROGRESS",
                bufferHoldingTask: nil, hasBuffer: { _ in false }))
    }

    func testAChannelEventStaysInItsChannel() {
        XCTAssertEqual(
            ActEventRouting.buffer(
                venue: "#work", taskId: opener, eventId: opener,
                bufferHoldingTask: nil, hasBuffer: { _ in false }),
            "#work")
        XCTAssertEqual(
            ActEventRouting.buffer(
                venue: "#work", taskId: opener, eventId: "01JRECEIPT",
                bufferHoldingTask: "#work", hasBuffer: { $0 == "#work" }),
            "#work")
    }

    // ── Where a confirmation line is drawn ──

    private let second: Int64 = 1_760_011_200_000

    private func row(_ id: String, _ at: Int64, from: String = "worker", deleted: Bool = false) -> ChatMessage {
        var m = ChatMessage(id: id, from: from, text: id, isAction: false,
                            timestamp: Date(timeIntervalSince1970: Double(at) / 1000), replyTo: nil)
        m.isDeleted = deleted
        return m
    }

    /// The line the home's confirmation draws, stamped by the home's clock.
    private func systemRow(_ id: String, _ at: Int64) -> ChatMessage { row(id, at, from: "") }

    private func confirmOf(_ id: String, _ subject: String) -> ActTaskEvent {
        ActTaskEvent(eventId: id, verb: "confirm", from: "home", did: nil,
                     fields: ["act-subject": subject], msgId: nil)
    }

    /// The card a claim draws on row `card`, in a task holding `rest` too.
    private func cardFor(_ card: String, _ claim: String, _ rest: [ActTaskEvent]) -> (String, ActCard) {
        let step = ActTaskEvent(eventId: claim, verb: "claim", from: "worker", did: nil, fields: [:], msgId: card)
        let task = ActTask(taskId: "t-\(claim)", kind: "handoff", title: "ship it", offerer: nil,
                           assignee: nil, verb: "claim", note: nil, events: [step] + rest)
        return (card, ActCard(task: task, event: step))
    }

    private func cards(_ pairs: (String, ActCard)...) -> [String: ActCard] {
        Dictionary(uniqueKeysWithValues: pairs)
    }

    private var claimed: [String: ActCard] { cards(cardFor("card", "claim", [confirmOf("line", "claim")])) }

    private func ids(_ rows: [ChatMessage]) -> [String] { rows.map(\.id) }

    func testALineStoredAboveItsCardIsDrawnUnderItInEitherStamping() {
        for cardAt in [second, second + 1000] {
            let stored = [row("before", second - 5000), systemRow("line", second + 400),
                          row("card", cardAt), row("after", second + 9000)]
            XCTAssertEqual(ids(actConfirmLinesUnderCards(stored, cards: claimed)),
                           ["before", "card", "line", "after"])
        }
    }

    func testALineAlreadyUnderItsCardStays() {
        for cardAt in [second, second + 1000] {
            let stored = [row("card", cardAt), systemRow("line", cardAt + 400), row("after", second + 9000)]
            XCTAssertEqual(ids(actConfirmLinesUnderCards(stored, cards: claimed)), ["card", "line", "after"])
        }
    }

    func testALineWhoseCardIsNotDrawnWasDeletedOrIsHiddenStaysByItsTime() {
        let missing = [systemRow("line", second + 400), row("after", second + 9000)]
        XCTAssertEqual(ids(actConfirmLinesUnderCards(missing, cards: claimed)), ["line", "after"])

        let deleted = [systemRow("line", second + 400), row("card", second, deleted: true)]
        XCTAssertEqual(ids(actConfirmLinesUnderCards(deleted, cards: claimed)), ["line", "card"])

        // A blocked sender's row stays in the list, drawn empty.
        let blocked = [systemRow("line", second + 400), row("card", second)]
        XCTAssertEqual(
            ids(actConfirmLinesUnderCards(blocked, cards: claimed, hidden: { $0.from == "worker" })),
            ["line", "card"])
    }

    func testAnExpiryLineStaysByItsTime() {
        let expire = ActTaskEvent(eventId: "gone", verb: "expire", from: "home", did: nil, fields: [:], msgId: nil)
        let stored = [systemRow("gone", second + 400), row("card", second)]
        XCTAssertEqual(ids(actConfirmLinesUnderCards(stored, cards: cards(cardFor("card", "claim", [expire])))),
                       ["gone", "card"])
    }

    func testEachOfTwoTasksLinesGoesUnderItsOwnCard() {
        let both = cards(cardFor("cardA", "a", [confirmOf("lineA", "a")]),
                         cardFor("cardB", "b", [confirmOf("lineB", "b")]))
        let stored = [systemRow("lineA", second + 100), systemRow("lineB", second + 200),
                      row("cardA", second), row("between", second), row("cardB", second + 1000)]
        XCTAssertEqual(ids(actConfirmLinesUnderCards(stored, cards: both)),
                       ["cardA", "lineA", "between", "cardB", "lineB"])
    }

    func testTwoLinesUnderOneCardKeepTheirOrder() {
        let twice = cards(cardFor("card", "claim", [confirmOf("first", "claim"), confirmOf("second", "claim")]))
        let stored = [systemRow("first", second + 100), systemRow("second", second + 200), row("card", second + 1000)]
        XCTAssertEqual(ids(actConfirmLinesUnderCards(stored, cards: twice)), ["card", "first", "second"])
    }

    func testALiveConfirmationIsDrawnUnderItsCardWhateverOrderItWasStoredIn() {
        // Live order: the step, the home's confirmation and its line, then the
        // card's line. Stamped in the step's second, the card sorts before the
        // line's millisecond; stamped in the next, after it.
        let claim = idAt(second + 400)
        let receipt = idAt(second + 450)
        for (cardAt, stored) in [(second, ["m-card", receipt]), (second + 1000, [receipt, "m-card"])] {
            let ch = ChannelState(name: "#work")
            _ = ch.recordActEvent(ev())
            _ = ch.recordActEvent(move("claim", claim))
            let text = ch.recordActEvent(move("confirm", receipt, ["act-subject": claim], who: "acceptance", did: nil))
            ch.appendIfNew(ChatMessage(id: receipt, from: "", text: text ?? "", isAction: false,
                                       timestamp: Date(timeIntervalSince1970: Double(second + 450) / 1000),
                                       replyTo: nil))
            var card = ChatMessage(id: "m-card", from: "worker", text: "on it", isAction: false,
                                   timestamp: Date(timeIntervalSince1970: Double(cardAt) / 1000), replyTo: nil)
            card.account = worker
            card.actRef = opener
            ch.appendIfNew(card)

            XCTAssertEqual(ids(ch.messages), stored)
            XCTAssertEqual(ids(actConfirmLinesUnderCards(ch.messages, cards: ch.actCards)), ["m-card", receipt])
        }
    }
}
