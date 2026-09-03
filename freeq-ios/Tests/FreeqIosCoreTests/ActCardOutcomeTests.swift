import XCTest
@testable import FreeqIosCore

/// What the reader ends up looking at, from the layers that actually run:
/// the local cache, the replay batch, event recording, and pairing. The
/// per-layer tests each pass on their own and still let a wrong transcript
/// through — the offer and accept cards landed on each other's lines — so
/// this is the order's regression net and they are not.
///
/// The fixture is the live channel's shape. The offer and its accept are
/// minted 195ms apart inside one second; each companion line goes out a few
/// ms into the NEXT second and replays under that second's `.000` stamp. The
/// later event is then nearer to both lines (37ms against 232ms), which is
/// what let the accept take the offer's line.
final class ActCardOutcomeTests: XCTestCase {
    private let worker = "did:key:z6MkWorker"
    private let home = "did:web:irc.zerosum.org"
    private let second: Int64 = 1_756_760_000_000

    private func ulid(_ ms: Int64, _ tail: String) -> String {
        let crockford = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var left = ms
        var time = ""
        for _ in 0..<10 {
            time = String(crockford[Int(left % 32)]) + time
            left /= 32
        }
        return time + tail
    }

    private var offerEventId: String { ulid(second + 768, "ZZZZZZZZZZZZZZZZ") }
    private var acceptEventId: String { ulid(second + 963, "ZZZZZZZZZZZZZZZZ") }
    private var confirmEventId: String { ulid(second + 3_000, "ZZZZZZZZZZZZZZZZ") }
    private var offerLineId: String { ulid(second + 1_002, "AAAAAAAAAAAAAAAA") }
    private var acceptLineId: String { ulid(second + 1_005, "BBBBBBBBBBBBBBBB") }

    /// Both companion lines replay under the truncated stamp of the second
    /// they were sent in — the same value for both.
    private var replayedLineStamp: Date {
        Date(timeIntervalSince1970: Double(second + 1_000) / 1000)
    }

    private func companion(_ id: String, _ text: String) -> ChatMessage {
        var m = ChatMessage(id: id, from: "worker", text: text, isAction: false,
                            timestamp: replayedLineStamp, replyTo: nil)
        m.account = worker
        m.actRef = offerEventId
        return m
    }

    /// A coordination event that still cards. It sits in the cache too, so a
    /// relaunch decides it before replay ever arrives.
    private func carding(_ id: String) -> ChatMessage {
        var m = ChatMessage(id: id, from: "oldbot", text: "handed the fetch to bob",
                            isAction: false,
                            timestamp: Date(timeIntervalSince1970: Double(second + 1_500) / 1000),
                            replyTo: nil)
        m.coordination = CoordinationInfo(eventType: "delegation_notice", taskId: "TASK001",
                                          phase: nil, evidenceType: nil,
                                          reference: nil, payload: nil)
        return m
    }

    private var delegationLineId: String { ulid(second + 1_500, "CCCCCCCCCCCCCCCC") }

    private func retired(_ id: String, _ eventType: String, _ text: String) -> ChatMessage {
        var m = ChatMessage(id: id, from: "oldbot", text: text, isAction: false,
                            timestamp: Date(timeIntervalSince1970: Double(second + 2_000) / 1000),
                            replyTo: nil)
        m.coordination = CoordinationInfo(eventType: eventType, taskId: "TASK001",
                                          phase: nil, evidenceType: nil,
                                          reference: nil, payload: nil)
        return m
    }

    private func offerEvent() -> ActEventInput {
        ActEventInput(from: "worker", did: worker, kind: "handoff", verb: "offer",
                      eventId: offerEventId, taskId: offerEventId,
                      fields: ["act": "handoff", "act-verb": "offer",
                               "act-title": "ship the release", "act-to": worker])
    }

    private func acceptEvent() -> ActEventInput {
        ActEventInput(from: "worker", did: worker, kind: "handoff", verb: "accept",
                      eventId: acceptEventId, taskId: offerEventId,
                      fields: ["act": "handoff", "act-verb": "accept", "act-id": offerEventId])
    }

    private func confirmEvent() -> ActEventInput {
        ActEventInput(from: "irc.zerosum.org", did: home, kind: "handoff", verb: "confirm",
                      eventId: confirmEventId, taskId: offerEventId,
                      fields: ["act": "handoff", "act-verb": "confirm",
                               "act-id": offerEventId, "act-subject": acceptEventId])
    }

    /// The transcript as the reader sees it: for each row, either the verb of
    /// the card it draws, `.system` for a line the client wrote itself, or
    /// `.text` for a row that renders as its own words.
    private func transcript(_ ch: ChannelState) -> [String] {
        ch.messages.map { m in
            if let card = ch.actCards[m.id] { return "card:\(card.event.verb)" }
            // Every event-tagged message is a card, whatever its type says.
            if let coord = m.coordination { return "card:\(coord.eventType)" }
            if m.from.isEmpty { return "system" }
            return "text"
        }
    }

    /// The rows a previous session left in `buffers.json`, hydrated as
    /// `hydrateBuffersFromCache` does it: the file is a JSON array, so it
    /// hands them back in the order they were written and the sort on the way
    /// in is what decides them.
    private func cached() -> [ChatMessage] {
        [companion(acceptLineId, "accepted: ship the release"),
         companion(offerLineId, "offered: ship the release"),
         carding(delegationLineId)]
            .sorted(by: ChatMessage.replayOrder)
    }

    /// Everything the layers do, in one arrival order or the other.
    private func run(eventsFirst: Bool, cachedRows: [ChatMessage]) -> ChannelState {
        let ch = ChannelState(name: "#actrepoint")
        for m in cachedRows { ch.appendIfNew(m) }

        let record = {
            _ = ch.recordActEvent(self.offerEvent())
            _ = ch.recordActEvent(self.acceptEvent())
            if let line = ch.recordActEvent(self.confirmEvent()) {
                ch.appendIfNew(ChatMessage(
                    id: self.confirmEventId + "-line", from: "", text: line,
                    isAction: false,
                    timestamp: Date(timeIntervalSince1970: Double(self.second + 3_000) / 1000),
                    replyTo: nil))
            }
        }

        let deliver = {
            // The replay batch, deliberately out of wire order, flushed the
            // way `AppState` flushes one at batchEnd.
            let batch = [
                self.retired(self.ulid(self.second + 2_000, "DDDDDDDDDDDDDDDD"),
                             "task_request", "📋 New task: something the old family sent"),
                self.companion(self.acceptLineId, "accepted: ship the release"),
                self.retired(self.ulid(self.second + 2_100, "EEEEEEEEEEEEEEEE"),
                             "task_complete", "✅ Task complete: something the old family sent"),
                self.companion(self.offerLineId, "offered: ship the release"),
                // The tag-bearing copy of a row the cache already placed —
                // dedup keeps the cached one, so the cache decides this card.
                self.carding(self.delegationLineId),
            ]
            for m in batch.sorted(by: ChatMessage.replayOrder) { ch.appendIfNew(m) }
        }

        if eventsFirst { record(); deliver() } else { deliver(); record() }
        ch.pairActCompanions()
        return ch
    }

    func testTheTranscriptReadsTheSameWhicheverSideLandsFirst() {
        let rows = cached()
        for eventsFirst in [true, false] {
            let ch = run(eventsFirst: eventsFirst, cachedRows: rows)
            XCTAssertEqual(
                transcript(ch),
                ["card:offer", "card:accept", "card:delegation_notice",
                 "card:task_request", "card:task_complete", "system"],
                "eventsFirst=\(eventsFirst)")
        }
    }

    func testEachCardLandsOnItsOwnSendersLine() {
        let rows = cached()
        for eventsFirst in [true, false] {
            let ch = run(eventsFirst: eventsFirst, cachedRows: rows)
            XCTAssertEqual(ch.actCards[offerLineId]?.event.verb, "offer",
                           "eventsFirst=\(eventsFirst)")
            XCTAssertEqual(ch.actCards[acceptLineId]?.event.verb, "accept",
                           "eventsFirst=\(eventsFirst)")
        }
    }

    /// The cache is the layer that decides these two rows: it hydrates before
    /// replay, and replay dedups against it by id rather than reordering it.
    func testTheCacheHandsBackTheTwoLinesInMintOrder() {
        let rows = cached()
        XCTAssertEqual(rows.prefix(2).map(\.id), [offerLineId, acceptLineId])
    }

    /// And it has to keep the task each line names, or no card can draw.
    /// UNREACHABLE from here: `CachedMessage` and `BufferCacheStore` are
    /// private to `AppState.swift`, which this target excludes, so the JSON
    /// round trip that drops `actRef` is not exercised — only the pairing
    /// that depends on it. macOS covers the store round trip for real.
    func testTheCacheKeepsTheTaskEachLineNames() {
        let rows = cached()
        XCTAssertEqual(rows.prefix(2).map(\.actRef), [offerEventId, offerEventId])
    }

    /// The same limit applies to the coordination event: `CachedMessage` is
    /// out of reach, so what runs here is the encoding the cache stores it
    /// under. A `CoordinationInfo` that does not survive `JSONEncoder` /
    /// `JSONDecoder` cannot come back out of `buffers.json` either, and a
    /// row that lost it renders as plain text after a relaunch.
    func testTheCoordinationEventSurvivesTheEncodingTheCacheStoresItUnder() throws {
        let info = carding(delegationLineId).coordination
        let data = try JSONEncoder().encode(XCTUnwrap(info))
        let back = try JSONDecoder().decode(CoordinationInfo.self, from: data)
        XCTAssertEqual(back, info)
    }
}
