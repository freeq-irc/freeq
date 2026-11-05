import XCTest
@testable import FreeqIosCore

/// Join/part/quit lines are hidden by default, folded per run when grouped,
/// and drawn one by one when all are wanted. Kicks are never presence lines.
final class PresenceLinesTests: XCTestCase {
    private var n = 0
    private func sys(_ text: String) -> ChatMessage {
        n += 1
        return ChatMessage(id: "s\(n)", from: "", text: text, isAction: false,
                           timestamp: Date(timeIntervalSince1970: Double(n)), replyTo: nil)
    }
    private func said(_ from: String, _ text: String) -> ChatMessage {
        n += 1
        return ChatMessage(id: "m\(n)", from: from, text: text, isAction: false,
                           timestamp: Date(timeIntervalSince1970: Double(n)), replyTo: nil)
    }

    func testDefaultIsHidden() {
        XCTAssertEqual(JoinPartDisplay.default, .hidden)
    }

    func testHiddenDropsPresenceButKeepsKicksAndMessages() {
        let msgs = [said("a", "hi"), sys("bob joined"), sys("bob left"),
                    sys("carol quit (Ping timeout)"), sys("dan was kicked by a (spam)"), said("a", "yo")]
        let out = PresenceLines.apply(msgs, mode: .hidden)
        XCTAssertEqual(out.map(\.text), ["hi", "dan was kicked by a (spam)", "yo"])
    }

    func testSenderTextIsNeverPresence() {
        let msgs = [said("bob", "alice joined")]
        XCTAssertEqual(PresenceLines.apply(msgs, mode: .hidden).count, 1)
    }

    func testAllLeavesEveryLine() {
        let msgs = [sys("bob joined"), sys("carol joined")]
        XCTAssertEqual(PresenceLines.apply(msgs, mode: .all), msgs)
    }

    func testGroupedFoldsARunUnderTheFirstId() {
        let msgs = [said("a", "hi"), sys("bob joined"), sys("carol joined"),
                    sys("dan quit (bye)"), said("a", "yo")]
        let out = PresenceLines.apply(msgs, mode: .grouped)
        XCTAssertEqual(out.map(\.text), ["hi", "bob, carol joined · dan left", "yo"])
        XCTAssertEqual(out[1].id, msgs[1].id)
        XCTAssertTrue(out[1].from.isEmpty)
    }

    func testGroupedLeavesALoneLine() {
        let msgs = [said("a", "hi"), sys("bob joined"), said("a", "yo")]
        XCTAssertEqual(PresenceLines.apply(msgs, mode: .grouped), msgs)
    }

    func testGroupedOnePersonsChurnReadsAsReconnects() {
        let msgs = [sys("nap quit"), sys("nap joined"), sys("nap left"), sys("nap joined")]
        XCTAssertEqual(PresenceLines.apply(msgs, mode: .grouped).map(\.text), ["nap reconnected 2×"])
    }

    func testGroupedCapsNamesAtThree() {
        let msgs = ["a", "b", "c", "d", "e"].map { sys("\($0) joined") }
        XCTAssertEqual(PresenceLines.apply(msgs, mode: .grouped).map(\.text), ["a, b, c and 2 more joined"])
    }

    func testAKickBreaksARun() {
        let msgs = [sys("bob joined"), sys("x was kicked by y"), sys("carol joined")]
        XCTAssertEqual(PresenceLines.apply(msgs, mode: .grouped).count, 3)
    }
}
