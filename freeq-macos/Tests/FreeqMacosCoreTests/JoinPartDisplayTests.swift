import XCTest
@testable import FreeqMacosCore

final class JoinPartDisplayTests: XCTestCase {
    private func sys(_ text: String, _ id: String = UUID().uuidString) -> ChatMessage {
        ChatMessage(id: id, from: "", text: text, isAction: false, timestamp: Date(), replyTo: nil)
    }

    private func msg(_ from: String, _ text: String) -> ChatMessage {
        ChatMessage(id: UUID().uuidString, from: from, text: text, isAction: false, timestamp: Date(), replyTo: nil)
    }

    // MARK: - Classification

    func testPresenceLines() {
        XCTAssertTrue(PresenceLines.isPresence(sys("alice joined")))
        XCTAssertTrue(PresenceLines.isPresence(sys("alice left")))
        XCTAssertTrue(PresenceLines.isPresence(sys("alice quit")))
        XCTAssertTrue(PresenceLines.isPresence(sys("alice quit (Ping timeout)")))
    }

    func testModerationAndOtherLinesAreNotPresence() {
        XCTAssertFalse(PresenceLines.isPresence(sys("alice was kicked by bob (spam)")))
        XCTAssertFalse(PresenceLines.isPresence(sys("bob set the topic")))
        XCTAssertFalse(PresenceLines.isPresence(msg("alice", "bob joined")))
        var deleted = sys("alice joined")
        deleted.isDeleted = true
        XCTAssertFalse(PresenceLines.isPresence(deleted))
    }

    // MARK: - Modes

    func testHiddenDropsPresenceButKeepsKicks() {
        let kick = sys("carol was kicked by bob")
        let segs = PresenceLines.segments(
            [msg("a", "hi"), sys("x joined"), sys("y left"), kick, msg("a", "yo")], mode: .hidden)
        XCTAssertEqual(segs.count, 3)
        XCTAssertEqual(segs[1], .message(kick))
    }

    func testHiddenLeavesSenderRunAdjacent() {
        let first = msg("a", "one"), second = msg("a", "two")
        let segs = PresenceLines.segments([first, sys("x joined"), second], mode: .hidden)
        XCTAssertEqual(segs, [.message(first), .message(second)])
    }

    func testGroupedFoldsRunsOfTwoOrMore() {
        let j1 = sys("x joined"), j2 = sys("y joined"), lone = sys("z left")
        let segs = PresenceLines.segments(
            [j1, j2, msg("a", "hi"), lone], mode: .grouped)
        XCTAssertEqual(segs.count, 3)
        XCTAssertEqual(segs[0], .presenceRun([j1, j2]))
        XCTAssertEqual(segs[2], .message(lone))
    }

    func testGroupedNeverFoldsKicksIntoARun() {
        let kick = sys("carol was kicked by bob")
        let segs = PresenceLines.segments(
            [sys("x joined"), kick, sys("y joined")], mode: .grouped)
        XCTAssertEqual(segs.count, 3)
        XCTAssertEqual(segs[1], .message(kick))
    }

    func testAllShowsEveryLineUnfolded() {
        let lines = [sys("x joined"), sys("y joined"), sys("z left")]
        XCTAssertEqual(PresenceLines.segments(lines, mode: .all), lines.map { .message($0) })
    }

    // MARK: - Summary

    func testSummarySinglePersonChurn() {
        XCTAssertEqual(PresenceLines.summary(
            [sys("nap quit (x)"), sys("nap joined"), sys("nap left"), sys("nap joined")]),
            "nap reconnected 2×")
        XCTAssertEqual(PresenceLines.summary([sys("nap joined"), sys("nap joined")]), "nap joined 2×")
    }

    func testSummaryManyPeople() {
        let s = PresenceLines.summary([
            sys("a joined"), sys("b joined"), sys("c joined"), sys("d joined"), sys("e joined"),
            sys("f left"), sys("g quit (bye)"),
        ])
        XCTAssertEqual(s, "a, b, c and 2 more joined · f, g left")
    }

    // MARK: - Setting

    func testDefaultIsHidden() {
        XCTAssertEqual(JoinPartDisplay.resolve(stored: nil, legacyShowJoinPart: nil), .hidden)
        XCTAssertEqual(JoinPartDisplay.resolve(stored: nil, legacyShowJoinPart: false), .hidden)
    }

    func testExplicitOldToggleOnBecomesGrouped() {
        XCTAssertEqual(JoinPartDisplay.resolve(stored: nil, legacyShowJoinPart: true), .grouped)
    }

    func testStoredValueWins() {
        XCTAssertEqual(JoinPartDisplay.resolve(stored: "all", legacyShowJoinPart: false), .all)
        XCTAssertEqual(JoinPartDisplay.resolve(stored: "bogus", legacyShowJoinPart: nil), .hidden)
    }

    func testMigrationWritesOnce() {
        let d = UserDefaults(suiteName: "JoinPartDisplayTests-\(UUID().uuidString)")!
        d.set(true, forKey: JoinPartDisplay.legacyStorageKey)
        JoinPartDisplay.migrateLegacySetting(d)
        XCTAssertEqual(d.string(forKey: JoinPartDisplay.storageKey), "grouped")
        d.set("all", forKey: JoinPartDisplay.storageKey)
        JoinPartDisplay.migrateLegacySetting(d)
        XCTAssertEqual(d.string(forKey: JoinPartDisplay.storageKey), "all")
    }
}
