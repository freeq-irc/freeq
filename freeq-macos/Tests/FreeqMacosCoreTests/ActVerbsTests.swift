import XCTest
@testable import FreeqMacosCore

/// The word each verb shows a reader — the same rows the web client and the
/// Android app read, so the same move is called the same thing wherever it is
/// read.
final class ActVerbsTests: XCTestCase {

    func testEveryVerbHasItsWord() {
        let expected = [
            "offer": "offered",
            "accept": "accepted",
            "decline": "declined",
            "claim": "claimed",
            "progress": "in progress",
            "complete": "completed",
            "fail": "failed",
            "cancel": "cancelled",
            "bid": "bid",
            "award": "awarded",
            "submit": "submitted",
            "revise": "revisions requested",
            "accept-work": "accepted",
            "forfeit": "forfeited",
            "confirm": "confirmed",
            "expire": "expired",
        ]
        for (verb, word) in expected {
            XCTAssertEqual(ActVerbs.headline(verb), word, "verb \(verb)")
        }
    }

    func testAVerbWithNoRowShowsItself() {
        // Which is how a kind may add one without this having to be taught it.
        XCTAssertEqual(ActVerbs.headline("escalate"), "escalate")
        XCTAssertEqual(ActVerbs.headline(""), "")
    }

    func testEveryVerbHasItsGlyph() {
        let expected = [
            "offer": "📋",
            "accept": "👍",
            "decline": "👎",
            "claim": "✋",
            "progress": "📌",
            "complete": "🎉",
            "fail": "❌",
            "cancel": "🚫",
            "bid": "💰",
            "award": "🏆",
            "submit": "📤",
            "revise": "🔁",
            "accept-work": "✅",
            "forfeit": "🏳️",
        ]
        for (verb, glyph) in expected {
            XCTAssertEqual(ActVerbs.emoji(verb), glyph, "verb \(verb)")
        }
    }

    func testAVerbWithNoRowGetsThePin() {
        // Same discipline as the word table: a kind may add a move without
        // this having to be taught it.
        XCTAssertEqual(ActVerbs.emoji("escalate"), "📌")
        XCTAssertEqual(ActVerbs.emoji(""), "📌")
    }

    func testTheHomesOwnVerbsCarryTheGlyphsTheirLinesOpenWith() {
        XCTAssertEqual(ActVerbs.emoji("confirm"), "✔️")
        XCTAssertEqual(ActVerbs.emoji("expire"), "⌛")
    }

    func testTheMovesThatPutWorkOnAPlateAreAccented() {
        XCTAssertEqual(ActVerbs.accent("offer"), .handoff)
        XCTAssertEqual(ActVerbs.accent("award"), .handoff)
    }

    func testAGoodEndAndABadOneAreAccented() {
        XCTAssertEqual(ActVerbs.accent("complete"), .success)
        XCTAssertEqual(ActVerbs.accent("accept-work"), .success)
        XCTAssertEqual(ActVerbs.accent("fail"), .failure)
    }

    func testEveryOtherVerbGoesUnaccented() {
        for verb in ["accept", "decline", "claim", "progress", "cancel", "bid",
                     "submit", "revise", "forfeit", "escalate"] {
            XCTAssertEqual(ActVerbs.accent(verb), ActAccent.none, "verb \(verb)")
        }
    }
}
