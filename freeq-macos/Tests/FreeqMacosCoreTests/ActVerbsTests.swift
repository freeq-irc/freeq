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
}
