import XCTest
@testable import FreeqIosCore

/// The duplicated-edited-message bug (caught staging client screenshots,
/// 2026-07-23): the server's history replays BOTH the edited-in-place
/// original row and the edit row (new msgid + editOf). Whatever order they
/// arrive in — and however many times history replays — the buffer must
/// hold exactly ONE row.
final class EditDedupTests: XCTestCase {

    private func msg(_ id: String, _ text: String, from: String = "chad",
                     editOf: String? = nil, at seconds: TimeInterval = 0) -> ChatMessage {
        var m = ChatMessage(id: id, from: from, text: text, isAction: false,
                            timestamp: Date(timeIntervalSince1970: seconds), replyTo: nil)
        m.editOf = editOf
        return m
    }

    func testEditRowAfterOriginalDoesNotDuplicate() {
        let ch = ChannelState(name: "#ship")
        ch.appendIfNew(msg("01A", "v1", at: 1))
        ch.appendIfNew(msg("01B", "v2", editOf: "01A", at: 2))
        XCTAssertEqual(ch.messages.count, 1, "\(ch.messages.map(\.text))")
    }

    func testOriginalReplayAfterEditDoesNotResurrect() {
        let ch = ChannelState(name: "#ship")
        ch.appendIfNew(msg("01A", "v1", at: 1))
        ch.applyEdit(originalId: "01A", newId: "01B", newText: "v2")
        // History replays the pre-edit row under the original id.
        ch.appendIfNew(msg("01A", "v1", at: 1))
        XCTAssertEqual(ch.messages.count, 1, "\(ch.messages.map(\.text))")
        XCTAssertEqual(ch.messages[0].text, "v2")
    }

    func testChainedEditKeepsMatchingOriginalId() {
        let ch = ChannelState(name: "#ship")
        ch.appendIfNew(msg("01A", "v1", at: 1))
        ch.applyEdit(originalId: "01A", newId: "01B", newText: "v2")
        // A second edit still references the ORIGINAL msgid.
        ch.applyEdit(originalId: "01A", newId: "01C", newText: "v3")
        XCTAssertEqual(ch.messages.count, 1)
        XCTAssertEqual(ch.messages[0].text, "v3")
        XCTAssertEqual(ch.messages[0].id, "01A", "edits change text, not identity")
    }

    func testApplyEditLeavesTheIndexOnTheOriginalId() {
        let ch = ChannelState(name: "#ship")
        ch.appendIfNew(msg("01A", "v1", at: 1))
        ch.applyEdit(originalId: "01A", newId: "01B", newText: "v2")
        // The message is still itself: the index resolves the id it was born
        // with, and a revision id resolves to nothing (clients never hold one).
        XCTAssertNotNil(ch.findMessage(byId: "01A"))
        XCTAssertNil(ch.findMessage(byId: "01B"))
    }
}
