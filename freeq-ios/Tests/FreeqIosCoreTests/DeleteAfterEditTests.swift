import XCTest
@testable import FreeqIosCore

/// Deleting an *edited* message must still work.
///
/// Deletes always name the ORIGINAL msgid — that is the identity clients hold
/// and what the server relays in `+draft/delete`. `applyDelete` went through
/// `findMessage(byId:)`, which matches `id` only, so after any edit the delete
/// found nothing and the message stayed on screen even though the server had
/// removed it.
final class DeleteAfterEditTests: XCTestCase {
    private func msg(_ id: String, _ text: String = "hi") -> ChatMessage {
        ChatMessage(id: id, from: "alice", text: text, isAction: false,
                    timestamp: Date(timeIntervalSince1970: 0), replyTo: nil)
    }

    func testDeleteByOriginalIdAfterEdit() {
        let ch = ChannelState(name: "#t")
        ch.appendIfNew(msg("orig", "secret v1"))
        ch.applyEdit(originalId: "orig", newId: "edit1", newText: "secret v2")
        // Sanity: the edit changed the text and left the identity alone.
        XCTAssertEqual(ch.messages.first?.id, "orig")
        XCTAssertEqual(ch.messages.first?.editOf, "orig")

        ch.applyDelete(msgId: "orig")

        let m = ch.messages.first
        XCTAssertEqual(m?.isDeleted, true, "delete naming the original msgid must apply")
        XCTAssertEqual(m?.text, "")
    }

    func testDeleteReachesARowAnOlderBuildReKeyed() {
        // Rows written by a build that re-keyed on edit are still in the local
        // cache: id = the revision, editOf = the root. The server names the
        // root, so the `editOf` arm of the match is what reaches them. This is
        // the transition cover; it can go once such rows can't be around.
        let ch = ChannelState(name: "#t")
        var stale = msg("edit1", "v2")
        stale.editOf = "orig"
        ch.appendIfNew(stale)
        ch.applyDelete(msgId: "orig")
        XCTAssertEqual(ch.messages.first?.isDeleted, true)
    }

    func testDeleteDoesNotTouchUnrelatedMessages() {
        let ch = ChannelState(name: "#t")
        ch.appendIfNew(msg("orig", "v1"))
        ch.appendIfNew(msg("other", "keep me"))
        ch.applyEdit(originalId: "orig", newId: "edit1", newText: "v2")
        ch.applyDelete(msgId: "orig")
        let other = ch.messages.first(where: { $0.text == "keep me" })
        XCTAssertEqual(other?.isDeleted, false)
    }
}
