import XCTest
@testable import FreeqIosCore

/// What the compose bar's state resolves to, and what each send looks like
/// once it carries ciphertext instead of text.
final class OutboundSendTests: XCTestCase {

    // MARK: - Planning

    func testPlainSendWhenNothingIsPending() {
        XCTAssertEqual(
            ComposeSend.plan(target: "#freeq", text: "hi", editingId: nil, replyToId: nil),
            .plain(target: "#freeq", text: "hi")
        )
    }

    func testEditingWins() {
        XCTAssertEqual(
            ComposeSend.plan(target: "#freeq", text: "fixed", editingId: "m1", replyToId: "m2"),
            .edit(target: "#freeq", msgId: "m1", text: "fixed")
        )
    }

    func testReplyWhenNotEditing() {
        XCTAssertEqual(
            ComposeSend.plan(target: "#freeq", text: "yes", editingId: nil, replyToId: "m2"),
            .reply(target: "#freeq", msgId: "m2", text: "yes")
        )
    }

    func testBlankInputPlansNothing() {
        XCTAssertNil(ComposeSend.plan(target: "#freeq", text: "   \n ", editingId: nil, replyToId: nil))
    }

    /// The SDK routes a newline-bearing body into a multiline batch and signs
    /// what a receiver reassembles. Splitting it here turned one thought into
    /// several messages; escaping it would sign bytes nobody holds.
    func testNewlinesSurvivePlanning() {
        let plan = ComposeSend.plan(target: "#freeq", text: "one\ntwo\nthree",
                                    editingId: nil, replyToId: nil)
        XCTAssertEqual(plan, .plain(target: "#freeq", text: "one\ntwo\nthree"))
    }

    func testMultilineEditKeepsItsLines() {
        let plan = ComposeSend.plan(target: "#freeq", text: "one\ntwo",
                                    editingId: "m1", replyToId: nil)
        XCTAssertEqual(plan, .edit(target: "#freeq", msgId: "m1", text: "one\ntwo"))
    }

    /// A pasted CRLF body is still one message; the carriage returns would end
    /// the IRC line early.
    func testCarriageReturnsAreStripped() {
        let plan = ComposeSend.plan(target: "#freeq", text: "one\r\ntwo",
                                    editingId: nil, replyToId: nil)
        XCTAssertEqual(plan, .plain(target: "#freeq", text: "one\ntwo"))
    }

    func testSurroundingWhitespaceIsTrimmed() {
        let plan = ComposeSend.plan(target: "#freeq", text: "\n  hi  \n",
                                    editingId: nil, replyToId: nil)
        XCTAssertEqual(plan, .plain(target: "#freeq", text: "hi"))
    }

    // MARK: - Re-addressing

    func testAddressedToVenueKeepsEverythingElse() {
        let send = OutboundSend.reply(target: "bob", msgId: "m1", text: "hi")
        XCTAssertEqual(
            send.addressed(to: "did:plc:abc"),
            .reply(target: "did:plc:abc", msgId: "m1", text: "hi")
        )
    }

    // MARK: - Encrypted tag sets

    func testEncryptedPlainCarriesOnlyTheEncryptedTag() {
        let tags = OutboundSend.plain(target: "#freeq", text: "x").encryptedTags
        XCTAssertEqual(tags, ["+encrypted": ""])
    }

    func testEncryptedEditCarriesBothTags() {
        let tags = OutboundSend.edit(target: "#freeq", msgId: "m1", text: "x").encryptedTags
        XCTAssertEqual(tags, ["+draft/edit": "m1", "+encrypted": ""])
    }

    func testEncryptedReplyCarriesBothTags() {
        let tags = OutboundSend.reply(target: "#freeq", msgId: "m1", text: "x").encryptedTags
        XCTAssertEqual(tags, ["+reply": "m1", "+encrypted": ""])
    }

    /// A valueless IRC tag is an empty value on the wire (`@+encrypted`), not
    /// the string "true" — a receiver testing for presence sees either, but a
    /// receiver comparing values does not.
    func testEncryptedTagIsValueless() {
        XCTAssertEqual(OutboundSend.plain(target: "#c", text: "x").encryptedTags["+encrypted"], "")
    }

    // MARK: - Reaction toggle

    func testFirstTapAdds() {
        XCTAssertEqual(
            ReactionOp.plan(target: "#freeq", msgId: "m1", emoji: "🔥", alreadyReacted: false),
            .add(target: "#freeq", msgId: "m1", emoji: "🔥")
        )
    }

    func testSecondTapRemoves() {
        XCTAssertEqual(
            ReactionOp.plan(target: "#freeq", msgId: "m1", emoji: "🔥", alreadyReacted: true),
            .remove(target: "#freeq", msgId: "m1", emoji: "🔥")
        )
    }
}
