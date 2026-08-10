import XCTest
@testable import freeq

/// What the app actually puts on the wire when someone sends, edits, replies,
/// reacts, or deletes.
///
/// These live in the app-hosted bundle rather than the SwiftPM suite because
/// AppState is not part of that package: the pure decisions (what a compose
/// state plans, which half of a reaction toggle to send) are asserted there,
/// and what only AppState can answer — which venue a send is addressed to,
/// what applies locally without an echo, what the user is told when a send
/// fails — is asserted here.
final class SendPathTests: XCTestCase {

    private let me = "alice"
    private let peer = "bob"

    private func makeState() -> AppState {
        for k in ["freeq.nick", "freeq.server", "freeq.channels", "freeq.closedDMs",
                  "freeq.favorites", "freeq.bookmarks"] {
            UserDefaults.standard.removeObject(forKey: k)
        }
        let s = AppState()
        s.nick = me
        return s
    }

    /// A nick no other test has bound. `ProfileCache.shared` is process-wide
    /// and outlives any one AppState, so a nick another test taught a DID to
    /// resolves instantly here and the wait under test never happens.
    private func strangerNick(_ name: String = #function) -> String {
        "stranger-" + name.prefix(while: { $0 != "(" }).lowercased()
    }

    /// Every send that reached the wire, in order.
    private func recording(_ s: AppState) -> Recorder {
        let r = Recorder()
        s.onOutboundSend = { r.sends.append($0) }
        return r
    }

    private final class Recorder {
        var sends: [OutboundSend] = []
    }

    private func seedChannelMessage(
        in s: AppState, channel: String, id: String, from: String, text: String = "hi"
    ) -> ChannelState {
        let ch = s.getOrCreateChannel(channel)
        ch.appendIfNew(ChatMessage(id: id, from: from, text: text, isAction: false,
                                   timestamp: Date(), replyTo: nil))
        return ch
    }

    private func seedDMMessage(
        in s: AppState, peer: String, id: String, from: String, text: String = "hi"
    ) -> ChannelState {
        let dm = s.getOrCreateDM(peer)
        dm.appendIfNew(ChatMessage(id: id, from: from, text: text, isAction: false,
                                   timestamp: Date(), replyTo: nil))
        return dm
    }

    // MARK: - What each compose state sends

    func testPlainSubmitIsAPlainSend() {
        let s = makeState()
        let r = recording(s)
        s.submitInput("hello", target: "#freeq")
        XCTAssertEqual(r.sends, [.plain(target: "#freeq", text: "hello")])
    }

    func testEditingSubmitSendsAnEditAndClearsTheState() {
        let s = makeState()
        let r = recording(s)
        s.editingMessageId = "m1"
        s.editingText = "before"
        s.submitInput("after", target: "#freeq")
        XCTAssertEqual(r.sends, [.edit(target: "#freeq", msgId: "m1", text: "after")])
        XCTAssertNil(s.editingMessageId)
        XCTAssertNil(s.editingText)
    }

    /// A revision that starts with a slash is still text, not a command.
    func testEditingSubmitBeatsSlashCommandParsing() {
        let s = makeState()
        let r = recording(s)
        s.editingMessageId = "m1"
        s.submitInput("/topic is a fine thing", target: "#freeq")
        XCTAssertEqual(r.sends, [.edit(target: "#freeq", msgId: "m1", text: "/topic is a fine thing")])
    }

    func testReplyingSubmitSendsAReplyAndClearsTheState() {
        let s = makeState()
        let r = recording(s)
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: peer)
        s.replyingToMessage = ch.messages.first
        s.submitInput("answering", target: "#freeq")
        XCTAssertEqual(r.sends, [.reply(target: "#freeq", msgId: "m1", text: "answering")])
        XCTAssertNil(s.replyingToMessage)
    }

    /// One submission is one message, newlines and all. Splitting it turned a
    /// single thought into several, each with an id of its own — so an edit or
    /// a reaction could only ever reach one line of it.
    func testMultilineSubmitIsOneSend() {
        let s = makeState()
        let r = recording(s)
        s.submitInput("one\ntwo\nthree", target: "#freeq")
        XCTAssertEqual(r.sends, [.plain(target: "#freeq", text: "one\ntwo\nthree")])
    }

    func testMultilineEditIsOneSend() {
        let s = makeState()
        let r = recording(s)
        s.editingMessageId = "m1"
        s.submitInput("one\ntwo", target: "#freeq")
        XCTAssertEqual(r.sends, [.edit(target: "#freeq", msgId: "m1", text: "one\ntwo")])
    }

    func testSlashMeSendsAnActionBody() {
        let s = makeState()
        let r = recording(s)
        s.submitInput("/me waves", target: "#freeq")
        XCTAssertEqual(r.sends, [.plain(target: "#freeq", text: "\u{01}ACTION waves\u{01}")])
    }

    func testSlashReplyAddressesTheNamedMessage() {
        let s = makeState()
        let r = recording(s)
        _ = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: peer)
        s.activeChannel = "#freeq"
        s.submitInput("/reply m1 sure", target: "#freeq")
        XCTAssertEqual(r.sends, [.reply(target: "#freeq", msgId: "m1", text: "sure")])
    }

    func testThreadReplyGoesThroughTheSamePath() {
        let s = makeState()
        let r = recording(s)
        s.sendReply(target: "#freeq", msgId: "root", text: "in thread")
        XCTAssertEqual(r.sends, [.reply(target: "#freeq", msgId: "root", text: "in thread")])
    }

    // MARK: - Venue: a signature covers the venue it was written for

    /// A DM to a peer whose DID we already hold is addressed to the DID, which
    /// is the venue a verifier can rebuild. Sent at the bare nick it would go
    /// unsigned.
    func testDmToAKnownPeerIsAddressedToTheirDid() {
        let s = makeState()
        let r = recording(s)
        s.recordUserDid(nick: peer, did: "did:plc:bob")
        s.sendMessage(to: peer, text: "hi")
        XCTAssertEqual(r.sends, [.plain(target: "did:plc:bob", text: "hi")])
    }

    func testChannelSendIsNeverReaddressed() {
        let s = makeState()
        let r = recording(s)
        s.sendMessage(to: "#freeq", text: "hi")
        XCTAssertEqual(r.sends, [.plain(target: "#freeq", text: "hi")])
    }

    /// A first DM to a stranger asks who they are, and sends at the nick when
    /// the answer doesn't come — asking must never cost the user their message.
    func testFirstDmToAStrangerStillSends() {
        let s = makeState()
        let r = recording(s)
        let who = strangerNick()
        let sent = expectation(description: "sent at the nick after the wait")
        s.onOutboundSend = { send in
            r.sends.append(send)
            sent.fulfill()
        }
        s.sendMessage(to: who, text: "hello")
        XCTAssertTrue(r.sends.isEmpty, "the send waits for the answer rather than going out unsigned")
        wait(for: [sent], timeout: 10)
        XCTAssertEqual(r.sends, [.plain(target: who, text: "hello")])
    }

    /// The answer arriving in time re-addresses the waiting send to the DID.
    func testAnswerDuringTheWaitAddressesTheDid() {
        let s = makeState()
        let r = recording(s)
        let who = strangerNick()
        let sent = expectation(description: "sent to the DID")
        s.onOutboundSend = { send in
            r.sends.append(send)
            sent.fulfill()
        }
        s.sendMessage(to: who, text: "hello")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            s.recordUserDid(nick: who, did: "did:plc:\(who)")
        }
        wait(for: [sent], timeout: 10)
        XCTAssertEqual(r.sends, [.plain(target: "did:plc:\(who)", text: "hello")])
    }

    // MARK: - Optimistic apply (the server relays these but never echoes them)

    func testReactionAppliesLocallyWithoutAnEcho() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: peer)
        s.sendReaction(target: "#freeq", msgId: "m1", emoji: "🎉")
        XCTAssertEqual(ch.messages.first?.reactions["🎉"], Set([me]))
    }

    func testSecondTapWithdrawsTheReactionLocally() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: peer)
        s.sendReaction(target: "#freeq", msgId: "m1", emoji: "🎉")
        s.sendReaction(target: "#freeq", msgId: "m1", emoji: "🎉")
        XCTAssertNil(ch.messages.first?.reactions["🎉"])
    }

    func testReactionInADmAppliesLocallyToo() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        s.sendReaction(target: peer, msgId: "m1", emoji: "❤️")
        XCTAssertEqual(dm.messages.first?.reactions["❤️"], Set([me]))
    }

    func testDeleteTombstonesLocallyWithoutAnEcho() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: me, text: "regret")
        s.deleteMessage(target: "#freeq", msgId: "m1")
        XCTAssertEqual(ch.messages.first?.isDeleted, true)
        XCTAssertEqual(ch.messages.first?.text, "")
    }

    func testDeleteOfAnUnknownMessageIsASilentNoOp() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: me)
        s.deleteMessage(target: "#freeq", msgId: "ghost")
        XCTAssertEqual(ch.messages.first?.isDeleted, false)
    }

    /// An edit is echoed back by the server, so applying it locally would
    /// double-apply. Nothing may change on the sender's screen here.
    func testEditDoesNotApplyOptimistically() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: me, text: "before")
        s.editMessage(target: "#freeq", msgId: "m1", newText: "after")
        XCTAssertEqual(ch.messages.first?.text, "before")
        XCTAssertEqual(ch.messages.first?.isEdited, false)
    }

    // MARK: - Failures are said out loud

    /// A send with nothing to send it over used to vanish without a word.
    func testSendWithoutAConnectionTellsTheUser() {
        let s = makeState()
        s.errorMessage = nil
        s.sendMessage(to: "#freeq", text: "hi")
        XCTAssertNotNil(s.errorMessage)
    }
}
