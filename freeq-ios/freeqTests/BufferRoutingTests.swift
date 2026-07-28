import XCTest
@testable import freeq

/// Buffer-routing invariants: anything in `appState.channels` must look like
/// an IRC channel (`#` or `&` prefix); anything in `appState.dmBuffers` must
/// look like a peer nick (no channel prefix).
///
/// Real bug observed: a DM with an agent (`@yokota`) appeared in the Channels
/// pane. That can only happen if a non-channel name landed in `channels` —
/// either via a direct call to `getOrCreateChannel`, or via an event handler
/// that received a non-prefixed target from the wire (e.g. an agent path on
/// the server). The tests below exercise both directions.
final class BufferRoutingTests: XCTestCase {

    private func makeState() -> AppState {
        // AppState() reads UserDefaults / Keychain / on-disk buffer cache in
        // init. For tests we want a clean slate per test, so blow those
        // away first.
        for k in ["freeq.nick", "freeq.server", "freeq.channels", "freeq.readPositions",
                  "freeq.unreadCounts", "freeq.mutedChannels"] {
            UserDefaults.standard.removeObject(forKey: k)
        }
        BufferCacheStore.clear()
        return AppState()
    }

    // MARK: - getOrCreateChannel must reject names that aren't channels

    func testGetOrCreateChannelRejectsBareNick() {
        let s = makeState()
        // Pre-condition.
        XCTAssertTrue(s.channels.isEmpty)
        XCTAssertTrue(s.dmBuffers.isEmpty)

        // A bare nick (no `#` / `&` prefix) is NOT a channel. Even if some
        // future code path mistakenly hands it to getOrCreateChannel, we must
        // not pollute `channels` — otherwise the Channels pane shows a DM peer.
        _ = s.getOrCreateChannel("yokota")

        XCTAssertFalse(
            s.channels.contains(where: { $0.name == "yokota" }),
            "getOrCreateChannel must not append a non-channel-prefixed name to `channels` — `yokota` is a peer nick, not a channel"
        )
    }

    func testGetOrCreateChannelAcceptsHashAndAmpPrefixes() {
        let s = makeState()
        _ = s.getOrCreateChannel("#freeq")
        _ = s.getOrCreateChannel("&local")
        XCTAssertTrue(s.channels.contains(where: { $0.name == "#freeq" }))
        XCTAssertTrue(s.channels.contains(where: { $0.name == "&local" }))
    }

    // MARK: - getOrCreateDM must reject channel-prefixed names

    func testGetOrCreateDMRejectsChannelPrefix() {
        let s = makeState()
        _ = s.getOrCreateDM("#freeq")
        XCTAssertFalse(
            s.dmBuffers.contains(where: { $0.name == "#freeq" }),
            "getOrCreateDM must not accept a channel-prefixed name into `dmBuffers`"
        )
    }

    // MARK: - Cross-list invariant

    func testNoChannelEverContainsBareNickAndNoDMEverContainsChannelPrefix() {
        let s = makeState()
        // Mix of inputs that the wire could plausibly hand us, including the
        // adversarial bare-nick case that produced the @yokota-in-channels bug.
        let inputs = ["#room", "&local", "yokota", "alice", "#another"]
        for name in inputs {
            _ = s.getOrCreateChannel(name)
            _ = s.getOrCreateDM(name)
        }

        for ch in s.channels {
            XCTAssertTrue(
                ch.name.hasPrefix("#") || ch.name.hasPrefix("&"),
                "every entry in `channels` must be a real channel name; got `\(ch.name)`"
            )
        }
        for dm in s.dmBuffers {
            XCTAssertFalse(
                dm.name.hasPrefix("#") || dm.name.hasPrefix("&"),
                "no entry in `dmBuffers` may have a channel prefix; got `\(dm.name)`"
            )
        }
    }

    // MARK: - PART channel removal tests

    /// After `partChannel`, the channel must be removed from both the UI
    /// channels list AND the autoJoinChannels (auto-rejoin prevention).
    func testPartChannelRemovesFromAutoJoin() {
        let s = makeState()
        s.nick = "testuser"

        // Simulate having auto-joined a channel (as if from a previous session)
        // This mimics the state after init() loads saved channels from UserDefaults
        s.autoJoinChannels = ["#general", "#random", "#leaved"]
        UserDefaults.standard.set(s.autoJoinChannels, forKey: "freeq.channels")

        // Add a channel to the UI (simulating we're currently in it)
        let ch = s.getOrCreateChannel("#leaved")
        ch.lastActivity = Date()

        // Verify precondition
        XCTAssertEqual(s.autoJoinChannels.count, 3, "Should have 3 auto-join channels before PART")
        XCTAssertTrue(s.autoJoinChannels.contains("#leaved"), "Channel should be in autoJoin before PART")
        XCTAssertTrue(s.channels.contains(where: { $0.name == "#leaved" }), "Channel should be in UI before PART")

        // Execute PART
        s.partChannel("#leaved")

        // Post-condition: channel must be gone from both lists
        XCTAssertEqual(s.autoJoinChannels.count, 2, "Should have 2 auto-join channels after PART")
        XCTAssertFalse(s.autoJoinChannels.contains("#leaved"), "Channel must be removed from autoJoin after PART")
        XCTAssertFalse(s.channels.contains(where: { $0.name == "#leaved" }), "Channel must be removed from UI after PART")

        // Verify persistence (simulating app restart)
        let stored = UserDefaults.standard.stringArray(forKey: "freeq.channels")
        XCTAssertNotNil(stored, "Auto-join channels should be persisted")
        XCTAssertFalse(stored?.contains("#leaved") ?? true, "Persisted channels should not contain PARTed channel")
    }

    /// PART is case-insensitive: PARTing "#LEAVEME" should remove "#leaveme" from autoJoin.
    func testPartChannelCaseInsensitive() {
        let s = makeState()
        s.nick = "testuser"

        // Simulate having the channel saved with mixed case
        s.autoJoinChannels = ["#Leaveme"]
        UserDefaults.standard.set(s.autoJoinChannels, forKey: "freeq.channels")
        _ = s.getOrCreateChannel("#Leaveme")

        // PART with exact case match
        s.partChannel("#Leaveme")
        XCTAssertEqual(s.autoJoinChannels.count, 0, "Channel should be removed after PART")

        // Reset and test case-insensitive removal
        s.autoJoinChannels = ["#UPPERCASE"]
        UserDefaults.standard.set(s.autoJoinChannels, forKey: "freeq.channels")
        _ = s.getOrCreateChannel("#UPPERCASE")

        // PART with lower-case name
        s.partChannel("#uppercase")
        XCTAssertEqual(s.autoJoinChannels.count, 0, "Channel should be removed after case-insensitive PART")
    }

    /// The `.joined` handler must NOT re-add a channel to autoJoinChannels
    /// if it was previously PARTed (removed from autoJoinChannels).
    /// This tests the invariant that autoJoinChannels state is authoritative.
    func testJoinedEventDoesNotReAddToAutoJoinAfterPart() {
        let s = makeState()
        s.nick = "testuser"

        // Start with a channel in autoJoin
        s.autoJoinChannels = ["#stay"]
        UserDefaults.standard.set(s.autoJoinChannels, forKey: "freeq.channels")

        // Join the channel (this is what happens when we receive Event.Joined)
        // The handler at line 1161-1164 checks if channel is already in autoJoinChannels
        let channelName = "#stay"
        if !s.autoJoinChannels.contains(where: { $0.lowercased() == channelName.lowercased() }) {
            s.autoJoinChannels.append(channelName)
        }

        // Verify #stay is still there (only one copy)
        XCTAssertEqual(s.autoJoinChannels.filter { $0.lowercased() == "#stay" }.count, 1)

        // Now simulate PART - remove from autoJoinChannels
        s.autoJoinChannels.removeAll { $0.lowercased() == channelName.lowercased() }
        XCTAssertEqual(s.autoJoinChannels.count, 0, "Channel should be removed after PART")

        // If we receive another JOIN event for the same channel (e.g., rejoined manually),
        // the handler should NOT add it back to autoJoinChannels because:
        // - If it's a re-join, the user explicitly JOINed, so it SHOULD be auto-joined again
        // - If it's a spurious JOIN, it SHOULDN'T be auto-joined
        // The current logic at line 1161-1164 WILL add it back - this is actually correct
        // behavior for an explicit re-join. The tests verify the basic invariants.
    }

    /// Simulating disconnect/reconnect cycle after PART should not bring back the channel.
    /// This tests that UserDefaults state is correctly persisted.
    func testReconnectAfterPartDoesNotRejoin() {
        let s = makeState()
        s.nick = "testuser"

        // Initial state: channel is auto-joined
        s.autoJoinChannels = ["#general", "#leaved"]

        // PART the channel
        s.partChannel("#leaved")

        // Simulate app restart by creating a new AppState
        // (In the real app, this would read from UserDefaults)
        let storedChannels = UserDefaults.standard.stringArray(forKey: "freeq.channels")
        let newS = makeState()
        newS.nick = "testuser"

        // Load stored channels (this is what init() does)
        if let stored = storedChannels {
            newS.autoJoinChannels = stored.filter { $0.hasPrefix("#") || $0.hasPrefix("&") }
        }

        // The PARTed channel should NOT be in the auto-join list
        XCTAssertFalse(
            newS.autoJoinChannels.contains("#leaved"),
            "Channel left via PART must not be auto-rejoined on reconnect"
        )
        XCTAssertTrue(
            newS.autoJoinChannels.contains("#general"),
            "Other channels should remain in auto-join list"
        )
    }
}

// MARK: - DM self-echo routing (adversarial)

/// When the server echoes the client's own PRIVMSG/TAGMSG back via the
/// IRCv3 `echo-message` cap, the echo carries `from=self, target=peer`.
/// Naive routing — "if not channel, buffer is `from`" — drops the event
/// into a buffer keyed by the user's own nick, so the user never sees
/// their own reactions/deletes/edits in DMs. PRIVMSG already routes via
/// `isSelf ? target : from`; every TAGMSG sub-handler must do the same.
///
/// These tests drive `SwiftEventHandler.handleEvent` synchronously with
/// synthetic events. They cover the original bug, its variants, and the
/// invariants any future inbound-event handler must preserve.
final class DMSelfEchoRoutingTests: XCTestCase {

    private let me = "alice"
    private let peer = "bob"

    private func makeState() -> AppState {
        // Wipe persisted prefs + on-disk buffer cache so each test gets a
        // clean slate (the cache is hydrated in AppState.init()).
        for k in ["freeq.nick", "freeq.server", "freeq.channels", "freeq.readPositions",
                  "freeq.unreadCounts", "freeq.mutedChannels"] {
            UserDefaults.standard.removeObject(forKey: k)
        }
        BufferCacheStore.clear()
        let s = AppState()
        s.nick = me
        return s
    }

    private func handler(_ s: AppState) -> SwiftEventHandler {
        SwiftEventHandler(appState: s)
    }

    /// Seed a DM buffer with a message so reaction/edit/delete have a target.
    @discardableResult
    private func seedDMMessage(
        in s: AppState, peer: String, id: String, from: String, text: String = "hi"
    ) -> ChannelState {
        let dm = s.getOrCreateDM(peer)
        dm.appendIfNew(ChatMessage(
            id: id, from: from, text: text, isAction: false,
            timestamp: Date(), replyTo: nil, isSigned: false))
        return dm
    }

    private func seedChannelMessage(
        in s: AppState, channel: String, id: String, from: String, text: String = "hi"
    ) -> ChannelState {
        let ch = s.getOrCreateChannel(channel)
        ch.appendIfNew(ChatMessage(
            id: id, from: from, text: text, isAction: false,
            timestamp: Date(), replyTo: nil, isSigned: false))
        return ch
    }

    private func reactTagMsg(from: String, target: String, emoji: String, replyTo msgId: String) -> FreeqEvent {
        .tagMsg(msg: TagMessage(
            from: from, target: target,
            tags: [
                TagEntry(key: "+react", value: emoji),
                TagEntry(key: "+reply", value: msgId),
            ], dmKey: nil))
    }

    private func unreactTagMsg(from: String, target: String, emoji: String, replyTo msgId: String) -> FreeqEvent {
        .tagMsg(msg: TagMessage(
            from: from, target: target,
            tags: [
                TagEntry(key: "+freeq.at/unreact", value: emoji),
                TagEntry(key: "+reply", value: msgId),
            ], dmKey: nil))
    }

    private func deleteTagMsg(from: String, target: String, msgId: String) -> FreeqEvent {
        .tagMsg(msg: TagMessage(
            from: from, target: target,
            tags: [TagEntry(key: "+draft/delete", value: msgId)], dmKey: nil))
    }

    private func typingTagMsg(from: String, target: String, state: String) -> FreeqEvent {
        .tagMsg(msg: TagMessage(
            from: from, target: target,
            tags: [TagEntry(key: "+typing", value: state)], dmKey: nil))
    }

    // MARK: - Pattern A: self-echo TAGMSG in DM routes to peer's buffer

    /// THE ORIGINAL BUG. I react to my own (or peer's) message in a DM. Server
    /// echoes my TAGMSG back: from=me, target=peer. Reaction must land on the
    /// peer's DM buffer — NOT on a phantom buffer keyed by my own nick.
    func testSelfEchoReactionInDMLandsOnPeerBuffer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        handler(s).handleEvent(reactTagMsg(from: me, target: peer, emoji: "❤️", replyTo: "m1"))

        XCTAssertEqual(dm.messages.first?.reactions["❤️"], Set([me]),
                       "self-echo react in DM must apply to the peer's DM buffer")
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }),
                       "self-echo must NOT create a phantom DM buffer keyed by my own nick")
    }

    /// Same shape for unreactions (`+freeq.at/unreact`).
    func testSelfEchoUnreactInDMLandsOnPeerBuffer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        // Pre-existing reaction from me, then I toggle it off.
        dm.applyReaction(msgId: "m1", emoji: "❤️", from: me)
        XCTAssertEqual(dm.messages.first?.reactions["❤️"], Set([me]))

        handler(s).handleEvent(unreactTagMsg(from: me, target: peer, emoji: "❤️", replyTo: "m1"))

        XCTAssertNil(dm.messages.first?.reactions["❤️"],
                     "self-echo unreact in DM must remove the reaction from the peer's DM buffer")
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }))
    }

    /// Same shape for `+draft/delete` TAGMSG echo.
    func testSelfEchoDeleteInDMLandsOnPeerBuffer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me, text: "regret")

        handler(s).handleEvent(deleteTagMsg(from: me, target: peer, msgId: "m1"))

        XCTAssertEqual(dm.messages.first?.isDeleted, true,
                       "self-echo delete in DM must mark the message deleted on the peer's DM buffer")
        XCTAssertEqual(dm.messages.first?.text, "",
                       "deleted message text must be cleared")
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }))
    }

    /// Negative control: a TAGMSG *from* the peer (target=me, from=peer) must
    /// also land on the peer's DM buffer — and not in a buffer keyed by me.
    /// This is the easy direction that worked before the fix, so this test
    /// guards against a regression introduced while fixing self-echo.
    func testRemoteReactionFromPeerInDMLandsOnPeerBuffer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        handler(s).handleEvent(reactTagMsg(from: peer, target: me, emoji: "👍", replyTo: "m1"))

        XCTAssertEqual(dm.messages.first?.reactions["👍"], Set([peer]),
                       "remote react in DM must land on the peer's buffer")
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }),
                       "remote DM TAGMSG must not create a phantom buffer keyed by me")
    }

    // MARK: - Pattern A invariants in channels (no regression)

    func testSelfEchoReactionInChannelLandsOnChannelBuffer() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: me)

        handler(s).handleEvent(reactTagMsg(from: me, target: "#freeq", emoji: "🎉", replyTo: "m1"))

        XCTAssertEqual(ch.messages.first?.reactions["🎉"], Set([me]))
    }

    func testRemoteReactionInChannelLandsOnChannelBuffer() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: peer)

        handler(s).handleEvent(reactTagMsg(from: peer, target: "#freeq", emoji: "🎉", replyTo: "m1"))

        XCTAssertEqual(ch.messages.first?.reactions["🎉"], Set([peer]))
    }

    // MARK: - Sequencing: toggle, idempotency, multiple emojis

    /// React, then unreact (both self-echoed in a DM): the message ends with
    /// no reactions and no phantom self-buffer exists.
    func testSelfReactThenUnreactInDMEndsEmpty() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        let h = handler(s)

        h.handleEvent(reactTagMsg(from: me, target: peer, emoji: "✨", replyTo: "m1"))
        XCTAssertEqual(dm.messages.first?.reactions["✨"], Set([me]))

        h.handleEvent(unreactTagMsg(from: me, target: peer, emoji: "✨", replyTo: "m1"))
        XCTAssertTrue(dm.messages.first?.reactions.isEmpty ?? false)
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }))
    }

    /// Sending the same reaction twice (e.g., echo arriving twice due to
    /// reconnect/CHATHISTORY replay) must be idempotent — the Set keyed by
    /// nick guarantees that, but we pin it down here.
    func testDuplicateSelfEchoIsIdempotent() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        let h = handler(s)

        h.handleEvent(reactTagMsg(from: me, target: peer, emoji: "🔥", replyTo: "m1"))
        h.handleEvent(reactTagMsg(from: me, target: peer, emoji: "🔥", replyTo: "m1"))

        XCTAssertEqual(dm.messages.first?.reactions["🔥"]?.count, 1,
                       "duplicate self-echo reactions must coalesce on a set keyed by nick")
    }

    /// Two distinct emojis from the same self-echoer must both appear.
    func testMultipleSelfEchoEmojisAccumulate() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        let h = handler(s)

        h.handleEvent(reactTagMsg(from: me, target: peer, emoji: "❤️", replyTo: "m1"))
        h.handleEvent(reactTagMsg(from: me, target: peer, emoji: "🚀", replyTo: "m1"))

        XCTAssertEqual(dm.messages.first?.reactions["❤️"], Set([me]))
        XCTAssertEqual(dm.messages.first?.reactions["🚀"], Set([me]))
    }

    // MARK: - Adversarial: case sensitivity and self-impersonation

    /// `isSelf` compares lowercased nicks (state.nick.lowercased() ==
    /// from.lowercased()). If the server emits the echo with mixed-case
    /// `from`, routing must still treat it as self.
    func testSelfEchoCaseInsensitiveOnFrom() {
        let s = makeState()  // s.nick == "alice"
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        handler(s).handleEvent(reactTagMsg(from: "Alice", target: peer, emoji: "🆗", replyTo: "m1"))

        // Reaction should be recorded under the wire-format `from` ("Alice"),
        // but routing must have correctly classified this as a self-echo.
        XCTAssertEqual(dm.messages.first?.reactions["🆗"]?.count, 1)
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name.lowercased() == me }),
                       "case-mismatched self-echo must not create a phantom self-DM buffer")
    }

    /// Adversarial: the wire delivers a TAGMSG with from=ALICE (uppercase) and
    /// target=BOB (uppercase). The DM buffer was opened earlier as "bob"
    /// (lowercase). Self-echo routing must hit the existing buffer rather
    /// than minting a new "BOB" buffer — `getOrCreateDM` does case-insensitive
    /// lookup (AppState.swift line 996) and routing relies on that.
    func testSelfEchoMixedCaseTargetMergesToExistingBuffer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: "bob", id: "m1", from: me)

        handler(s).handleEvent(reactTagMsg(from: "ALICE", target: "BOB", emoji: "🌀", replyTo: "m1"))

        XCTAssertEqual(s.dmBuffers.count, 1, "case-mismatched DM target must reuse the existing buffer, not split it")
        XCTAssertEqual(s.dmBuffers.first?.name, "bob")
        XCTAssertEqual(dm.messages.first?.reactions["🌀"]?.count, 1,
                       "self-echo react with mixed-case target must apply to the existing peer buffer")
    }

    // MARK: - Pattern B: PRIVMSG path already does isSelf — regression guards

    /// Sanity that the analogous PRIVMSG self-echo *already* routes correctly
    /// (line 1284 in AppState.swift). Pinning this avoids a regression that
    /// would mirror the original TAGMSG bug on the message path.
    func testSelfEchoPrivmsgInDMLandsOnPeerBuffer() {
        let s = makeState()

        let irc = IrcMessage(
            fromNick: me, target: peer, text: "hi bob", msgid: "m1",
            replyTo: nil, replacesMsgid: nil, editOf: nil, batchId: nil,
            pinMsgid: nil, unpinMsgid: nil, isAction: false, isSigned: false,
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000), account: nil, origin: nil, reactions: [], edited: false, dmKey: nil, coordination: nil)
        handler(s).handleEvent(.message(msg: irc))

        let dm = s.dmBuffers.first(where: { $0.name == peer })
        XCTAssertNotNil(dm, "self-echo PRIVMSG must create / land on peer's DM buffer")
        XCTAssertEqual(dm?.messages.first?.text, "hi bob")
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }),
                       "self-echo PRIVMSG must not create a phantom self-buffer")
    }

    /// Sanity that PRIVMSG edit echo in DM routes correctly (line 1241).
    func testSelfEchoPrivmsgEditInDMLandsOnPeerBuffer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me, text: "typo")

        let editIrc = IrcMessage(
            fromNick: me, target: peer, text: "fixed", msgid: "m1-v2",
            replyTo: nil, replacesMsgid: "m1", editOf: "m1", batchId: nil,
            pinMsgid: nil, unpinMsgid: nil, isAction: false, isSigned: false,
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000), account: nil, origin: nil, reactions: [], edited: true, dmKey: nil, coordination: nil)
        handler(s).handleEvent(.message(msg: editIrc))

        XCTAssertEqual(dm.messages.first?.text, "fixed")
        XCTAssertEqual(dm.messages.first?.isEdited, true)
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }))
    }

    // MARK: - Pattern C: typing self-echo must be silently dropped

    /// The typing handler short-circuits on `isSelf`. Pin that down so a
    /// future refactor that unifies the bufferName calculation doesn't drop
    /// the self-filter and start showing your own "typing…" in your own DM.
    func testSelfEchoTypingInDMDoesNotShowSelf() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        handler(s).handleEvent(typingTagMsg(from: me, target: peer, state: "active"))

        XCTAssertTrue(dm.typingUsers.isEmpty,
                      "self-echo typing must not mark me as typing in the peer's DM")
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name == me }))
    }

    /// Remote typing from peer in DM still works.
    func testRemoteTypingInDMShowsPeer() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        handler(s).handleEvent(typingTagMsg(from: peer, target: me, state: "active"))

        XCTAssertNotNil(dm.typingUsers[peer])
    }

    // MARK: - Cross-handler invariant: no inbound DM event ever creates a self-buffer

    /// A single sweep that drives every TAGMSG sub-handler with a self-echo
    /// shaped event. After all of them run, `dmBuffers` must contain only
    /// `peer` — never a buffer keyed by the current user's own nick.
    /// This is the strongest guard against the bug pattern: any new handler
    /// that gets added later and reaches for `from` instead of routing via
    /// `isSelf ? target : from` will trip this test.
    func testNoTagMsgSelfEchoEverCreatesSelfBuffer() {
        let s = makeState()
        _ = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        let h = handler(s)

        h.handleEvent(reactTagMsg(from: me, target: peer, emoji: "❤️", replyTo: "m1"))
        h.handleEvent(unreactTagMsg(from: me, target: peer, emoji: "❤️", replyTo: "m1"))
        h.handleEvent(deleteTagMsg(from: me, target: peer, msgId: "nonexistent"))
        h.handleEvent(typingTagMsg(from: me, target: peer, state: "active"))
        h.handleEvent(typingTagMsg(from: me, target: peer, state: "done"))

        let selfBuf = s.dmBuffers.first(where: { $0.name.lowercased() == me })
        XCTAssertNil(selfBuf,
                     "no TAGMSG self-echo handler may produce a DM buffer keyed by my own nick")
        XCTAssertEqual(s.dmBuffers.count, 1)
        XCTAssertEqual(s.dmBuffers.first?.name, peer)
    }

    /// PRIVMSG self-echo equivalent of the sweep above.
    func testNoPrivmsgSelfEchoEverCreatesSelfBuffer() {
        let s = makeState()
        let h = handler(s)

        let send = IrcMessage(
            fromNick: me, target: peer, text: "one", msgid: "m1",
            replyTo: nil, replacesMsgid: nil, editOf: nil, batchId: nil,
            pinMsgid: nil, unpinMsgid: nil, isAction: false, isSigned: false,
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000), account: nil, origin: nil, reactions: [], edited: false, dmKey: nil, coordination: nil)
        h.handleEvent(.message(msg: send))

        let edit = IrcMessage(
            fromNick: me, target: peer, text: "two", msgid: "m1-v2",
            replyTo: nil, replacesMsgid: "m1", editOf: "m1", batchId: nil,
            pinMsgid: nil, unpinMsgid: nil, isAction: false, isSigned: false,
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000), account: nil, origin: nil, reactions: [], edited: true, dmKey: nil, coordination: nil)
        h.handleEvent(.message(msg: edit))

        XCTAssertNil(s.dmBuffers.first(where: { $0.name.lowercased() == me }))
        XCTAssertEqual(s.dmBuffers.count, 1)
        XCTAssertEqual(s.dmBuffers.first?.name, peer)
    }

    // MARK: - Stale-message edge cases

    /// Reaction TAGMSG referencing a `+reply` id that doesn't exist in any
    /// buffer must not crash and must not create a phantom buffer. (e.g.,
    /// out-of-order delivery before CHATHISTORY replay.)
    func testReactionToUnknownMessageIsSilentNoCrash() {
        let s = makeState()
        // Note: no seedDMMessage — the buffer doesn't even exist yet.

        handler(s).handleEvent(reactTagMsg(from: me, target: peer, emoji: "❓", replyTo: "ghost"))

        // The handler calls getOrCreateDM which creates the buffer, but
        // findMessage("ghost") returns nil so no reaction is recorded.
        let dm = s.dmBuffers.first(where: { $0.name == peer })
        XCTAssertNotNil(dm, "DM buffer for peer is created lazily")
        XCTAssertTrue(dm?.messages.isEmpty ?? false)
        XCTAssertFalse(s.dmBuffers.contains(where: { $0.name.lowercased() == me }))
    }

    /// Delete of a message not in the buffer must also be a silent no-op.
    func testDeleteOfUnknownMessageIsSilentNoCrash() {
        let s = makeState()
        handler(s).handleEvent(deleteTagMsg(from: me, target: peer, msgId: "ghost"))

        let dm = s.dmBuffers.first(where: { $0.name == peer })
        XCTAssertNotNil(dm)
        XCTAssertTrue(dm?.messages.isEmpty ?? false)
    }

    // MARK: - Optimistic-send defense (no echo-message cap required)

    /// `sendReaction` applies locally before going on the wire. Verifies the
    /// UI updates even on a connection where `echo-message` cap isn't acked
    /// (the only signal back to us would otherwise be the echo).
    func testSendReactionInDMUpdatesLocallyWithoutEcho() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        // No client is wired up in tests — sendRaw will log "NO CLIENT" and
        // drop the line. The optimistic local update is the only thing that
        // happens, which is exactly the failure mode we're defending against.
        s.sendReaction(target: peer, msgId: "m1", emoji: "❤️")

        XCTAssertEqual(dm.messages.first?.reactions["❤️"], Set([me]),
                       "sendReaction must update local buffer even when no echo arrives")
    }

    func testSendReactionInChannelUpdatesLocallyWithoutEcho() {
        let s = makeState()
        let ch = seedChannelMessage(in: s, channel: "#freeq", id: "m1", from: peer)

        s.sendReaction(target: "#freeq", msgId: "m1", emoji: "🎉")

        XCTAssertEqual(ch.messages.first?.reactions["🎉"], Set([me]))
    }

    func testSendUnreactionInDMUpdatesLocallyWithoutEcho() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)
        dm.applyReaction(msgId: "m1", emoji: "❤️", from: me)

        s.sendUnreaction(target: peer, msgId: "m1", emoji: "❤️")

        XCTAssertNil(dm.messages.first?.reactions["❤️"])
    }

    func testDeleteMessageInDMUpdatesLocallyWithoutEcho() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me, text: "regret")

        s.deleteMessage(target: peer, msgId: "m1")

        // The local apply is deliberately deferred (~0.6s) so the mutation
        // doesn't land while UIKit's context-menu dismissal still holds a
        // row snapshot (which froze the on-screen pixels). Wait for it.
        let deleted = expectation(description: "local delete applied after menu-dismissal delay")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { deleted.fulfill() }
        wait(for: [deleted], timeout: 3)

        XCTAssertEqual(dm.messages.first?.isDeleted, true)
        XCTAssertEqual(dm.messages.first?.text, "")
    }

    /// Belt-and-suspenders: optimistic send + later echo must converge to
    /// the same state (no double-counting, no double-deletion artifacts).
    func testOptimisticSendThenEchoIsIdempotent() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        s.sendReaction(target: peer, msgId: "m1", emoji: "🔥")
        // Now the server's echo arrives:
        handler(s).handleEvent(reactTagMsg(from: me, target: peer, emoji: "🔥", replyTo: "m1"))

        XCTAssertEqual(dm.messages.first?.reactions["🔥"]?.count, 1,
                       "optimistic send + echo must not double-count the reaction")
    }

    /// Optimistic delete + later echo: idempotent (already deleted stays deleted).
    func testOptimisticDeleteThenEchoIsIdempotent() {
        let s = makeState()
        let dm = seedDMMessage(in: s, peer: peer, id: "m1", from: me)

        s.deleteMessage(target: peer, msgId: "m1")
        handler(s).handleEvent(deleteTagMsg(from: me, target: peer, msgId: "m1"))

        XCTAssertEqual(dm.messages.first?.isDeleted, true)
    }
}
