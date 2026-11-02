import XCTest
import LocalAuthentication
import Security

@testable import FreeqMacosCore

final class ValidationTests: XCTestCase {

    // MARK: - Chat message display state

    func testChatMessageEqualityIncludesMutableDisplayFields() {
        var lhs = ChatMessage(
            id: "m1",
            from: "alice",
            text: "hello",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            replyTo: nil
        )
        var rhs = lhs
        XCTAssertEqual(lhs, rhs)

        rhs.reactions["👍"] = ["bob"]
        XCTAssertNotEqual(lhs, rhs)

        lhs.reactions["👍"] = ["bob"]
        XCTAssertEqual(lhs, rhs)

        rhs.isDeleted = true
        XCTAssertNotEqual(lhs, rhs)
    }

    func testChannelReactionOperationsAreIdempotentAndRemovable() {
        let channel = ChannelState(name: "#react")
        channel.appendIfNew(ChatMessage(
            id: "m1",
            from: "alice",
            text: "react to me",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            replyTo: nil
        ))

        channel.addReaction(msgId: "m1", emoji: "👍", from: "bob")
        channel.addReaction(msgId: "m1", emoji: "👍", from: "bob")
        XCTAssertTrue(channel.hasReaction(msgId: "m1", emoji: "👍", from: "bob"))
        XCTAssertEqual(channel.messages.first?.reactions["👍"]?.count, 1)

        channel.removeReaction(msgId: "m1", emoji: "👍", from: "bob")
        XCTAssertFalse(channel.hasReaction(msgId: "m1", emoji: "👍", from: "bob"))
        XCTAssertNil(channel.messages.first?.reactions["👍"])
    }

    func testChannelReactionRejectsEmptyEmoji() {
        let channel = ChannelState(name: "#react")
        channel.appendIfNew(ChatMessage(
            id: "m1",
            from: "alice",
            text: "react to me",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            replyTo: nil
        ))

        channel.addReaction(msgId: "m1", emoji: "   ", from: "bob")
        XCTAssertTrue(channel.messages.first?.reactions.isEmpty ?? false)
    }

    func testChannelVisibleMessagesIgnoreDeletedMessages() {
        let channel = ChannelState(name: "#visible")
        XCTAssertFalse(channel.hasVisibleMessages)

        channel.appendIfNew(ChatMessage(
            id: "m1",
            from: "alice",
            text: "this should render",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            replyTo: nil
        ))
        XCTAssertTrue(channel.hasVisibleMessages)

        channel.applyDelete(msgId: "m1")
        XCTAssertFalse(channel.hasVisibleMessages)
    }

    func testMessageVisibilityShowsWelcomeOnlyWhenNoRenderableMessagesExist() {
        let visible = ChatMessage(
            id: "m1",
            from: "alice",
            text: "this should render",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            replyTo: nil
        )
        var deleted = visible
        deleted.id = "m2"
        deleted.isDeleted = true

        XCTAssertTrue(MessageVisibility.shouldShowWelcome(messages: []))
        XCTAssertTrue(MessageVisibility.shouldShowWelcome(messages: [deleted]))
        XCTAssertFalse(MessageVisibility.shouldShowWelcome(messages: [deleted, visible]))
    }

    func testMessageVisibilityReturnsOnlyRenderableMessagesInOrder() {
        let first = ChatMessage(
            id: "m1",
            from: "alice",
            text: "first",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            replyTo: nil
        )
        var deleted = ChatMessage(
            id: "m2",
            from: "bob",
            text: "deleted",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_001),
            replyTo: nil
        )
        let last = ChatMessage(
            id: "m3",
            from: "carol",
            text: "last",
            isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_002),
            replyTo: nil
        )
        deleted.isDeleted = true

        XCTAssertEqual(
            MessageVisibility.visibleMessages(from: [first, deleted, last]).map(\.id),
            ["m1", "m3"]
        )
    }

    func testHistoryBatchRoutingBuffersTargetedHistoryBatches() {
        XCTAssertTrue(HistoryBatchRouting.shouldBuffer(batchType: "chathistory", target: "#freeq"))
        XCTAssertTrue(HistoryBatchRouting.shouldBuffer(batchType: "freeq.at/search", target: "#freeq"))
    }

    func testHistoryBatchRoutingIgnoresTargetlessDelimiterBatches() {
        XCTAssertFalse(HistoryBatchRouting.shouldBuffer(batchType: "draft/chathistory-targets", target: ""))
        XCTAssertFalse(HistoryBatchRouting.shouldApplyBatch(target: "", messageCount: 0))
    }

    func testHistoryBatchRoutingBuffersTargetlessMessageBatches() {
        XCTAssertTrue(HistoryBatchRouting.shouldBuffer(batchType: "chathistory", target: ""))
        XCTAssertTrue(HistoryBatchRouting.shouldBuffer(batchType: "draft/chathistory", target: "  "))
        XCTAssertTrue(HistoryBatchRouting.shouldBuffer(batchType: "freeq.at/search", target: ""))
    }

    func testHistoryBatchRoutingCanLearnMissingTargetFromFirstMessage() {
        XCTAssertEqual(
            HistoryBatchRouting.resolvedTarget(batchTarget: "", messageTarget: "#alexandria"),
            "#alexandria"
        )
        XCTAssertEqual(
            HistoryBatchRouting.resolvedTarget(batchTarget: "#freeq", messageTarget: "#alexandria"),
            "#freeq"
        )
    }

    func testHistoryBatchRoutingDoesNotApplyEmptyMessageBatches() {
        XCTAssertFalse(HistoryBatchRouting.shouldApplyBatch(target: "#freeq", messageCount: 0))
        XCTAssertTrue(HistoryBatchRouting.shouldApplyBatch(target: "#freeq", messageCount: 1))
    }

    func testHistoryBatchApplicationHydratesExistingChannelWithVisibleMessages() {
        var channels = [ChannelState(name: "#alexandria")]
        var dmBuffers: [ChannelState] = []
        var batch = HistoryBatchBuffer(target: "#alexandria")

        batch.append(
            ChatMessage(
                id: "newer",
                from: "bob",
                text: "newer history",
                isAction: false,
                timestamp: Date(timeIntervalSince1970: 1_700_000_010),
                replyTo: nil
            ),
            messageTarget: "#alexandria"
        )
        batch.append(
            ChatMessage(
                id: "older",
                from: "alice",
                text: "older history",
                isAction: false,
                timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                replyTo: nil
            ),
            messageTarget: "#alexandria"
        )

        XCTAssertTrue(HistoryBatchRouting.apply(buffer: batch, channels: &channels, dmBuffers: &dmBuffers))
        XCTAssertEqual(channels.count, 1)
        XCTAssertEqual(channels[0].messages.map(\.id), ["older", "newer"])
        XCTAssertFalse(MessageVisibility.shouldShowWelcome(messages: channels[0].messages))
    }

    func testHistoryBatchApplicationLearnsTargetAndCreatesChannel() {
        var channels: [ChannelState] = []
        var dmBuffers: [ChannelState] = []
        var batch = HistoryBatchBuffer(target: "")

        batch.append(
            ChatMessage(
                id: "m1",
                from: "alice",
                text: "visible history",
                isAction: false,
                timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                replyTo: nil
            ),
            messageTarget: "#alexandria"
        )

        XCTAssertTrue(HistoryBatchRouting.apply(buffer: batch, channels: &channels, dmBuffers: &dmBuffers))
        XCTAssertEqual(channels.map(\.name), ["#alexandria"])
        XCTAssertEqual(channels.first?.messages.first?.text, "visible history")
        XCTAssertTrue(dmBuffers.isEmpty)
    }

    func testProtectedChannelJoinRejectionRoutesToChannelAccessDenied() {
        XCTAssertEqual(
            ServerNoticeRouter.route("#freeq This channel requires authentication — sign in to join"),
            .channelAccessDenied(
                channel: "#freeq",
                reason: "This channel requires authentication — sign in to join"
            )
        )
    }

    func testProtectedChannelJoinRejectionMessageIsVisible() {
        let message = ServerNoticeRouter.channelAccessMessage(
            channel: "#freeq",
            reason: "This channel requires authentication — sign in to join",
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        XCTAssertEqual(message.id, "channel-access-denied-#freeq-This channel requires authentication — sign in to join")
        XCTAssertEqual(message.from, "server")
        XCTAssertEqual(message.text, "This channel requires authentication — sign in to join")
        XCTAssertFalse(MessageVisibility.shouldShowWelcome(messages: [message]))
    }

    func testSavedDidIsNotTreatedAsServerConfirmedAuthentication() {
        XCTAssertNil(AuthSessionState.confirmedDidFromSavedCredentials("did:plc:stale"))
    }

    func testBackgroundWhoisRepliesDoNotDisplayAsChannelMessages() {
        XCTAssertFalse(WhoisDisplayPolicy.shouldDisplay(explicitlyRequested: false))
        XCTAssertTrue(WhoisDisplayPolicy.shouldDisplay(explicitlyRequested: true))
    }

    func testFreeqWhoisDiagnosticsAreNotNormalChannelNotices() {
        XCTAssertEqual(
            ServerNoticeRouter.route("chadfowler.com AT Protocol handle: chadfowler.com"),
            .whoisDiagnostic(
                nick: "chadfowler.com",
                text: "chadfowler.com AT Protocol handle: chadfowler.com"
            )
        )
        XCTAssertEqual(
            ServerNoticeRouter.route("nandi.uk client: freeq"),
            .whoisDiagnostic(nick: "nandi.uk", text: "nandi.uk client: freeq")
        )
        XCTAssertEqual(
            ServerNoticeRouter.route("yokotabot actor_class=agent"),
            .whoisDiagnostic(nick: "yokotabot", text: "yokotabot actor_class=agent")
        )
    }

    func testFreeqWhoisDiagnosticsDoNotHideChannelAccessDenials() {
        XCTAssertEqual(
            ServerNoticeRouter.route("#freeq This channel requires authentication — sign in to join"),
            .channelAccessDenied(
                channel: "#freeq",
                reason: "This channel requires authentication — sign in to join"
            )
        )
        XCTAssertEqual(
            ServerNoticeRouter.route("#freeq client: freeq"),
            .display("#freeq client: freeq")
        )
    }

    func testSelfJoinRequestsLatestChannelHistory() {
        XCTAssertEqual(
            ChannelHydration.historyCommand(for: "#has-messages"),
            "CHATHISTORY LATEST #has-messages * 50"
        )
    }

    func testSelfJoinDoesNotRequestChannelHistoryForDMTarget() {
        XCTAssertNil(ChannelHydration.historyCommand(for: "alice"))
    }

    // MARK: - AV commands

    func testAvCommandParserRecognizesScreenShareAliases() {
        XCTAssertEqual(AvCommandParser.action(for: "screen"), .screenShare)
        XCTAssertEqual(AvCommandParser.action(for: "share"), .screenShare)
        XCTAssertEqual(AvCommandParser.action(for: "screenshare"), .screenShare)
    }

    func testAvCommandParserRecognizesCoreActions() {
        XCTAssertEqual(AvCommandParser.action(for: ""), .startOrJoin)
        XCTAssertEqual(AvCommandParser.action(for: "join"), .startOrJoin)
        XCTAssertEqual(AvCommandParser.action(for: "leave"), .leave)
        XCTAssertEqual(AvCommandParser.action(for: "mute"), .mute)
        XCTAssertEqual(AvCommandParser.action(for: "video"), .camera)
        XCTAssertEqual(AvCommandParser.action(for: "wat"), .help)
    }

    // MARK: - Keychain policy

    func testKeychainQueriesUseDataProtectionKeychain() {
        let query = KeychainHelper.baseQuery(key: "brokerToken")

        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(query[kSecAttrService as String] as? String, KeychainHelper.service)
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, "brokerToken")
    }

    func testKeychainLoadQueryDisablesInteractiveAuthPrompts() {
        let query = KeychainHelper.loadQuery(key: "brokerToken")
        let context = query[kSecUseAuthenticationContext as String] as? LAContext

        XCTAssertNotNil(context)
        XCTAssertEqual(context?.interactionNotAllowed, true)
        XCTAssertEqual(query[kSecReturnData as String] as? Bool, true)
    }

    // MARK: - DM target bootstrap

    func testDmTargetBootstrapWaitsForRegisteredAuthenticatedConnection() {
        XCTAssertFalse(DmTargetBootstrap.shouldRequest(
            isRegistered: false,
            authenticatedDID: "did:plc:alice",
            alreadyRequested: false
        ))
        XCTAssertFalse(DmTargetBootstrap.shouldRequest(
            isRegistered: true,
            authenticatedDID: nil,
            alreadyRequested: false
        ))
        XCTAssertTrue(DmTargetBootstrap.shouldRequest(
            isRegistered: true,
            authenticatedDID: "did:plc:alice",
            alreadyRequested: false
        ))
    }

    func testDmTargetBootstrapRequestsOnlyOncePerConnection() {
        XCTAssertFalse(DmTargetBootstrap.shouldRequest(
            isRegistered: true,
            authenticatedDID: "did:plc:alice",
            alreadyRequested: true
        ))
    }

    func testDmTargetBootstrapUsesServerConversationListCommand() {
        XCTAssertEqual(DmTargetBootstrap.command, "CHATHISTORY TARGETS * * 50")
    }

    // MARK: - Bluesky profile bootstrap

    func testBlueskyProfileBootstrapPrefersPlcDid() {
        XCTAssertEqual(
            BlueskyProfileBootstrap.actor(nick: "jessmart.in", did: "did:plc:ydmqzovfn7leytozprtjyOox".lowercased()),
            "did:plc:ydmqzovfn7leytozprtjyoox"
        )
    }

    func testBlueskyProfileBootstrapUsesHandleLikeDmNickWithoutDid() {
        XCTAssertEqual(BlueskyProfileBootstrap.actor(nick: "jessmart.in", did: nil), "jessmart.in")
    }

    func testBlueskyProfileBootstrapSkipsDidKeyAndPlainIrcNick() {
        XCTAssertNil(BlueskyProfileBootstrap.actor(nick: "agent", did: "did:key:z6Mkabc"))
        XCTAssertNil(BlueskyProfileBootstrap.actor(nick: "plainnick", did: nil))
        XCTAssertNil(BlueskyProfileBootstrap.actor(nick: "#freeq", did: nil))
    }

    // MARK: - Server notice routing

    func testServerNoticeRouterConsumesApiBearerNotice() {
        XCTAssertEqual(ServerNoticeRouter.route("API-BEARER stream-715"), .apiBearer("stream-715"))
    }

    func testServerNoticeRouterClassifiesInternalMotdAndNamesSignals() {
        XCTAssertEqual(ServerNoticeRouter.route("MOTD:START"), .motdStart)
        XCTAssertEqual(ServerNoticeRouter.route("MOTD:hello"), .motdLine("hello"))
        XCTAssertEqual(ServerNoticeRouter.route("MOTD:END"), .motdEnd)
        XCTAssertEqual(ServerNoticeRouter.route("__NAMES_END__#freeq"), .namesEnd("#freeq"))
    }

    func testServerNoticeRouterKeepsDisplayableNoticeText() {
        XCTAssertEqual(ServerNoticeRouter.route("You are not channel operator"), .display("You are not channel operator"))
        XCTAssertEqual(ServerNoticeRouter.route(""), .ignore)
    }

    // MARK: - Bluesky profile URL

    func testBlueSkyProfileURLBasic() {
        let url = Validation.makeBlueSkyProfileURL(handle: "chad.bsky.social")
        XCTAssertEqual(url?.absoluteString, "https://bsky.app/profile/chad.bsky.social")
    }

    func testBlueSkyProfileURLPercentEncodesUnicode() {
        // A handle with characters that would crash URL(string:)! get
        // percent-encoded before assembly. Specifically: a space would
        // make URL(string:) return nil; with encoding it becomes %20.
        // (Bluesky doesn't actually allow spaces, but the function
        // shouldn't crash on bad server data.)
        let url = Validation.makeBlueSkyProfileURL(handle: "weird name")
        XCTAssertNotNil(url, "encoded handle should yield a valid URL")
        XCTAssertTrue(
            url?.absoluteString.contains("weird%20name") ?? false,
            "got \(url?.absoluteString ?? "nil")")
    }

    func testBlueSkyProfileURLRejectsEmpty() {
        XCTAssertNil(Validation.makeBlueSkyProfileURL(handle: ""))
        XCTAssertNil(Validation.makeBlueSkyProfileURL(handle: "   "))
        XCTAssertNil(Validation.makeBlueSkyProfileURL(handle: "\n"))
    }

    func testBlueSkyProfileURLTrimsSurroundingWhitespace() {
        let url = Validation.makeBlueSkyProfileURL(handle: "  chad.bsky.social  ")
        XCTAssertEqual(url?.absoluteString, "https://bsky.app/profile/chad.bsky.social")
    }

    // MARK: - Bluesky post URL

    func testBlueSkyPostURLBasic() {
        let url = Validation.makeBlueSkyPostURL(handle: "chad.bsky.social", rkey: "3kabcd")
        XCTAssertEqual(url?.absoluteString, "https://bsky.app/profile/chad.bsky.social/post/3kabcd")
    }

    func testBlueSkyPostURLRejectsEmptyParts() {
        XCTAssertNil(Validation.makeBlueSkyPostURL(handle: "", rkey: "3kabcd"))
        XCTAssertNil(Validation.makeBlueSkyPostURL(handle: "chad.bsky.social", rkey: ""))
        XCTAssertNil(Validation.makeBlueSkyPostURL(handle: "", rkey: ""))
    }

    // MARK: - YouTube watch URL

    func testYouTubeWatchURLBasic() {
        let url = Validation.makeYouTubeWatchURL(videoId: "dQw4w9WgXcQ")
        XCTAssertEqual(url?.absoluteString, "https://youtube.com/watch?v=dQw4w9WgXcQ")
    }

    func testYouTubeWatchURLRejectsEmpty() {
        XCTAssertNil(Validation.makeYouTubeWatchURL(videoId: ""))
        XCTAssertNil(Validation.makeYouTubeWatchURL(videoId: "   "))
    }

    func testYouTubeWatchURLPercentEncodes() {
        // A malformed video id with characters URL won't accept gets
        // encoded so we don't crash.
        let url = Validation.makeYouTubeWatchURL(videoId: "abc def")
        XCTAssertNotNil(url)
        XCTAssertTrue(url?.absoluteString.contains("abc%20def") ?? false)
    }

    // MARK: - Broker URLs

    func testBrokerSessionURLBasic() {
        let url = Validation.brokerSessionURL(brokerBase: "https://broker.example.com")
        XCTAssertEqual(url?.absoluteString, "https://broker.example.com/session")
    }

    func testBrokerSessionURLStripsTrailingSlash() {
        let url = Validation.brokerSessionURL(brokerBase: "https://broker.example.com/")
        XCTAssertEqual(url?.absoluteString, "https://broker.example.com/session")
    }

    func testBrokerSessionURLRejectsEmpty() {
        XCTAssertNil(Validation.brokerSessionURL(brokerBase: ""))
        XCTAssertNil(Validation.brokerSessionURL(brokerBase: "   "))
    }

    func testBrokerLoginURLBuildsParsableQuery() {
        // `.urlQueryAllowed` deliberately leaves `:`, `/`, `@` unencoded
        // (they're legal in URL queries), so we don't pin the literal
        // encoded form. We just verify URLComponents can parse the
        // result and each query item is recoverable.
        let url = Validation.brokerLoginURL(
            brokerBase: "https://broker.example.com",
            handle: "chad@example.com",
            returnTo: "https://irc.freeq.at/auth/mobile"
        )
        XCTAssertNotNil(url)
        guard let comps = URLComponents(url: url!, resolvingAgainstBaseURL: false)
        else {
            XCTFail("URL didn't parse: \(url!.absoluteString)")
            return
        }
        XCTAssertEqual(comps.host, "broker.example.com")
        XCTAssertEqual(comps.path, "/auth/login")
        let items = Dictionary(
            uniqueKeysWithValues: (comps.queryItems ?? []).map { ($0.name, $0.value ?? "") }
        )
        XCTAssertEqual(items["handle"], "chad@example.com")
        XCTAssertEqual(items["return_to"], "https://irc.freeq.at/auth/mobile")
        XCTAssertEqual(items["mobile"], "1")
    }

    func testBrokerLoginURLEncodesCharactersThatNeedIt() {
        // Spaces and ampersands DO need encoding even with
        // `.urlQueryAllowed`. A handle with a space would otherwise
        // corrupt the query string. Verify it stays intact.
        let url = Validation.brokerLoginURL(
            brokerBase: "https://broker.example.com",
            handle: "weird name&injected=true",
            returnTo: "https://irc.freeq.at/auth/mobile"
        )
        XCTAssertNotNil(url)
        let comps = URLComponents(url: url!, resolvingAgainstBaseURL: false)
        let items = Dictionary(
            uniqueKeysWithValues: (comps?.queryItems ?? []).map { ($0.name, $0.value ?? "") }
        )
        // No injection: the full nasty string lands inside the handle param.
        XCTAssertEqual(items["handle"], "weird name&injected=true")
    }

    func testBrokerLoginURLRequestsMobileFlow() {
        // The broker must complete via the freeq:// app scheme, so the
        // login URL always carries mobile=1 and never the old popup flag.
        let url = Validation.brokerLoginURL(
            brokerBase: "https://broker.example.com",
            handle: "chad",
            returnTo: "https://irc.example.com/auth/mobile"
        )
        XCTAssertNotNil(url)
        let items = Dictionary(
            uniqueKeysWithValues: (URLComponents(url: url!, resolvingAgainstBaseURL: false)?
                .queryItems ?? []).map { ($0.name, $0.value ?? "") }
        )
        XCTAssertEqual(items["mobile"], "1")
        XCTAssertEqual(items["return_to"], "https://irc.example.com/auth/mobile")
        XCTAssertNil(items["popup"])
    }

    // MARK: - IRC nick validation

    func testValidNicks() {
        for nick in ["chad", "chad-fowler", "User_42", "alice[home]", "{nickname}"] {
            switch Validation.validateIrcNick(nick) {
            case .success(let v): XCTAssertEqual(v, nick.trimmingCharacters(in: .whitespacesAndNewlines))
            case .failure(let e): XCTFail("expected success for \(nick), got \(e)")
            }
        }
    }

    func testEmptyNickRejected() {
        XCTAssertEqual(Validation.validateIrcNick(""), .failure(.empty))
        XCTAssertEqual(Validation.validateIrcNick("   "), .failure(.empty))
    }

    func testTooLongNickRejected() {
        let nick = String(repeating: "a", count: 31)
        XCTAssertEqual(Validation.validateIrcNick(nick), .failure(.tooLong(maxLen: 30)))
    }

    func testNicksWithWhitespaceRejected() {
        // Whitespace in the middle — leading/trailing get trimmed first.
        XCTAssertEqual(
            Validation.validateIrcNick("chad fowler"),
            .failure(.containsWhitespace))
        XCTAssertEqual(
            Validation.validateIrcNick("chad\tfowler"),
            .failure(.containsWhitespace))
    }

    func testNicksStartingWithDigitRejected() {
        XCTAssertEqual(
            Validation.validateIrcNick("1chad"),
            .failure(.startsWithDigit))
    }

    func testNicksWithInvalidCharsRejected() {
        // Punctuation that's not part of the allowed RFC 2812 set.
        if case .failure(.invalidCharacter(let scalar)) =
            Validation.validateIrcNick("chad.fowler")
        {
            XCTAssertEqual(scalar, ".")
        } else {
            XCTFail("expected invalidCharacter")
        }
        if case .failure(.invalidCharacter(_)) =
            Validation.validateIrcNick("chad@host")
        { /* ok */ } else { XCTFail("expected invalidCharacter") }
    }

    func testNickTrimsLeadingTrailingWhitespace() {
        switch Validation.validateIrcNick("  chad  ") {
        case .success(let v): XCTAssertEqual(v, "chad")
        case .failure(let e): XCTFail("expected success, got \(e)")
        }
    }

    // MARK: - NSDataDetector wrapper

    func testLinkDetectorReturnsNonNil() {
        XCTAssertNotNil(Validation.linkDetector())
    }

    func testLinkMatchesFindsURL() {
        let matches = Validation.linkMatches(in: "Check https://example.com/foo for details")
        XCTAssertEqual(matches.count, 1)
        XCTAssertEqual(matches.first?.url?.absoluteString, "https://example.com/foo")
    }

    func testLinkMatchesEmptyOnPlainText() {
        XCTAssertEqual(Validation.linkMatches(in: "no urls here").count, 0)
    }

    func testLinkMatchesFindsMultiple() {
        let text = "Two: https://a.com and https://b.com"
        let matches = Validation.linkMatches(in: text)
        XCTAssertEqual(matches.count, 2)
    }
}

// MARK: - Keychain legacy fallback (sandbox + ad-hoc signature)

extension ValidationTests {
    func testLegacyQueryOmitsDataProtection() {
        let query = KeychainHelper.legacyQuery(key: "k")
        XCTAssertNil(query[kSecUseDataProtectionKeychain as String],
                     "legacy fallback must not request the data-protection keychain")
        XCTAssertEqual(query[kSecAttrService as String] as? String, KeychainHelper.service)
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, "k")
    }

    func testLegacyLoadQueryAllowsInteraction() {
        // The legacy path may show a one-time ACL prompt; blocking
        // interaction there would fail loads instead of prompting.
        let query = KeychainHelper.loadQuery(key: "k", dataProtection: false)
        XCTAssertNil(query[kSecUseAuthenticationContext as String])
        XCTAssertNil(query[kSecUseDataProtectionKeychain as String])
    }

    func testDataProtectionQueryUnchanged() {
        let query = KeychainHelper.baseQuery(key: "k")
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
    }
}
