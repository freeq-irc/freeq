import Foundation

enum ChannelHydration {
    static let defaultHistoryLimit = 50

    static func historyCommand(for channel: String, limit: Int = defaultHistoryLimit) -> String? {
        let trimmed = channel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("#") || trimmed.hasPrefix("&") else { return nil }
        return "CHATHISTORY LATEST \(trimmed) * \(limit)"
    }
}

enum MessageVisibility {
    static func visibleMessages(from messages: [ChatMessage]) -> [ChatMessage] {
        messages.filter { !$0.isDeleted }
    }

    static func shouldShowWelcome(messages: [ChatMessage]) -> Bool {
        visibleMessages(from: messages).isEmpty
    }
}

enum HistoryBatchRouting {
    static func shouldBuffer(batchType: String, target: String) -> Bool {
        if !target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return true
        }

        // `CHATHISTORY TARGETS` uses a batch only as a list delimiter; it
        // emits dedicated ChatHistoryTarget events, not messages for a buffer.
        let normalizedType = batchType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalizedType == "chathistory"
            || normalizedType == "draft/chathistory"
            || normalizedType == "freeq.at/search"
    }

    static func resolvedTarget(batchTarget: String, messageTarget: String) -> String {
        let trimmedBatchTarget = batchTarget.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedBatchTarget.isEmpty { return trimmedBatchTarget }
        return messageTarget.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func shouldApplyBatch(target: String, messageCount: Int) -> Bool {
        messageCount > 0 && !target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    @discardableResult
    static func apply(
        buffer: HistoryBatchBuffer,
        channels: inout [ChannelState],
        dmBuffers: inout [ChannelState]
    ) -> Bool {
        let target = buffer.target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard shouldApplyBatch(target: target, messageCount: buffer.messages.count) else {
            return false
        }

        let destination: ChannelState
        if target.hasPrefix("#") || target.hasPrefix("&") {
            if let existing = channels.first(where: { $0.name.lowercased() == target.lowercased() }) {
                destination = existing
            } else {
                destination = ChannelState(name: target)
                channels.append(destination)
            }
        } else {
            if let existing = dmBuffers.first(where: { $0.name.lowercased() == target.lowercased() }) {
                destination = existing
            } else {
                destination = ChannelState(name: target)
                dmBuffers.append(destination)
            }
        }

        for message in buffer.messages.sorted(by: { $0.timestamp < $1.timestamp }) {
            destination.appendIfNew(message)
        }
        return true
    }
}

struct HistoryBatchBuffer {
    var target: String
    var messages: [ChatMessage] = []

    mutating func learnTarget(from messageTarget: String) {
        target = HistoryBatchRouting.resolvedTarget(
            batchTarget: target,
            messageTarget: messageTarget
        )
    }

    mutating func append(_ message: ChatMessage, messageTarget: String) {
        learnTarget(from: messageTarget)
        messages.append(message)
    }
}

/// Decides when the client should ask the server for authenticated DM targets.
/// Registration and DID-authentication can arrive in either order, so the
/// request must wait for both and still only fire once per TCP connection.
struct DmTargetBootstrap {
    static let command = "CHATHISTORY TARGETS * * 50"

    static func shouldRequest(isRegistered: Bool, authenticatedDID: String?, alreadyRequested: Bool) -> Bool {
        isRegistered && authenticatedDID != nil && !alreadyRequested
    }
}

enum BlueskyProfileBootstrap {
    static func actor(nick: String, did: String?) -> String? {
        if let did, did.hasPrefix("did:plc:") {
            return did
        }
        if let did, did.hasPrefix("did:key:") {
            return nil
        }

        let trimmed = nick.trimmingCharacters(in: .whitespacesAndNewlines)
        guard looksLikeHandle(trimmed) else { return nil }
        return trimmed
    }

    static func looksLikeHandle(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.contains("."),
              !trimmed.contains(" "),
              !trimmed.hasPrefix("."),
              !trimmed.hasSuffix("."),
              !trimmed.hasPrefix("#"),
              !trimmed.hasPrefix("&"),
              !trimmed.hasPrefix("did:") else {
            return false
        }
        return trimmed.allSatisfy { char in
            char.isLetter || char.isNumber || char == "." || char == "-"
        }
    }
}

enum AvCommandAction: Equatable {
    case startOrJoin
    case leave
    case mute
    case camera
    case screenShare
    /// `/av screen display` — share the primary display without the
    /// interactive system picker (automation + muscle memory).
    case screenShareDisplay
    case help
}

enum AvCommandParser {
    static func action(for argument: String) -> AvCommandAction {
        let subcommand = argument
            .split(separator: " ")
            .first
            .map { String($0).lowercased() } ?? ""
        switch subcommand {
        case "", "start", "join":
            return .startOrJoin
        case "leave", "end", "hangup":
            return .leave
        case "mute":
            return .mute
        case "camera", "video":
            return .camera
        case "screen", "share", "screenshare":
            let arg = argument.split(separator: " ").dropFirst().first
                .map { String($0).lowercased() }
            return arg == "display" ? .screenShareDisplay : .screenShare
        default:
            return .help
        }
    }
}

enum ServerNoticeRoute: Equatable {
    case ignore
    case motdStart
    case motdLine(String)
    case motdEnd
    case namesEnd(String)
    case apiBearer(String)
    case channelAccessDenied(channel: String, reason: String)
    case whoisDiagnostic(nick: String, text: String)
    case display(String)
}

enum ServerNoticeRouter {
    static func route(_ text: String) -> ServerNoticeRoute {
        if text.isEmpty { return .ignore }
        // Speculative-history failures: the client requests DM history on its
        // own when a conversation opens; a guest (or a DM with a guest peer)
        // gets `CHATHISTORY <CODE> <target> …` back for a request the user
        // never made — showing it reads as an error in the thread. Exactly the
        // two codes that answer an unfetchable target are swallowed, whatever
        // the target, which is the web client's rule; every other CHATHISTORY
        // failure is a real refusal and shows.
        if text.hasPrefix("CHATHISTORY ") {
            let parts = text.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
            if parts.count >= 2,
               parts[1] == "INVALID_TARGET" || parts[1] == "ACCOUNT_REQUIRED" {
                return .ignore
            }
        }
        if text == "MOTD:START" { return .motdStart }
        if text == "MOTD:END" { return .motdEnd }
        if text.hasPrefix("MOTD:") {
            return .motdLine(String(text.dropFirst("MOTD:".count)))
        }
        if text.hasPrefix("__NAMES_END__") {
            return .namesEnd(String(text.dropFirst("__NAMES_END__".count)))
        }
        if text.hasPrefix("API-BEARER ") {
            let token = text.dropFirst("API-BEARER ".count)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return token.isEmpty ? .ignore : .apiBearer(token)
        }
        if let denial = channelAccessDenied(from: text) {
            return .channelAccessDenied(channel: denial.channel, reason: denial.reason)
        }
        if let diagnostic = whoisDiagnostic(from: text) {
            return .whoisDiagnostic(nick: diagnostic.nick, text: diagnostic.text)
        }
        return .display(text)
    }

    static func channelAccessMessage(channel: String, reason: String, now: Date = Date()) -> ChatMessage {
        ChatMessage(
            id: "channel-access-denied-\(channel)-\(reason)",
            from: "server",
            text: reason,
            isAction: false,
            timestamp: now,
            replyTo: nil
        )
    }

    private static func channelAccessDenied(from text: String) -> (channel: String, reason: String)? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count == 2 else { return nil }

        let channel = String(parts[0])
        guard channel.hasPrefix("#") || channel.hasPrefix("&") else { return nil }

        let reason = String(parts[1]).trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized = reason.lowercased()
        let denialPhrases = [
            "requires authentication",
            "cannot join",
            "invite",
            "banned",
            "bad channel key",
            "channel is full",
            "not authorized",
            "permission",
        ]

        guard denialPhrases.contains(where: { normalized.contains($0) }) else {
            return nil
        }
        return (channel, reason)
    }

    private static func whoisDiagnostic(from text: String) -> (nick: String, text: String)? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count == 2 else { return nil }

        let nick = String(parts[0])
        guard !nick.hasPrefix("#"), !nick.hasPrefix("&") else { return nil }

        let detail = String(parts[1]).trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized = detail.lowercased()
        let diagnosticPrefixes = [
            "at protocol handle:",
            "client:",
            "actor_class=",
        ]

        guard diagnosticPrefixes.contains(where: { normalized.hasPrefix($0) }) else {
            return nil
        }
        return (nick, trimmed)
    }
}

enum AuthSessionState {
    /// A saved DID or broker session says who we intend to authenticate as, but
    /// only the IRC server's SASL success event confirms this TCP connection.
    static func confirmedDidFromSavedCredentials(_ savedDID: String?) -> String? {
        nil
    }

    /// After any SASL failure, the current connection is not authenticated even
    /// if a previous app launch had a DID saved in Keychain.
    static func didAfterAuthFailure(current: String?) -> String? {
        nil
    }
}

enum WhoisDisplayPolicy {
    static func shouldDisplay(explicitlyRequested: Bool) -> Bool {
        explicitlyRequested
    }
}
