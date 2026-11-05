import Foundation

/// How join/part/quit lines show in a channel timeline. Off by default: a busy
/// room's presence churn drowns the conversation, and the member list already
/// says who is here. Kicks and other moderation lines are not presence lines
/// and always show.
enum JoinPartDisplay: String, CaseIterable, Identifiable {
    /// Presence lines are not shown at all.
    case hidden
    /// A run of consecutive presence lines folds into one summary line.
    case grouped
    /// Every presence line shows on its own.
    case all

    var id: String { rawValue }

    static let storageKey = "freeq.joinPartDisplay"
    /// The boolean this setting replaced (true meant "show", the old default).
    static let legacyStorageKey = "freeq.showJoinPart"

    var label: String {
        switch self {
        case .hidden: return "Hidden"
        case .grouped: return "Grouped"
        case .all: return "All"
        }
    }

    /// The setting a stored value names. Nothing stored means the default,
    /// except for someone who turned the old toggle on explicitly: they asked
    /// to see presence lines, and grouped is what that toggle showed them.
    static func resolve(stored: String?, legacyShowJoinPart: Bool?) -> JoinPartDisplay {
        if let stored, let mode = JoinPartDisplay(rawValue: stored) { return mode }
        return legacyShowJoinPart == true ? .grouped : .hidden
    }

    /// Carry an explicit old toggle over to the new key, once.
    static func migrateLegacySetting(_ defaults: UserDefaults = .standard) {
        guard defaults.string(forKey: storageKey) == nil else { return }
        let legacy = defaults.object(forKey: legacyStorageKey) as? Bool
        defaults.set(resolve(stored: nil, legacyShowJoinPart: legacy).rawValue, forKey: storageKey)
    }
}

/// One entry of a timeline after the presence setting is applied.
enum PresenceSegment: Equatable {
    /// Any message, including a lone presence line.
    case message(ChatMessage)
    /// Two or more consecutive presence lines, shown as one summary.
    case presenceRun([ChatMessage])
}

enum PresenceLines {
    /// "nick joined", "nick left", "nick quit", "nick quit (reason)".
    private static let pattern = try! NSRegularExpression(
        pattern: #"^\S+ (joined|left|quit)( \(.*\))?$"#)

    /// A system line (empty `from`, not a tombstone) reporting that someone
    /// joined, left or quit. Kicks and every other system line are not.
    static func isPresence(_ msg: ChatMessage) -> Bool {
        guard msg.from.isEmpty, !msg.isDeleted else { return false }
        let range = NSRange(msg.text.startIndex..., in: msg.text)
        return pattern.firstMatch(in: msg.text, range: range) != nil
    }

    /// `messages` with the setting applied, in order.
    static func segments(_ messages: [ChatMessage], mode: JoinPartDisplay) -> [PresenceSegment] {
        switch mode {
        case .all:
            return messages.map { .message($0) }
        case .hidden:
            return messages.filter { !isPresence($0) }.map { .message($0) }
        case .grouped:
            var out: [PresenceSegment] = []
            var i = 0
            while i < messages.count {
                guard isPresence(messages[i]) else {
                    out.append(.message(messages[i]))
                    i += 1
                    continue
                }
                var j = i
                while j < messages.count, isPresence(messages[j]) { j += 1 }
                let run = Array(messages[i..<j])
                out.append(run.count >= 2 ? .presenceRun(run) : .message(run[0]))
                i = j
            }
            return out
        }
    }

    /// One person's churn reads as "nap reconnected 4×"; several people as
    /// "alice, bob, carol and 2 more joined · dan left".
    static func summary(_ events: [ChatMessage]) -> String {
        var joined: [String] = [], left: [String] = []
        var joins = 0, leaves = 0
        var nicks = Set<String>()
        for e in events {
            guard let nick = e.text.split(separator: " ").first.map(String.init) else { continue }
            nicks.insert(nick.lowercased())
            if e.text.hasPrefix("\(nick) joined") {
                joins += 1
                if !joined.contains(where: { $0.caseInsensitiveCompare(nick) == .orderedSame }) { joined.append(nick) }
            } else {
                leaves += 1
                if !left.contains(where: { $0.caseInsensitiveCompare(nick) == .orderedSame }) { left.append(nick) }
            }
        }
        if nicks.count == 1, let nick = joined.first ?? left.first {
            if joins > 0 && leaves > 0 { return "\(nick) reconnected \(min(joins, leaves))×" }
            if joins > 0 { return joins == 1 ? "\(nick) joined" : "\(nick) joined \(joins)×" }
            return leaves == 1 ? "\(nick) left" : "\(nick) left \(leaves)×"
        }
        var parts: [String] = []
        if !joined.isEmpty { parts.append("\(names(joined)) joined") }
        if !left.isEmpty { parts.append("\(names(left)) left") }
        return parts.joined(separator: " · ")
    }

    private static func names(_ nicks: [String]) -> String {
        let shown = nicks.prefix(3).joined(separator: ", ")
        return nicks.count > 3 ? "\(shown) and \(nicks.count - 3) more" : shown
    }
}
