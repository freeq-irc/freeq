import Foundation

/// How a channel shows join/part/quit lines. Hidden by default — presence
/// churn is noise in a busy room — with one compact summary per run, or every
/// line, a setting away. Kicks and other moderation lines are not presence
/// lines and always show.
enum JoinPartDisplay: String, CaseIterable, Identifiable {
    case hidden, grouped, all

    static let storageKey = "freeq.joinPartDisplay"
    static let `default`: JoinPartDisplay = .hidden

    var id: String { rawValue }

    var label: String {
        switch self {
        case .hidden: return "Hidden"
        case .grouped: return "Grouped"
        case .all: return "All"
        }
    }
}

/// The pure transform from a channel's buffer to the rows the transcript
/// draws, as far as presence lines go.
enum PresenceLines {
    private static let pattern = try! NSRegularExpression(
        pattern: #"^(\S+) (joined|left|quit)( \(.*\))?$"#)

    private enum Kind { case join, leave }

    /// The nick and direction of a presence line, or nil for anything else
    /// (a sender's message, a kick, a mode change).
    private static func parse(_ msg: ChatMessage) -> (nick: String, kind: Kind)? {
        guard msg.from.isEmpty, !msg.isDeleted else { return nil }
        let text = msg.text
        let range = NSRange(text.startIndex..., in: text)
        guard let m = pattern.firstMatch(in: text, range: range),
              let nickR = Range(m.range(at: 1), in: text),
              let verbR = Range(m.range(at: 2), in: text) else { return nil }
        return (String(text[nickR]), text[verbR] == "joined" ? .join : .leave)
    }

    static func isPresence(_ msg: ChatMessage) -> Bool { parse(msg) != nil }

    /// `messages` as the transcript should draw them under `mode`. Grouped
    /// folds each run of two or more consecutive presence lines into one
    /// synthetic line carrying the first line's id, so it keeps a stable
    /// place in the list; a lone line is left as it is.
    static func apply(_ messages: [ChatMessage], mode: JoinPartDisplay) -> [ChatMessage] {
        switch mode {
        case .all:
            return messages
        case .hidden:
            return messages.filter { !isPresence($0) }
        case .grouped:
            var out: [ChatMessage] = []
            out.reserveCapacity(messages.count)
            var i = 0
            while i < messages.count {
                guard parse(messages[i]) != nil else {
                    out.append(messages[i]); i += 1; continue
                }
                var run: [(ChatMessage, String, Kind)] = []
                while i < messages.count, let p = parse(messages[i]) {
                    run.append((messages[i], p.nick, p.kind)); i += 1
                }
                if run.count == 1 {
                    out.append(run[0].0)
                } else {
                    let first = run[0].0
                    out.append(ChatMessage(
                        id: first.id, from: "",
                        text: summary(run.map { ($0.1, $0.2) }),
                        isAction: false, timestamp: run[run.count - 1].0.timestamp,
                        replyTo: nil))
                }
            }
            return out
        }
    }

    /// "nap reconnected 2×" for one person's churn, else
    /// "alice, bob joined · carol left".
    private static func summary(_ events: [(nick: String, kind: Kind)]) -> String {
        let joins = events.filter { $0.kind == .join }.map(\.nick)
        let leaves = events.filter { $0.kind == .leave }.map(\.nick)
        let unique = Set(events.map { $0.nick.lowercased() })
        if unique.count == 1, let nick = events.first?.nick {
            if !joins.isEmpty && !leaves.isEmpty { return "\(nick) reconnected \(min(joins.count, leaves.count))×" }
            if !joins.isEmpty { return "\(nick) joined \(joins.count)×" }
            return "\(nick) left \(leaves.count)×"
        }
        var parts: [String] = []
        if !joins.isEmpty { parts.append("\(names(joins)) joined") }
        if !leaves.isEmpty { parts.append("\(names(leaves)) left") }
        return parts.joined(separator: " · ")
    }

    /// Up to three distinct nicks, then "and N more".
    private static func names(_ nicks: [String]) -> String {
        var seen = Set<String>()
        let distinct = nicks.filter { seen.insert($0.lowercased()).inserted }
        let shown = distinct.prefix(3).joined(separator: ", ")
        return distinct.count > 3 ? "\(shown) and \(distinct.count - 3) more" : shown
    }
}
