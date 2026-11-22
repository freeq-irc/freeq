import Foundation

/// An agent's presence status, decoded.
///
/// Agents built on harness-kit publish their status as space-separated
/// `key=value` pairs, with the prose `doing` field's spaces sent as `+`:
///
///     project=phoenix-agent model=opus doing=answering+chad+in+#phoenix+·+0s
///
/// Carried in an AWAY reason it is prefixed with the presence state
/// (`executing: project=…`). Shown raw it is unreadable, so every surface
/// decodes it with this first. Mirrors freeq-app/src/lib/status.ts and freeq-macos Models/AgentStatus.swift.
struct AgentStatus: Equatable {
    var state: String?
    var doing: String?
    var project: String?
    var branch: String?
    var repo: String?
    var model: String?

    private static let known: Set<String> = ["project", "branch", "repo", "model", "session", "doing"]

    private static func isPair(_ token: Substring) -> Bool {
        guard let eq = token.firstIndex(of: "="), eq != token.startIndex else { return false }
        return token[..<eq].allSatisfy { $0 == "_" || ($0.isASCII && $0.isLowercase) }
    }

    /// Decode, or nil when `raw` is not an agent status (a person's free
    /// text, JSON, empty).
    static func parse(_ raw: String?) -> AgentStatus? {
        guard var text = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { return nil }
        var out = AgentStatus()
        // "executing: project=…" — a state prefix, but only in front of pairs.
        if let colon = text.range(of: ": ") {
            let head = text[..<colon.lowerBound]
            let rest = text[colon.upperBound...]
            if !head.isEmpty, head.allSatisfy({ $0 == "_" || ($0.isASCII && $0.isLowercase) }),
               let first = rest.split(separator: " ").first, isPair(first) {
                out.state = String(head)
                text = String(rest)
            }
        }
        let tokens = text.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard !tokens.isEmpty, tokens.allSatisfy(isPair) else { return nil }
        var recognised = 0
        for token in tokens {
            let eq = token.firstIndex(of: "=")!
            let key = String(token[..<eq])
            let value = String(token[token.index(after: eq)...])
            guard known.contains(key) else { continue }
            recognised += 1
            guard !value.isEmpty else { continue }
            switch key {
            case "doing": out.doing = value.replacingOccurrences(of: "+", with: " ")
            case "project": out.project = value
            case "branch": out.branch = value
            case "repo": out.repo = value
            case "model": out.model = value
            default: break
            }
        }
        return recognised > 0 ? out : nil
    }

    /// Words for a presence state.
    static func label(forState state: String?) -> String? {
        guard let state, !state.isEmpty else { return nil }
        switch state {
        case "executing": return "Working"
        case "active", "online": return "Available"
        case "idle": return "Idle"
        case "waiting_for_input": return "Waiting for input"
        case "blocked_on_permission": return "Needs approval"
        case "blocked_on_budget": return "Out of budget"
        case "rate_limited": return "Rate limited"
        case "degraded": return "Degraded"
        case "paused": return "Paused"
        case "sandboxed": return "Sandboxed"
        case "revoked": return "Revoked"
        case "offline": return "Offline"
        default: return state.replacingOccurrences(of: "_", with: " ")
        }
    }

    /// "phoenix-agent @main · opus": where the agent is working.
    var context: String? {
        let whereParts = [project, branch.map { "@\($0)" }].compactMap { $0 }
        let parts = [whereParts.isEmpty ? nil : whereParts.joined(separator: " "), model].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// One line: "Working · answering chad in #phoenix".
    var summary: String? {
        let parts = [AgentStatus.label(forState: state), doing ?? context].compactMap { $0 }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// An AWAY reason as display text: an agent's decoded, anyone else's as is.
    static func displayAway(_ away: String?) -> String? {
        guard let away, !away.isEmpty else { return nil }
        if let agent = parse(away) { return agent.summary }
        return away
    }
}
