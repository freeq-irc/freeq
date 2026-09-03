import Foundation

/// A parsed agent coordination event carried on a message
/// (`+freeq.at/event` + friends). Pure/Foundation-only so it lives in the
/// test-harness core; `AppState` maps the FFI `CoordinationEvent` into this
/// at the event boundary.
///
/// `Codable` because the local caches persist it: a cached row that lost its
/// event renders as plain text after a relaunch, and dedup on load keeps the
/// cached copy, so the replay that carries the tags is discarded.
struct CoordinationInfo: Equatable, Codable {
    var eventType: String
    var taskId: String?
    var phase: String?
    var evidenceType: String?
    var reference: String?
    var payload: String?
}

/// Presentation policy for a coordination card — the macOS/iOS analogue of
/// the web `CoordinationCards` dispatcher. Pure mapping (event → icon, label,
/// accent) so the whole decision tree is unit-testable without SwiftUI.
enum CoordinationCard {
    enum Accent: Equatable { case neutral, agent, success, error }

    struct Style: Equatable {
        var icon: String
        var label: String
        var accent: Accent
        /// Evidence cards expose a disclosure for their JSON payload.
        var expandablePayload: Bool
    }

    /// Phase → glyph (matches the web `PhaseIcon`).
    static func phaseIcon(_ phase: String?) -> String {
        switch phase {
        case "specifying": return "📝"
        case "designing": return "🏗"
        case "building": return "🔨"
        case "reviewing": return "🔍"
        case "testing": return "🧪"
        case "deploying": return "🚀"
        case "monitoring": return "📊"
        default: return "📌"
        }
    }

    /// Evidence type → glyph (matches the web `EvidenceIcon`).
    static func evidenceIcon(_ type: String?) -> String {
        switch type {
        case "spec_document": return "📄"
        case "architecture_doc": return "📐"
        case "file_manifest": return "📁"
        case "code_review": return "🔍"
        case "test_result": return "🧪"
        case "deploy_log": return "🚀"
        case "commit": return "📦"
        case "artifact_link": return "🔗"
        default: return "📎"
        }
    }

    /// The card style for an event. Unknown event types get a generic card
    /// labeled with the raw event name (graceful fallback, like web).
    static func style(for info: CoordinationInfo) -> Style {
        switch info.eventType {
        case "task_request":
            return Style(icon: "📋", label: "New Task", accent: .agent, expandablePayload: false)
        case "task_accept":
            return Style(icon: "👍", label: "Task Accepted", accent: .neutral, expandablePayload: false)
        case "task_update":
            return Style(icon: phaseIcon(info.phase),
                         label: info.phase?.capitalized ?? "Update",
                         accent: .neutral, expandablePayload: false)
        case "task_complete":
            return Style(icon: "🎉", label: "Task Complete", accent: .success, expandablePayload: false)
        case "task_failed":
            return Style(icon: "❌", label: "Task Failed", accent: .error, expandablePayload: false)
        case "evidence_attach":
            return Style(icon: evidenceIcon(info.evidenceType),
                         label: (info.evidenceType ?? "evidence").replacingOccurrences(of: "_", with: " "),
                         accent: .neutral, expandablePayload: true)
        case "delegation_notice":
            return Style(icon: "🔀", label: "Delegation", accent: .neutral, expandablePayload: false)
        case "status_update":
            return Style(icon: "💬", label: "Status", accent: .neutral, expandablePayload: false)
        default:
            return Style(icon: "📌", label: info.eventType, accent: .neutral, expandablePayload: false)
        }
    }

    /// Pretty-print a JSON payload for the evidence disclosure; returns the
    /// raw string if it isn't valid JSON (never throws away information).
    static func prettyPayload(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        guard let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(withJSONObject: obj,
                                                       options: [.prettyPrinted, .sortedKeys]),
              let str = String(data: pretty, encoding: .utf8)
        else { return raw }
        return str
    }
}
