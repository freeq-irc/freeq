import Foundation

/// The word each task verb shows a reader.
///
/// The headline of a card is the word for the verb its event carried — the
/// verb is on the wire and the client computes nothing from it, so a progress
/// report never reads as a claim. A verb with no row here shows itself, which
/// is how a kind may add one without this having to be taught it.
///
/// The same rows the web client reads (`freeq-app/src/lib/act-verbs.ts`) and
/// the Android app reads (`ActVerbs.kt`), so the same move is called the same
/// thing wherever it is read.
enum ActVerbs {
    private static let headlines: [String: String] = [
        "offer": "offered",
        "accept": "accepted",
        "decline": "declined",
        "claim": "claimed",
        "progress": "in progress",
        "complete": "completed",
        "fail": "failed",
        "cancel": "cancelled",
        "bid": "bid",
        "award": "awarded",
        "submit": "submitted",
        "revise": "revisions requested",
        "accept-work": "accepted",
        "forfeit": "forfeited",
        // The two the home signs for itself. They write no companion line, so
        // these words are read in the timeline rather than on a card.
        "confirm": "confirmed",
        "expire": "expired",
    ]

    static func headline(_ verb: String) -> String { headlines[verb] ?? verb }

    /// The glyph each task verb shows a reader, beside its word.
    ///
    /// One row per verb, read the same way the word above it is: off the verb
    /// the event carried, never off where the task got to. A verb with no row
    /// here gets the generic pin, so a kind may add a move without this being
    /// taught it.
    private static let glyphs: [String: String] = [
        "offer": "📋",
        "accept": "👍",
        "decline": "👎",
        "claim": "✋",
        "progress": "📌",
        "complete": "🎉",
        "fail": "❌",
        "cancel": "🚫",
        "bid": "💰",
        "award": "🏆",
        "submit": "📤",
        "revise": "🔁",
        "accept-work": "✅",
        "forfeit": "🏳️",
        // The two the home signs for itself. They write no companion line, so
        // they carry their glyph on a system line rather than on a card.
        "confirm": "✔️",
        "expire": "⌛",
    ]

    static func emoji(_ verb: String) -> String { glyphs[verb] ?? "📌" }

    /// The accent a card's left edge carries. Purple where the work lands on
    /// someone's plate, green on a good end, red on a failure; every other
    /// verb goes without, since an edge on everything is an edge that says
    /// nothing.
    static func accent(_ verb: String) -> ActAccent {
        switch verb {
        case "offer", "award": return .handoff
        case "complete", "accept-work": return .success
        case "fail": return .failure
        default: return .none
        }
    }
}

/// An accent as a role rather than a colour — each client paints it in its own
/// theme.
enum ActAccent: Equatable { case none, handoff, success, failure }
