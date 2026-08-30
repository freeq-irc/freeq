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
}
