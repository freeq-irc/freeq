import Foundation

/// Whether opening a thread should ask the server for its history.
///
/// A channel is rejoined on every connect and the server replays that
/// channel's task events with the JOIN, so its cards rebuild themselves. A DM
/// has no join to hang replay off: its task events arrive live, or inside a
/// history page, or never. This app restores DM threads from its own disk
/// cache, so without the ask a restored thread's lines sit uncarded. Opening
/// the thread is the closest thing a DM has to a join, and once per session is
/// enough — the page is the same page.
///
/// Pure, so the rule is testable without a simulator. The rule Android reads
/// (`DmHistoryOnOpen.kt`).
enum DmHistoryOnOpen {
    static func shouldFetch(name: String, authenticated: Bool, alreadyAsked: Set<String>) -> Bool {
        if name.hasPrefix("#") || name.hasPrefix("&") { return false }
        // The server serves DM history only to the identity it belongs to.
        if !authenticated { return false }
        return !alreadyAsked.contains(name.lowercased())
    }
}
