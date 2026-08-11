import Foundation

/// A single chat message.
///
/// Pure Foundation model — no UIKit/SwiftUI/ActivityKit — so it (and the
/// `MessageActions` decisions that operate on it) compile under the SwiftPM
/// test harness. Kept field-for-field in sync with the macOS `ChatMessage`.
struct ChatMessage: Identifiable, Equatable {
    var id: String  // msgid or UUID
    let from: String
    var text: String
    let isAction: Bool
    let timestamp: Date
    let replyTo: String?
    var isEdited: Bool = false
    var isDeleted: Bool = false
    var isSigned: Bool = false
    // True when the body arrived (or was sent) as channel E2EE ciphertext
    // (the `+encrypted` wire tag). Stored `text` is already the decrypted
    // form; this drives the lock badge. Parity with macOS.
    var isEncrypted: Bool = false
    // Origin server name when relayed from a federated peer (+freeq.at/origin).
    // nil = locally-originated. Drives "via {origin}" + suppresses the local
    // verified/signed badges, which would overstate trust for a peer-vouched msg.
    var origin: String? = nil
    // The sender's server-bound DID from the row's `account` tag, when one
    // arrived. The row's own evidence for identity claims — never a cache.
    var account: String? = nil
    // The original msgid this message replaces, when it arrived as an edit
    // (+draft/edit). One logical message can surface under two msgids — the
    // original (edited in place locally) and the edit's msgid (CHATHISTORY
    // replays BOTH rows). Dedup keys off both so they collapse to one
    // (parity with macOS ChatMessage.editOf).
    var editOf: String? = nil
    // Agent coordination event (+freeq.at/event family). When set, the row
    // renders as a structured task/evidence card (parity with web + macOS).
    var coordination: CoordinationInfo? = nil
    var reactions: [String: Set<String>] = [:]  // emoji -> set of nicks

    // Equality is memberwise (synthesized). An id-only == here made SwiftUI
    // treat same-id content changes (delete tombstone, reactions) as "equal"
    // and skip the row re-render — the row then stayed stale until the whole
    // list was rebuilt. Dedup by id belongs to ChannelState.messageIds, not
    // to Equatable.

    /// Row identity for the transcript ForEach. Folds the renderable content
    /// into the identity so any in-place change (delete tombstone, edit,
    /// reaction) is a structural remove+insert — an in-place update of a
    /// same-identity row has been observed to not reach the screen.
    /// Only stable within a run (hashValue is seeded per-launch); never
    /// persist it.
    var renderKey: String {
        let reactionsPart = reactions.map { "\($0.key)\($0.value.count)" }.sorted().joined()
        return "\(id)|\(isDeleted ? 1 : 0)|\(isEdited ? 1 : 0)|\(text.hashValue)|\(reactionsPart)"
    }
}
