import Foundation

/// What one press of Send actually is: a new message, a revision of an earlier
/// one, or an answer to one.
///
/// Each case maps to a typed SDK sender, which signs the message and files an
/// event id for it. A hand-built line reaches the wire as a raw command, and
/// the SDK deliberately never signs those — an edit sent that way carried no
/// proof of who made it.
enum OutboundSend: Equatable {
    case plain(target: String, text: String)
    case edit(target: String, msgId: String, text: String)
    case reply(target: String, msgId: String, text: String)

    var target: String {
        switch self {
        case .plain(let t, _), .edit(let t, _, _), .reply(let t, _, _): t
        }
    }

    var text: String {
        switch self {
        case .plain(_, let x), .edit(_, _, let x), .reply(_, _, let x): x
        }
    }

    /// The same send addressed to `venue` instead — the DID a DM peer turned
    /// out to be, once we know it.
    func addressed(to venue: String) -> OutboundSend {
        switch self {
        case .plain(_, let text): .plain(target: venue, text: text)
        case .edit(_, let msgId, let text): .edit(target: venue, msgId: msgId, text: text)
        case .reply(_, let msgId, let text): .reply(target: venue, msgId: msgId, text: text)
        }
    }

    /// Tags for a send whose body is ciphertext.
    ///
    /// The encrypted path can't use the typed edit/reply senders: their tag is
    /// implicit and there is no room to also say `+encrypted`. So it goes out
    /// through the tagged sender carrying the whole set — still structured,
    /// still signed, the signature covering the ciphertext that actually
    /// travels. An empty value is a valueless IRC tag (`@+encrypted`).
    var encryptedTags: [String: String] {
        switch self {
        case .plain: ["+encrypted": ""]
        case .edit(_, let msgId, _): ["+draft/edit": msgId, "+encrypted": ""]
        case .reply(_, let msgId, _): ["+reply": msgId, "+encrypted": ""]
        }
    }
}

enum ComposeSend {
    /// Resolve the compose bar's state into one send, or nil when there is
    /// nothing to send.
    ///
    /// Newlines survive. The SDK routes a multi-line body into a
    /// `draft/multiline` batch and signs the body a receiver reassembles —
    /// splitting the text into one message per line (which is what this used
    /// to do) turned one thought into several, and escaping the newlines would
    /// have the signature cover bytes nobody ever holds.
    static func plan(
        target: String,
        text: String,
        editingId: String?,
        replyToId: String?
    ) -> OutboundSend? {
        let cleaned = text
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return nil }
        if let editingId { return .edit(target: target, msgId: editingId, text: cleaned) }
        if let replyToId { return .reply(target: target, msgId: replyToId, text: cleaned) }
        return .plain(target: target, text: cleaned)
    }
}

/// Adding a reaction and withdrawing one are separate events, each signed and
/// filed under an id of its own, so history records who took a reaction back
/// rather than losing that it was ever there.
enum ReactionSend: Equatable {
    case add(target: String, msgId: String, emoji: String)
    case remove(target: String, msgId: String, emoji: String)
}

enum ReactionOp {
    /// Which half of the toggle a tap on `emoji` is, given whether we have
    /// already reacted with it.
    static func plan(
        target: String,
        msgId: String,
        emoji: String,
        alreadyReacted: Bool
    ) -> ReactionSend {
        alreadyReacted
            ? .remove(target: target, msgId: msgId, emoji: emoji)
            : .add(target: target, msgId: msgId, emoji: emoji)
    }
}
