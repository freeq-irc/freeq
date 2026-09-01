import Foundation

/// A single chat message.
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
    // True when the body arrived (or was sent) as E2EE ciphertext — drives
    // the lock badge. The stored `text` is already the decrypted form.
    var isEncrypted: Bool = false
    // Origin server name when relayed from a federated peer (+freeq.at/origin).
    // nil = locally-originated. Drives "via {origin}" + suppresses the local
    // verified/signed badges, which would overstate trust for a peer-vouched msg.
    var origin: String? = nil
    // The sender's server-bound DID from the row's `account` tag, when one
    // arrived. The row's own evidence for identity claims — never a cache.
    var account: String? = nil
    // The original msgid this message replaces, when it arrived as an edit
    // (+draft/edit). A single logical message can surface under two msgids —
    // the original (used by the local cache, which edits in place) and the
    // edit's new msgid (used by server CHATHISTORY, which replays both rows).
    // Dedup keys off both so the two copies collapse to one.
    var editOf: String? = nil
    // Agent coordination event (+freeq.at/event family). When set, the row
    // renders as a structured task/evidence card (parity with web).
    var coordination: CoordinationInfo? = nil
    // The task a companion line names (`+freeq.at/ref`). The only thing
    // joining a line to the act event it was written beside; the row renders
    // as a task card once its event has arrived.
    var actRef: String? = nil
    var reactions: [String: Set<String>] = [:]  // emoji -> set of nicks

    static func == (lhs: ChatMessage, rhs: ChatMessage) -> Bool {
        lhs.id == rhs.id
            && lhs.from == rhs.from
            && lhs.text == rhs.text
            && lhs.isAction == rhs.isAction
            && lhs.timestamp == rhs.timestamp
            && lhs.replyTo == rhs.replyTo
            && lhs.isEdited == rhs.isEdited
            && lhs.isDeleted == rhs.isDeleted
            && lhs.isSigned == rhs.isSigned
            && lhs.isEncrypted == rhs.isEncrypted
            && lhs.origin == rhs.origin
            && lhs.editOf == rhs.editOf
            && lhs.coordination == rhs.coordination
            && lhs.actRef == rhs.actRef
            && lhs.reactions == rhs.reactions
    }
}

/// Member info for the member list.
struct MemberInfo: Identifiable, Equatable {
    let nick: String
    let isOp: Bool
    let isHalfop: Bool
    let isVoiced: Bool
    let awayMsg: String?
    let did: String?

    /// `agent` | `external_agent` | `human`, when the server has told us.
    ///
    /// Learned from the roster (vendor numeric 674) or an extended JOIN.
    /// `nil` means "not stated", which is treated as human — the server only
    /// reports the exceptions.
    var actorClass: String? = nil

    /// Live agent state (`active`, `executing`, `waiting_for_input`, …) and
    /// what it is doing. Only agents publish these.
    var presenceState: String? = nil
    var presenceStatus: String? = nil

    var id: String { nick }

    var prefix: String {
        if isOp { return "@" }
        if isHalfop { return "%" }
        if isVoiced { return "+" }
        return ""
    }

    var isAway: Bool { awayMsg != nil }
    var isVerified: Bool { did != nil }

    var isAgent: Bool { actorClass == "agent" || actorClass == "external_agent" }

    /// What to show beside an agent's name: what it is doing, else its state.
    ///
    /// An agent that is merely available says nothing — a row that always
    /// carries a label teaches people to stop reading it.
    var activityLabel: String? {
        guard isAgent else { return nil }
        if let status = presenceStatus, !status.isEmpty { return status }
        switch presenceState {
        case "executing": return "working"
        case "waiting_for_input": return "waiting for input"
        case "blocked_on_permission": return "needs approval"
        case "paused": return "paused"
        case "degraded": return "degraded"
        case "rate_limited": return "rate limited"
        default: return nil
        }
    }
}
