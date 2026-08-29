import Foundation
import Combine

/// A channel with its messages and members.
class ChannelState: ObservableObject, Identifiable {
    let name: String
    @Published var messages: [ChatMessage] = []
    @Published var members: [MemberInfo] = []
    @Published var topic: String = ""
    @Published var typingUsers: [String: Date] = [:]  // nick -> last typing time
    @Published var pins: Set<String> = []  // pinned message IDs
    /// True when this channel has a local E2EE passphrase key set — drives
    /// the lock indicator in the header. Parity with macOS.
    @Published var isEncrypted: Bool = false
    /// Set from a server access-denial NOTICE (invite-only, bad key, banned,
    /// auth required, …) so the UI can explain why a join didn't happen.
    /// Cleared on a successful join. Parity with macOS.
    @Published var accessDeniedReason: String? = nil
    /// Tracks the most recent activity (message, join, topic change, etc.)
    var lastActivity: Date = Date()

    var id: String { name }

    var activeTypers: [String] {
        let cutoff = Date().addingTimeInterval(-5)
        return typingUsers.filter { $0.value > cutoff }.map { $0.key }.sorted()
    }

    init(name: String) {
        self.name = name
    }

    private var messageIds: Set<String> = []
    /// id → index into `messages`. Makes findMessage / reactions / edits /
    /// deletes / reply resolution O(1) instead of a linear scan of the whole
    /// (unbounded) transcript on every TAGMSG and every reply row. Rebuilt
    /// when indices shift (out-of-order history insert); updated in place on
    /// the common in-order live append.
    private var messageIndex: [String: Int] = [:]

    func findMessage(byId id: String) -> Int? {
        messageIndex[id]
    }

    func memberInfo(for nick: String) -> MemberInfo? {
        members.first(where: { $0.nick.lowercased() == nick.lowercased() })
    }

    private func rebuildMessageIndex() {
        messageIndex.removeAll(keepingCapacity: true)
        for (i, m) in messages.enumerated() { messageIndex[m.id] = i }
    }

    /// Adopt another buffer's transcript (used when a DM buffer is renamed
    /// after a peer NICK change). Copies the messages AND rebuilds the dedup
    /// set + index — previously only `messages` was copied, leaving the dedup
    /// Set empty so the next live/history message re-appended and duplicated
    /// the whole transcript.
    func adoptMessages(from other: ChannelState) {
        messages = other.messages
        messageIds = Set(messages.map(\.id))
        rebuildMessageIndex()
    }

    /// Append a message only if its ID hasn't been seen before.
    /// Inserts in timestamp order to handle CHATHISTORY arriving after live messages.
    func appendIfNew(_ msg: ChatMessage) {
        if messageIds.contains(msg.id) {
            // Already have this message (e.g. the local cache copy loaded
            // first). A CHATHISTORY replay may still carry authoritative
            // server-persisted reactions the cached copy lacked — fold them in
            // so reactions survive logout/login (parity with macOS).
            if !msg.reactions.isEmpty, let idx = findMessage(byId: msg.id) {
                for (emoji, nicks) in msg.reactions where !nicks.isEmpty {
                    messages[idx].reactions[emoji] = nicks
                }
            }
            // Same for the row's identity evidence: a copy that arrived
            // without `account`/`origin` (an old cache) must not shadow the
            // replay that carries them — the claim engine reads the row.
            if msg.account != nil || msg.origin != nil,
               let idx = findMessage(byId: msg.id) {
                if messages[idx].account == nil { messages[idx].account = msg.account }
                if messages[idx].origin == nil { messages[idx].origin = msg.origin }
            }
            return
        }
        // An edit whose ORIGINAL we already hold must not append as a second
        // row — the server's history replays both the (edited-in-place)
        // original row and the edit row. Register both ids so either replay
        // order collapses to one row (the duplicated-edited-message bug,
        // caught staging screenshots 2026-07-23; parity with macOS).
        if let editOf = msg.editOf, messageIds.contains(editOf) { return }
        messageIds.insert(msg.id)
        if let editOf = msg.editOf { messageIds.insert(editOf) }

        // If the message is older than the last message, insert in sorted
        // position (history backfill) — this shifts subsequent indices, so
        // rebuild the map. The common live case appends at the end (O(1)).
        if let last = messages.last, msg.timestamp < last.timestamp {
            let idx = messages.firstIndex(where: { $0.timestamp > msg.timestamp }) ?? messages.endIndex
            messages.insert(msg, at: idx)
            rebuildMessageIndex()
        } else {
            messages.append(msg)
            messageIndex[msg.id] = messages.count - 1
        }
        // Update last activity for sorting
        if msg.timestamp > lastActivity {
            lastActivity = msg.timestamp
        }
    }

    func applyEdit(originalId: String, newId: String?, newText: String) {
        // Match the current id OR a prior editOf. `editOf` covers rows a
        // previous build re-keyed to a revision's msgid and cached locally.
        if let idx = findMessage(byId: originalId)
            ?? messages.firstIndex(where: { $0.editOf == originalId }) {
            messages[idx].text = newText
            messages[idx].isEdited = true
            messages[idx].editOf = messages[idx].editOf ?? originalId
            // The id does NOT move to the revision's. A message keeps the id
            // it was born with — the one the server files reactions, pins and
            // deletes under, and the one replay returns it under. The row
            // still rebuilds on screen: `renderKey` folds in the text and the
            // edited flag, so the identity the list diffs on changes anyway.
            messageIds.insert(originalId)
            // The revision's id still counts as seen, so a later replay of
            // that row isn't mistaken for a new message.
            if let newId = newId { messageIds.insert(newId) }
        }
    }

    /// Tombstone via identity swap — mirrors applyEdit's mechanics exactly,
    /// which are the only in-place update that reliably renders: rows carry
    /// an explicit `.id(msg.id)` in the view, so a same-id mutation stays
    /// pinned to the stale row while an id CHANGE releases it and rebuilds.
    /// The original id stays in `messageIds` so a replay can't resurrect it.
    func applyDelete(msgId: String) {
        // Match on the current id OR a prior editOf, exactly as applyEdit does:
        // an edit re-keys the row to the edit's msgid while a delete names the
        // ORIGINAL msgid, so matching id alone left edited messages on screen.
        if let idx = messages.firstIndex(where: { $0.id == msgId || $0.editOf == msgId }) {
            var tomb = messages[idx]
            tomb.id = msgId + ":tombstone"
            tomb.isDeleted = true
            tomb.text = ""
            messages[idx] = tomb
            messageIds.insert(tomb.id)
            messageIndex.removeValue(forKey: msgId)
            messageIndex[tomb.id] = idx
        }
    }

    func applyReaction(msgId: String, emoji: String, from: String) {
        if let idx = findMessage(byId: msgId) {
            var reactions = messages[idx].reactions
            var nicks = reactions[emoji] ?? Set<String>()
            nicks.insert(from)
            reactions[emoji] = nicks
            messages[idx].reactions = reactions
        }
    }

    func removeReaction(msgId: String, emoji: String, from: String) {
        guard let idx = findMessage(byId: msgId) else { return }
        var reactions = messages[idx].reactions
        guard var nicks = reactions[emoji] else { return }
        nicks.remove(from)
        if nicks.isEmpty {
            reactions.removeValue(forKey: emoji)
        } else {
            reactions[emoji] = nicks
        }
        messages[idx].reactions = reactions
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
    /// Learned from the roster (vendor numeric 674) or an extended JOIN.
    /// `nil` means "not stated", which reads as human — the server reports
    /// only the exceptions.
    var actorClass: String? = nil

    /// Live agent state and what it is doing. Only agents publish these.
    var presenceState: String? = nil
    var presenceStatus: String? = nil

    var id: String { nick.lowercased() }

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
    /// An idle agent says nothing — a row that always carries a label teaches
    /// people to stop reading it.
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
