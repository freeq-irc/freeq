import Foundation
import Observation

/// A channel with its messages and members.
@Observable
class ChannelState: Identifiable {
    let name: String
    var messages: [ChatMessage] = []
    var members: [MemberInfo] = []
    var topic: String = ""
    var topicSetBy: String?
    var pinnedMessages: [ChatMessage] = []
    var typingUsers: [String: Date] = [:]
    var lastActivity: Date = Date()
    var isEncrypted: Bool = false
    var accessDeniedReason: String?
    /// The tasks this buffer has seen, keyed by each opener's event id.
    let actTasks = ActTaskStore()
    /// The card each companion line draws, keyed by that line's id. Observed,
    /// so a line already on screen becomes its card the moment its event lands.
    var actCards: [String: ActCard] = [:]

    var id: String { name }
    var isChannel: Bool { name.hasPrefix("#") }
    var isDM: Bool { !name.hasPrefix("#") }

    /// Members collapsed to one row per account (same DID). Multi-session or
    /// nick-collision twins (e.g. chadfowler.com / chadfowlercom, or a bot that
    /// reconnected N times) count once. DID resolves from the roster or the
    /// profile cache; guests (no resolvable DID) are kept. Prefers the fuller
    /// (dotted) handle for display. Single source for member lists + counts.
    /// `resolveDid` supplies a DID for members whose `MemberInfo.did` is nil
    /// (on macOS the roster leaves it nil and the DID lives in ProfileCache).
    /// Kept as an injected closure so this model stays free of the app-only
    /// ProfileCache and remains unit-testable in FreeqMacosCore.
    func uniqueMembers(resolveDid: (String) -> String? = { _ in nil }) -> [MemberInfo] {
        var indexByDid: [String: Int] = [:]
        var out: [MemberInfo] = []
        for m in members {
            guard let did = m.did ?? resolveDid(m.nick) else {
                out.append(m); continue
            }
            if let idx = indexByDid[did] {
                if m.nick.contains("."), !out[idx].nick.contains(".") { out[idx] = m }
            } else {
                indexByDid[did] = out.count
                out.append(m)
            }
        }
        return out
    }

    func uniqueMemberCount(resolveDid: (String) -> String? = { _ in nil }) -> Int {
        uniqueMembers(resolveDid: resolveDid).count
    }
    var hasVisibleMessages: Bool { messages.contains { !$0.isDeleted } }

    var activeTypers: [String] {
        let cutoff = Date().addingTimeInterval(-5)
        return typingUsers.filter { $0.value > cutoff }.map(\.key).sorted()
    }

    private var messageIds: Set<String> = []

    init(name: String) {
        self.name = name
    }

    func findMessage(byId id: String) -> Int? {
        messages.firstIndex(where: { $0.id == id })
    }

    func memberInfo(for nick: String) -> MemberInfo? {
        members.first(where: { $0.nick.lowercased() == nick.lowercased() })
    }

    /// Append a message only if its ID hasn't been seen before.
    ///
    /// An edit and its original are the same logical message that can arrive
    /// under two different msgids: the local cache keeps the original id (it
    /// edits the row in place), while server CHATHISTORY replays the edit
    /// under a fresh msgid. Dedup on both the current id and the original
    /// (`editOf`) so those two copies collapse instead of rendering twice.
    func appendIfNew(_ msg: ChatMessage) {
        if messageIds.contains(msg.id) {
            // Already have this message (e.g. the local cache copy loaded
            // first). A CHATHISTORY replay may still carry authoritative
            // server-persisted reactions the cached copy lacked — fold them in
            // so reactions survive logout/login, not just live ones.
            if !msg.reactions.isEmpty, let idx = findMessage(byId: msg.id) {
                for (emoji, nicks) in msg.reactions where !nicks.isEmpty {
                    messages[idx].reactions[emoji] = nicks
                }
            }
            return
        }
        if let editOf = msg.editOf, messageIds.contains(editOf) { return }
        messageIds.insert(msg.id)
        if let editOf = msg.editOf { messageIds.insert(editOf) }

        if let last = messages.last, msg.timestamp < last.timestamp {
            let idx = messages.firstIndex(where: { $0.timestamp > msg.timestamp }) ?? messages.endIndex
            messages.insert(msg, at: idx)
        } else {
            messages.append(msg)
        }
        if msg.timestamp > lastActivity {
            lastActivity = msg.timestamp
        }
        // Either side can land first, so joining runs from both.
        if msg.actRef != nil { pairActCompanions() }
    }

    /// Join the task events this buffer holds to the companion lines it holds.
    ///
    /// Cheap to repeat: already-joined pairs are left alone, and a line whose
    /// event has not arrived waits for it.
    func pairActCompanions() {
        if actTasks.tasks.isEmpty { return }
        actTasks.pair(messages.compactMap { m in
            m.actRef.map {
                ActLine(id: m.id, from: m.from, account: m.account,
                        timestampMs: Int64(m.timestamp.timeIntervalSince1970 * 1000), ref: $0)
            }
        })
        refreshActCards()
    }

    /// File one task event, and hand back the line the room is told, if any.
    func recordActEvent(_ ev: ActEventInput) -> String? {
        let line = actTasks.record(ev)
        refreshActCards()
        return line
    }

    private func refreshActCards() {
        for task in actTasks.tasks.values {
            for ev in task.events {
                guard let id = ev.msgId else { continue }
                let card = ActCard(task: task, event: ev)
                if actCards[id] != card { actCards[id] = card }
            }
        }
    }

    func applyEdit(originalId: String, newId: String?, newText: String) {
        // Match on the current id OR a prior editOf. `editOf` covers rows a
        // previous build re-keyed to a revision's msgid and cached locally.
        if let idx = messages.firstIndex(where: { $0.id == originalId || $0.editOf == originalId }) {
            messages[idx].text = newText
            messages[idx].isEdited = true
            messages[idx].editOf = messages[idx].editOf ?? originalId
            // The id does NOT move to the revision's. A message keeps the id
            // it was born with — the one the server files reactions, pins and
            // deletes under, and the one replay returns it under. Moving it
            // was what left reactions stranded on an edited message.
            messageIds.insert(originalId)
            // The revision's id still counts as seen, so a later replay of
            // that row isn't mistaken for a new message.
            if let newId { messageIds.insert(newId) }
        }
    }

    func applyDelete(msgId: String) {
        // Match on the current id OR a prior editOf, exactly as applyEdit does.
        // An edit rewrites the in-memory id to the edit's msgid, while a delete
        // always names the ORIGINAL msgid (the identity clients hold, and what
        // the server relays in +draft/delete). Matching id alone meant a delete
        // of an edited message found nothing and left it on screen after the
        // server had already removed it.
        if let idx = messages.firstIndex(where: { $0.id == msgId || $0.editOf == msgId }) {
            messages[idx].isDeleted = true
            messages[idx].text = ""
        }
    }

    func applyReaction(msgId: String, emoji: String, from: String) {
        if let idx = findMessage(byId: msgId) {
            var reactions = messages[idx].reactions
            var nicks = reactions[emoji] ?? Set()
            if nicks.contains(from) {
                nicks.remove(from)
                if nicks.isEmpty { reactions.removeValue(forKey: emoji) }
                else { reactions[emoji] = nicks }
            } else {
                nicks.insert(from)
                reactions[emoji] = nicks
            }
            messages[idx].reactions = reactions
        }
    }

    func addReaction(msgId: String, emoji: String, from: String) {
        guard !emoji.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let idx = findMessage(byId: msgId) else { return }
        var reactions = messages[idx].reactions
        var nicks = reactions[emoji] ?? Set()
        nicks.insert(from)
        reactions[emoji] = nicks
        messages[idx].reactions = reactions
    }

    func removeReaction(msgId: String, emoji: String, from: String) {
        guard let idx = findMessage(byId: msgId),
              var nicks = messages[idx].reactions[emoji] else { return }
        nicks.remove(from)
        if nicks.isEmpty {
            messages[idx].reactions.removeValue(forKey: emoji)
        } else {
            messages[idx].reactions[emoji] = nicks
        }
    }

    func hasReaction(msgId: String, emoji: String, from: String) -> Bool {
        guard let idx = findMessage(byId: msgId) else { return false }
        return messages[idx].reactions[emoji]?.contains(from) ?? false
    }
}
