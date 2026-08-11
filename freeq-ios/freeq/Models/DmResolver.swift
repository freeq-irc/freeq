import Foundation

/// Who a bare nick actually is, learned before the first DM goes to them.
///
/// A signature covers the venue it was written for, and a nick is not an
/// identity — the same letters can belong to someone else tomorrow. So the SDK
/// declines to sign a DM addressed to a bare nick, and a first message to a
/// stranger went out unsigned purely because nobody had asked who they were.
/// Asking is a WHOIS; the answer comes back as a `MemberDid` event.
///
/// Asking must never cost the user their message. The wait is short, a peer
/// that stays silent gets the message at their nick exactly as before, no
/// error is shown, and the question is not asked twice in a session.
///
/// Not thread-safe by design: every caller — the event handler and the send
/// path alike — runs on the main thread, and the timeout fires there too.
/// `@unchecked Sendable` states that contract to the compiler: the only
/// cross-boundary capture is the main-queue timeout closure, which runs on
/// the same thread as every other caller.
final class DmResolver: @unchecked Sendable {
    /// Long enough for a WHOIS round trip, short enough that a silent peer
    /// does not feel like a hung send.
    static let defaultTimeout: TimeInterval = 2

    private let nickToDid: (String) -> String?
    private let askWhois: (String) -> Void
    private let timeout: TimeInterval

    private var asked: Set<String> = []
    private var waiting: [String: [CheckedContinuation<String?, Never>]] = [:]
    private var learnedDids: [String: String] = [:]

    init(
        timeout: TimeInterval = DmResolver.defaultTimeout,
        nickToDid: @escaping (String) -> String?,
        askWhois: @escaping (String) -> Void
    ) {
        self.timeout = timeout
        self.nickToDid = nickToDid
        self.askWhois = askWhois
    }

    /// Ask about `target` now, without waiting — called when a DM thread is
    /// opened, so the answer is usually in hand by the time anything is typed.
    func probe(_ target: String) {
        guard let nick = pendingNick(target) else { return }
        ask(nick)
    }

    /// The venue to address `target` by, when no waiting is required: a
    /// channel, a DID, a peer we already hold a binding for, or a peer we
    /// asked about once and never heard back on. nil means a wait would help.
    ///
    /// The send path takes this first so ordinary sends stay synchronous and
    /// keep their exact order — only a first DM to an unknown nick suspends.
    func venueIfSettled(_ target: String) -> String? {
        let trimmed = target.trimmingCharacters(in: .whitespaces)
        guard let nick = pendingNick(trimmed) else { return known(trimmed) ?? trimmed }
        // Asked once and never answered — don't make every later message pay
        // the wait for a peer whose server isn't going to tell us.
        return asked.contains(nick) ? trimmed : nil
    }

    /// The venue to address `target` by: its DID where one can be learned in
    /// time, otherwise `target` unchanged.
    func resolve(_ target: String) async -> String {
        let trimmed = target.trimmingCharacters(in: .whitespaces)
        if let settled = venueIfSettled(trimmed) { return settled }
        guard let nick = pendingNick(trimmed) else { return trimmed }
        ask(nick)
        let learned = await withCheckedContinuation { (c: CheckedContinuation<String?, Never>) in
            waiting[nick, default: []].append(c)
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                self?.giveUp(on: nick)
            }
        }
        return learned ?? trimmed
    }

    /// A nick↔DID binding arrived, from WHOIS or anything else that carries
    /// one. Releases whoever is waiting on it.
    func learned(nick: String, did: String) {
        let key = nick.trimmingCharacters(in: .whitespaces).lowercased()
        guard !key.isEmpty else { return }
        learnedDids[key] = did
        release(key, with: did)
    }

    /// Forget everything asked and learned — a new connection may be a new
    /// server, whose answers are its own.
    func reset() {
        asked.removeAll()
        learnedDids.removeAll()
        for key in waiting.keys { release(key, with: nil) }
    }

    /// The lowercased nick that still needs looking up, or nil when `target`
    /// is not a bare nick or its DID is already known.
    private func pendingNick(_ target: String) -> String? {
        let trimmed = target.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("#"), !trimmed.hasPrefix("&"),
              !DidDisplay.isDid(trimmed),
              known(trimmed) == nil
        else { return nil }
        return trimmed.lowercased()
    }

    /// The DID on file for a target: what the app has bound, then what we
    /// learned by asking.
    private func known(_ target: String) -> String? {
        if DidDisplay.isDid(target) { return target }
        return nickToDid(target) ?? learnedDids[target.lowercased()]
    }

    private func ask(_ nick: String) {
        guard asked.insert(nick).inserted else { return }
        askWhois(nick)
    }

    private func giveUp(on nick: String) {
        release(nick, with: nil)
    }

    private func release(_ nick: String, with did: String?) {
        guard let waiters = waiting.removeValue(forKey: nick) else { return }
        for waiter in waiters { waiter.resume(returning: did) }
    }
}
