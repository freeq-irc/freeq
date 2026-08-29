import ActivityKit
import AVFoundation
import CoreSpotlight
import Foundation
import os.log
import SwiftUI
import WidgetKit

/// Auth-path diagnostic log. Visible in Console.app attached to the device.
/// We log credential-clearing events with the decision inputs so we can tell
/// after the fact whether a re-OAuth was justified or whether the broker
/// flapped past the 3-strike threshold for transient reasons.
private let authLog = Logger(subsystem: "at.freeq.ios", category: "auth")

// `ChatMessage` now lives in ChatMessage.swift (extracted so the pure model +
// its MessageActions decisions can be unit-tested under SwiftPM without the
// AppState UIKit/ActivityKit dependencies).

// MARK: - Local buffer cache
//
// Persists the last N messages per channel/DM (plus channel topics and DM
// peer list) to `Library/Application Support/freeq/buffers.json` so cold
// launch can render the user's recent context instantly — before SASL +
// JOIN + CHATHISTORY round-trips have completed. Saved on scene-background,
// disconnect, and logout. CHATHISTORY from the wire dedupes against the
// hydrated state via `ChannelState.appendIfNew`.

private struct CachedReactions: Codable {
    let byEmoji: [String: [String]]
    init(_ r: [String: Set<String>]) {
        var d: [String: [String]] = [:]
        for (k, v) in r { d[k] = Array(v) }
        self.byEmoji = d
    }
    func toDict() -> [String: Set<String>] {
        var d: [String: Set<String>] = [:]
        for (k, v) in byEmoji { d[k] = Set(v) }
        return d
    }
}

private struct CachedMessage: Codable {
    let id: String
    let from: String
    let text: String
    let isAction: Bool
    let timestamp: Date
    let replyTo: String?
    let isEdited: Bool
    let isDeleted: Bool
    let isSigned: Bool
    let reactions: CachedReactions
    // The row's identity evidence. A hydrated row that lost these read
    // "Unknown" on surfaces the live ingest answered correctly — and the
    // stripped copy then shadowed the tag-bearing CHATHISTORY replay.
    let origin: String?
    let account: String?

    init(_ m: ChatMessage) {
        self.id = m.id
        self.from = m.from
        self.text = m.text
        self.isAction = m.isAction
        self.timestamp = m.timestamp
        self.replyTo = m.replyTo
        self.isEdited = m.isEdited
        self.isDeleted = m.isDeleted
        self.isSigned = m.isSigned
        self.reactions = CachedReactions(m.reactions)
        self.origin = m.origin
        self.account = m.account
    }

    func toChatMessage() -> ChatMessage {
        var m = ChatMessage(
            id: id, from: from, text: text, isAction: isAction,
            timestamp: timestamp, replyTo: replyTo, isSigned: isSigned)
        m.isEdited = isEdited
        m.isDeleted = isDeleted
        m.reactions = reactions.toDict()
        m.origin = origin
        m.account = account
        return m
    }
}

private struct CachedBuffer: Codable {
    let name: String
    let isDM: Bool
    let topic: String?
    let messages: [CachedMessage]
}

private struct BufferCacheRoot: Codable {
    let version: Int
    let buffers: [CachedBuffer]
}

enum BufferCacheStore {
    // 2: messages carry origin + account. The bump discards caches written
    // without them, so stale evidence-less rows rebuild from replay.
    static let version = 2
    static let maxMessagesPerBuffer = 50

    static func cacheURL() -> URL? {
        let fm = FileManager.default
        guard let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
        let dir = appSupport.appendingPathComponent("freeq", isDirectory: true)
        if !fm.fileExists(atPath: dir.path) {
            do { try fm.createDirectory(at: dir, withIntermediateDirectories: true) } catch { return nil }
        }
        return dir.appendingPathComponent("buffers.json")
    }

    fileprivate static func load() -> BufferCacheRoot? {
        guard let url = cacheURL(),
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(BufferCacheRoot.self, from: data)
    }

    fileprivate static func save(_ root: BufferCacheRoot) {
        guard let url = cacheURL() else { return }
        guard let data = try? JSONEncoder().encode(root) else { return }
        // `.completeFileProtection` matches the Keychain's
        // `kSecAttrAccessibleAfterFirstUnlock` accessibility class: data is
        // encrypted at rest and only readable while the device is unlocked.
        try? data.write(to: url, options: [.atomic, .completeFileProtection])
    }

    static func clear() {
        guard let url = cacheURL() else { return }
        try? FileManager.default.removeItem(at: url)
    }
}

extension ISO8601DateFormatter {
    /// Shared formatter for the server's CHATHISTORY TARGETS `time` tag
    /// (`YYYY-MM-DDTHH:MM:SS.sssZ`). Cached because `ISO8601DateFormatter`
    /// is expensive to construct.
    static let freeqTargets: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
}

// ChannelState + MemberInfo live in Models/ChannelState.swift (SwiftPM
// FreeqIosCore member, so the DM identity/merge logic is unit-testable).
// The AvatarCache-dependent member collapsing stays here, app-side:
extension ChannelState {
    /// Members collapsed to one row per account (same DID). Multi-session or
    /// nick-collision twins (e.g. chadfowler.com / chadfowlercom, or a bot that
    /// reconnected N times) count once. DID resolves from the roster or the
    /// avatar cache; guests (no resolvable DID) are kept. Prefers the fuller
    /// (dotted) handle for display. Single source for member lists + counts.
    /// @MainActor because it reads the main-actor AvatarCache; all callers are
    /// SwiftUI views.
    @MainActor
    var uniqueMembers: [MemberInfo] {
        var indexByDid: [String: Int] = [:]
        var out: [MemberInfo] = []
        for m in members {
            guard let did = m.did ?? AvatarCache.shared.did(for: m.nick) else {
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

    @MainActor
    var uniqueMemberCount: Int { uniqueMembers.count }
}


/// Connection state.
enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case registered
}

// MARK: - AV testability shims

/// Minimal interface AppState needs out of the MoQ-backed AV session. The
/// concrete `FreeqAv` from the Rust SDK conforms via the extension below.
/// Tests substitute a fake.
protocol AvSessionDriver: AnyObject {
    func setMuted(muted: Bool)
    func setCameraEnabled(enabled: Bool) throws
    func pushVideoFrame(bgra: [UInt8], width: UInt32, height: UInt32, timestampUs: UInt64)
    func pushAudioFrame(samples: [Float])
    func leave()
    func isConnected() -> Bool
}

// Default no-op so test fakes don't have to implement audio push — the
// real `FreeqAv` provides the UniFFI-generated implementation.
extension AvSessionDriver {
    func pushAudioFrame(samples: [Float]) {}
}

extension FreeqAv: AvSessionDriver {}

/// Outcome of a REST probe for an active session on a channel.
enum ActiveSessionProbe {
    case found(sessionId: String)
    case none
}

/// Main application state — bridges the Rust SDK to SwiftUI.
class AppState: ObservableObject {
    private static let minimumPersistentSessionDuration: TimeInterval = 14 * 24 * 60 * 60  // 14 days
    struct BatchBuffer {
        let target: String
        var messages: [ChatMessage]
    }

    @Published var connectionState: ConnectionState = .disconnected
    @Published var nick: String = ""
    /// Passphrase channel E2EE (parity with web + macOS). Value type; mutated
    /// in place. Keys persist to the keychain per channel.
    var channelE2ee = ChannelE2eeState()
    /// Cross-device read markers (draft/read-marker): target (lowercased) →
    /// latest read timestamp. Forward-only, enforced server-side. Stored so
    /// the unread-divider / catch-up UI can consume it.
    var readMarkers: [String: String] = [:]
    @Published var serverAddress: String = ServerConfig.ircServer
    /// Per-session REST bearer (session id), parsed from the API-BEARER
    /// NOTICE. Identifies our DID for authenticated REST (roaming favorites).
    var apiBearerSessionId: String?
    @Published var authBrokerBase: String = ServerConfig.authBrokerBase
    @Published var channels: [ChannelState] = []
    @Published var activeChannel: String? = nil {
        didSet {
            // Persist so the app reopens the last conversation on next launch.
            if let activeChannel { UserDefaults.standard.set(activeChannel, forKey: LastChannel.key) }
        }
    }
    /// True once we've restored the last-open channel this launch, so a later
    /// channel joining doesn't re-hijack the user's current selection.
    private var didRestoreLastChannel = false
    @Published var errorMessage: String? = nil
    @Published var authenticatedDID: String? = nil
    @Published var dmBuffers: [ChannelState] = []
    @Published var autoJoinChannels: [String] = ["#general"]

    /// Channels this device asked to leave, and when.
    ///
    /// A PART echo identifies the leaver by nick, shared by every device of this
    /// identity, so intent is the only way to attribute it. See `SelfPartResolve`.
    var pendingPartRequests: [String: Date] = [:]
    @Published var unreadCounts: [String: Int] = [:] {
        didSet { UserDefaults.standard.set(unreadCounts, forKey: "freeq.unreadCounts") }
    }

    /// Muted channels — no notifications, no badge increment
    @Published var mutedChannels: Set<String> = [] {
        didSet { UserDefaults.standard.set(Array(mutedChannels), forKey: "freeq.mutedChannels") }
    }

    /// Favorited channels/DMs, pinned to the top of the list. Stored by exact
    /// name so it round-trips through UserDefaults.
    @Published var favorites: Set<String> = [] {
        didSet { UserDefaults.standard.set(Array(favorites), forKey: "freeq.favorites") }
    }

    /// Favorite buffer names in user-visible order (newest-favorited last).
    /// Drives the Favorites section order and ⌃⌘1–9 "go to favorite N". Kept in
    /// sync with `favorites` by `toggleFavorite`.
    @Published var favoritesOrder: [String] = [] {
        didSet { UserDefaults.standard.set(favoritesOrder, forKey: "freeq.favoritesOrder") }
    }

    /// Saved messages (parity with web + macOS). Persisted to UserDefaults.
    struct Bookmark: Identifiable, Codable, Equatable {
        var id: String { msgId }
        let channel: String
        let msgId: String
        let from: String
        let text: String
        let timestamp: Date
    }
    @Published var bookmarks: [Bookmark] = [] {
        didSet {
            if let data = try? JSONEncoder().encode(bookmarks) {
                UserDefaults.standard.set(data, forKey: "freeq.bookmarks")
            }
        }
    }
    @Published var showBookmarks = false

    func isBookmarked(_ msgId: String) -> Bool {
        bookmarks.contains { $0.msgId == msgId }
    }

    func toggleBookmark(channel: String, msg: ChatMessage) {
        if let idx = bookmarks.firstIndex(where: { $0.msgId == msg.id }) {
            bookmarks.remove(at: idx)
        } else {
            bookmarks.append(Bookmark(channel: channel, msgId: msg.id,
                                      from: msg.from, text: msg.text, timestamp: msg.timestamp))
        }
    }

    // Command-driven sheet triggers (hardware-keyboard shortcuts on iPad).
    @Published var showQuickSwitcher = false
    @Published var showJoinSheet = false
    @Published var showSearchSheet = false
    @Published var showShortcutsHelp = false
    @Published var showNewDMSheet = false
    /// Member-list panel visibility for the active channel (⇧⌘D). Lifted from
    /// ChatDetailView so a keyboard shortcut can toggle it.
    @Published var showMemberList = false

    /// DM peers the user has explicitly closed. Stored lowercased so we
    /// can compare against any case-shape the server hands back. Closed
    /// DMs are:
    ///   - skipped during cache hydration on cold launch
    ///   - skipped when the server sends `CHATHISTORY TARGETS` on register
    /// A close is automatically *undone* when the peer sends a new PRIVMSG
    /// (incoming activity is the universal signal that we want the DM
    /// back), or when the user manually opens a new DM with that nick.
    // MARK: - DID-keyed DM identity
    /// DID → display nick, learned from account tags, MemberDid events, and
    /// the conversation list's partner-did. Display-grade: survives the peer
    /// going offline, so a DID-keyed thread keeps rendering as a name.
    @Published var didDisplayNames: [String: String] = [:]
    /// Lowercased nick → DID (account tags / MemberDid / partner-did).
    /// Includes did:key identities, which AvatarCache deliberately refuses.
    var knownDids: [String: String] = [:]

    /// Human label for a thread key that may be a raw DID (see DidDisplay).
    func displayNameForKey(_ key: String) -> String {
        DidDisplay.displayName(
            key: key,
            bindings: didDisplayNames,
            reverseNick: { [weak self] did in
                self?.knownDids.first(where: { $0.value == did })?.key
            }
        )
    }

    /// The DID bound to a nick, when known. Used to open/key DM threads
    /// under their canonical (DID) key.
    func didForNick(_ nick: String) -> String? {
        knownDids[nick.lowercased()]
    }

    // ── The identity lookup machine (port of macOS, 401-first from day one) ──

    /// What a card should assume about a nick it has asked about.
    @Published var identityLookups: [String: IdentityLookup] = [:]

    /// Signature answers the reader has already asked for, by message id.
    /// A settled answer is the same every time; only a checked mismatch
    /// marks a row, so this is also what the row marker reads.
    @Published var checkedVerdicts: [String: VerifyAnswer] = [:]

    /// Nicks the server answered with "no such nick". They are not guests —
    /// nobody is holding the name, so there is nobody to have an account.
    private var whoisNoSuchNick: Set<String> = []

    /// Only a backstop; the real answer is the server's end-of-WHOIS.
    private static let identityLookupTimeout: TimeInterval = 5.0

    /// Ask who this nick is, for a card the reader just opened. Asks once;
    /// a live-known binding needs nothing; an ask already out is not
    /// repeated.
    func lookUpIdentity(nick: String) {
        let key = nick.lowercased()
        guard !key.isEmpty else { return }
        guard liveDidForNick(nick) == nil, identityLookups[key] == nil else { return }
        whoisNoSuchNick.remove(key)
        identityLookups[key] = .inFlight
        try? client?.requestWhois(nick: nick)
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.identityLookupTimeout) { [weak self] in
            guard let self, self.identityLookups[key] == .inFlight else { return }
            self.identityLookups.removeValue(forKey: key)
        }
    }

    /// The server says nobody holds this name.
    func noteWhoisNoSuchNick(nick: String) {
        whoisNoSuchNick.insert(nick.lowercased())
    }

    /// The server has finished answering. Nobody-holds-this-name always
    /// wins: a 401 says nothing about anybody, and a DID the cache happens
    /// to remember must never be laundered into "the answer named one" —
    /// that is the stale-cache vote this design exists to end.
    func settleIdentityLookup(_ nickOrKey: String) {
        let key = nickOrKey.lowercased()
        guard identityLookups[key] == .inFlight else { return }
        if whoisNoSuchNick.contains(key) {
            identityLookups.removeValue(forKey: key)
        } else if didForNick(key) != nil {
            identityLookups[key] = .answeredDid
        } else {
            identityLookups[key] = .noAccount
        }
    }

    /// True when the nick is in some channel roster right now.
    func isNickPresent(_ nick: String) -> Bool {
        channels.contains { ch in
            ch.members.contains { $0.nick.caseInsensitiveCompare(nick) == .orderedSame }
        }
    }

    /// The nick's DID, only when it is live-known: in a roster right now, or
    /// a WHOIS answered with it this session. A binding remembered from an
    /// earlier session never votes on identity; the persisted map stays for
    /// display and addressing, where staleness costs a name, not a claim.
    func liveDidForNick(_ nick: String) -> String? {
        let answered = identityLookups[nick.lowercased()] == .answeredDid
        return (answered || isNickPresent(nick)) ? didForNick(nick) : nil
    }

    /// The lookup state in the SDK's vocabulary, for the claim functions.
    func personLookup(for nick: String) -> PersonLookup {
        let key = nick.lowercased()
        switch identityLookups[key] {
        case .inFlight: return .inFlight
        case .noAccount: return .noAccount
        default: return whoisNoSuchNick.contains(key) ? .noSuchNick : .notAsked
        }
    }

    /// Canonical buffer key for opening a conversation: channels and DIDs pass
    /// through; a nick follows its DID binding when known, so every open path
    /// (compose sheet, deep link, intent, profile tap) lands in the one thread.
    func canonicalDmKey(_ target: String) -> String {
        if target.hasPrefix("#") || target.hasPrefix("&") || DidDisplay.isDid(target) {
            return target
        }
        return didForNick(target) ?? target
    }

    /// Only the original sender may edit/delete a message: DID comparison
    /// when both sides are known, else nick. Unpersisted guest threads rely
    /// on this — the server relays their edits/deletes without a DB row to
    /// verify against. A missing original passes (apply will no-op anyway).
    func authorMatches(in buffer: ChannelState, originalId: String,
                       actorNick: String, actorAccount: String?) -> Bool {
        guard let idx = buffer.findMessage(byId: originalId) else { return true }
        let original = buffer.messages[idx]
        if let acct = actorAccount, let origDid = didForNick(original.from) {
            return acct == origDid
        }
        return actorNick.lowercased() == original.from.lowercased()
    }

    /// Blocked check for a DM buffer key, which may be a DID rather than the
    /// nick the block was recorded under.
    func isBufferBlocked(_ key: String) -> Bool {
        if DidDisplay.isDid(key) {
            if blockedDIDs.contains(key) { return true }
            return isBlocked(nick: displayNameForKey(key))
        }
        return isBlocked(nick: key, did: didForNick(key))
    }

    /// Record a learned nick↔DID binding everywhere identity is consumed:
    /// the identity maps (thread keying + labels) and channel member entries
    /// (DID-gated UI).
    func recordUserDid(nick: String, did: String) {
        knownDids[nick.lowercased()] = did
        didDisplayNames[did] = nick
        for ch in channels {
            if let idx = ch.members.firstIndex(where: { $0.nick.lowercased() == nick.lowercased() }),
               ch.members[idx].did == nil {
                let m = ch.members[idx]
                ch.members[idx] = MemberInfo(nick: m.nick, isOp: m.isOp, isHalfop: m.isHalfop,
                                             isVoiced: m.isVoiced, awayMsg: m.awayMsg, did: did)
            }
        }
    }

    /// Record a binding and fold any nick-keyed DM thread into the DID-keyed
    /// one, repointing the active thread and carrying closed state. Shared by
    /// MemberDid (live learning) and the conversation list's partner-did —
    /// an OFFLINE peer never produces a live MemberDid, so without the
    /// TARGETS path a stale nick thread and the DID thread coexist as
    /// duplicate rows.
    func adoptDmBinding(nick: String, did: String) {
        recordUserDid(nick: nick, did: did)
        if DidDisplay.mergeDmBuffers(
            dmBuffers: &dmBuffers, unreadCounts: &unreadCounts, nick: nick, did: did
        ) {
            if activeChannel?.lowercased() == nick.lowercased() {
                activeChannel = did
            }
            if closedDMs.contains(nick.lowercased()) {
                closedDMs.insert(did.lowercased())
            }
        }
    }

    @Published var closedDMs: Set<String> = [] {
        didSet { UserDefaults.standard.set(Array(closedDMs), forKey: "freeq.closedDMs") }
    }

    /// MOTD lines collected from server
    @Published var motdLines: [String] = []
    @Published var showMotd: Bool = false
    fileprivate var collectingMotd: Bool = false

    // In-flight CHATHISTORY batches
    fileprivate var batches: [String: BatchBuffer] = [:]

    /// Pending DM navigation — set by profile "Message" button, consumed by ChatsTab
    @Published var pendingDMNick: String? = nil
    /// Pending channel navigation — set by the catch-up digest, consumed by the
    /// Channels pane of ChatsTab to push that channel.
    @Published var pendingChannelNav: String? = nil

    // ── Safety: blocking & reporting (App Store UGC requirement) ──
    // Blocked by DID when we have one (stable across nick changes); by
    // lowercased nick otherwise. Blocked people's messages are hidden and their
    // DMs suppressed.
    @Published var blockedDIDs: Set<String> = Set(UserDefaults.standard.stringArray(forKey: "freeq.blockedDIDs") ?? []) {
        didSet { UserDefaults.standard.set(Array(blockedDIDs), forKey: "freeq.blockedDIDs") }
    }
    @Published var blockedNicks: Set<String> = Set(UserDefaults.standard.stringArray(forKey: "freeq.blockedNicks") ?? []) {
        didSet { UserDefaults.standard.set(Array(blockedNicks), forKey: "freeq.blockedNicks") }
    }

    func isBlocked(nick: String, did: String? = nil) -> Bool {
        if let did, !did.isEmpty, blockedDIDs.contains(did) { return true }
        return blockedNicks.contains(nick.lowercased())
    }

    /// Whether a message/tag came from us. Prefers the account DID — robust to
    /// nick case and to force-renames across our own sessions, unlike a raw nick
    /// compare (a stale `nick` made our own DM echoes look like incoming DMs,
    /// spawning a phantom self-DM buffer + notification). Falls back to nick.
    func isSelfSender(nick sender: String, account: String?) -> Bool {
        if let account, !account.isEmpty, let mine = authenticatedDID, account == mine { return true }
        return sender.lowercased() == nick.lowercased()
    }

    func blockUser(nick: String, did: String?) {
        if let did, !did.isEmpty { blockedDIDs.insert(did) }
        blockedNicks.insert(nick.lowercased())
    }

    func unblockUser(nick: String?, did: String?) {
        if let did { blockedDIDs.remove(did) }
        if let nick { blockedNicks.remove(nick.lowercased()) }
    }

    /// Record a user's report of a message/user. There's no server report
    /// endpoint yet, so we hide the content immediately and block the author —
    /// report-and-block — which is the user-visible remedy App Review requires.
    /// The reason is logged for the eventual moderation pipeline.
    func reportUser(nick: String, did: String?, reason: String) {
        authLog.notice("user report: nick=\(nick, privacy: .public) reason=\(reason, privacy: .public)")
        blockUser(nick: nick, did: did)
    }

    // ── AV (voice/video calls) ──
    @Published var isInCall: Bool = false
    @Published var isMuted: Bool = false
    @Published var isCameraOn: Bool = false
    /// True when the user has expanded the call to fill the screen.
    @Published var isCallExpanded: Bool = false
    /// True when call audio is on the loud speaker (vs the quiet handset
    /// receiver). Defaults on — a call should be audible at arm's length.
    @Published var isSpeakerOn: Bool = true
    @Published var callParticipants: [String] = []
    /// channel (lowercased) → active session id, populated from `+freeq.at/av-state` TAGMSGs
    @Published var activeAvSessions: [String: String] = [:]
    /// Channel + session id of the call we're currently in (if any).
    @Published var currentCallChannel: String? = nil
    @Published var currentCallSessionId: String? = nil
    var currentNick: String? { client != nil ? nick : nil }
    /// Active AV session driver. Typed as a protocol so tests can swap in a
    /// fake — production binds the concrete `FreeqAv` via `avSessionFactory`.
    internal var avSession: AvSessionDriver? = nil
    /// Channels where we sent `av-start` and are waiting on the server's `started` echo.
    internal var pendingAvStart: Set<String> = []

    /// Test hook: when set, `sendRaw` lines for AV TAGMSGs are diverted to
    /// this closure instead of `client?.sendRaw`. Tests use it to capture
    /// the exact wire payloads we put on the IRC connection.
    internal var rawSenderForTest: ((String) -> Void)? = nil

    /// Media dial held between av-join and the server's av-token TAGMSG
    /// (tokenless fallback after a short wait). See `mediaDialUrl` (audit F7).
    internal var pendingMediaDial: PendingMediaDial? = nil
    /// Periodic roster reconciliation while in a call (audit F9).
    internal var rosterReconcileTimer: Timer? = nil

    /// Test hook: returns the active session id (or .none) for a channel,
    /// replacing the live REST probe used in `discoverAndJoinOrStart`. When
    /// nil (the production default), the REST probe runs normally.
    internal var activeSessionProbeForTest: ((String) async -> ActiveSessionProbe)? = nil

    /// Test hook: factory for the AV driver. Production builds a `FreeqAv`;
    /// tests substitute a stub that records calls and re-emits AvEvents via
    /// the handler. Returning nil from the closure simulates a failed
    /// constructor (the production path catches and rolls back).
    internal var avSessionFactory: ((_ serverUrl: String, _ sessionId: String, _ nick: String, _ instanceId: String, _ handler: AvEventHandler) throws -> AvSessionDriver)? = nil
    /// Live Activity tracking the in-call state. Drives the Dynamic Island.
    fileprivate var callActivity: Activity<CallActivityAttributes>? = nil

    /// Front-camera capture. Allocated on first `toggleCamera(true)`; the
    /// capture session itself is started/stopped here. Held across toggles
    /// so we don't pay the AVCaptureSession setup cost more than once per
    /// call.
    internal var cameraCapture: CallCameraCapture? = nil

    /// Swift-driven mic capture. Runs for the whole call (audio is
    /// always-on, unlike the camera). Held so `leaveCall` can stop it.
    internal var micCapture: CallMicCapture? = nil

    /// Per-nick remote video display layers, keyed by lower-cased nick. Set
    /// by `RemoteVideoTile` when it appears; cleared when the underlying
    /// view goes away (weak values let the table drop the entry).
    fileprivate var remoteVideoLayers: NSMapTable<NSString, AVSampleBufferDisplayLayer> =
        NSMapTable.strongToWeakObjects()

    /// Per-nick remote screen-share display layers, keyed by lower-cased nick.
    /// Set by `RemoteScreenTile` when it appears; cleared when the view goes
    /// away (weak values). Kept separate from `remoteVideoLayers` so a peer's
    /// camera and screen render into independent tiles.
    fileprivate var remoteScreenLayers: NSMapTable<NSString, AVSampleBufferDisplayLayer> =
        NSMapTable.strongToWeakObjects()

    /// Set of nicks for which we've received at least one frame this call.
    /// Drives the "video active" indicator on the participant tile.
    @Published var participantsWithVideo: Set<String> = []

    /// Nicks with a live screen-share broadcast (the `{peer}/screen` MoQ
    /// path). Distinct from `participantsWithVideo` (the camera track) so a
    /// participant can share their screen and their camera at the same time,
    /// each rendered in its own tile.
    @Published var participantsWithScreen: Set<String> = []

    /// Remote playout levels (lowercased nick → 0…1) from
    /// `AvEvent.audioLevel`. Stored for active-speaker highlighting; the iOS
    /// call UI does not draw a speaking ring yet, so this is currently a data
    /// sink the UI can start reading whenever that indicator lands.
    @Published var remoteAudioLevels: [String: Float] = [:]

    /// Quiet in-call transport status ("Reconnecting…"), shown inline in the
    /// call controls bar — never as a modal alert. Reconnection is automatic,
    /// so it must not look like a hard failure. nil when the transport is
    /// healthy.
    @Published var callTransportStatus: String? = nil

    /// Local-preview wrapper for the call UI to bind against. Returns nil
    /// when the camera is off.
    var localPreviewCapture: CallCameraCapture? { cameraCapture }

    /// Per-call instance identifier — short random hex generated when we
    /// start or join an AV session. Sent on every av-join/av-leave TAGMSG
    /// as `+freeq.at/av-instance=<id>`, and used by the SDK to suffix the
    /// MoQ broadcast path so two devices on the same DID don't collide.
    internal var currentAvInstance: String? = nil

    /// Maps a remote device's stable AV instance id → the nick it joined
    /// under. Populated from `AvEvent.participantJoined` (and the `joined`
    /// `av-state` TAGMSG). Used to key presence teardown on the instance
    /// rather than the nick, since a multi-nick account can present a
    /// different nick on the `left` signal than the one it joined with.
    internal var avInstanceToNick: [String: String] = [:]

    /// If a connection blip tears down a live call, we stash its identity here
    /// so a reconnect that re-joins the same channel can rejoin the *same* AV
    /// session with the *same* instance — reactivating the server's grace-held
    /// slot in place rather than starting a fresh call. Cleared on an explicit
    /// leave (an intentional leave must never auto-rejoin) and once consumed or
    /// once the grace window has passed.
    internal var pendingCallRejoin: PendingCallRejoin? = nil

    func startCall(channel: String, sessionId: String) {
        guard client != nil || rawSenderForTest != nil else { return }
        // (The dial URL is built in dialMedia — ServerConfig.sfuBaseUrl plus
        // `inst=` and, when the server mints one, `jwt=`. Native and web both
        // terminate in the SAME moq_relay::Cluster and share one broadcast
        // namespace, so QUIC/WS participants see and hear each other.)

        // iOS won't let cpal/iroh-live open both mic and speaker until the
        // app's AVAudioSession is configured for two-way voice. Without this,
        // the audio backend gets 0 Hz back from the hardware and bails out
        // with "device no longer available" before the MoQ session is even
        // constructed. Other code paths (voice-message recording, audio
        // playback) leave the session in `.record` or `.playback`, both of
        // which would block the AV path.
        Self.activateVoiceCallSession()

        // Reuse the instance generated at av-start if we have one (so the
        // server-side instance recorded for the av-start TAGMSG, the FreeqAv
        // broadcast path, and the av-join TAGMSG all match). Otherwise mint
        // a fresh one — that's the path taken when we're joining a session
        // someone else already started.
        let instance = currentAvInstance ?? Self.generateAvInstanceId()
        currentAvInstance = instance

        // Join FIRST (join → token → dial; audit F7): the roster admits us
        // and the server replies with the per-session media token
        // (+freeq.at/av-token TAGMSG). The media dial is held until the token
        // lands, with a short tokenless fallback for servers that don't mint.
        sendRawLine(
            "@+freeq.at/av-join;+freeq.at/av-id=\(sessionId);+freeq.at/av-instance=\(instance) TAGMSG \(channel)"
        )
        // Tests run synchronously without a real RunLoop spinning the
        // main queue; dispatch async would defer state mutation past the
        // end of the test. Use `runOnMain` so tests see immediate updates.
        runOnMain {
            self.isInCall = true
            self.isSpeakerOn = true
            self.currentCallChannel = channel
            self.currentCallSessionId = sessionId
            self.startCallActivity(channel: channel, sessionId: sessionId)
            // Surface as a system call (Recents, lock screen, green pill).
            CallKitManager.shared.onEnd = { [weak self] in self?.leaveCall() }
            CallKitManager.shared.onSetMuted = { [weak self] muted in
                guard let self, self.isMuted != muted else { return }
                self.toggleMute()
            }
            CallKitManager.shared.reportStarted(channel: channel)
        }
        let pending = PendingMediaDial(channel: channel, sessionId: sessionId, instance: instance)
        pendingMediaDial = pending
        startRosterReconciliation()
        if rawSenderForTest != nil {
            // Test harness: no RunLoop to fire the fallback timer — dial
            // immediately (tokenless), same observable flow as before.
            dialMedia(token: nil)
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
                guard let self,
                      shouldDialOnFallback(pending: self.pendingMediaDial, expected: pending)
                else { return }
                print("[av] no av-token within fallback window — dialing tokenless")
                self.dialMedia(token: nil)
            }
        }
    }

    /// `+freeq.at/av-token` TAGMSG — the per-session media token minted by
    /// the server right after our av-join. Triggers the held dial.
    func handleAvToken(sessionId: String, token: String) {
        guard shouldDialOnToken(pending: pendingMediaDial, tokenSessionId: sessionId) else { return }
        dialMedia(token: token)
    }

    /// Construct the MoQ session and start mic capture. `token` nil = legacy
    /// tokenless dial (fallback/test path).
    private func dialMedia(token: String?) {
        guard let pending = pendingMediaDial else { return }
        pendingMediaDial = nil
        // The call may have been torn down (av-error, leave) since the join.
        guard avSession == nil, isInCall, currentCallSessionId == pending.sessionId else { return }
        let url = mediaDialUrl(base: ServerConfig.sfuBaseUrl, instance: pending.instance, token: token)
        do {
            let handler = AvCallbackHandler(appState: self)
            if let factory = avSessionFactory {
                avSession = try factory(url, pending.sessionId, nick, pending.instance, handler)
            } else {
                avSession = try FreeqAv(
                    serverUrl: url,
                    sessionId: pending.sessionId,
                    nick: nick,
                    instanceId: pending.instance,
                    handler: handler
                )
            }
            // Start Swift-driven mic capture for the broadcast. Audio is
            // always-on for a call, so this runs for the whole session.
            startLocalMic()
        } catch {
            print("[av] Failed to dial media: \(error)")
            // Hand the audio hardware back and tear down the half-open call.
            Self.deactivateVoiceCallSession()
            tearDownCallLocallyOnDisconnect()
        }
    }

    /// Reconcile the visible participant strip against the REST roster every
    /// 5 s while in a call (audit F9). Display-only — media is announcement-
    /// driven and unaffected.
    private func startRosterReconciliation() {
        stopRosterReconciliation()
        guard rawSenderForTest == nil else { return } // no polling in tests
        rosterReconcileTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { await self?.reconcileRosterOnce() }
        }
    }

    internal func stopRosterReconciliation() {
        rosterReconcileTimer?.invalidate()
        rosterReconcileTimer = nil
    }

    func reconcileRosterOnce() async {
        guard isInCall, let sid = currentCallSessionId,
              let url = URL(string: "\(ServerConfig.apiBaseUrl)/api/v1/sessions/\(sid)") else { return }
        var req = URLRequest(url: url)
        req.timeoutInterval = 4
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let parts = json["participants"] as? [[String: Any]] else { return }
        let roster: [AvRosterEntry] = parts.compactMap { p in
            guard let n = p["nick"] as? String else { return nil }
            return AvRosterEntry(nick: n, instance: p["instance_id"] as? String)
        }
        await MainActor.run {
            guard self.isInCall, self.currentCallSessionId == sid else { return }
            for entry in roster {
                if let inst = entry.instance, !inst.isEmpty {
                    self.avInstanceToNick[inst] = entry.nick
                }
            }
            self.callParticipants = reconcileCallParticipants(
                roster: roster, myNick: self.nick, myInstance: self.currentAvInstance)
        }
    }

    /// Internal raw-send shim. In production this routes to the IRC client;
    /// tests can swap in `rawSenderForTest` to capture the wire payload.
    fileprivate func sendRawLine(_ line: String) {
        if let hook = rawSenderForTest {
            hook(line)
            return
        }
        try? client?.sendRaw(line: line)
    }

    /// Run a block on main without an async dispatch. Tests run on the main
    /// thread without an active RunLoop, so `DispatchQueue.main.async` would
    /// never fire before the test assertions execute. Production keeps its
    /// async semantics.
    fileprivate func runOnMain(_ block: @escaping () -> Void) {
        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    /// 8-char lowercase hex. Short enough to keep broadcast paths readable;
    /// 4 bytes of entropy is plenty for collision avoidance within a session.
    private static func generateAvInstanceId() -> String {
        var bytes = [UInt8](repeating: 0, count: 4)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Set up the iOS audio session for a duplex voice call before the Rust
    /// AV backend tries to open any audio units. `.playAndRecord` allows
    /// simultaneous mic + speaker; `.voiceChat` mode picks an echo-cancelled
    /// audio route appropriate for a call; `.defaultToSpeaker` keeps audio
    /// on the loudspeaker by default; `.allowBluetooth` lets headsets work.
    private static func activateVoiceCallSession() {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(
                .playAndRecord,
                mode: .voiceChat,
                options: [.defaultToSpeaker, .allowBluetooth, .allowBluetoothA2DP]
            )
            try session.setActive(true, options: [])
        } catch {
            print("[av] AVAudioSession setup failed: \(error)")
        }
    }

    /// Deactivate the voice call session so other audio paths (push
    /// notifications, voice-message recording, link previews) can grab the
    /// hardware back. `.notifyOthersOnDeactivation` lets the system know to
    /// resume any music apps that were ducked during the call.
    private static func deactivateVoiceCallSession() {
        try? AVAudioSession.sharedInstance().setActive(
            false,
            options: .notifyOthersOnDeactivation
        )
    }

    func leaveCall() {
        // Send av-leave for the channel we're currently in, if any.
        if let channel = currentCallChannel, let sessionId = currentCallSessionId {
            let instanceTag = currentAvInstance.map { ";+freeq.at/av-instance=\($0)" } ?? ""
            sendRawLine("@+freeq.at/av-leave;+freeq.at/av-id=\(sessionId)\(instanceTag) TAGMSG \(channel)")
        }
        // Explicit leave — a reconnect must NOT drag us back into the call.
        pendingCallRejoin = nil
        pendingMediaDial = nil
        stopRosterReconciliation()
        cameraCapture?.stop()
        cameraCapture = nil
        micCapture?.stop()
        micCapture = nil
        avSession?.leave()
        avSession = nil
        currentAvInstance = nil
        Self.deactivateVoiceCallSession()
        CallKitManager.shared.reportEnded()
        runOnMain {
            self.isInCall = false
            self.isMuted = false
            self.isCameraOn = false
            self.isCallExpanded = false
            self.callParticipants = []
            self.participantsWithVideo = []
            self.participantsWithScreen = []
            self.remoteAudioLevels = [:]
            self.callTransportStatus = nil
            self.currentCallChannel = nil
            self.currentCallSessionId = nil
            self.endCallActivity()
        }
    }

    func toggleMute() {
        isMuted.toggle()
        avSession?.setMuted(muted: isMuted)
        updateCallActivity()
        CallKitManager.shared.reflectMuted(isMuted)
    }

    /// Toggle call audio between the loud speaker and the handset
    /// receiver — the iOS equivalent of a speakerphone button.
    func toggleSpeaker() {
        isSpeakerOn.toggle()
        let port: AVAudioSession.PortOverride = isSpeakerOn ? .speaker : .none
        do {
            try AVAudioSession.sharedInstance().overrideOutputAudioPort(port)
        } catch {
            print("[av] speaker toggle failed: \(error)")
        }
    }

    /// Test helper: drives the AV event handler synchronously from outside
    /// the FFI. Production code never calls this; tests use it to simulate
    /// participant join/leave/disconnect events without standing up a real
    /// `FreeqAv`.
    internal func deliverAvEventForTest(_ event: AvEvent) {
        let handler = AvCallbackHandler(appState: self)
        handler.onAvEvent(event: event)
        withExtendedLifetime(handler) {}
    }

    /// Tear down an in-progress call when the IRC connection itself dropped.
    /// Unlike `leaveCall`, this does NOT try to send `av-leave` — the wire is
    /// gone. Otherwise identical: stop capture, close the MoQ session, clear
    /// UI state.
    internal func tearDownCallLocallyOnDisconnect() {
        pendingMediaDial = nil
        stopRosterReconciliation()
        // Capture the call identity BEFORE clearing state so a reconnect that
        // re-joins this channel can rejoin the same session+instance within
        // the server's AV grace window. Only when we're actually in a call.
        if isInCall,
           let channel = currentCallChannel,
           let sessionId = currentCallSessionId,
           let instance = currentAvInstance {
            pendingCallRejoin = PendingCallRejoin(
                channel: channel,
                sessionId: sessionId,
                instance: instance,
                disconnectedAt: Date()
            )
        }
        cameraCapture?.stop()
        cameraCapture = nil
        micCapture?.stop()
        micCapture = nil
        avSession?.leave()
        avSession = nil
        currentAvInstance = nil
        Self.deactivateVoiceCallSession()
        CallKitManager.shared.reportEnded()
        runOnMain {
            self.isInCall = false
            self.isMuted = false
            self.isCameraOn = false
            self.isCallExpanded = false
            self.callParticipants = []
            self.participantsWithVideo = []
            self.participantsWithScreen = []
            self.remoteAudioLevels = [:]
            self.callTransportStatus = nil
            self.currentCallChannel = nil
            self.currentCallSessionId = nil
            self.endCallActivity()
        }
    }

    // MARK: - Live Activity (Dynamic Island)

    /// Start the in-call Live Activity. The Dynamic Island will show the
    /// channel + duration + participant count + mute state until `endCallActivity`.
    fileprivate func startCallActivity(channel: String, sessionId: String) {
        // Make sure no stale activity from a prior call is still alive.
        endCallActivity()
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            // User has Live Activities disabled at the OS level.
            return
        }
        let attrs = CallActivityAttributes(channel: channel, sessionId: sessionId)
        let state = CallActivityAttributes.ContentState(
            participantCount: max(callParticipants.count, 1),
            isMuted: isMuted,
            startedAt: Date()
        )
        do {
            callActivity = try Activity<CallActivityAttributes>.request(
                attributes: attrs,
                content: .init(state: state, staleDate: nil),
                pushType: nil
            )
        } catch {
            print("[av] Failed to start Live Activity: \(error)")
        }
    }

    /// Push the current participant / mute state to the Live Activity.
    fileprivate func updateCallActivity() {
        guard let activity = callActivity else { return }
        let started = activity.content.state.startedAt
        let new = CallActivityAttributes.ContentState(
            participantCount: max(callParticipants.count, 1),
            isMuted: isMuted,
            startedAt: started
        )
        Task {
            await activity.update(.init(state: new, staleDate: nil))
        }
    }

    /// End the Live Activity. Called from `leaveCall` and on AV disconnect.
    fileprivate func endCallActivity() {
        guard let activity = callActivity else { return }
        callActivity = nil
        Task {
            await activity.end(nil, dismissalPolicy: .immediate)
        }
    }

    func toggleCamera() {
        let next = !isCameraOn
        if next {
            startLocalCamera()
        } else {
            stopLocalCamera()
        }
        isCameraOn = next
    }

    /// Start Swift-driven mic capture for the call and feed samples to the
    /// broadcast. Audio is always-on, so this runs the whole call.
    fileprivate func startLocalMic() {
        guard avSession != nil else { return }
        let cap = CallMicCapture()
        cap.onSamples = { [weak self] samples in
            self?.avSession?.pushAudioFrame(samples: samples)
        }
        micCapture = cap
        cap.start()
    }

    /// Spin up `AVCaptureSession` (if needed) and turn on the publish-side
    /// video track. Idempotent.
    fileprivate func startLocalCamera() {
        guard let av = avSession else { return }
        if cameraCapture == nil {
            let cap = CallCameraCapture()
            cap.onFrame = { [weak self] ptr, length, width, height, ts in
                guard let av = self?.avSession else { return }
                let bytes = Array(UnsafeBufferPointer(start: ptr, count: length))
                av.pushVideoFrame(
                    bgra: bytes,
                    width: UInt32(width),
                    height: UInt32(height),
                    timestampUs: ts
                )
            }
            cameraCapture = cap
        }
        do {
            try av.setCameraEnabled(enabled: true)
        } catch {
            print("[av] setCameraEnabled(true) failed: \(error)")
            return
        }
        cameraCapture?.start()
    }

    fileprivate func stopLocalCamera() {
        cameraCapture?.stop()
        do {
            try avSession?.setCameraEnabled(enabled: false)
        } catch {
            // NotConnected is fine — we may be leaving the call.
            print("[av] setCameraEnabled(false): \(error)")
        }
    }

    /// Called by `RemoteVideoTile.makeUIView/updateUIView`. Weakly retains
    /// the display layer; when the SwiftUI view disappears, the layer is
    /// released and the entry self-clears.
    func bindVideoSink(nick: String, to layer: AVSampleBufferDisplayLayer) {
        remoteVideoLayers.setObject(layer, forKey: nick.lowercased() as NSString)
    }

    /// Lookup helper used by the AV event handler.
    fileprivate func videoLayer(for nick: String) -> AVSampleBufferDisplayLayer? {
        remoteVideoLayers.object(forKey: nick.lowercased() as NSString)
    }

    /// Called by `RemoteScreenTile`. Weakly retains the screen display layer.
    func bindScreenSink(nick: String, to layer: AVSampleBufferDisplayLayer) {
        remoteScreenLayers.setObject(layer, forKey: nick.lowercased() as NSString)
    }

    /// Lookup helper used by the AV event handler for screen frames.
    fileprivate func screenLayer(for nick: String) -> AVSampleBufferDisplayLayer? {
        remoteScreenLayers.object(forKey: nick.lowercased() as NSString)
    }

    /// Start or join a voice session on a channel.
    ///
    /// Always resolves the channel's *live* session from the server before
    /// joining — never from the in-memory `activeAvSessions` cache. That
    /// cache is only cleared by an `av-state=ended` TAGMSG, which is easily
    /// missed: app backgrounded, a brief disconnect, or a session that the
    /// server auto-ended with no broadcast (every Eliza/bot restart does
    /// exactly this — the old session is auto-ended and a new id minted).
    /// A stale cache entry points at a dead session, and joining it puts
    /// our MoQ broadcast under a session prefix no other participant
    /// watches — so we publish audio and video and are still unheard. The
    /// REST probe in `discoverAndJoinOrStart` is the single source of truth.
    func startOrJoinVoice(channel: String) {
        guard !isInCall else { return }

        if let probe = activeSessionProbeForTest {
            Task { @MainActor in
                switch await probe(channel) {
                case .found(let sessionId):
                    self.activeAvSessions[channel.lowercased()] = sessionId
                    self.startCall(channel: channel, sessionId: sessionId)
                case .none:
                    self.activeAvSessions.removeValue(forKey: channel.lowercased())
                    self.startFreshAvSession(channel: channel)
                }
            }
        } else {
            Task { await self.discoverAndJoinOrStart(channel: channel) }
        }
    }

    /// Resolve the channel's active AV session from the server and join it,
    /// or start a fresh one if none is running. Three outcomes:
    ///  - probe succeeds, a session is Active → join exactly that session id
    ///  - probe succeeds, nothing Active      → drop any stale cache entry,
    ///                                          send `av-start`
    ///  - probe fails (offline/unreachable)   → fall back to a cached id if
    ///                                          we have one, else `av-start`
    private func discoverAndJoinOrStart(channel: String) async {
        let key = channel.lowercased()
        let encoded = channel.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? channel
        let url = URL(string: "\(ServerConfig.apiBaseUrl)/api/v1/channels/\(encoded)/sessions")

        if let url {
            // Private channels require the bearer (same access rule as history),
            // otherwise discovery silently finds no active call.
            var req = ApiAuth.request(url, bearer: apiBearerSessionId)
            req.timeoutInterval = 4
            if let (data, _) = try? await URLSession.shared.data(for: req),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                // The probe reached the server and parsed. Its answer is
                // authoritative — trust it over any cached session id.
                if let active = json["active"] as? [String: Any],
                   let sessionState = active["state"] as? String,
                   sessionState == "Active",
                   let sessionId = active["id"] as? String {
                    await MainActor.run {
                        self.activeAvSessions[key] = sessionId
                        self.startCall(channel: channel, sessionId: sessionId)
                    }
                } else {
                    await MainActor.run {
                        self.activeAvSessions.removeValue(forKey: key)
                        self.startFreshAvSession(channel: channel)
                    }
                }
                return
            }
        }

        // Probe failed (no network / server unreachable). Fall back to a
        // cached session id if we have one — it may be stale, but it's the
        // only hint available; otherwise start fresh.
        await MainActor.run {
            if let cached = self.activeAvSessions[key] {
                self.startCall(channel: channel, sessionId: cached)
            } else {
                self.startFreshAvSession(channel: channel)
            }
        }
    }

    /// Handle a `+freeq.at/av-error` TAGMSG (machine-readable AV failure).
    /// Decision logic is the pure, unit-tested `resolveAvError`.
    func handleAvError(code: String, sessionId: String, reason: String) {
        let channel = currentCallChannel ?? (pendingAvStart.count == 1 ? pendingAvStart.first : nil)
        switch resolveAvError(
            code: code,
            errorSessionId: sessionId,
            currentCallSessionId: currentCallSessionId,
            pendingStart: !pendingAvStart.isEmpty
        ) {
        case .teardownAndRediscover:
            print("[av] join rejected (\(reason)) — tearing down ghost call state")
            tearDownCallLocallyOnDisconnect()
            if let channel {
                Task { await self.discoverAndJoinOrStart(channel: channel) }
            }
        case .joinSession(let winner):
            print("[av] start lost a race — converging on winning session \(winner)")
            if let channel {
                pendingAvStart.remove(channel.lowercased())
                startCall(channel: channel, sessionId: winner)
            }
        case .ignore:
            break
        }
    }

    /// Mint a per-device instance id, mark this channel as pending, and put
    /// `av-start` on the wire. Factored out so the testable probe-injected
    /// path can share the same body as the production REST path.
    fileprivate func startFreshAvSession(channel: String) {
        let instance = Self.generateAvInstanceId()
        currentAvInstance = instance
        pendingAvStart.insert(channel.lowercased())
        sendRawLine("@+freeq.at/av-start;+freeq.at/av-instance=\(instance) TAGMSG \(channel)")
    }

    /// For reply UI
    @Published var replyingTo: ChatMessage? = nil
    /// For edit UI
    @Published var editingMessage: ChatMessage? = nil
    /// Image lightbox
    @Published var lightboxURL: URL? = nil
    /// Pending web-token for SASL auth (from AT Protocol OAuth)
    var pendingWebToken: String? = nil
    /// Persistent broker session token. `@Published` so credential changes
    /// (sign-in, automatic wipe past grace, explicit logout) immediately
    /// re-evaluate `hasSavedSession` and flip the root UI between
    /// MainTabView and ConnectView.
    @Published var brokerToken: String? = nil
    /// Cached web-token + expiry (reuse across reconnects within TTL)
    fileprivate var cachedWebToken: String? = nil
    fileprivate var cachedWebTokenExpiry: Date = .distantPast

    /// Read position tracking — channel name -> last read message ID
    @Published var lastReadMessageIds: [String: String] = [:]

    /// Unread count captured the instant a channel is opened, BEFORE markRead
    /// clears it — powers the "while you were away" summary card. Session-only.
    @Published var awayCardCounts: [String: Int] = [:]

    /// Theme
    @Published var isDarkTheme: Bool = true

    private var client: FreeqClient? = nil
    private var typingTimer: Timer? = nil
    private var lastTypingSent: Date = .distantPast
    fileprivate var reconnectAttempts: Int = 0

    var activeChannelState: ChannelState? {
        if let name = activeChannel {
            return channels.first { $0.name == name } ?? dmBuffers.first { $0.name == name }
        }
        return nil
    }

    /// Whether we have a saved session that should auto-reconnect.
    /// True if we have a broker token — the durable, long-lived credential.
    /// No expiry window: the broker token is valid until the PDS revokes the
    /// underlying refresh token (typically 90+ days of inactivity).
    var hasSavedSession: Bool {
        // Broker token is the only signal — it's the long-lived credential.
        // Nick might be empty on first launch after migration; the broker
        // session response will provide the correct nick.
        return brokerToken != nil
    }

    /// Singleton handle for App Intents / Spotlight handoff. Set by `init`.
    /// App Intents can't easily inject the SwiftUI environment, so we expose
    /// the live instance here. Always read on main.
    static weak var shared: AppState? = nil

    /// Drops saved auth + server-scoped state when the build has been
    /// retargeted at a different deployment since the last run. The default
    /// freeq.at build never trips this; it only fires when `IRC_SERVER` /
    /// `AUTH_BROKER_BASE` change (e.g. a zerosum scheme), where the
    /// bundle-shared keychain/UserDefaults would otherwise carry a freeq.at
    /// token and session into the new host.
    private func reconcileDeploymentChange() {
        let current = ServerConfig.deploymentID
        let key = "freeq.deployment"
        let previous = UserDefaults.standard.string(forKey: key)
        UserDefaults.standard.set(current, forKey: key)
        guard let previous, previous != current else { return }

        for credential in ["brokerToken", "did", "webToken", "webTokenExpiry"] {
            KeychainHelper.delete(key: credential)
        }
        for staleKey in [
            "freeq.brokerBase", "freeq.nick", "freeq.channels", "freeq.closedDMs",
            "freeq.mutedChannels", "freeq.lastLogin", "freeq.webTokenExpiry",
            "freeq.readPositions", "freeq.unreadCounts", "freeq.motdSeenHash",
            // Legacy keychain-migration sources: clear them too, else the
            // migrateFromUserDefaults pass below re-imports a stale freeq.at
            // DID/token into the freshly-cleared keychain on retarget.
            "freeq.did", "freeq.brokerToken",
        ] {
            UserDefaults.standard.removeObject(forKey: staleKey)
        }
    }

    init() {
        AppState.shared = self
        // Interactive Live Activity buttons (mute / end call) post here; the
        // intent runs in this process so the notification reaches us directly.
        NotificationCenter.default.addObserver(
            forName: .freeqCallControl, object: nil, queue: .main
        ) { [weak self] note in
            guard let self, let action = note.object as? String else { return }
            switch CallControlAction(rawValue: action) {
            case .toggleMute: self.toggleMute()
            case .endCall: self.leaveCall()
            case .none: break
            }
        }
        reconcileDeploymentChange()
        if let savedNick = UserDefaults.standard.string(forKey: "freeq.nick") {
            nick = savedNick
        }
        // Always boot against the production server defined in ServerConfig.
        // Any legacy `freeq.server` value (from earlier staging builds) is
        // discarded so existing installs don't keep talking to the wrong host.
        serverAddress = ServerConfig.ircServer
        UserDefaults.standard.removeObject(forKey: "freeq.server")
        if let savedChannels = UserDefaults.standard.stringArray(forKey: "freeq.channels") {
            // Drop anything that isn't a channel-prefixed name. Older builds
            // could land bare nicks in here (the @yokota-as-channel bug); we
            // never want to send `JOIN` for those.
            let cleaned = savedChannels.filter { $0.hasPrefix("#") || $0.hasPrefix("&") }
            autoJoinChannels = cleaned
            if cleaned.count != savedChannels.count {
                UserDefaults.standard.set(cleaned, forKey: "freeq.channels")
            }
        }
        if let savedReadPositions = UserDefaults.standard.dictionary(forKey: "freeq.readPositions") as? [String: String] {
            lastReadMessageIds = savedReadPositions
        }
        if let savedUnreads = UserDefaults.standard.dictionary(forKey: "freeq.unreadCounts") as? [String: Int] {
            unreadCounts = savedUnreads
        }
        if let savedMuted = UserDefaults.standard.stringArray(forKey: "freeq.mutedChannels") {
            mutedChannels = Set(savedMuted)
        }
        if let savedFavorites = UserDefaults.standard.stringArray(forKey: "freeq.favorites") {
            favorites = Set(savedFavorites)
        }
        if let data = UserDefaults.standard.data(forKey: "freeq.bookmarks"),
           let saved = try? JSONDecoder().decode([Bookmark].self, from: data) {
            bookmarks = saved
        }
        // Ordered favorites (for the Favorites section order + ⌃⌘1–9). Migrate
        // from the unordered set on first run, and reconcile any drift.
        var order = UserDefaults.standard.stringArray(forKey: "freeq.favoritesOrder") ?? []
        order = order.filter { favorites.contains($0) }
        for name in favorites where !order.contains(name) { order.append(name) }
        favoritesOrder = order
        if let savedClosed = UserDefaults.standard.stringArray(forKey: "freeq.closedDMs") {
            closedDMs = Set(savedClosed)
        }
        // Migrate secrets from UserDefaults to Keychain (one-time)
        KeychainHelper.migrateFromUserDefaults(userDefaultsKey: "freeq.did", keychainKey: "did")
        KeychainHelper.migrateFromUserDefaults(userDefaultsKey: "freeq.brokerToken", keychainKey: "brokerToken")

        if let savedDID = KeychainHelper.load(key: "did") {
            authenticatedDID = savedDID
        }
        if let savedBroker = KeychainHelper.load(key: "brokerToken") {
            brokerToken = savedBroker
        }
        if let savedBrokerBase = UserDefaults.standard.string(forKey: "freeq.brokerBase") {
            authBrokerBase = savedBrokerBase
        }
        // Restore cached web token if still valid. The expiry is kept in
        // the Keychain — NOT UserDefaults — so it survives an app
        // reinstall alongside the token itself. When the expiry lived in
        // UserDefaults, a fresh build wiped it, the still-valid token
        // could no longer be trusted, and every fresh install was forced
        // into a broker round-trip that hung the launch on "Reconnecting".
        // The UserDefaults read is a one-time migration fallback for
        // installs that predate this change.
        if let savedToken = KeychainHelper.load(key: "webToken"),
           let expiryStr = KeychainHelper.load(key: "webTokenExpiry")
               ?? UserDefaults.standard.string(forKey: "freeq.webTokenExpiry"),
           let expiryTs = Double(expiryStr) {
            let expiry = Date(timeIntervalSince1970: expiryTs)
            if Date() < expiry {
                cachedWebToken = savedToken
                cachedWebTokenExpiry = expiry
            } else {
                KeychainHelper.delete(key: "webToken")
                KeychainHelper.delete(key: "webTokenExpiry")
            }
        }
        isDarkTheme = UserDefaults.standard.object(forKey: "freeq.darkTheme") as? Bool ?? true

        // Hydrate channels/DMs from on-disk cache so the UI can render the
        // last session's context before the network round-trips complete.
        hydrateBuffersFromCache()

        // Prune stale typing indicators every 3 seconds
        Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            DispatchQueue.main.async {
                self?.pruneTypingIndicators()
            }
        }

        // Kick off the broker round-trip the moment we know we have a saved
        // session — well before SwiftUI mounts ContentView. The broker call
        // then runs in parallel with view hydration instead of waiting for
        // `.onAppear`. `reconnectSavedSession` is idempotent (guards on
        // `connectionState == .disconnected`), so a second call from
        // ContentView.onAppear is a no-op.
        if hasSavedSession {
            DispatchQueue.main.async { [weak self] in
                self?.reconnectSavedSession()
            }
        }
    }

    // MARK: - Buffer cache hydrate/save

    /// Read cached channels/DMs from disk and populate `channels` and
    /// `dmBuffers`. CHATHISTORY from the wire dedupes against the hydrated
    /// state via `ChannelState.appendIfNew(msg:)`.
    private func hydrateBuffersFromCache() {
        guard let root = BufferCacheStore.load() else { return }
        guard root.version == BufferCacheStore.version else {
            // Future migration hook — discard incompatible caches rather
            // than crashing on a partial decode.
            BufferCacheStore.clear()
            return
        }
        for cb in root.buffers {
            // Respect user-closed DMs even if a stale cache file (written
            // before the current closedDMs set was added) carries them.
            if cb.isDM && closedDMs.contains(cb.name.lowercased()) { continue }
            let buffer = cb.isDM
                ? getOrCreateDM(cb.name)
                : getOrCreateChannel(cb.name)
            if let topic = cb.topic, !topic.isEmpty {
                buffer.topic = topic
            }
            for cm in cb.messages {
                buffer.appendIfNew(cm.toChatMessage())
            }
            // The most recent cached message sets a reasonable lastActivity
            // so the sidebar sort order on cold launch matches what the user
            // saw last session, instead of dumping everything to the bottom.
            if let last = buffer.messages.last {
                buffer.lastActivity = last.timestamp
            }
        }
    }

    /// Background-refresh the cached web token if it's within
    /// `proactiveRefreshLeadTime` of expiry. No-op if the cache is fresh,
    /// no broker token is available, or a fetch is already in flight.
    /// Failures are silent — the cache simply stays at its current value
    /// and the next genuine reconnect will retry through the standard path.
    /// Web tokens have a ~30 min server TTL. Cache for 28 min — pair with the
    /// 10-min proactive-refresh window so the cached token transitions to a
    /// fresh one in the background well before any reconnect needs it. The
    /// older 25-min cache wasted ~3 min of every token's life forcing broker
    /// round-trips that didn't need to happen.
    static let webTokenCacheLifetime: TimeInterval = 28 * 60
    private static let proactiveRefreshLeadTime: TimeInterval = 10 * 60  // 10 min
    /// One broker `/session` round-trip at a time, ever — shared by the
    /// reconnect path and the proactive refresh. AT Protocol refresh
    /// tokens are single-use and rotate on every refresh; two concurrent
    /// `/session` calls race, and the loser writes back a token the PDS
    /// has already invalidated — permanently bricking the saved session
    /// until a fresh login. Serializing every broker fetch is the fix.
    private var brokerFetchInFlight = false
    private func proactivelyRefreshWebTokenIfStale() {
        guard !brokerFetchInFlight else { return }
        guard let brokerToken else { return }
        // Threshold: cached token's remaining lifetime < 10 minutes.
        let remaining = cachedWebTokenExpiry.timeIntervalSinceNow
        guard remaining < Self.proactiveRefreshLeadTime else { return }
        brokerFetchInFlight = true
        Task { [weak self] in
            guard let self else { return }
            defer { Task { @MainActor in self.brokerFetchInFlight = false } }
            do {
                let session = try await self.fetchBrokerSession(brokerToken: brokerToken)
                await MainActor.run {
                    self.cachedWebToken = session.token
                    self.cachedWebTokenExpiry = Date().addingTimeInterval(Self.webTokenCacheLifetime)
                    KeychainHelper.save(key: "webToken", value: session.token)
                    KeychainHelper.save(
                        key: "webTokenExpiry",
                        value: String(self.cachedWebTokenExpiry.timeIntervalSince1970))
                    authLog.info("proactive web-token refresh succeeded")
                }
            } catch {
                // Genuine 401 may have wiped credentials inside fetchBrokerSession;
                // that already flips the UI via @Published. Otherwise stay quiet —
                // the existing token is still valid for several more minutes.
                await MainActor.run {
                    authLog.notice("proactive web-token refresh failed: \(String(describing: error), privacy: .public)")
                }
            }
        }
    }

    /// Snapshot all channels/DMs and write to disk. Safe to call from any
    /// thread; the snapshot is taken synchronously on the calling thread.
    /// `flushBuffersToCache()` is the only entry point — `handleScenePhase`,
    /// `disconnect`, and `logout` all call it.
    func flushBuffersToCache() {
        let snapshot: [CachedBuffer] = (channels + dmBuffers).map { buf in
            let isDM = !(buf.name.hasPrefix("#") || buf.name.hasPrefix("&"))
            let tail = buf.messages.suffix(BufferCacheStore.maxMessagesPerBuffer)
            return CachedBuffer(
                name: buf.name,
                isDM: isDM,
                topic: buf.topic.isEmpty ? nil : buf.topic,
                messages: tail.map(CachedMessage.init)
            )
        }
        let root = BufferCacheRoot(version: BufferCacheStore.version, buffers: snapshot)
        BufferCacheStore.save(root)
    }

    /// Reconnect with saved session (requires SASL web-token).
    /// Retries broker fetch with backoff on failure.
    fileprivate var brokerRetryCount = 0

    /// Increments at the start of each `reconnectSavedSession()` invocation.
    /// `ContentView` watches this to reset its "Connecting…" timer per
    /// attempt instead of running it continuously from first appearance.
    @Published var reconnectAttempt: Int = 0

    func reconnectSavedSession() {
        guard hasSavedSession, connectionState == .disconnected else { return }
        reconnectAttempt &+= 1

        // 1. Already have a pending token (e.g., from initial login)
        if pendingWebToken != nil && !nick.isEmpty {
            connect(nick: nick)
            return
        }

        // 2. Reuse cached web-token if still valid (25 min window — token TTL is 30 min)
        if let cached = cachedWebToken, Date() < cachedWebTokenExpiry, !nick.isEmpty {
            pendingWebToken = cached
            connect(nick: nick)
            return
        }

        // 3. Fetch a fresh web-token from broker
        guard let brokerToken else {
            // No broker token at all — must log in fresh
            return
        }
        // Never overlap broker /session calls — see `brokerFetchInFlight`.
        // reconnectSavedSession fires from several triggers (boot, the
        // network monitor, the retry scheduler, AV teardown), so without
        // this guard they stack into concurrent refreshes that race the
        // rotating refresh token and brick the session.
        guard !brokerFetchInFlight else { return }
        brokerFetchInFlight = true
        Task {
            do {
                let session = try await fetchBrokerSession(brokerToken: brokerToken)
                await MainActor.run {
                    self.brokerFetchInFlight = false
                    self.brokerRetryCount = 0
                    self.pendingWebToken = session.token
                    self.cachedWebToken = session.token
                    let expiry = Date().addingTimeInterval(Self.webTokenCacheLifetime)
                    self.cachedWebTokenExpiry = expiry
                    KeychainHelper.save(key: "webToken", value: session.token)
                    KeychainHelper.save(key: "webTokenExpiry", value: String(expiry.timeIntervalSince1970))
                    self.authenticatedDID = session.did
                    KeychainHelper.save(key: "did", value: session.did)
                    self.connect(nick: session.nick)
                }
            } catch let error as NSError {
                await MainActor.run {
                    self.brokerFetchInFlight = false
                    // If broker token was cleared (genuinely expired), stop retrying
                    if error.code == 401 && self.brokerToken == nil {
                        // Credentials cleared — show login screen
                        return
                    }

                    self.brokerRetryCount += 1
                    // After a run of failures the broker isn't blipping —
                    // the saved session genuinely can't be refreshed (its
                    // AT Protocol refresh token is dead). Stop looping and
                    // drop to the sign-in screen so the user can re-auth,
                    // instead of being trapped on "Connecting…" forever.
                    if self.brokerRetryCount >= 8 {
                        authLog.error("broker unrecoverable after \(self.brokerRetryCount, privacy: .public) attempts — clearing session for re-login")
                        self.brokerToken = nil
                        self.cachedWebToken = nil
                        self.cachedWebTokenExpiry = .distantPast
                        KeychainHelper.delete(key: "brokerToken")
                        KeychainHelper.delete(key: "webToken")
                        KeychainHelper.delete(key: "webTokenExpiry")
                        self.errorMessage = "Couldn't restore your session — please sign in again."
                        return
                    }
                    // Capped-backoff retry (max 60s).
                    let delay: Double
                    if self.brokerRetryCount <= 3 {
                        delay = Double(self.brokerRetryCount) // 1, 2, 3s
                    } else if self.brokerRetryCount <= 10 {
                        delay = min(Double(self.brokerRetryCount * 2), 20.0) // 8..20s
                    } else {
                        delay = 60.0 // After 10 failures, try once per minute
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                        if self.connectionState == .disconnected && self.hasSavedSession {
                            self.reconnectSavedSession()
                        }
                    }
                    // Don't set errorMessage — let it keep trying silently
                }
            }
        }
    }

    /// Tracks whether the current session has already fallen back from
    /// WebSocket to TCP. We only allow one fallback per `connect(nick:)`
    /// call to avoid an infinite loop if both transports fail.
    fileprivate var transportFallbackUsed = false

    func connect(nick: String) {
        // Fresh connect attempt — start by preferring WebSocket again.
        transportFallbackUsed = false
        connect(nick: nick, useWebSocket: true)
    }

    fileprivate func connect(nick: String, useWebSocket: Bool) {
        self.nick = nick
        self.connectionState = .connecting
        self.errorMessage = nil

        UserDefaults.standard.set(nick, forKey: "freeq.nick")
        UserDefaults.standard.set(serverAddress, forKey: "freeq.server")
        UserDefaults.standard.set(authBrokerBase, forKey: "freeq.brokerBase")

        do {
            let handler = SwiftEventHandler(appState: self)
            client = try FreeqClient(
                server: serverAddress,
                nick: nick,
                handler: handler
            )

            // Prefer WebSocket on port 443. Pass an empty string to disable
            // and use the configured TCP server when falling back.
            let wsUrl = useWebSocket ? ServerConfig.wssServer : ""
            try client?.setWebsocketUrl(url: wsUrl)
            print("[freeq.connect] transport=\(useWebSocket ? "ws" : "tcp") wsUrl=\(wsUrl) tcp=\(serverAddress) nick=\(nick) hasToken=\(pendingWebToken != nil)")
            authLog.info("connect transport=\(useWebSocket ? "ws" : "tcp", privacy: .public) ws_url=\(wsUrl, privacy: .public)")

            // Set web-token for SASL auth if available (from AT Protocol OAuth)
            if let token = pendingWebToken {
                try client?.setWebToken(token: token)
                pendingWebToken = nil
            }

            try client?.connect()
            print("[freeq.connect] client?.connect() returned")
        } catch {
            print("[freeq.connect] threw error: \(error)")
            DispatchQueue.main.async {
                self.connectionState = .disconnected
                self.errorMessage = "Connection failed: \(error)"
            }
        }
    }

    /// Fall back from WebSocket to plain TCP if a WS connect fails — but only
    /// once per `connect(nick:)` call. Triggered by `Event.Disconnected` whose
    /// reason starts with "WebSocket".
    fileprivate func attemptTransportFallback(reason: String) -> Bool {
        guard !transportFallbackUsed,
              reason.lowercased().contains("websocket"),
              hasSavedSession,
              !nick.isEmpty else {
            return false
        }
        transportFallbackUsed = true
        authLog.notice("WS connect failed; falling back to TCP. reason=\(reason, privacy: .public)")
        DispatchQueue.main.async {
            // Tear the (failed) client down cleanly before re-issuing connect.
            self.client?.disconnect()
            self.client = nil
            self.connect(nick: self.nick, useWebSocket: false)
        }
        return true
    }

    func disconnect() {
        // Persist the current buffer state before tearing down. Without this,
        // a Guest-fallback retry or manual disconnect drops the last session
        // and the next cold launch hydrates from a stale cache.
        flushBuffersToCache()
        client?.disconnect()
        DispatchQueue.main.async {
            self.connectionState = .disconnected
            self.channels = []
            self.dmBuffers = []
            self.activeChannel = nil
            self.replyingTo = nil
            self.editingMessage = nil
        }
    }

    /// Full logout — clears saved session so ConnectView shows next launch
    /// (or this launch, since `hasSavedSession` is driven by the published
    /// `brokerToken` and ContentView routes on it).
    func logout() {
        disconnect()
        UserDefaults.standard.removeObject(forKey: "freeq.lastLogin")
        KeychainHelper.delete(key: "did")
        KeychainHelper.delete(key: "brokerToken")
        KeychainHelper.delete(key: "webToken")
        KeychainHelper.delete(key: "webTokenExpiry")
        UserDefaults.standard.removeObject(forKey: "freeq.webTokenExpiry")
        UserDefaults.standard.removeObject(forKey: "freeq.channels")
        // Intentionally NOT clearing `freeq.handle` and `freeq.nick`. They're
        // the user-typed identity from the previous session; ConnectView
        // pre-fills the Bluesky handle field from `freeq.handle` so the
        // user doesn't have to retype it after a sign-out / forced
        // re-auth. Credentials are in the keychain and have already been
        // removed above.
        cachedWebToken = nil
        cachedWebTokenExpiry = .distantPast
        SpotlightIndexer.clear()
        // Drop the on-disk buffer cache — never leak the previous user's
        // messages into a fresh sign-in.
        BufferCacheStore.clear()
        DispatchQueue.main.async {
            // CRITICAL: must nil the in-memory copies. `hasSavedSession`
            // reads `brokerToken != nil`; without this, ContentView keeps
            // routing to MainTabView and `reconnectSavedSession` keeps
            // firing even after the keychain is empty.
            self.brokerToken = nil
            self.pendingWebToken = nil
            self.authenticatedDID = nil
            self.nick = ""
            self.autoJoinChannels = []
            self.channels = []
            self.dmBuffers = []
            self.activeChannel = nil
            self.reconnectAttempt = 0
            self.brokerRetryCount = 0
            self.connectionState = .disconnected
            self.errorMessage = nil
        }
    }

    func joinChannel(_ channel: String) {
        let ch = channel.hasPrefix("#") ? channel : "#\(channel)"
        do { try client?.join(channel: ch) }
        catch { DispatchQueue.main.async { self.errorMessage = "Failed to join \(ch)" } }
    }

    func partChannel(_ channel: String) {
        // Record intent before sending: the echoed PART names only a nick, which
        // every device of this identity shares, so this is the only way to tell our
        // own PART from a sibling device's. See `SelfPartResolve`.
        pendingPartRequests[channel.lowercased()] = Date()
        try? client?.part(channel: channel)
        // Optimistically remove from UI — don't wait for server confirmation
        channels.removeAll { $0.name.lowercased() == channel.lowercased() }
        autoJoinChannels.removeAll { $0.lowercased() == channel.lowercased() }
        UserDefaults.standard.set(autoJoinChannels, forKey: "freeq.channels")
        if activeChannel?.lowercased() == channel.lowercased() {
            activeChannel = channels.first?.name
        }
    }

    /// Send a message. Returns true on success, false on failure (so caller can preserve text).
    @discardableResult
    // MARK: - Channel E2EE (passphrase)

    private static func channelKeyKeychainKey(_ channel: String) -> String {
        "channelKey.\(channel.lowercased())"
    }

    func setChannelKey(_ channel: String, passphrase: String) {
        channelE2ee.setKey(channel: channel, passphrase: passphrase)
        if let exported = channelE2ee.exportKey(channel: channel) {
            _ = KeychainHelper.save(key: Self.channelKeyKeychainKey(channel), value: exported)
        }
        getOrCreateChannel(channel).isEncrypted = true
        objectWillChange.send()
    }

    func removeChannelKey(_ channel: String) {
        channelE2ee.removeKey(channel: channel)
        KeychainHelper.delete(key: Self.channelKeyKeychainKey(channel))
        channels.first { $0.name.lowercased() == channel.lowercased() }?.isEncrypted = false
        objectWillChange.send()
    }

    /// Rehydrate a channel key saved by a prior /encrypt (called on join).
    func restoreChannelKeyIfSaved(_ channel: String) {
        guard !channelE2ee.hasKey(channel: channel),
              let b64 = KeychainHelper.load(key: Self.channelKeyKeychainKey(channel)) else { return }
        channelE2ee.importKey(channel: channel, base64: b64)
        getOrCreateChannel(channel).isEncrypted = true
    }

    /// Who a first DM is really for, learned before it goes out. Wired
    /// lazily so init stays untouched; every use is main-thread.
    lazy var dmResolver = DmResolver(
        nickToDid: { [weak self] nick in self?.didForNick(nick) },
        askWhois: { [weak self] nick in try? self?.client?.requestWhois(nick: nick) }
    )

    func sendMessage(target: String, text: String) -> Bool {
        guard !text.isEmpty else { return false }
        // What this press of Send actually is; the typed senders sign it and
        // file an event id. Nothing message-bearing goes out as a raw line.
        let send: OutboundSend
        if let editing = editingMessage {
            send = .edit(target: target, msgId: editing.id, text: text)
            editingMessage = nil
        } else if let reply = replyingTo {
            send = .reply(target: target, msgId: reply.id, text: text)
            replyingTo = nil
        } else {
            send = .plain(target: target, text: text)
        }
        try? client?.typingStop(target: target)
        lastTypingSent = .distantPast
        dispatch(send)
        return true
    }

    /// `/me` as a CTCP ACTION. The framing lives in the body, so the SDK
    /// signs it as the ordinary message it is. Never encrypted: a ciphertext
    /// body would reach readers as literal control characters.
    func sendAction(to target: String, text: String) {
        dispatch(.plain(target: target, text: "\u{01}ACTION \(text)\u{01}"), encrypt: false)
    }

    /// One send, addressed to the venue a signature can name. Channels and
    /// known peers never suspend; only a first DM to a nick nobody has asked
    /// about waits briefly for the WHOIS answer, and goes out at the nick
    /// unchanged if none comes.
    func dispatch(_ send: OutboundSend, encrypt: Bool = true) {
        if let venue = dmResolver.venueIfSettled(send.target) {
            transmit(send.addressed(to: venue), encrypt: encrypt)
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let venue = await self.dmResolver.resolve(send.target)
            self.transmit(send.addressed(to: venue), encrypt: encrypt)
        }
    }

    /// The only path to the wire for message-bearing sends — the SDK's typed
    /// senders, which sign. An E2EE body travels as ciphertext under the
    /// `+encrypted` tag, so the signature covers the bytes that actually go
    /// out; the echo cache restores our plaintext on server echo. Multiline
    /// passes through untouched — the SDK routes it into a draft/multiline
    /// BATCH itself, one logical message.
    private func transmit(_ send: OutboundSend, encrypt: Bool) {
        guard let client else {
            DispatchQueue.main.async { self.errorMessage = "Send failed" }
            return
        }
        do {
            let wireText = send.text.replacingOccurrences(of: "\r", with: "")
            if encrypt, send.target.hasPrefix("#"),
               let wire = channelE2ee.outgoing(text: wireText, channel: send.target) {
                try client.sendTagged(
                    target: send.target,
                    text: wire,
                    tags: send.encryptedTags.map { TagEntry(key: $0.key, value: $0.value) }
                )
                return
            }
            switch send {
            case .plain(let target, _):
                try client.sendMessage(target: target, text: wireText)
            case .edit(let target, let msgId, _):
                try client.editMessage(target: target, msgid: msgId, newText: wireText)
            case .reply(let target, let msgId, _):
                try client.reply(target: target, msgid: msgId, text: wireText)
            }
        } catch {
            DispatchQueue.main.async { self.errorMessage = "Send failed" }
        }
    }

    func sendRaw(_ line: String) {
        guard let client = client else {
            print("❌ sendRaw: NO CLIENT")
            return
        }
        do {
            try client.sendRaw(line: line)
            print("✅ sendRaw OK: \(line.prefix(50))")
        } catch {
            print("❌ sendRaw ERROR: \(error)")
        }
    }

    /// Close a DM: remove from the live list and persist a "stay closed"
    /// marker so it doesn't come back via cache hydration or the server's
    /// CHATHISTORY TARGETS list on next register. The peer messaging us
    /// (or us messaging them) automatically un-closes it.
    func closeDM(_ name: String) {
        closedDMs.insert(name.lowercased())
        dmBuffers.removeAll { $0.name.lowercased() == name.lowercased() }
        activeChannel = nil
    }

    /// Resolve a wire target (channel `#…`/`&…` or peer nick) to its local
    /// buffer for optimistic-send updates. Mirrors the inbound routing logic.
    private func bufferForSend(_ target: String) -> ChannelState {
        if target.hasPrefix("#") || target.hasPrefix("&") {
            return getOrCreateChannel(target)
        } else {
            return getOrCreateDM(target)
        }
    }

    func sendReaction(target: String, msgId: String, emoji: String) {
        // Optimistic local update — keeps the UI consistent even if the
        // `echo-message` cap isn't negotiated on the current connection.
        // `applyReaction` is idempotent (Set keyed by nick), so the inbound
        // echo (if any) is a no-op.
        bufferForSend(target).applyReaction(msgId: msgId, emoji: emoji, from: nick)
        do { try client?.react(target: target, emoji: emoji, msgid: msgId) } catch {
            DispatchQueue.main.async { self.errorMessage = "Reaction failed" }
        }
    }

    func sendUnreaction(target: String, msgId: String, emoji: String) {
        bufferForSend(target).removeReaction(msgId: msgId, emoji: emoji, from: nick)
        do { try client?.unreact(target: target, emoji: emoji, msgid: msgId) } catch {
            DispatchQueue.main.async { self.errorMessage = "Reaction failed" }
        }
    }

    /// Toggle the current user's reaction on a message: react if absent, unreact if present.
    func toggleReaction(target: String, msgId: String, emoji: String, currentlyMine: Bool) {
        if currentlyMine {
            sendUnreaction(target: target, msgId: msgId, emoji: emoji)
        } else {
            sendReaction(target: target, msgId: msgId, emoji: emoji)
        }
    }

    func deleteMessage(target: String, msgId: String) {
        do { try client?.deleteMessage(target: target, msgid: msgId) } catch {
            DispatchQueue.main.async { self.errorMessage = "Delete failed" }
        }
        // Apply the local row removal only after the context menu's dismissal
        // fully settles. The visual change from an edit works because its
        // echo lands seconds after the menu is gone; a mutation during the
        // dismissal window hits the row while UIKit still holds its preview
        // snapshot and the on-screen pixels never update (verified: data,
        // body re-eval, and even the replacement row all correct — display
        // stayed frozen).
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
            self?.bufferForSend(target).applyDelete(msgId: msgId)
        }
    }

    func sendTyping(target: String) {
        let now = Date()
        guard now.timeIntervalSince(lastTypingSent) > 3 else { return }
        lastTypingSent = now
        try? client?.typingStart(target: target)
    }

    func requestHistory(channel: String, before: Date? = nil) {
        // DM history exists only for did<->did threads. Skip requests that
        // can only fail: as a guest ourselves (ACCOUNT_REQUIRED), or for a
        // guest peer — a nick-keyed thread with no DID binding
        // (INVALID_TARGET on every thread open otherwise).
        if !channel.hasPrefix("#"), !channel.hasPrefix("&") {
            if authenticatedDID == nil { return }
            if !DidDisplay.isDid(channel), didForNick(channel) == nil { return }
        }
        if let before = before {
            let iso = ISO8601DateFormatter().string(from: before)
            sendRaw("CHATHISTORY BEFORE \(channel) timestamp=\(iso) 50")
        } else {
            sendRaw("CHATHISTORY LATEST \(channel) * 50")
        }
    }

    func fetchPins(channel: String) {
        let name = channel.hasPrefix("#") ? String(channel.dropFirst()) : channel
        guard let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
              let url = URL(string: "\(ServerConfig.apiBaseUrl)/api/v1/channels/\(encoded)/pins") else { return }
        // Pins on a mode-restricted channel need the session bearer.
        let req = ApiAuth.request(url, bearer: apiBearerSessionId)
        Task {
            do {
                let (data, _) = try await URLSession.shared.data(for: req)
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let pinsArray = json["pins"] as? [[String: Any]] {
                    let msgIds = Set(pinsArray.compactMap { $0["msgid"] as? String })
                    await MainActor.run {
                        if let ch = self.channels.first(where: { $0.name.lowercased() == channel.lowercased() }) {
                            ch.pins = msgIds
                        }
                    }
                }
            } catch { /* network error */ }
        }
    }

    struct BrokerSessionResponse: Decodable {
        let token: String
        let nick: String
        let did: String
        let handle: String
    }

    /// Track consecutive 401s — only clear broker token after multiple failures
    private var consecutive401Count = 0
    private var lastLoginDate: Date? {
        let ts = UserDefaults.standard.double(forKey: "freeq.lastLogin")
        guard ts > 0 else { return nil }
        return Date(timeIntervalSince1970: ts)
    }

    /// Keep users logged in for at least two weeks unless they explicitly log out.
    /// During this window, never clear broker credentials automatically.
    private var canAutoClearBrokerCredentials: Bool {
        guard let lastLoginDate else { return false }
        return Date().timeIntervalSince(lastLoginDate) >= Self.minimumPersistentSessionDuration
    }

    private func fetchBrokerSession(brokerToken: String) async throws -> BrokerSessionResponse {
        // Retry up to 4 times with backoff — DPoP nonce rotation and transient errors
        for attempt in 0..<4 {
            let url = URL(string: "\(authBrokerBase)/session")!
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["broker_token": brokerToken])
            // Cap a single attempt at 8 s. URLSession's default (~60 s) is far
            // too long for cold-launch UX — the user is staring at a status
            // banner while the request sits in connect/TLS. With our buffer
            // cache hydrated, falling back to "the cached UI works, send is
            // disabled" is strictly better than blocking on a doomed request.
            request.timeoutInterval = 8

            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await URLSession.shared.data(for: request)
            } catch {
                // Network error (offline, timeout, DNS) — don't clear anything, just throw
                if attempt < 3 {
                    try? await Task.sleep(nanoseconds: UInt64(1_000_000_000 * (attempt + 1)))
                    continue
                }
                throw error
            }

            let status = (response as? HTTPURLResponse)?.statusCode ?? 0

            // 5xx is a *server* error, not an auth verdict. Treat every 502/
            // 503/504 as transient: retry inside this fetch, then let the
            // outer reconnect loop back off. NEVER clear credentials on a 5xx.
            //
            // History: we used to substring-search the response body for
            // "invalid_grant" / "invalid_token" / "expired" / "revoked" and
            // wipe credentials immediately on a match. That was dangerously
            // brittle — any 5xx body containing those words (CDN error pages,
            // stack traces, unrelated PDS chatter) silently logged users
            // out. The genuine "PDS refused refresh" signal must come from
            // the broker as a structured discriminator (a specific status
            // code or JSON field), not inferred from English text. Until
            // the broker exposes that, treat 5xx as recoverable; if the
            // refresh truly is dead the broker will surface it as a 401
            // and the 3-strikes-past-grace path will eventually wipe.
            if status == 502 || status == 503 || status == 504 {
                authLog.notice("broker \(status, privacy: .public) attempt=\(attempt, privacy: .public) — treating as transient")
                if attempt < 3 {
                    try? await Task.sleep(nanoseconds: UInt64(500_000_000 * (attempt + 1)))
                    continue
                }
                throw NSError(domain: "Broker", code: status, userInfo: [NSLocalizedDescriptionKey: "Broker temporarily unavailable"])
            }

            // 401 = broker token might be invalid, but could also be transient
            // (broker DB recreated, broker restarting, deploy in flight, etc.).
            // Within the 14-day grace window we NEVER auto-clear credentials —
            // the user signs in often enough that 14 days of nothing-but-401
            // means something is genuinely wrong with their PDS, and that
            // case is better surfaced as a banner than by silently dropping
            // them onto ConnectScreen mid-flight.
            //
            // Past grace: 3 consecutive 401s (across reconnect cycles) is our
            // only auto-wipe path. There is intentionally no "escalated"
            // bypass — burst 401s during a broker hiccup should not nuke a
            // logged-in user.
            if status == 401 {
                await MainActor.run { self.consecutive401Count += 1 }
                if attempt < 3 {
                    // Retry — the broker might recover (e.g., DB migration, restart)
                    try? await Task.sleep(nanoseconds: UInt64(1_000_000_000 * (attempt + 1)))
                    continue
                }
                let count = await MainActor.run { self.consecutive401Count }
                let lastLogin = await MainActor.run { self.lastLoginDate }
                let withinGrace = !canAutoClearBrokerCredentials
                let shouldClear = count >= 3 && !withinGrace
                if shouldClear {
                    // Genuinely invalid — clear credentials.
                    let sinceLoginHours = lastLogin.map { Date().timeIntervalSince($0) / 3600 } ?? -1
                    authLog.error(
                        "Clearing broker credentials: consecutive401=\(count, privacy: .public) sinceLoginHours=\(sinceLoginHours, privacy: .public) lastStatus=401"
                    )
                    await MainActor.run {
                        self.brokerToken = nil
                        self.cachedWebToken = nil
                        self.cachedWebTokenExpiry = .distantPast
                        KeychainHelper.delete(key: "brokerToken")
                        KeychainHelper.delete(key: "webToken")
                        KeychainHelper.delete(key: "webTokenExpiry")
                        UserDefaults.standard.removeObject(forKey: "freeq.webTokenExpiry")
                    }
                } else {
                    authLog.notice(
                        "Broker 401 NOT clearing creds: consecutive401=\(count, privacy: .public) withinGraceWindow=\(withinGrace, privacy: .public)"
                    )
                }
                throw NSError(domain: "Broker", code: 401, userInfo: [NSLocalizedDescriptionKey: "Session expired — please sign in again"])
            }
            guard status == 200 else { throw NSError(domain: "Broker", code: status) }
            // Success — reset 401 counter.
            await MainActor.run { self.consecutive401Count = 0 }
            return try JSONDecoder().decode(BrokerSessionResponse.self, from: data)
        }
        throw NSError(domain: "Broker", code: 502)
    }

    func markRead(_ channel: String) {
        unreadCounts[channel] = 0
        updateBadgeCount()
        // Persist last-read message ID
        if let state = channels.first(where: { $0.name == channel }) ?? dmBuffers.first(where: { $0.name == channel }),
           let lastMsg = state.messages.last {
            lastReadMessageIds[channel] = lastMsg.id
            UserDefaults.standard.set(lastReadMessageIds, forKey: "freeq.readPositions")
        }
    }

    func updateBadgeCount() {
        let total = unreadCounts.filter { !mutedChannels.contains($0.key) }.values.reduce(0, +)
        UNUserNotificationCenter.current().setBadgeCount(total)
        updateWidgetSnapshot(total: total)
    }

    /// Publish the widget snapshot (App Group) and nudge WidgetKit to reload.
    /// Cheap and idempotent; called whenever unread changes.
    private func updateWidgetSnapshot(total: Int) {
        let top = unreadCounts
            .filter { $0.value > 0 && !mutedChannels.contains($0.key) }
            .sorted { $0.value > $1.value }
            .prefix(4)
            .map { SharedStore.ChannelUnread(name: $0.key, unread: $0.value) }
        let snapshot = SharedStore.Snapshot(
            totalUnread: total,
            topChannels: Array(top),
            connected: connectionState == .registered,
            updatedAt: Date()
        )
        SharedStore.write(snapshot)
        WidgetCenter.shared.reloadTimelines(ofKind: "FreeqUnreadWidget")
    }

    func toggleMute(_ channel: String) {
        if mutedChannels.contains(channel) {
            mutedChannels.remove(channel)
        } else {
            mutedChannels.insert(channel)
        }
    }

    func isMuted(_ channel: String) -> Bool {
        mutedChannels.contains(channel)
    }

    // MARK: - Favorites

    func isFavorite(_ channel: String) -> Bool {
        favorites.contains(channel)
    }

    func toggleFavorite(_ channel: String) {
        if favorites.contains(channel) {
            favorites.remove(channel)
            favoritesOrder.removeAll { $0 == channel }
        } else {
            favorites.insert(channel)
            if !favoritesOrder.contains(channel) { favoritesOrder.append(channel) }
        }
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        pushFavorites()
    }

    private func favoritesURL() -> URL? {
        let host = serverAddress.split(separator: ":").first.map(String.init) ?? "irc.freeq.at"
        return URL(string: "https://\(host)/api/v1/favorites")
    }

    /// Roaming favorites: pull the DID's server list, union with local
    /// (order-preserving), write back if changed. Per-DID (parity w/ web+macOS).
    func syncFavoritesFromServer() {
        guard let bearer = apiBearerSessionId, let url = favoritesURL() else { return }
        var req = URLRequest(url: url)
        req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: req) { [weak self] data, _, _ in
            guard let self, let data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let server = json["favorites"] as? [String] else { return }
            Task { @MainActor in
                let local = self.favoritesOrder
                let merged = FavoritesSync.merge(server: server, local: local)
                if merged != self.favoritesOrder {
                    self.favoritesOrder = merged
                    self.favorites = Set(merged)
                }
                if !FavoritesSync.equal(merged, server) { self.pushFavorites() }
            }
        }.resume()
    }

    private func pushFavorites() {
        guard let bearer = apiBearerSessionId, let url = favoritesURL() else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "PUT"
        req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["favorites": favoritesOrder])
        URLSession.shared.dataTask(with: req).resume()
    }

    func toggleTheme() {
        isDarkTheme.toggle()
        UserDefaults.standard.set(isDarkTheme, forKey: "freeq.darkTheme")
    }

    /// Called when the app transitions between foreground/background.
    func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .active:
            // Returning to foreground — reconnect if needed.
            NotificationManager.shared.clearBadge()
            // FEAT-004: skip the broker round-trip when the SDK still has a
            // live transport. Backgrounded apps with healthy WebSocket /
            // TCP keep their connection across short pauses; tearing it
            // down to re-fetch a web token burns broker requests for
            // nothing — and on a slow broker, lights up the user-visible
            // reconnect UI for what was a working connection.
            if let c = client, c.isConnected() {
                // Even with a healthy transport, if the cached web token is
                // about to expire we want a fresh one ready *before* the
                // next reconnect (e.g., the user is on a flaky train and
                // the WebSocket drops 20 minutes from now). A reactive
                // fetch on that drop would block reconnect on the broker;
                // a proactive fetch here means the next reconnect uses a
                // cached fresh token and bypasses the broker entirely.
                proactivelyRefreshWebTokenIfStale()
                return
            }
            if connectionState == .disconnected && hasSavedSession {
                brokerRetryCount = 0  // Reset retries on foreground
                reconnectSavedSession()
            }
        case .background:
            // Going to background — WebSocket dies naturally. Persist the
            // buffer cache here so the next cold launch can hydrate with
            // the latest state. iOS also calls .inactive shortly before
            // .background; we save on both for belt-and-suspenders.
            flushBuffersToCache()
        case .inactive:
            flushBuffersToCache()
        @unknown default:
            break
        }
    }

    func incrementUnread(_ channel: String) {
        guard activeChannel != channel else { return }
        guard !mutedChannels.contains(channel) else { return }
        unreadCounts[channel, default: 0] += 1
        updateBadgeCount()
    }

    /// IRC channel names must start with `#` (federated) or `&` (local-only).
    /// Anything else is a peer nick and belongs in `dmBuffers`, not here.
    /// We route mis-typed callers automatically so a stray event from the
    /// wire (or a future code path) can't pollute the Channels pane —
    /// that's how `@yokota` ended up showing as a channel.
    func getOrCreateChannel(_ name: String) -> ChannelState {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("#") || trimmed.hasPrefix("&") else {
            return getOrCreateDM(trimmed)
        }
        if let existing = channels.first(where: { $0.name.lowercased() == trimmed.lowercased() }) {
            return existing
        }
        let channel = ChannelState(name: trimmed)
        channels.append(channel)
        SpotlightIndexer.reindex(self)
        attemptRestoreLastChannel()
        return channel
    }

    /// Reopen the conversation the user was last in (persisted in `activeChannel`'s
    /// `didSet`). Called as channels/DMs load after connect: selects the saved
    /// target once it's present, or falls back to the first channel once all the
    /// auto-join channels have loaded and the saved one didn't reappear (it was
    /// left). Runs at most once per launch so a late JOIN can't hijack the user's
    /// current selection.
    func attemptRestoreLastChannel() {
        guard !didRestoreLastChannel else { return }
        let saved = UserDefaults.standard.string(forKey: LastChannel.key)
        let chanNames = channels.map(\.name)
        let dmNames = dmBuffers.map(\.name)
        let savedIsPresent = saved.map { s in
            (chanNames + dmNames).contains { $0.caseInsensitiveCompare(s) == .orderedSame }
        } ?? false

        // Wait for the saved target to appear; only fall back once every
        // expected auto-join channel has loaded (so we don't prematurely land
        // on the first channel while the real one is still joining).
        guard savedIsPresent || (!chanNames.isEmpty && chanNames.count >= autoJoinChannels.count) else {
            return
        }
        if let target = LastChannel.restore(saved: saved, channels: chanNames, dms: dmNames) {
            activeChannel = target
            didRestoreLastChannel = true
        }
    }

    /// DMs are keyed by peer nick. Refuse anything that looks like a channel —
    /// a `#`/`&` name in `dmBuffers` would render with the DM avatar/style and
    /// silently shadow the real channel.
    private var resolvingDids: Set<String> = []

    /// A DM thread keyed by a bare DID with no learned nick (an OFFLINE peer,
    /// or a conversation created on another client) renders the raw DID and
    /// can't fold its nick twin. Resolve the DID → handle via the Bluesky
    /// profile API (it accepts a DID), then adopt: names the thread and merges
    /// the twin. Also tries the handle's local part, since freeq nicks are
    /// often the handle without its domain (e.g. "kellyjeanne" from
    /// "kellyjeanne.bsky.social"). Deduped; parity with macOS.
    func resolveDmDidIfNeeded(_ key: String) {
        guard DidDisplay.isDid(key),
              didDisplayNames[key] == nil,
              !knownDids.values.contains(key),
              !resolvingDids.contains(key) else { return }
        resolvingDids.insert(key)
        Task { @MainActor in
            defer { self.resolvingDids.remove(key) }
            guard let handle = await AppState.resolveHandle(forDid: key) else { return }
            self.adoptDmBinding(nick: handle, did: key)
            if let dot = handle.firstIndex(of: "."),
               String(handle[..<dot]).lowercased() != handle.lowercased() {
                self.adoptDmBinding(nick: String(handle[..<dot]), did: key)
            }
        }
    }

    private static func resolveHandle(forDid did: String) async -> String? {
        let encoded = did.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? did
        guard let url = URL(string: "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=\(encoded)")
        else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let handle = json["handle"] as? String else { return nil }
            return handle
        } catch { return nil }
    }

    func getOrCreateDM(_ nick: String) -> ChannelState {
        let trimmed = nick.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            // Return a throwaway buffer — never append empty nicks to the list
            return ChannelState(name: "_empty")
        }
        guard !trimmed.hasPrefix("#"), !trimmed.hasPrefix("&") else {
            // Caller handed us a channel name; route to the channel store instead.
            return getOrCreateChannel(trimmed)
        }
        // Follow a known nick→DID binding so a nick-addressed open (compose
        // sheet, optimistic send, deep link) lands in the DID-keyed thread.
        let key = canonicalDmKey(trimmed)
        resolveDmDidIfNeeded(key)
        if let existing = dmBuffers.first(where: { $0.name.lowercased() == key.lowercased() }) {
            return existing
        }
        let dm = ChannelState(name: key)
        dmBuffers.append(dm)
        requestHistory(channel: key)
        SpotlightIndexer.reindex(self)
        attemptRestoreLastChannel()
        return dm
    }

    private func pruneTypingIndicators() {
        let cutoff = Date().addingTimeInterval(-5)
        for ch in channels + dmBuffers {
            let stale = ch.typingUsers.filter { $0.value < cutoff }
            if !stale.isEmpty {
                for key in stale.keys {
                    ch.typingUsers.removeValue(forKey: key)
                }
            }
        }
    }

    fileprivate func updateAwayStatus(nick: String, awayMsg: String?) {
        for ch in channels {
            if let idx = ch.members.firstIndex(where: { $0.nick.lowercased() == nick.lowercased() }) {
                let m = ch.members[idx]
                // Keep the agent metadata: an AWAY change says nothing about
                // whether someone is an agent, and rebuilding without these
                // silently un-badges every agent that goes away.
                ch.members[idx] = MemberInfo(
                    nick: m.nick, isOp: m.isOp, isHalfop: m.isHalfop,
                    isVoiced: m.isVoiced, awayMsg: awayMsg, did: m.did,
                    actorClass: m.actorClass, presenceState: m.presenceState,
                    presenceStatus: m.presenceStatus)
            }
        }
    }

    /// Apply roster-time actor classes (vendor numeric 674) to one channel.
    /// Humans are omitted by the server, so anything absent stays human.
    fileprivate func applyActorClasses(channel: String, classes: [ActorClassEntry]) {
        guard let ch = channels.first(where: { $0.name.lowercased() == channel.lowercased() })
        else { return }
        for entry in classes {
            guard let idx = ch.members.firstIndex(where: {
                $0.nick.lowercased() == entry.nick.lowercased()
            }) else { continue }
            let m = ch.members[idx]
            ch.members[idx] = MemberInfo(
                nick: m.nick, isOp: m.isOp, isHalfop: m.isHalfop,
                isVoiced: m.isVoiced, awayMsg: m.awayMsg, did: m.did,
                actorClass: entry.actorClass,
                presenceState: m.presenceState, presenceStatus: m.presenceStatus)
        }
    }

    /// Apply live agent presence everywhere we can see this nick, so a working
    /// agent reads as working in every channel it is visible in.
    fileprivate func applyPresence(nick: String, state: String, status: String?) {
        for ch in channels {
            guard let idx = ch.members.firstIndex(where: {
                $0.nick.lowercased() == nick.lowercased()
            }) else { continue }
            let m = ch.members[idx]
            ch.members[idx] = MemberInfo(
                nick: m.nick, isOp: m.isOp, isHalfop: m.isHalfop,
                isVoiced: m.isVoiced, awayMsg: m.awayMsg, did: m.did,
                // Publishing presence is itself proof this is an agent.
                actorClass: m.actorClass ?? "agent",
                presenceState: state, presenceStatus: status)
        }
    }

    /// The user's own custom status (emoji + text), carried over IRC AWAY so it
    /// broadcasts to everyone in shared channels natively. Persists across
    /// launches and is re-broadcast after each (re)connect.
    @Published var selfStatus: String? = UserDefaults.standard.string(forKey: "freeq.status")

    func setStatus(_ text: String?) {
        let trimmed = text?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let t = trimmed, !t.isEmpty {
            selfStatus = t
            UserDefaults.standard.set(t, forKey: "freeq.status")
            sendRaw("AWAY :\(t)")
        } else {
            selfStatus = nil
            UserDefaults.standard.removeObject(forKey: "freeq.status")
            sendRaw("AWAY")
        }
        // Reflect immediately on our own roster entries so the UI updates before
        // the away-notify echo returns.
        updateAwayStatus(nick: nick, awayMsg: selfStatus)
    }

    /// Re-broadcast a saved status after (re)connect so others see it again.
    func reapplyStatusIfNeeded() {
        if let s = selfStatus, !s.isEmpty { sendRaw("AWAY :\(s)") }
    }

    /// Handle freeq://auth?token=...&broker_token=...&nick=...&did=...&handle=...
    /// — the broker's OAuth completion. Reached two ways: the in-app
    /// ASWebAuthenticationSession completion (primary), or onOpenURL if the
    /// flow ever bounces through Safari (legacy/fallback).
    func handleAuthCallback(_ url: URL) {
        guard url.scheme == "freeq", url.host == "auth" else { return }
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return }

        if let error = components.queryItems?.first(where: { $0.name == "error" })?.value {
            errorMessage = error
            connectionState = .disconnected
            return
        }

        guard let token = components.queryItems?.first(where: { $0.name == "token" })?.value,
              let nick = components.queryItems?.first(where: { $0.name == "nick" })?.value,
              let did = components.queryItems?.first(where: { $0.name == "did" })?.value
        else {
            errorMessage = "Invalid auth response"
            return
        }

        let brokerTok = components.queryItems?.first(where: { $0.name == "broker_token" })?.value
        let handle = components.queryItems?.first(where: { $0.name == "handle" })?.value ?? nick

        // Save session
        UserDefaults.standard.set(handle, forKey: "freeq.handle")
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "freeq.lastLogin")
        if let brokerTok { KeychainHelper.save(key: "brokerToken", value: brokerTok) }
        UserDefaults.standard.removeObject(forKey: "freeq.loginPending")

        // Connect
        pendingWebToken = token
        brokerToken = brokerTok
        authenticatedDID = did
        serverAddress = ServerConfig.ircServer
        connect(nick: nick)
    }

    func awayMessage(for nick: String) -> String? {
        for ch in channels {
            if let m = ch.members.first(where: { $0.nick.lowercased() == nick.lowercased() }) {
                return m.awayMsg
            }
        }
        return nil
    }

    fileprivate func renameUser(oldNick: String, newNick: String) {
        // Keep DID-keyed thread identity current across the rename.
        if let did = knownDids.removeValue(forKey: oldNick.lowercased()) {
            knownDids[newNick.lowercased()] = did
            didDisplayNames[did] = newNick
        }
        for ch in channels {
            if let idx = ch.members.firstIndex(where: { $0.nick.lowercased() == oldNick.lowercased() }) {
                let m = ch.members[idx]
                ch.members[idx] = MemberInfo(nick: newNick, isOp: m.isOp, isHalfop: m.isHalfop, isVoiced: m.isVoiced, awayMsg: m.awayMsg, did: m.did)
            }
            if let ts = ch.typingUsers.removeValue(forKey: oldNick) {
                ch.typingUsers[newNick] = ts
            }
        }

        if let idx = dmBuffers.firstIndex(where: { $0.name.lowercased() == oldNick.lowercased() }) {
            let old = dmBuffers[idx]
            let renamed = ChannelState(name: newNick)
            renamed.adoptMessages(from: old)
            renamed.members = old.members
            renamed.topic = old.topic
            renamed.typingUsers = old.typingUsers
            dmBuffers.remove(at: idx)
            dmBuffers.append(renamed)

            if let count = unreadCounts.removeValue(forKey: old.name) {
                unreadCounts[newNick] = count
            }
            if let last = lastReadMessageIds.removeValue(forKey: old.name) {
                lastReadMessageIds[newNick] = last
                UserDefaults.standard.set(lastReadMessageIds, forKey: "freeq.readPositions")
            }
        }

        if activeChannel?.lowercased() == oldNick.lowercased() {
            activeChannel = newNick
        }
    }
}

/// Bridges Rust SDK events to SwiftUI state updates on main thread.
final class SwiftEventHandler: @unchecked Sendable, EventHandler {
    private weak var appState: AppState?

    init(appState: AppState) {
        self.appState = appState
    }

    func onEvent(event: FreeqEvent) {
        DispatchQueue.main.async { [weak self] in
            self?.handleEvent(event)
        }
    }

    // Internal (not private) so tests in `freeqTests` can invoke the dispatcher
    // directly via `@testable import freeq` without going through the FFI.
    func handleEvent(_ event: FreeqEvent) {
        guard let state = appState else { return }

        switch event {
        case .act:
            // A task event; the native card for it is upcoming work, so the
            // event is deliberately ignored rather than unhandled.
            break

        case .connected:
            print("[freeq.event] .connected")
            state.connectionState = .connected

        case .registered(let nick):
            print("[freeq.event] .registered nick=\(nick)")
            // (continue to existing handler)
            state.connectionState = .registered
            state.reconnectAttempts = 0
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            // Prefetch our own Bluesky avatar via the authenticated DID. Without
            // this we'd fall back to "<nick>.bsky.social" — which fails for users
            // whose handle is a custom domain (e.g. chadfowler.com), leaving
            // the self-avatar blank while other users' avatars resolve fine
            // because their messages carry account=did tags.
            if let did = state.authenticatedDID {
                Task { @MainActor in
                    AvatarCache.shared.prefetch(nick, did: did)
                }
            }
            // If we expected an authenticated session but got Guest, retry
            // instead of showing login screen. Token may have been stale.
            if state.authenticatedDID != nil && nick.lowercased().hasPrefix("guest") {
                state.disconnect()
                // Invalidate cached token — it was stale
                state.cachedWebToken = nil
                state.cachedWebTokenExpiry = .distantPast
                state.brokerRetryCount = 0
                // Retry via broker — will get a fresh token
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    if state.connectionState == .disconnected && state.hasSavedSession {
                        state.pendingWebToken = nil  // Force broker refresh
                        state.reconnectSavedSession()
                    }
                }
                return
            }
            state.nick = nick
            // Auto-join saved channels
            for channel in state.autoJoinChannels {
                state.joinChannel(channel)
            }
            // Fetch DM conversation list if authenticated
            if state.authenticatedDID != nil {
                state.sendRaw("CHATHISTORY TARGETS * * 50")
            }
            // Re-broadcast a saved custom status so peers see it again.
            state.reapplyStatusIfNeeded()

        case .authenticated(let did):
            state.authenticatedDID = did
            KeychainHelper.save(key: "did", value: did)
            // Refresh login timestamp so hasSavedSession stays valid
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "freeq.lastLogin")
            // Self-avatar by DID — covers the case where `.authenticated`
            // arrives after `.registered` so the prefetch in that handler
            // saw a nil DID.
            if !state.nick.isEmpty {
                Task { @MainActor in
                    AvatarCache.shared.prefetch(state.nick, did: did)
                }
            }

        case .authFailed(let reason):
            state.errorMessage = "Auth failed: \(reason)"

        case .joined(let channel, let nick):
            let ch = state.getOrCreateChannel(channel)
            ch.lastActivity = Date()
            if nick.lowercased() == state.nick.lowercased() {
                ch.accessDeniedReason = nil  // a real join clears any prior denial
                // Rehydrate a saved channel E2EE key so encrypted history
                // decrypts on rejoin (parity with macOS).
                state.restoreChannelKeyIfSaved(channel)
                if state.activeChannel == nil {
                    state.activeChannel = channel
                }
                if !state.autoJoinChannels.contains(where: { $0.lowercased() == channel.lowercased() }) {
                    state.autoJoinChannels.append(channel)
                    UserDefaults.standard.set(state.autoJoinChannels, forKey: "freeq.channels")
                }
                // Request history
                state.requestHistory(channel: channel)
                // Fetch pinned messages
                state.fetchPins(channel: channel)
                // Don't show "you joined" system message — the user knows they joined
                // If a blip dropped us mid-call in this channel, rejoin the
                // same AV session with the same instance — the server held the
                // slot in its grace window, so this re-enters in place.
                if shouldRejoinCall(pending: state.pendingCallRejoin, joinedChannel: channel, now: Date()),
                   let rejoin = state.pendingCallRejoin {
                    state.pendingCallRejoin = nil
                    state.currentAvInstance = rejoin.instance
                    print("[av] rejoining call after reconnect (session \(rejoin.sessionId))")
                    state.startCall(channel: rejoin.channel, sessionId: rejoin.sessionId)
                } else if let p = state.pendingCallRejoin,
                          Date().timeIntervalSince(p.disconnectedAt) >= 30 {
                    // Any other join clears a stale pending (wrong channel or
                    // past the window) so it can't fire later.
                    state.pendingCallRejoin = nil
                }
            } else {
                let msg = ChatMessage(
                    id: UUID().uuidString, from: "", text: "\(nick) joined",
                    isAction: false, timestamp: Date(), replyTo: nil
                )
                ch.appendIfNew(msg)
                if !ch.members.contains(where: { $0.nick.lowercased() == nick.lowercased() }) {
                    ch.members.append(MemberInfo(nick: nick, isOp: false, isHalfop: false, isVoiced: false, awayMsg: nil, did: nil))
                }
            }

        case .parted(let channel, let nick):
            // A PART names a nick, and all of this identity's devices share it, so
            // "the nick is mine" does not mean "I left". Treating it as such let a
            // browser tab or a game session delete a channel here, durably, because
            // the removal was written to the auto-join list.
            let partDecision = SelfPartResolve.decide(
                channel: channel,
                partNick: nick,
                myNick: state.nick,
                pendingRequests: state.pendingPartRequests
            )
            if partDecision == .leaveChannel {
                state.pendingPartRequests.removeValue(forKey: channel.lowercased())
                state.channels.removeAll { $0.name == channel }
                state.autoJoinChannels.removeAll { $0.lowercased() == channel.lowercased() }
                UserDefaults.standard.set(state.autoJoinChannels, forKey: "freeq.channels")
                if state.activeChannel == channel {
                    state.activeChannel = state.channels.first?.name
                }
            } else if partDecision == .ignoreOtherDevice {
                // Another of this identity's devices left. Keep the channel.
            } else {
                let ch = state.getOrCreateChannel(channel)
                ch.appendIfNew(ChatMessage(
                    id: UUID().uuidString, from: "", text: "\(nick) left",
                    isAction: false, timestamp: Date(), replyTo: nil
                ))
                ch.members.removeAll { $0.nick.lowercased() == nick.lowercased() }
            }

        case .message(let ircMsg):
            let target = ircMsg.target
            let from = ircMsg.fromNick
            let isSelf = state.isSelfSender(nick: from, account: ircMsg.account)
            // A blocked sender's message still lands in the buffer (filtered at
            // render, so unblocking restores it) but must not ring, badge, or
            // haptic — block is the advertised safety remedy, so it has to
            // suppress notifications too (by nick AND DID).
            let senderBlocked = !isSelf && state.isBlocked(nick: from, did: ircMsg.account)

            // Prefetch avatar using DID if available (from account-tag), and
            // adopt the binding (record AND fold a nick-keyed DM thread into
            // its DID-keyed one) — a conversation opened by nick and the same
            // one the server keys by DID (e.g. sent from web, or an offline
            // peer) must not show up as two threads.
            if let did = ircMsg.account {
                state.adoptDmBinding(nick: from, did: did)
                Task { @MainActor in
                    AvatarCache.shared.prefetch(from, did: did)
                }
            }

            // Server-persisted reactions replayed by CHATHISTORY ride the
            // `+freeq.at/reactions` tag → carry them onto the message so
            // reactions survive logout/login, not just live +react TAGMSGs.
            var initialReactions: [String: Set<String>] = [:]
            for tally in ircMsg.reactions where !tally.nicks.isEmpty {
                initialReactions[tally.emoji] = Set(tally.nicks)
            }

            // One conversation, one buffer: DMs key by the SDK's canonical
            // dm_key (peer DID when known, else nick); fallback preserves
            // behavior against an older SDK build.
            let dmBufName = ircMsg.dmKey ?? (isSelf ? target : from)

            // Channel E2EE: map ENC1 ciphertext to its display form (our own
            // echo-cached plaintext, a decrypt with the channel key, or a
            // placeholder when we lack the key). Parity with macOS.
            var displayText = ircMsg.text
            var wasEncrypted = false
            if target.hasPrefix("#") {
                (displayText, wasEncrypted) = state.channelE2ee.incoming(text: ircMsg.text, channel: target)
            }

            // SDK normalizes both wire forms (draft/multiline BATCH and
            // legacy +freeq.at/multiline) into real `\n` before this
            // point; no decode here. SwiftUI Text renders `\n` natively.
            // Own messages attribute to our current nick, whichever client
            // alias sent them — one DID, one visible identity; edit/delete
            // "my last message" selection follows.
            let msg = ChatMessage(
                id: ircMsg.msgid ?? UUID().uuidString,
                from: isSelf ? state.nick : from,
                text: displayText,
                isAction: ircMsg.isAction,
                timestamp: Date(timeIntervalSince1970: Double(ircMsg.timestampMs) / 1000.0),
                replyTo: ircMsg.replyTo,
                // Covers both signals: a live edit (`edit_of`) and one the
                // server already collapsed into join replay, which carries no
                // `+draft/edit` and would otherwise read as the original.
                isEdited: ircMsg.edited,
                isSigned: ircMsg.isSigned,
                isEncrypted: wasEncrypted,
                origin: ircMsg.origin,
                account: ircMsg.account,
                editOf: ircMsg.editOf,
                coordination: ircMsg.coordination.map {
                    CoordinationInfo(
                        eventType: $0.eventType, taskId: $0.taskId, phase: $0.phase,
                        evidenceType: $0.evidenceType, reference: $0.reference, payload: $0.payload)
                },
                reactions: initialReactions
            )

            // Handle edits
            if let editOf = ircMsg.editOf {
                if let batchId = ircMsg.batchId, var batch = state.batches[batchId] {
                    // Match the original id OR a prior editOf — chained edits
                    // keep referencing the original msgid after the first edit
                    // rewrote the in-memory id (parity with macOS).
                    if let idx = batch.messages.firstIndex(where: { $0.id == editOf || $0.editOf == editOf }) {
                        batch.messages[idx].text = displayText
                        batch.messages[idx].isEdited = true
                        batch.messages[idx].editOf = batch.messages[idx].editOf ?? editOf
                        // Keeps the id it was born with — see ChannelState.applyEdit.
                        // Reactions attach to the msgid the user reacted to —
                        // usually the latest edit id — so replay delivers
                        // them ON the edit row. Merge them or reactions on
                        // edited messages vanish every relaunch.
                        for (emoji, nicks) in msg.reactions where !nicks.isEmpty {
                            batch.messages[idx].reactions[emoji] = nicks
                        }
                    } else {
                        batch.messages.append(msg)
                    }
                    state.batches[batchId] = batch
                    return
                }

                let editBuf = target.hasPrefix("#")
                    ? state.getOrCreateChannel(target)
                    : state.getOrCreateDM(dmBufName)
                // Only the original sender may edit. The server enforces this
                // for persisted threads; for unpersisted (guest) DMs it
                // relays without a row to check, so the client is the
                // authority. Use displayText so an edit to an E2EE channel
                // message applies its decrypted form, not the ciphertext.
                if state.authorMatches(in: editBuf, originalId: editOf,
                                       actorNick: from, actorAccount: ircMsg.account) {
                    editBuf.applyEdit(originalId: editOf, newId: ircMsg.msgid, newText: displayText)
                }
                return
            }

            // Handle pin/unpin notifications (update pins set, show as action message)
            if let pinMsgid = ircMsg.pinMsgid, target.hasPrefix("#") {
                let ch = state.getOrCreateChannel(target)
                ch.pins.insert(pinMsgid)
                ch.appendIfNew(msg)
                return
            }
            if let unpinMsgid = ircMsg.unpinMsgid, target.hasPrefix("#") {
                let ch = state.getOrCreateChannel(target)
                ch.pins.remove(unpinMsgid)
                ch.appendIfNew(msg)
                return
            }

            // If part of CHATHISTORY batch, buffer it for later merge
            if let batchId = ircMsg.batchId, var batch = state.batches[batchId] {
                batch.messages.append(msg)
                state.batches[batchId] = batch
                return
            }

            if target.hasPrefix("#") {
                let ch = state.getOrCreateChannel(target)
                ch.appendIfNew(msg)
                if !senderBlocked { state.incrementUnread(target) }
                ch.typingUsers.removeValue(forKey: from)

                // Notify on mention (skip if muted, blocked, or our nick is
                // empty — an empty nick makes `contains` match every message).
                let mentioned = !state.nick.isEmpty
                    && ircMsg.text.range(of: state.nick, options: .caseInsensitive) != nil
                if !isSelf && !senderBlocked && mentioned && !state.isMuted(target) {
                    NotificationManager.shared.sendMessageNotification(
                        from: from, text: ircMsg.text, channel: target, isMention: true
                    )
                    // Haptic when mentioned in active app
                    UINotificationFeedbackGenerator().notificationOccurred(.warning)
                }
            } else {
                // Our OWN echoed DM carries the recipient's nick as `target`
                // and their canonical DID as `dmKey`. Adopt that binding FIRST
                // so a thread opened by nick folds into the DID-keyed thread the
                // echo routes to — otherwise the sender never sees their own DM.
                if let bind = DmEcho.recipientBinding(isSelf: isSelf, target: target, dmKey: ircMsg.dmKey) {
                    state.adoptDmBinding(nick: bind.nick, did: bind.did)
                }
                let bufferName = dmBufName
                // New activity in a previously-closed DM un-closes it. If
                // the peer messages me, or I message them, I want the DM
                // back in the list.
                state.closedDMs.remove(bufferName.lowercased())
                let dm = state.getOrCreateDM(bufferName)
                dm.appendIfNew(msg)
                if !senderBlocked { state.incrementUnread(bufferName) }

                // Always notify on DMs (unless blocked)
                if !isSelf && !senderBlocked {
                    NotificationManager.shared.sendMessageNotification(
                        from: from, text: ircMsg.text, channel: bufferName
                    )
                }
            }

        case .names(let channel, let members):
            let ch = state.getOrCreateChannel(channel)
            // Deduplicate by lowercased nick (server may send same nick with different cases)
            var seen = Set<String>()
            ch.members = members.compactMap { m -> MemberInfo? in
                let key = m.nick.lowercased()
                guard !seen.contains(key) else { return nil }
                seen.insert(key)
                return MemberInfo(nick: m.nick, isOp: m.isOp, isHalfop: m.isHalfop, isVoiced: m.isVoiced, awayMsg: m.awayMsg, did: nil)
            }
            // Prefetch avatars for all channel members
            let nicks = members.map { $0.nick }
            Task { @MainActor in
                AvatarCache.shared.prefetchAll(nicks)
            }

        case .topicChanged(let channel, let topic):
            let ch = state.getOrCreateChannel(channel)
            ch.topic = topic.text
            ch.lastActivity = Date()

        case .modeChanged(let channel, let mode, let arg, _):
            guard let nick = arg else { break }
            let ch = state.getOrCreateChannel(channel)
            if let idx = ch.members.firstIndex(where: { $0.nick.lowercased() == nick.lowercased() }) {
                let member = ch.members[idx]
                switch mode {
                case "+o": ch.members[idx] = MemberInfo(nick: member.nick, isOp: true, isHalfop: false, isVoiced: member.isVoiced, awayMsg: member.awayMsg, did: member.did)
                case "-o": ch.members[idx] = MemberInfo(nick: member.nick, isOp: false, isHalfop: member.isHalfop, isVoiced: member.isVoiced, awayMsg: member.awayMsg, did: member.did)
                case "+h": ch.members[idx] = MemberInfo(nick: member.nick, isOp: member.isOp, isHalfop: true, isVoiced: member.isVoiced, awayMsg: member.awayMsg, did: member.did)
                case "-h": ch.members[idx] = MemberInfo(nick: member.nick, isOp: member.isOp, isHalfop: false, isVoiced: member.isVoiced, awayMsg: member.awayMsg, did: member.did)
                case "+v": ch.members[idx] = MemberInfo(nick: member.nick, isOp: member.isOp, isHalfop: member.isHalfop, isVoiced: true, awayMsg: member.awayMsg, did: member.did)
                case "-v": ch.members[idx] = MemberInfo(nick: member.nick, isOp: member.isOp, isHalfop: member.isHalfop, isVoiced: false, awayMsg: member.awayMsg, did: member.did)
                default: break
                }
            }

        case .kicked(let channel, let nick, let by, let reason):
            if nick.lowercased() == state.nick.lowercased() {
                state.channels.removeAll { $0.name == channel }
                state.autoJoinChannels.removeAll { $0.lowercased() == channel.lowercased() }
                UserDefaults.standard.set(state.autoJoinChannels, forKey: "freeq.channels")
                if state.activeChannel == channel {
                    state.activeChannel = state.channels.first?.name
                }
                state.errorMessage = "Kicked from \(channel) by \(by): \(reason)"
                Task { @MainActor in
                    ToastManager.shared.show("Kicked from \(channel)", icon: "xmark.circle.fill")
                }
            } else {
                let ch = state.getOrCreateChannel(channel)
                ch.appendIfNew(ChatMessage(
                    id: UUID().uuidString, from: "",
                    text: "\(nick) was kicked by \(by) (\(reason))",
                    isAction: false, timestamp: Date(), replyTo: nil
                ))
                ch.members.removeAll { $0.nick.lowercased() == nick.lowercased() }
            }

        case .batchStart(let id, _, let target):
            state.batches[id] = AppState.BatchBuffer(target: target, messages: [])

        case .batchEnd(let id):
            guard let batch = state.batches.removeValue(forKey: id) else { return }
            let sorted = batch.messages.sorted { $0.timestamp < $1.timestamp }
            if batch.target.hasPrefix("#") {
                let ch = state.getOrCreateChannel(batch.target)
                for msg in sorted { ch.appendIfNew(msg) }
            } else {
                let dm = state.getOrCreateDM(batch.target)
                for msg in sorted { dm.appendIfNew(msg) }
            }

        case .whoisEnd(let whoisNick):
            // The server has finished. A card that was waiting has its
            // answer now, whatever the answer turned out to be.
            state.settleIdentityLookup(whoisNick)

        case .memberDid(let bindNick, let bindDid):
            state.dmResolver.learned(nick: bindNick, did: bindDid)
            // A nick↔DID binding was learned (join/whois/account tag): record
            // it and fold any nick-keyed DM thread into the DID-keyed one —
            // a cold first DM keys by nick until the peer's reply teaches
            // the binding.
            state.adoptDmBinding(nick: bindNick, did: bindDid)

        case .chatHistoryTarget(let nick, let timestamp, let partnerDid):
            // Server tells us "you have history with this peer"; create the
            // DM buffer and seed lastActivity from the server-provided
            // timestamp (`time` tag, ISO8601). Without this, every DM
            // created from CHATHISTORY TARGETS gets `Date()` as its
            // lastActivity and the DM list sorts by registration order
            // (effectively random) until messages backfill.
            //
            // Respect user-closed DMs: server-side history is what made
            // closed DMs reappear on reload before we tracked them locally.
            // Key the conversation by its stable identity when the server
            // names it (freeq.at/partner-did); the nick renders via
            // displayNameForKey. Closed state is honored under BOTH keys —
            // a DM closed before this pass is nick-keyed.
            let key = partnerDid ?? nick
            if state.closedDMs.contains(key.lowercased())
                || state.closedDMs.contains(nick.lowercased()) { return }
            if let did = partnerDid {
                // Record + merge exactly like MemberDid — an OFFLINE peer
                // never emits one, so a leftover nick-keyed thread would
                // otherwise duplicate the DID-keyed row.
                state.adoptDmBinding(nick: nick, did: did)
            }
            let dm = state.getOrCreateDM(key)
            if let ts = timestamp,
               let parsed = ISO8601DateFormatter.freeqTargets.date(from: ts) {
                // If the buffer has no real messages yet, the current
                // lastActivity is just `Date()` from `getOrCreateDM` —
                // overwrite it. If the buffer was hydrated with messages
                // (cache or in-session), only update when the server's
                // timestamp is more recent. The previous version only had
                // the `parsed > dm.lastActivity` branch, which always
                // failed for fresh buffers (parsed is older than `now`).
                if dm.messages.isEmpty || parsed > dm.lastActivity {
                    dm.lastActivity = parsed
                }
            }

        case .tagMsg(let tagMsg):
            let tags = Dictionary(uniqueKeysWithValues: tagMsg.tags.map { ($0.key, $0.value) })
            let target = tagMsg.target
            let from = tagMsg.from
            let isSelf = state.isSelfSender(nick: from, account: tags["account"] ?? tags["+freeq.at/account"])
            // For DMs, an echoed TAGMSG from ourselves carries target=peer, from=self —
            // route to the peer's DM buffer, not a DM keyed by our own nick.
            // Same conversation keying as .message: the SDK's dm_key (peer
            // DID when known), with the legacy nick fallback.
            let dmBuffer = tagMsg.dmKey ?? (isSelf ? target : from)
            let bufferName = target.hasPrefix("#") ? target : dmBuffer

            // Typing indicators
            if let typing = tags["+typing"] {
                if !isSelf {
                    let ch = bufferName.hasPrefix("#") ? state.getOrCreateChannel(bufferName) : state.getOrCreateDM(bufferName)
                    if typing == "active" {
                        ch.typingUsers[from] = Date()
                    } else if typing == "done" {
                        ch.typingUsers.removeValue(forKey: from)
                    }
                }
            }

            // Message deletion
            if let deleteId = tags["+draft/delete"] {
                let ch = bufferName.hasPrefix("#") ? state.getOrCreateChannel(bufferName) : state.getOrCreateDM(bufferName)
                // Same authorship rule as edits (see the message arm).
                let account = tags["account"] ?? tags["+freeq.at/account"]
                if state.authorMatches(in: ch, originalId: deleteId,
                                       actorNick: from, actorAccount: account) {
                    ch.applyDelete(msgId: deleteId)
                }
            }

            // Reactions
            if let emoji = tags["+react"], let replyId = tags["+reply"] {
                let ch = bufferName.hasPrefix("#") ? state.getOrCreateChannel(bufferName) : state.getOrCreateDM(bufferName)
                ch.applyReaction(msgId: replyId, emoji: emoji, from: from)
            }

            // Reaction removal (toggle off)
            if let emoji = tags["+freeq.at/unreact"], let replyId = tags["+reply"] {
                let ch = bufferName.hasPrefix("#") ? state.getOrCreateChannel(bufferName) : state.getOrCreateDM(bufferName)
                ch.removeReaction(msgId: replyId, emoji: emoji, from: from)
            }

            // AV session lifecycle (`+freeq.at/av-state`)
            if let avState = tags["+freeq.at/av-state"],
               let avId = tags["+freeq.at/av-id"],
               target.hasPrefix("#") {
                let avActor = tags["+freeq.at/av-actor"] ?? from
                let chanKey = target.lowercased()
                let inThisCall = state.isInCall
                    && state.currentCallChannel?.lowercased() == chanKey
                switch avState {
                case "started":
                    state.activeAvSessions[chanKey] = avId
                    // Converge via the unit-tested race resolver: if we were
                    // trying to start this channel's call AT ALL, join the
                    // session that actually won — even when the actor is the
                    // OTHER starter. Keying on actor==self left the loser of a
                    // concurrent start wedged outside the call (macOS had the
                    // same bug; this is the parity fix).
                    if case .joinSession(let sid) = resolveAvStarted(
                        pendingStart: state.pendingAvStart.contains(chanKey),
                        actorIsSelf: avActor.lowercased() == state.nick.lowercased(),
                        sessionId: avId
                    ) {
                        state.pendingAvStart.remove(chanKey)
                        if !state.isInCall {
                            state.startCall(channel: target, sessionId: sid)
                        }
                    }
                case "ended":
                    state.activeAvSessions.removeValue(forKey: chanKey)
                    state.pendingAvStart.remove(chanKey)
                    // If we were in this session, tear it down. But never let
                    // an `ended` for a channel we're not in (or no longer in)
                    // accidentally trigger a `leaveCall` on the current call.
                    if inThisCall {
                        state.tearDownCallLocallyOnDisconnect()
                    }
                case "joined":
                    // Only mutate the participant roster if we're in this
                    // call AND the joiner is someone else. (Self-joined is a
                    // self-echo of our own av-join; FreeqAv ParticipantJoined
                    // will also fire for everyone else's video tracks.)
                    // Record the actor's instance→nick so a later `left` for
                    // a multi-nick account still resolves to the right tile.
                    if let avInstance = tags["+freeq.at/av-instance"], !avInstance.isEmpty {
                        state.avInstanceToNick[avInstance] = avActor
                    }
                    if inThisCall
                       && avActor.lowercased() != state.nick.lowercased()
                       && !state.callParticipants.contains(where: { $0.lowercased() == avActor.lowercased() }) {
                        state.callParticipants.append(avActor)
                    }
                case "left":
                    // Same gating: only update if it's a different participant
                    // and we're in this call. Symmetric with `joined`.
                    // Prefer the av-instance tag to resolve who left: the
                    // actor nick can differ from the joined nick for a
                    // multi-nick account. Fall back to the actor when the
                    // instance is absent or unmapped.
                    let avInstance = tags["+freeq.at/av-instance"]
                    let leaver = (avInstance.flatMap { $0.isEmpty ? nil : state.avInstanceToNick[$0] }) ?? avActor
                    let leaverKey = leaver.lowercased()
                    if inThisCall {
                        state.callParticipants.removeAll { $0.lowercased() == leaverKey }
                        state.participantsWithVideo = state.participantsWithVideo.filter {
                            $0.lowercased() != leaverKey
                        }
                        state.participantsWithScreen = state.participantsWithScreen.filter {
                            $0.lowercased() != leaverKey
                        }
                        state.remoteAudioLevels.removeValue(forKey: leaverKey)
                    }
                    if let avInstance, !avInstance.isEmpty {
                        state.avInstanceToNick.removeValue(forKey: avInstance)
                    }
                default:
                    break
                }
            }

            // Machine-readable AV failure (`+freeq.at/av-error`, directed at
            // us). A rejected av-join must tear down the optimistic call
            // state — we're not in the roster, so nobody will ever hear us.
            if let avError = tags["+freeq.at/av-error"] {
                state.handleAvError(code: avError,
                                    sessionId: tags["+freeq.at/av-id"] ?? "",
                                    reason: tags["+freeq.at/av-reason"] ?? "")
            }

            // Per-session media token (`+freeq.at/av-token`, directed at us
            // right after our av-join) — triggers the held media dial
            // (join → token → dial; audit F7).
            if let avToken = tags["+freeq.at/av-token"],
               let avId = tags["+freeq.at/av-id"] {
                state.handleAvToken(sessionId: avId, token: avToken)
            }

        case .nickChanged(let oldNick, let newNick):
            state.renameUser(oldNick: oldNick, newNick: newNick)

        case .actorClasses(let channel, let classes):
            state.applyActorClasses(channel: channel, classes: classes)

        case .presence(let nick, let presenceState, let status, _):
            state.applyPresence(nick: nick, state: presenceState, status: status)

        case .awayChanged(let nick, let awayMsg):
            state.updateAwayStatus(nick: nick, awayMsg: awayMsg)

        case .userQuit(let nick, _):
            for ch in state.channels {
                ch.members.removeAll { $0.nick.lowercased() == nick.lowercased() }
                ch.typingUsers.removeValue(forKey: nick)
            }

        case .notice(let text):
            // MOTD collection
            if text == "MOTD:START" {
                state.collectingMotd = true
                state.motdLines = []
            } else if text == "MOTD:END" {
                state.collectingMotd = false
                if !state.motdLines.isEmpty {
                    // Only show if content changed since last dismiss
                    let content = state.motdLines.joined(separator: "\n")
                    let hash = String(content.hashValue, radix: 36)
                    let seenHash = UserDefaults.standard.string(forKey: "freeq.motdSeenHash")
                    if hash != seenHash {
                        state.showMotd = true
                    }
                }
            } else if text.hasPrefix("MOTD:") {
                if state.collectingMotd {
                    state.motdLines.append(String(text.dropFirst(5)))
                }
            } else if text.hasPrefix("API-BEARER ") {
                // Capture the per-session REST bearer (parity with macOS) so
                // authenticated REST (roaming favorites) can identify our DID.
                let sid = String(text.dropFirst("API-BEARER ".count))
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !sid.isEmpty {
                    state.apiBearerSessionId = sid
                    state.syncFavoritesFromServer()
                }
            } else if let denial = ChannelAccessNotice.parse(text) {
                // Surface WHY a gated join failed instead of silently doing
                // nothing (parity with macOS). Banner + system line + toast.
                let ch = state.getOrCreateChannel(denial.channel)
                ch.accessDeniedReason = denial.reason
                ch.appendIfNew(ChatMessage(
                    id: "access-denied-\(denial.channel)-\(denial.reason)",
                    from: "", text: denial.reason,
                    isAction: false, timestamp: Date(), replyTo: nil))
                Task { @MainActor in
                    ToastManager.shared.show(denial.reason, icon: "lock.slash")
                }
            } else if !text.isEmpty {
                // IRCv3 FAIL lines arrive as ServerNotice text shaped
                // "COMMAND ERROR_CODE description". Surface them — a silent
                // server rejection is indistinguishable from a client bug
                // (a guest-DM edit failing invisibly cost an evening).
                // Background history probes (speculative CHATHISTORY on
                // opening a thread) fail routinely for guest peers —
                // toasting those spams with nothing actionable (mirror of
                // the web client's filter).
                if text.range(of: #"^[A-Z]+ [A-Z_]+ "#, options: .regularExpression) != nil,
                   !text.hasPrefix("CHATHISTORY ") {
                    Task { @MainActor in
                        ToastManager.shared.show("Server: \(text)", icon: "exclamationmark.triangle")
                    }
                }
                print("Notice: \(text)")
            }

        case .whoisReply(let whoisNick, let whoisInfo):
            // "No such nick" is an answer about the name, not about a
            // person: an unheld name has nobody to have an account.
            if whoisInfo.contains("No such nick") {
                state.noteWhoisNoSuchNick(nick: whoisNick)
            }
            // WHOIS replies — currently unused in UI
            break

        case .disconnected(let reason):
            // A dropped connection ends every question that was out on it,
            // and a WHOIS answer from the old session is not a live binding
            // on the new one.
            state.identityLookups.removeAll()

            print("[freeq.event] .disconnected reason=\(reason)")
            state.connectionState = .disconnected
            if !reason.isEmpty && !reason.contains("EOF") {
                state.errorMessage = "Disconnected: \(reason)"
            }
            // If we were in a call when the IRC connection dropped, tear it
            // down locally. The MoQ session is on a separate transport but
            // peers will only learn we left via the IRC `av-leave` TAGMSG —
            // which we obviously can't send right now. Surfacing a phantom
            // in-call state in the UI while the wire is dead is worse than
            // dropping the call: tap-to-rejoin is one tap, but trying to
            // mute/leave a zombie call is broken UX.
            if state.isInCall {
                state.tearDownCallLocallyOnDisconnect()
            }
            // FEAT-003: a WebSocket-named failure on this very attempt means
            // the network is hostile to WS — try plain TCP once before going
            // through the broker / showing the user any error UI.
            if state.attemptTransportFallback(reason: reason) {
                print("[freeq.event] -> falling back to TCP")
                return
            }
            // Auto-reconnect with exponential backoff
            if state.hasSavedSession {
                state.reconnectAttempts += 1
                // Fast first retry (1s), then 2, 4, 8, 15, 15...
                let delay = state.reconnectAttempts <= 1 ? 1.0 : min(Double(1 << min(state.reconnectAttempts - 1, 4)), 15.0)
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                    if state.connectionState == .disconnected && state.hasSavedSession {
                        state.reconnectSavedSession()
                    }
                }
            }

        case .readMarker(let target, let timestamp):
            // draft/read-marker — cross-device read state (forward-only,
            // enforced server-side). Store the latest marker so the unread
            // divider / catch-up UI can consume it. No standalone UI yet.
            if let timestamp { state.readMarkers[target.lowercased()] = timestamp }
        }
    }
}

// ── AV Event Handler ──

final class AvCallbackHandler: @unchecked Sendable, AvEventHandler {
    private weak var appState: AppState?

    init(appState: AppState) {
        self.appState = appState
    }

    func onAvEvent(event: AvEvent) {
        // FreeqAv delivers events from a background queue. Hop to main for
        // any state mutation, but stay synchronous when we're already there
        // (tests drive this synchronously; an async hop would defer past
        // the assertions).
        if Thread.isMainThread {
            handle(event: event)
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.handle(event: event)
            }
        }
    }

    private func handle(event: AvEvent) {
        guard let state = self.appState else { return }
        let myNick = state.nick.lowercased()

        switch event {
        case .connected:
            state.isInCall = true
            print("[av] Connected to MoQ SFU")

        case .disconnected(let reason):
            state.isInCall = false
            state.callParticipants = []
            state.participantsWithVideo = []
            state.participantsWithScreen = []
            state.remoteAudioLevels = [:]
            state.callTransportStatus = nil
            state.isCameraOn = false
            state.isMuted = false
            state.isCallExpanded = false
            state.currentCallChannel = nil
            state.currentCallSessionId = nil
            state.endCallActivity()
            print("[av] Disconnected: \(reason)")

        case .participantJoined(let nick, let instance):
            // Don't filter on nick alone here — the SDK already drops our
            // own broadcast at the path level (`path == our_name`), so
            // anything that reaches us is a *different device's* broadcast,
            // including same-DID multi-device (chadfowler on iOS + chadfowler
            // on web). The bare-nick "self-echo" filter we used to have
            // here was the cause of "iOS doesn't show my web client" — it
            // collapsed the multi-device case into a no-op.
            // Remember which nick this device joined under so a later `left`
            // signal (which can carry a different nick for a multi-nick
            // account) still resolves to the right tile via its instance.
            if !instance.isEmpty {
                state.avInstanceToNick[instance] = nick
            }
            if !state.callParticipants.contains(where: { $0.lowercased() == nick.lowercased() }) {
                state.callParticipants.append(nick)
            }
            state.updateCallActivity()
            print("[av] Participant joined: \(nick) [instance=\(instance)]")

        case .participantLeft(let nick, let instance):
            // Prefer the instance→nick mapping recorded at join time: the
            // `left` signal's nick can differ from the joined nick for a
            // multi-nick account, so keying teardown on the instance removes
            // the correct tile. Fall back to the signalled nick when the
            // instance is absent (legacy peer) or unmapped.
            let target = (!instance.isEmpty ? state.avInstanceToNick[instance] : nil) ?? nick
            let key = target.lowercased()
            // Symmetric removal: drop the tile AND the video-active marker.
            // Leaving the latter behind made the next call show a frozen-frame
            // tile for the departed nick the moment a same-named user joined.
            state.callParticipants.removeAll { $0.lowercased() == key }
            state.participantsWithVideo = state.participantsWithVideo.filter {
                $0.lowercased() != key
            }
            state.participantsWithScreen = state.participantsWithScreen.filter {
                $0.lowercased() != key
            }
            state.remoteAudioLevels.removeValue(forKey: key)
            if !instance.isEmpty {
                state.avInstanceToNick.removeValue(forKey: instance)
            }
            state.updateCallActivity()
            print("[av] Participant left: \(target) [instance=\(instance)]")

        case .audioTrackStarted(let nick):
            print("[av] Audio started: \(nick)")

        case .audioTrackStopped(let nick):
            print("[av] Audio stopped: \(nick)")

        case .videoTrackStarted(let nick):
            print("[av] Video started: \(nick)")

        case .videoTrackStopped(let nick):
            state.participantsWithVideo = state.participantsWithVideo.filter {
                $0.lowercased() != nick.lowercased()
            }
            print("[av] Video stopped: \(nick)")

        case .videoFrame(let nick, let bgra, let width, let height):
            // SDK already filters our own broadcast at the path level;
            // anything reaching us is for a different device. Matching on
            // bare nick blocked the multi-device case (same handle on
            // iOS + web).
            // Race: a frame can arrive before the SFU's ParticipantJoined event
            // fires (out-of-order on the network). Drop the frame silently
            // rather than crash or create a phantom participant; the next
            // frame after the Joined arrives will render normally.
            guard state.callParticipants.contains(where: { $0.lowercased() == nick.lowercased() }) else {
                return
            }
            if let layer = state.videoLayer(for: nick) {
                VideoSampleBuffer.enqueue(
                    bgra: bgra,
                    width: Int(width),
                    height: Int(height),
                    on: layer
                )
            }
            _ = state.participantsWithVideo.insert(nick)

        case .screenTrackStarted(let nick):
            // A peer began sharing their screen on the `{peer}/screen` path.
            // Mark them so the UI can offer a screen tile even before the
            // first frame lands.
            _ = state.participantsWithScreen.insert(nick)
            print("[av] Screen started: \(nick)")

        case .screenTrackStopped(let nick):
            state.participantsWithScreen = state.participantsWithScreen.filter {
                $0.lowercased() != nick.lowercased()
            }
            print("[av] Screen stopped: \(nick)")

        case .screenFrame(let nick, let bgra, let width, let height):
            // Screen frames flow through a dedicated per-nick display layer
            // (bound by `RemoteScreenTile`), separate from the camera-track
            // layer, so a participant can share screen and camera at once.
            // Same join/frame race tolerance as videoFrame: a frame from a
            // nick we haven't logged as a participant yet is still real media,
            // so adopt them rather than dropping it.
            if !state.callParticipants.contains(where: { $0.lowercased() == nick.lowercased() }) {
                state.callParticipants.append(nick)
            }
            _ = state.participantsWithScreen.insert(nick)
            if let layer = state.screenLayer(for: nick) {
                VideoSampleBuffer.enqueue(
                    bgra: bgra,
                    width: Int(width),
                    height: Int(height),
                    on: layer
                )
            }

        case .audioLevel(let nick, let level):
            // Remote playout level → stored for active-speaker highlighting.
            // The iOS call UI doesn't render a speaking ring yet, so this is
            // just a data sink for now; the value is keyed lowercased to match
            // the other per-nick maps.
            state.remoteAudioLevels[nick.lowercased()] = level

        case .reconnecting(let attempt):
            // Inline call-bar status only — NOT an errorMessage/modal alert.
            // Automatic transport recovery must not read as a hard failure.
            state.callTransportStatus = attempt <= 1
                ? "Reconnecting…" : "Reconnecting… (attempt \(attempt))"
            print("[av] Reconnecting (attempt \(attempt))")

        case .reconnected:
            state.callTransportStatus = nil
            print("[av] Reconnected")

        case .error(let message):
            print("[av] Error: \(message)")
        }
    }
}
