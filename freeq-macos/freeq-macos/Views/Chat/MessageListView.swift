import SwiftUI

/// The channel message list.
///
/// Phase 2 rewrite: the default implementation is `AppKitMessageListView`
/// (an `NSViewRepresentable` over a view-based `NSTableView` with row reuse
/// and granular per-row updates). The old SwiftUI `LazyVStack` list is kept
/// behind the `freeq.useLegacyMessageList` debug flag so the FrameHitch
/// harness can A/B the two on demand. See `SPIKE-MESSAGE-LIST.md`.
///
/// This wrapper owns the two cross-cutting concerns both implementations
/// share: the empty-channel welcome overlay and the reading-surface
/// background. Reading `messages` here (via the timeline build) registers the
/// Observation dependency, so every append/edit/delete/reaction re-evaluates
/// this body and hands the chosen list fresh, pre-grouped rows.
struct MessageListView: View {
    @Environment(AppState.self) private var appState
    let channel: ChannelState?

    // A/B flag. Default OFF → the AppKit list. Flip on (in UserDefaults) to
    // fall back to the legacy LazyVStack for a side-by-side hitch comparison.
    @AppStorage("freeq.useLegacyMessageList") private var useLegacy = false
    // Read here (not just inside rows) so a compact-mode toggle re-evaluates
    // this body and lets the AppKit list re-measure every row height.
    @AppStorage("freeq.compactMode") private var compactMode = false

    // Blocked people's messages never reach the timeline (reading blockList
    // here registers the Observation dependency, so a block/unblock re-filters
    // live). System lines always pass.
    private var messages: [ChatMessage] {
        appState.blockList.visible(channel?.messages ?? []) {
            ProfileCache.shared.did(for: $0)
        }
    }

    // Deleted messages render as tombstones (reading flow must not silently
    // lose rows mid-scroll), so the timeline is over ALL messages.
    private var shouldShowWelcome: Bool { messages.isEmpty }

    var body: some View {
        ZStack {
            // One O(n) pass turns the raw messages into grouped rows (date
            // separators + sender-header decisions baked in). Cheap array work
            // — the expensive part (view layout) is what the AppKit list now
            // controls per-row instead of re-diffing the whole world.
            let rows = MessageListTimeline.build(from: messages)

            if useLegacy {
                LegacyMessageListView(channel: channel, rows: rows)
            } else {
                AppKitMessageListView(
                    rows: rows,
                    channelToken: channel?.name ?? "",
                    scrollTarget: appState.scrollToMessageId,
                    compactToken: compactMode,
                    showLoadMore: !messages.isEmpty,
                    appState: appState,
                    onLoadOlder: loadOlderHistory)
            }

            if shouldShowWelcome {
                ChannelWelcomeView()
            }

            if appState.hasMessageSelection {
                SelectionHintBar()
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                    .padding(.top, 8)
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .background(Theme.chatBackground)
        .animation(.easeInOut(duration: 0.15), value: appState.hasMessageSelection)
    }

    private func loadOlderHistory() {
        guard let target = appState.activeChannel,
              let oldest = messages.first else { return }
        appState.requestHistory(channel: target, before: oldest.timestamp)
    }
}

// MARK: - Selection hint bar

/// Floating pill shown while a block of messages is selected. Gives the copy
/// action a visible target (not just ⌘C) plus Select-all / Clear, and quietly
/// teaches the shortcuts. Selection lives in `AppState`; the AppKit list drives
/// it from shift/cmd-clicks.
private struct SelectionHintBar: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        let count = appState.selectedMessageIds.count
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(Theme.accent)
            Text("\(count) selected")
                .font(.system(.callout, weight: .medium))
                .monospacedDigit()

            Divider().frame(height: 14)

            Button {
                let n = appState.copySelectedMessages()
                if n > 0 { appState.clearMessageSelection() }
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .help("Copy the selected messages as clean text (⌘C)")

            Button("Select all") { appState.selectAllMessages() }
                .help("Select every message in this conversation")

            Button("Clear") { appState.clearMessageSelection() }
                .help("Clear the selection (Esc)")
        }
        .buttonStyle(.plain)
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(Theme.border, lineWidth: 1))
        .shadow(color: .black.opacity(0.18), radius: 8, y: 2)
    }
}

// MARK: - Hover-bar clamp

/// Where this row's top sits relative to the list's visible top edge
/// (`topGap` = rowTop − visibleTop; negative once the row has scrolled past
/// it). The AppKit list measures this per visible row — it owns the real
/// viewport geometry; SwiftUI `.global` can't see across the per-row hosting
/// views — and the hovered row positions its action bar off it: straddling
/// the row's top boundary when there's room, sliding down just enough to
/// stay inside the viewport when there isn't.
@Observable final class RowClamp {
    var topGap: CGFloat = .greatestFiniteMagnitude
    /// Set by the hosting cell; the row calls it on hover so the cell can lift
    /// itself above its neighbours (and drop clipping) — otherwise the action
    /// bar, which is taller than a compact/grouped row, is clipped by the cell
    /// or painted over by the next row.
    @ObservationIgnored var onHoverChanged: ((Bool) -> Void)?
}

// MARK: - Timeline model (shared by both list implementations)

/// One rendered row: the message plus the two grouping decisions that depend
/// on its neighbours. Equatable (via `ChatMessage` + the two Bools) so the
/// AppKit list can diff rows and reload only what actually changed — a header
/// or separator flip caused by an inserted neighbour reloads that one row.
struct RowModel: Equatable, Identifiable {
    var message: ChatMessage
    var showsDateSeparator: Bool
    var showHeader: Bool
    /// When set, this row represents a coalesced run of ≥2 consecutive
    /// join/part/quit lines (rendered as one collapsible summary instead of a
    /// pill per event — kills reconnect-storm spam while keeping the record).
    var coalescedSystem: [ChatMessage]? = nil
    var id: String { message.id }
}

/// Pure builder: `[ChatMessage] → [RowModel]` in a single forward pass.
/// Grouping/separator policy lives here (one place), so both the legacy and
/// AppKit lists render identically.
enum MessageListTimeline {
    static func build(from messages: [ChatMessage]) -> [RowModel] {
        var out: [RowModel] = []
        out.reserveCapacity(messages.count)
        var prev: ChatMessage?
        var i = 0
        while i < messages.count {
            let msg = messages[i]
            // A live join/part/quit line is a system message (empty `from`) that
            // isn't a deletion tombstone.
            if msg.from.isEmpty && !msg.isDeleted {
                var run: [ChatMessage] = []
                var j = i
                while j < messages.count, messages[j].from.isEmpty, !messages[j].isDeleted {
                    run.append(messages[j])
                    j += 1
                }
                let first = run[0]
                let sep = MessageTimeline.showsDateSeparator(
                    before: first.timestamp, previous: prev?.timestamp)
                out.append(RowModel(
                    message: first,
                    showsDateSeparator: sep,
                    showHeader: false,
                    // Only fold when there's an actual run — a lone join/leave
                    // still renders as a normal single pill.
                    coalescedSystem: run.count >= 2 ? run : nil))
                prev = run.last
                i = j
            } else {
                out.append(RowModel(
                    message: msg,
                    showsDateSeparator: MessageTimeline.showsDateSeparator(
                        before: msg.timestamp, previous: prev?.timestamp),
                    showHeader: showsHeader(prev: prev, current: msg)))
                prev = msg
                i += 1
            }
        }
        return out
    }

    /// A row draws its sender header unless it collapses under the previous
    /// message from the same sender (mirrors the old `MessageRow.showHeader`).
    static func showsHeader(prev: ChatMessage?, current: ChatMessage) -> Bool {
        guard let prev else { return true }
        if prev.from.isEmpty { return true }        // after a system line
        if prev.isDeleted { return true }           // tombstones break grouping
        if prev.from != current.from { return true }
        // Break across a provenance boundary: a federated message (origin set)
        // must not collapse under a local sender's header.
        if prev.origin != current.origin { return true }
        return current.timestamp.timeIntervalSince(prev.timestamp) > 300
    }
}

// MARK: - Row content (hosted in each AppKit cell; reused by the legacy list)

/// The exact per-row visual: optional date separator stacked above the row
/// body (message / tombstone / system line). One view per timeline entry, so
/// it drops straight into an `NSHostingView` cell or a `LazyVStack` element.
struct MessageTimelineRowContent: View {
    let row: RowModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if row.showsDateSeparator {
                DateSeparatorView(date: row.message.timestamp)
            }
            if let run = row.coalescedSystem {
                CoalescedSystemRow(events: run)
            } else if row.message.isDeleted {
                DeletedMessageRow(message: row.message)
            } else if row.message.from.isEmpty {
                SystemMessageRow(message: row.message)
            } else {
                MessageRow(message: row.message, showHeader: row.showHeader)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The "Load older messages" affordance (CHATHISTORY back-fill), pinned as the
/// first row of the list.
struct LoadMoreRowContent: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Spacer()
                Image(systemName: "arrow.up.circle")
                Text("Load older messages")
                Spacer()
            }
            .font(.caption)
            .foregroundStyle(Theme.textSecondary)
        }
        .buttonStyle(.plain)
        .padding(.vertical, 8)
        .background(
            Capsule()
                .fill(Theme.surfaceSoft)
                .padding(.horizontal, 220))
    }
}

// MARK: - Legacy SwiftUI list (behind freeq.useLegacyMessageList)

/// The pre-Phase-2 `ScrollView` + `LazyVStack` list. Retained verbatim (only
/// re-pointed at the shared `RowModel`/row content) so the hitch harness can
/// A/B it against the AppKit list. The spike proved it misses the <1% budget
/// by 40–100× under scroll + streaming-edit load — hence the rewrite.
struct LegacyMessageListView: View {
    @Environment(AppState.self) private var appState
    let channel: ChannelState?
    let rows: [RowModel]

    @State private var lastRenderedChannel: String?
    private let bottomAnchorID = "__bottom"

    private var messages: [ChatMessage] { channel?.messages ?? [] }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if !messages.isEmpty {
                        LoadMoreRowContent(action: loadOlderHistory)
                            .id("load-more")
                    }

                    // Each ForEach element must produce exactly ONE view or
                    // LazyVStack's in-place row updates break — the separator
                    // is folded into the row content view for that reason.
                    ForEach(rows) { row in
                        MessageTimelineRowContent(row: row)
                            .id(row.message.id)
                    }

                    Color.clear
                        .frame(height: 12)
                        .id(bottomAnchorID)
                }
                .padding(.top, 8)
            }
            .onChange(of: messages.count) { oldCount, newCount in
                let isInitialLoadForCurrentChannel =
                    lastRenderedChannel != appState.activeChannel
                guard newCount > 0 else { return }
                if isInitialLoadForCurrentChannel {
                    proxy.scrollTo(bottomAnchorID, anchor: .bottom)
                    lastRenderedChannel = appState.activeChannel
                } else if newCount > oldCount {
                    withAnimation(.easeOut(duration: 0.15)) {
                        proxy.scrollTo(bottomAnchorID, anchor: .bottom)
                    }
                }
            }
            .onChange(of: appState.activeChannel) { _, _ in
                DispatchQueue.main.async {
                    proxy.scrollTo(bottomAnchorID, anchor: .bottom)
                    lastRenderedChannel = appState.activeChannel
                }
            }
            .onAppear {
                proxy.scrollTo(bottomAnchorID, anchor: .bottom)
                lastRenderedChannel = appState.activeChannel
            }
            .onChange(of: appState.scrollToMessageId) { _, newId in
                if let id = newId {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        proxy.scrollTo(id, anchor: .center)
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        appState.scrollToMessageId = nil
                    }
                }
            }
        }
    }

    private func loadOlderHistory() {
        guard let target = appState.activeChannel,
              let oldest = messages.first else { return }
        appState.requestHistory(channel: target, before: oldest.timestamp)
    }
}

// MARK: - Date Separator

struct DateSeparatorView: View {
    let date: Date

    var body: some View {
        HStack(spacing: 8) {
            Rectangle()
                .fill(Theme.borderSoft)
                .frame(height: 1)
            Text(MessageTimeline.dayLabel(for: date))
                .font(.caption2.weight(.semibold))
                .foregroundStyle(Theme.textTertiary)
                .fixedSize()
            Rectangle()
                .fill(Theme.borderSoft)
                .frame(height: 1)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }
}

// MARK: - Deleted Message Tombstone

struct DeletedMessageRow: View {
    let message: ChatMessage

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "trash")
                .font(.caption2)
                .foregroundStyle(Theme.textTertiary)
            Text("Message from \(message.from) deleted")
                .font(.caption)
                .italic()
                .foregroundStyle(Theme.textTertiary)
            Text(formatTime(message.timestamp))
                .font(.caption2)
                .foregroundStyle(Theme.textTertiary.opacity(0.75))
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - System Messages (join/part/quit/kick)

struct SystemMessageRow: View {
    let message: ChatMessage
    @AppStorage("freeq.showJoinPart") private var showJoinPart = true

    var body: some View {
        if showJoinPart {
            HStack(spacing: 4) {
                Image(systemName: systemIcon)
                    .font(.caption2)
                    .foregroundStyle(Theme.textTertiary)
                Text(message.text)
                    .font(.caption)
                    .foregroundStyle(Theme.textSecondary)
                Text(formatTime(message.timestamp))
                    .font(.caption2)
                    .foregroundStyle(Theme.textTertiary.opacity(0.75))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(Capsule().fill(Theme.systemPill))
            .padding(.horizontal, 16)
            .padding(.vertical, 3)
            .frame(maxWidth: .infinity, alignment: .center)
        }
    }

    private var systemIcon: String {
        if message.text.contains("joined") { return "arrow.right.circle" }
        if message.text.contains("left") || message.text.contains("quit") { return "arrow.left.circle" }
        if message.text.contains("kicked") { return "xmark.circle" }
        return "info.circle"
    }
}

/// A coalesced run of consecutive join/part/quit lines, shown as one compact
/// pill ("nap reconnected 4×" / "3 joined · 1 left") that expands on click to
/// the individual events. Documents the churn without a pill per event, and —
/// like `SystemMessageRow` — honours the freeq.showJoinPart toggle.
struct CoalescedSystemRow: View {
    let events: [ChatMessage]
    @AppStorage("freeq.showJoinPart") private var showJoinPart = true
    @State private var expanded = false

    var body: some View {
        if showJoinPart {
            VStack(spacing: 3) {
                Button { withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() } } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.left.arrow.right.circle")
                            .font(.caption2)
                            .foregroundStyle(Theme.textTertiary)
                        Text(summary)
                            .font(.caption)
                            .foregroundStyle(Theme.textSecondary)
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 8, weight: .semibold))
                            .foregroundStyle(Theme.textTertiary)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Capsule().fill(Theme.systemPill))
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .help("\(events.count) presence changes — click to \(expanded ? "collapse" : "expand")")

                if expanded {
                    VStack(spacing: 2) {
                        ForEach(events) { event in
                            HStack(spacing: 4) {
                                Image(systemName: icon(for: event.text))
                                    .font(.system(size: 9))
                                    .foregroundStyle(Theme.textTertiary)
                                Text(event.text)
                                    .font(.caption2)
                                    .foregroundStyle(Theme.textTertiary)
                                Text(formatTime(event.timestamp))
                                    .font(.system(size: 9))
                                    .foregroundStyle(Theme.textTertiary.opacity(0.7))
                            }
                        }
                    }
                    .padding(.top, 1)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 3)
            .frame(maxWidth: .infinity, alignment: .center)
        }
    }

    private func icon(for text: String) -> String {
        if text.contains("joined") { return "arrow.right.circle" }
        if text.contains("left") || text.contains("quit") { return "arrow.left.circle" }
        if text.contains("kicked") { return "xmark.circle" }
        return "info.circle"
    }

    /// "nap reconnected 4×" when it's one person's churn, else "3 joined · 1 left".
    private var summary: String {
        var joins = 0, leaves = 0, other = 0
        var nicks = Set<String>()
        for e in events {
            let t = e.text
            if let nick = t.split(separator: " ").first { nicks.insert(nick.lowercased()) }
            if t.contains("joined") { joins += 1 }
            else if t.contains("left") || t.contains("quit") { leaves += 1 }
            else { other += 1 }
        }
        if nicks.count == 1, let nick = events.first?.text.split(separator: " ").first.map(String.init) {
            if joins > 0 && leaves > 0 { return "\(nick) reconnected \(min(joins, leaves))×" }
            if joins > 0 { return "\(nick) joined \(joins)×" }
            if leaves > 0 { return "\(nick) left \(leaves)×" }
        }
        var parts: [String] = []
        if joins > 0 { parts.append("\(joins) joined") }
        if leaves > 0 { parts.append("\(leaves) left") }
        if other > 0 { parts.append("\(other) event\(other == 1 ? "" : "s")") }
        return parts.joined(separator: " · ")
    }
}

// MARK: - Message Row

/// A tapped @mention, used to present that person's profile sheet.
struct MentionTarget: Identifiable {
    var id: String { nick }
    let nick: String
    var origin: String? = nil
    /// The anchoring row's evidence, when opened from a message: its account
    /// tag, its timestamp, and whether the sender is in a roster right now.
    /// When live identity can't answer, the row does — the SDK owns that
    /// precedence. A mention link with no row in hand carries none of it.
    var account: String? = nil
    var rowTime: Date? = nil
    var senderPresent: Bool = false
}

/// Why the proof sheet is open. Showing who someone is and checking whether a
/// specific message's signature holds up are different questions, and the
/// sheet leads with whichever was asked.
struct ProofRequest: Identifiable {
    let id = UUID()
    /// nil = identity only; set = check this message and lead with the answer.
    let msgId: String?

    static let identity = ProofRequest(msgId: nil)
    static func verify(_ messageId: String) -> ProofRequest { ProofRequest(msgId: messageId) }
}

struct MessageRow: View {
    @Environment(AppState.self) private var appState
    /// Present only in the AppKit list; nil in the legacy list (no clamp).
    @Environment(RowClamp.self) private var rowClamp: RowClamp?
    @AppStorage("freeq.compactMode") private var compactMode = false
    let message: ChatMessage
    /// Whether this row draws the sender header (avatar + name + badges).
    /// Computed once by `MessageListTimeline` from the preceding message, so
    /// grouping is a data property the list diffs on — not a per-row scan of
    /// the whole channel on every render (the old computed-property approach).
    let showHeader: Bool

    // Hover is a UNION of row-hover and bar-hover: the action bar can be
    // taller than a single-line grouped row, so the pointer legitimately
    // sits on the bar while outside the row. If the bar's visibility keyed
    // off row-hover alone, reaching for it would hide it under the cursor
    // (flicker loop, unclickable buttons). Row-unhover is debounced one
    // beat so the hover can hand off to the bar across the frame boundary.
    @State private var isRowHovered = false
    @State private var isBarHovered = false
    @State private var hoverToken = 0
    private var isHovered: Bool {
        isRowHovered || isBarHovered || appState.debugForceHoverMsgId == message.id
    }

    // Safety (report/block) + identity proof presentation
    @State private var reportTarget: ReportTarget?
    /// Which proof the sheet is open for: the sender's identity, or the
    /// checked answer for this specific message.
    @State private var proofRequest: ProofRequest?
    /// A tapped @mention, presenting that person's profile.
    @State private var mentionTarget: MentionTarget?

    private var isSelf: Bool {
        message.from.lowercased() == appState.nick.lowercased()
    }

    private var isSystem: Bool {
        message.from == "server" || message.from == "system"
    }

    private var profile: ProfileCache.Profile? {
        ProfileCache.shared.profile(for: message.from)
    }

    /// The answer, if the reader has already asked about this message.
    private var checkedVerdict: VerifyAnswer? {
        appState.checkedVerdicts[message.id]
    }

    /// What this row can honestly claim about its sender — computed by the
    /// SDK from the row's own tags and the live room, never from a cache.
    /// Presence is only consulted when the tags can't answer, so the roster
    /// scan is skipped for the common tagged row.
    private var rowClaim: IdentityClaim {
        let needsRoom = message.account == nil && message.origin == nil
        let present = needsRoom && appState.isNickPresent(message.from)
        return claimForMessage(input: MessageClaimInput(
            account: message.account,
            origin: message.origin,
            senderPresent: present,
            senderLiveDid: present ? appState.didForNick(message.from) : nil,
            rowTimeUnix: UInt64(message.timestamp.timeIntervalSince1970)
        ))
    }
    private var showsIdentityMark: Bool { rowClaim.showsMark }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if compactMode {
                // Compact: inline nick + time + text on one line
                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text(formatTime(message.timestamp))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary.opacity(0.75))
                        .frame(width: 36, alignment: .trailing)
                    Button { mentionTarget = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) } label: {
                        Text(message.from)
                            .font(.system(.caption, weight: .bold))
                            .foregroundStyle(isSystem ? Theme.textSecondary : Theme.nickColor(for: message.from))
                    }
                    .buttonStyle(.plain)
                    .disabled(isSystem)
                    .help("View profile")
                    if showsIdentityMark {
                        Button { proofRequest = .identity } label: {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.system(size: 8))
                                .foregroundStyle(Theme.verified)
                        }
                        .buttonStyle(.plain)
                        .help("AT Protocol identity — click for proof")
                    }
                    if let origin = message.origin {
                        Text("via \(origin)")
                            .font(.system(size: 9))
                            .foregroundStyle(Theme.textTertiary)
                    }
                }
            } else if showHeader {
                HStack(alignment: .top, spacing: 8) {
                    if !isSystem {
                        Button { mentionTarget = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) } label: {
                            AvatarView(nick: message.from, size: 24)
                        }
                        .buttonStyle(.plain)
                        .padding(.top, 2)
                        .help("View profile")
                    }
                    VStack(alignment: .leading, spacing: 0) {
                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            if let displayName = profile?.displayName, !displayName.isEmpty {
                                // Name and nick are one target. Split into a
                                // button and a bare label, the nick beside a
                                // clickable name reads as dead text.
                                Button { mentionTarget = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) } label: {
                                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                                        Text(displayName)
                                            .font(.system(.body, weight: .semibold))
                                            .foregroundStyle(Theme.nickColor(for: message.from))
                                        Text(message.from)
                                            .font(.caption)
                                            .foregroundStyle(Theme.textTertiary)
                                    }
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .help("View profile")
                            } else {
                                Button { mentionTarget = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) } label: {
                                    Text(message.from)
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundStyle(isSystem ? Theme.textSecondary : Theme.nickColor(for: message.from))
                                }
                                .buttonStyle(.plain)
                                .disabled(isSystem)
                                .help("View profile")
                            }

                            // The mark opens the proof behind the claim it
                            // makes, wherever it appears. The name opens the
                            // person's card.
                            if showsIdentityMark {
                                Button { proofRequest = .identity } label: {
                                    Image(systemName: "checkmark.seal.fill")
                                        .font(.caption2)
                                        .foregroundStyle(Theme.verified)
                                }
                                .buttonStyle(.plain)
                                .help("AT Protocol identity — click for proof")
                            }

                            // No badge for a signed message: almost every
                            // message is signed, so a badge on every row says
                            // nothing. Verification is an explicit action in
                            // the context menu, and only a checked mismatch
                            // shows a marker here.
                            if checkedVerdict?.marksTheRow == true {
                                Button { proofRequest = .verify(message.id) } label: {
                                    Image(systemName: "exclamationmark.shield.fill")
                                        .font(.system(size: 9))
                                        .foregroundStyle(Theme.danger)
                                }
                                .buttonStyle(.plain)
                                .help("This message's signature did not check out — click for detail")
                            }

                            if message.isEncrypted {
                                Image(systemName: "lock.shield.fill")
                                    .font(.system(size: 9))
                                    .foregroundStyle(Theme.success)
                                    .help("End-to-end encrypted")
                            }

                            // Federated: relayed from another server — peer-vouched,
                            // not verified here. Show provenance instead of the local
                            // verified/signed badges (which would overstate trust).
                            if let origin = message.origin {
                                Text("via \(origin)")
                                    .font(.caption2)
                                    .foregroundStyle(Theme.textTertiary)
                                    .help("Relayed from \(origin). This server didn't verify the sender — \(origin) vouches for it.")
                            }

                            Text(formatTime(message.timestamp))
                                .font(.caption)
                                .foregroundStyle(Theme.textTertiary)
                                .help(fullTimestamp(message.timestamp))

                            if message.isEdited {
                                Text("(edited)")
                                    .font(.caption2)
                                    .foregroundStyle(Theme.textTertiary)
                            }
                        }
                    }
                }
                .padding(.top, 6)
            }

            // Reply indicator (click → scroll + option to open thread)
            if let replyTo = message.replyTo {
                // Resolve the original once and reuse in both the label and the
                // click handler, instead of scanning the message array twice.
                let replyOriginal = appState.activeChannelState?.messages.first(where: { $0.id == replyTo })
                Button {
                    appState.scrollToMessageId = replyTo
                    // Also open the thread if the original message exists
                    if let original = replyOriginal {
                        appState.threadRootMessage = original
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "arrowshape.turn.up.left.fill")
                            .font(.caption2)
                        if let original = replyOriginal {
                            Text("\(original.from): \(original.text)")
                                .font(.caption2)
                                .lineLimit(1)
                        } else {
                            Text("replying to message")
                                .font(.caption2)
                        }
                    }
                    .foregroundStyle(Theme.textSecondary)
                    .padding(.leading, 2)
                }
                .buttonStyle(.plain)
            }

            // Message text + media
            if message.isAction {
                Text("• \(message.from) \(message.text)")
                    .italic()
                    .foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else if isSystem {
                Text(message.text)
                    .font(.system(.body, design: .monospaced).weight(.light))
                    .foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let coord = message.coordination {
                // Agent coordination event → structured card (parity with web).
                CoordinationCardView(info: coord, text: message.text)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let jumbo = Jumbomoji.size(message.text) {
                // Jumbomoji: a message of just 1–3 emoji renders large.
                Text(message.text.trimmingCharacters(in: .whitespacesAndNewlines))
                    .font(.system(size: jumbo))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                let imageURLs = extractImageURLs(from: message.text)
                let videoURLs = extractVideoURLs(from: message.text)
                let audioURLs = extractAudioURLs(from: message.text)
                let ytId = extractYouTubeID(from: message.text)
                let isVoice = isVoiceMessage(message.text)
                let mediaURLs = imageURLs + videoURLs + audioURLs
                // Compute once — this was previously extracted twice (embed +
                // link-preview guard), running the regex over the text twice.
                let bskyPost = extractBskyPost(from: message.text)
                let cleanText = mediaURLs.isEmpty ? message.text : textWithoutImages(message.text, imageURLs: mediaURLs)

                if !cleanText.isEmpty {
                    // Block markdown (fences/quotes/lists/tables) → structured
                    // renderer; everything else stays on the exact inline path.
                    // Same inline renderer feeds both, so styling is identical.
                    if MessageBlockParser.containsBlockSyntax(cleanText) {
                        MessageBlocksView(text: cleanText, inlineRenderer: parseMessageText)
                            // Claim full height like the plain-text path, so a
                            // multi-line block message doesn't under-measure and
                            // let a reaction badge overlap it.
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text(parseMessageText(cleanText))
                            .textSelection(.enabled)
                            // Claim full wrapped height. Without this the row's
                            // self-sizing host can allocate ~1 line while the
                            // text renders 2, so anything below it (a reaction
                            // badge) overlaps the wrapped line.
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                // Inline images
                if !imageURLs.isEmpty {
                    ForEach(imageURLs, id: \.self) { url in
                        InlineImageView(url: url)
                    }
                }

                // Inline video
                if !videoURLs.isEmpty {
                    ForEach(videoURLs, id: \.self) { url in
                        InlineVideoView(url: url)
                    }
                }

                // Inline audio / voice messages
                if !audioURLs.isEmpty {
                    ForEach(audioURLs, id: \.self) { url in
                        InlineAudioView(url: url, isVoice: isVoice)
                    }
                }

                // Bluesky post embed
                if let bsky = bskyPost {
                    BlueskyEmbed(handle: bsky.handle, rkey: bsky.rkey)
                }

                // YouTube embed
                if let ytId {
                    YouTubeThumbnail(videoId: ytId)
                }

                // Link preview (only if no other media)
                if mediaURLs.isEmpty && ytId == nil && bskyPost == nil,
                   let url = extractFirstURL(from: message.text) {
                    LinkPreviewView(url: url)
                }
            }

            // Reactions
            if !message.reactions.isEmpty {
                FlowLayout(spacing: 4) {
                    ForEach(Array(message.reactions.keys.sorted()), id: \.self) { emoji in
                        if let nicks = message.reactions[emoji] {
                            ReactionBadge(
                                emoji: emoji,
                                count: nicks.count,
                                isSelfReacted: nicks.contains(appState.nick),
                                reactors: Array(nicks),
                                action: {
                                    if let target = appState.activeChannel {
                                        appState.sendReaction(target: target, msgId: message.id, emoji: emoji)
                                    }
                                }
                            )
                        }
                    }
                }
                .padding(.top, 4)
                .padding(.bottom, 3)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 1)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .background(
            appState.scrollToMessageId == message.id
                ? Theme.accent.opacity(0.10)
                : isHovered ? Theme.surfaceSoft.opacity(0.80) : Color.clear
        )
        .onHover { hovering in
            if hovering {
                hoverToken &+= 1
                isRowHovered = true
            } else {
                let token = hoverToken
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.06) {
                    if hoverToken == token { isRowHovered = false }
                }
            }
        }
        // The bar straddles the row's TOP BOUNDARY — half above, half below,
        // Discord-style — so it never sits on the row's own header line or
        // text. It overlaps the gap (and, on tight grouped rows, the tail) of
        // the message above, which is why it draws as an opaque lifted card.
        // Near the viewport's top edge it slides down just enough to stay
        // fully visible, and once the row's top has scrolled past the edge it
        // rides the visible top of the message — `topGap` from the AppKit
        // list drives both. Capped to the row so it never walks off a short
        // row's bottom while its message is still the one under the pointer.
        .overlay(alignment: .topTrailing) {
            if isHovered && !isSystem {
                GeometryReader { geo in
                    // Legacy SwiftUI list has no viewport clamp and clips at
                    // the row — keep the bar inside the row there.
                    let straddle: CGFloat = rowClamp == nil ? 0 : -14
                    let gap = rowClamp?.topGap ?? .greatestFiniteMagnitude
                    // Slide down when straddling would poke above the visible
                    // top edge (gap < 14); never slide past the row's bottom.
                    let clampDown = max(0, 14 - min(gap, 14))
                    let shift = min(straddle + clampDown, max(straddle, geo.size.height - 30))
                    HoverActionBar(message: message)
                        .padding(.trailing, 12)
                        .offset(y: shift)
                        .frame(maxWidth: .infinity, alignment: .topTrailing)
                        .onHover { isBarHovered = $0 }
                }
            }
        }
        // Lift the hovered row above its neighbours (and drop cell clipping) so
        // the action bar — taller than a grouped/compact row — isn't clipped or
        // painted over by the next message.
        .onChange(of: isHovered) { _, hovering in
            rowClamp?.onHoverChanged?(hovering)
        }
        .contextMenu { messageContextMenu }
        .reportDialog($reportTarget) { t, reason in
            appState.reportUser(nick: t.nick, did: t.did, reason: reason)
        }
        .sheet(item: $proofRequest) { request in
            VerifiedProofSheet(
                did: appState.liveDidForNick(message.from),
                handle: profile?.handle,
                displayName: profile?.displayName,
                nick: message.from,
                origin: message.origin,
                msgId: request.msgId,
                signed: message.isSigned,
                account: message.account,
                rowTimeUnix: UInt64(message.timestamp.timeIntervalSince1970),
                senderPresent: appState.isNickPresent(message.from),
                rowMsgId: message.id,
                rowSigned: message.isSigned
            )
            .environment(appState)
        }
        // Route @mention taps to the profile; real URLs open normally.
        .environment(\.openURL, OpenURLAction(handler: handleMessageURL))
        .sheet(item: $mentionTarget) { target in
            UserProfileSheet(nick: target.nick, origin: target.origin, account: target.account,
                rowTime: target.rowTime,
                senderPresent: target.senderPresent)
                .environment(appState)
        }
    }

    /// Intercept `freeq://mention/<token>` links (open the profile); let every
    /// other URL fall through to the system handler.
    private func handleMessageURL(_ url: URL) -> OpenURLAction.Result {
        guard url.scheme == "freeq" else { return .systemAction }
        switch url.host {
        case "mention":
            let token = url.lastPathComponent.removingPercentEncoding ?? url.lastPathComponent
            mentionTarget = MentionTarget(nick: resolveMentionNick(token))
            return .handled
        case "channel":
            let name = url.lastPathComponent.removingPercentEncoding ?? url.lastPathComponent
            if appState.channels.contains(where: { $0.name.lowercased() == name.lowercased() }) {
                appState.activeChannel = name
            } else {
                appState.joinChannel(name)
            }
            return .handled
        default:
            return .systemAction
        }
    }

    /// Resolve a mention token to a real nick: a channel member matching the
    /// nick, then one matching the Bluesky handle, else the token as typed.
    private func resolveMentionNick(_ token: String) -> String {
        let members = appState.activeChannelState?.members ?? []
        let lower = token.lowercased()
        if let m = members.first(where: { $0.nick.lowercased() == lower }) { return m.nick }
        if let m = members.first(where: {
            ProfileCache.shared.profile(for: $0.nick)?.handle?.lowercased() == lower
        }) { return m.nick }
        return token
    }

    @ViewBuilder
    private var messageContextMenu: some View {
        // React
        if !isSystem {
            Menu("React") {
                ForEach(["👍", "❤️", "😂", "🎉", "👀", "🔥", "🕺", "💃", "🎶", "🎷"], id: \.self) { emoji in
                    Button(emoji) {
                        if let target = appState.activeChannel {
                            appState.sendReaction(target: target, msgId: message.id, emoji: emoji)
                        }
                    }
                }
            }
        }

        // Reply
        if !isSystem {
            Button("Reply") {
                appState.replyingToMessage = message
            }
        }

        Button("Copy Text") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(message.text, forType: .string)
        }

        if !isSystem {
            Button("Open Thread") {
                appState.threadRootMessage = message
            }
        }

        if let msgId = Optional(message.id) {
            Button("Copy Message ID") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(msgId, forType: .string)
            }
        }

        // Checking a signature is a question the reader asks, not a claim the
        // row makes on its own. Same label as the web and Android clients.
        // Profile sits beside it so the identity question has a path from the
        // same menu — the two questions, both reachable, never blended.
        if !isSystem {
            Button("View Profile") { mentionTarget = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) }
            Button("Verify Signature") { proofRequest = .verify(message.id) }
        }

        if !isSystem {
            if appState.bookmarks.contains(where: { $0.msgId == message.id }) {
                Button("Remove Bookmark") {
                    appState.removeBookmark(msgId: message.id)
                }
            } else {
                Button("Bookmark") {
                    if let target = appState.activeChannel {
                        appState.addBookmark(channel: target, msg: message)
                    }
                }
            }
            if let target = appState.activeChannel, target.hasPrefix("#") {
                let isPinned = appState.activeChannelState?.pinnedMessages.contains(where: { $0.id == message.id }) ?? false
                Button(isPinned ? "Unpin Message" : "Pin Message") {
                    if isPinned { appState.unpin(msgId: message.id, in: target) }
                    else { appState.pin(msgId: message.id, in: target) }
                }
            }
        }

        // Safety: report/block other people's messages (App Store UGC parity
        // with iOS). Reporting hides the content and blocks the author.
        if !isSystem && !isSelf {
            Divider()
            Button("Report…") {
                reportTarget = ReportTarget(
                    nick: message.from,
                    did: ProfileCache.shared.did(for: message.from),
                    text: message.text
                )
            }
            Button("Block \(message.from)", role: .destructive) {
                appState.blockUser(nick: message.from, did: ProfileCache.shared.did(for: message.from))
            }
        }

        let amOp = appState.activeChannelState?.memberInfo(for: appState.nick)?.isOp ?? false
        let canDelete = MessageActions.canDelete(message, by: appState.nick, isOp: amOp)
        if isSelf || canDelete {
            Divider()
            if isSelf {
                Button("Edit") {
                    appState.editingMessageId = message.id
                    appState.editingText = message.text
                }
            }
            if canDelete {
                // Author or channel op — the server authorizes both; the
                // optimistic tombstone in deleteMessage is therefore safe.
                Button("Delete", role: .destructive) {
                    if let target = appState.activeChannel {
                        appState.deleteMessage(target: target, msgId: message.id)
                    }
                }
            }
        }
    }

    /// Parse message text into AttributedString with formatting.
    private func parseMessageText(_ text: String) -> AttributedString {
        // Parse inline markdown (**bold**, *italic*, _italic_, `code`,
        // ~~strike~~, [label](url)) — this STRIPS the delimiters so they don't
        // show literally, matching the web/iOS clients. Falls back to plain
        // text if the string isn't valid markdown.
        var options = AttributedString.MarkdownParsingOptions()
        options.interpretedSyntax = .inlineOnlyPreservingWhitespace
        options.failurePolicy = .returnPartiallyParsedIfPossible
        var result = (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)

        // Give inline code a monospaced look (markdown marks it with an
        // inlinePresentationIntent but applies no visible style on its own).
        for run in result.runs where run.inlinePresentationIntent?.contains(.code) == true {
            result[run.range].font = .system(.body, design: .monospaced)
            result[run.range].backgroundColor = Color(nsColor: .quaternaryLabelColor)
        }

        // Markdown only links [label](url) / <url>; detect bare URLs too, on the
        // delimiter-stripped plain text so indices line up.
        let plain = String(result.characters)
        if let matches = sharedLinkDetector?.matches(in: plain, range: NSRange(plain.startIndex..., in: plain)) {
            for match in matches.reversed() {
                guard let r = Range(match.range, in: plain),
                      let attrRange = Range(r, in: result),
                      let url = match.url else { continue }
                if result[attrRange].link == nil { result[attrRange].link = url }
            }
        }

        // Color every link with the accent.
        for run in result.runs where run.link != nil {
            result[run.range].foregroundColor = .accentColor
        }

        // Highlight @mentions and make them tappable (opens the profile). Uses a
        // freeq://mention/<token> link the row intercepts. Runs last so it can
        // skip spans that are already real links (e.g. an @ inside a URL).
        if let regex = Self.mentionRegex {
            let ns = plain as NSString
            for m in regex.matches(in: plain, range: NSRange(location: 0, length: ns.length)) {
                // Skip emails: require the char before '@' to be a boundary.
                let at = m.range.location
                if at > 0, let s = UnicodeScalar(UInt32(ns.character(at: at - 1))),
                   CharacterSet.alphanumerics.contains(s) { continue }
                guard let r = Range(m.range, in: plain),
                      let attrRange = Range(r, in: result),
                      result[attrRange].link == nil else { continue }
                let token = ns.substring(with: m.range(at: 1))
                let encoded = token.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? token
                if let url = URL(string: "freeq://mention/\(encoded)") {
                    result[attrRange].link = url
                }
                result[attrRange].foregroundColor = .accentColor
                result[attrRange].font = .body.weight(.semibold)
            }
        }

        // Linkify #channels → freeq://channel/<name>, tapped to switch/join.
        // Same skip-if-already-linked discipline as mentions.
        if let regex = Self.channelRegex {
            let ns = plain as NSString
            for m in regex.matches(in: plain, range: NSRange(location: 0, length: ns.length)) {
                guard let r = Range(m.range, in: plain),
                      let attrRange = Range(r, in: result),
                      result[attrRange].link == nil else { continue }
                let name = ns.substring(with: m.range) // "#channel"
                let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
                if let url = URL(string: "freeq://channel/\(encoded)") {
                    result[attrRange].link = url
                }
                result[attrRange].foregroundColor = .accentColor
                result[attrRange].font = .body.weight(.semibold)
            }
        }

        return result
    }

    /// `@nick` / `@handle.tld` — a leading letter/digit then nick/handle chars.
    static let mentionRegex = try? NSRegularExpression(
        pattern: "@([A-Za-z0-9][A-Za-z0-9._-]*)")

    /// `#channel` — not preceded by a word char, slash, or another `#` (so URL
    /// fragments and `##` don't match).
    static let channelRegex = try? NSRegularExpression(
        pattern: "(?<![\\w/#])#[A-Za-z0-9][A-Za-z0-9._-]*")
}

// MARK: - Hover Action Bar (Slack/Discord style)

struct HoverActionBar: View {
    @Environment(AppState.self) private var appState
    let message: ChatMessage
    @State private var showEmojiPicker = false

    // The trailing four (dancers, notes, sax) are freeq's music/dance brand —
    // present by default everywhere alongside the usual reactions.
    private let quickEmoji = ["👍", "❤️", "😂", "🎉", "👀", "🔥", "🕺", "💃", "🎶", "🎷"]

    var body: some View {
        HStack(spacing: 2) {
            ForEach(quickEmoji, id: \.self) { emoji in
                Button {
                    if let target = appState.activeChannel {
                        appState.sendReaction(target: target, msgId: message.id, emoji: emoji)
                    }
                } label: {
                    Text(emoji)
                        .font(.system(size: 14))
                        .frame(width: 28, height: 26)
                }
                .buttonStyle(.plain)
                .help("React with \(emoji)")
            }

            Divider().frame(height: 16)

            // Reply
            Button {
                appState.replyingToMessage = message
            } label: {
                Image(systemName: "arrowshape.turn.up.left")
                    .font(.system(size: 11))
                    .frame(width: 28, height: 26)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Reply")

            // Thread
            Button {
                appState.threadRootMessage = message
            } label: {
                Image(systemName: "bubble.left.and.bubble.right")
                    .font(.system(size: 11))
                    .frame(width: 28, height: 26)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Open Thread")

            // More emoji (opens system picker)
            Button {
                NSApp.orderFrontCharacterPalette(nil)
            } label: {
                Image(systemName: "face.smiling")
                    .font(.system(size: 11))
                    .frame(width: 28, height: 26)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("More emoji…")
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 2)
        .background(.thickMaterial, in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.6), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.22), radius: 6, y: 2)
    }
}

// MARK: - Reaction Badge

struct ReactionBadge: View {
    let emoji: String
    let count: Int
    let isSelfReacted: Bool
    /// Nicks who reacted with this emoji — surfaced as a hover tooltip
    /// (the macOS equivalent of a long-press "who reacted" sheet).
    var reactors: [String] = []
    let action: () -> Void

    /// "🎉 alice, bob and you" — capped so a popular reaction stays readable.
    private var reactorTooltip: String {
        guard !reactors.isEmpty else { return "" }
        let sorted = reactors.sorted { $0.lowercased() < $1.lowercased() }
        let shown = sorted.prefix(12)
        var list = shown.joined(separator: ", ")
        if sorted.count > shown.count { list += " +\(sorted.count - shown.count) more" }
        return "reacted with \(emoji): \(list)"
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 3) {
                Text(emoji)
                    .font(.caption)
                if count > 1 {
                    Text("\(count)")
                        .font(.caption2.weight(.medium))
                        .foregroundColor(isSelfReacted ? .accentColor : .secondary)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(isSelfReacted ? Color.accentColor.opacity(0.15) : Color(nsColor: .quaternaryLabelColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(isSelfReacted ? Color.accentColor.opacity(0.3) : .clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .help(reactorTooltip)
    }
}

// MARK: - Flow Layout for reactions

struct FlowLayout: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth && x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: maxWidth, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX && x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

// MARK: - Full timestamp for hover

// Cached formatters. `DateFormatter` is one of the most expensive Cocoa
// objects to construct; these were being allocated fresh on every call from
// every visible row on every scroll frame. Configured once, read-only after
// (string(from:) is safe to call concurrently on an unmutated formatter, and
// these are only touched from the main-thread render path anyway).
private let fullTimestampFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = .current
    f.dateStyle = .full
    f.timeStyle = .medium
    return f
}()

private let timeOnlyFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = .current
    f.dateStyle = .none
    f.timeStyle = .short
    return f
}()

private let dateTimeFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = .current
    f.dateStyle = .medium
    f.timeStyle = .short
    return f
}()

private func fullTimestamp(_ date: Date) -> String {
    fullTimestampFormatter.string(from: date)
}

// MARK: - URL extraction

private func extractFirstURL(from text: String) -> String? {
    if let match = sharedLinkDetector?.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
       let range = Range(match.range, in: text) {
        return String(text[range])
    }
    return nil
}

// MARK: - Time formatting (shared)

func formatTime(_ date: Date) -> String {
    // Today → time only; otherwise date + time. Two cached formatters instead
    // of allocating one per call.
    if Calendar.current.isDateInToday(date) {
        return timeOnlyFormatter.string(from: date)
    } else {
        return dateTimeFormatter.string(from: date)
    }
}
