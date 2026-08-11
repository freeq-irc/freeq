import SwiftUI
import AVKit

struct MessageListView: View {
    @EnvironmentObject var appState: AppState
    @ObservedObject var channel: ChannelState
    @State private var emojiPickerMessage: ChatMessage? = nil
    @State private var profileTarget: ProfileNickTarget? = nil
    @State private var proofTarget: ProofTarget? = nil
    @State private var reportSource: ReportTarget? = nil
    @State private var threadMessage: ChatMessage? = nil
    @StateObject private var avatarCache = AvatarCache.shared

    @State private var showScrollButton = false
    @State private var lastReadId: String? = nil
    @State private var isNearBottom = true
    /// Throttle so a rapid scroll-up doesn't spam CHATHISTORY requests.
    @State private var lastHistoryFetch: Date = .distantPast
    /// Celebratory reaction burst — set when you add a positive reaction.
    @State private var reactionBurst: ReactionBurstEvent? = nil
    /// Channels whose "while you were away" card the user dismissed this view.
    @State private var awayCardDismissed: Set<String> = []

    /// Show the on-device catch-up card when you open a channel with a real
    /// backlog and on-device intelligence is available.
    private var showAwayCard: Bool {
        (appState.awayCardCounts[channel.name] ?? 0) >= 4
            && !awayCardDismissed.contains(channel.name)
            && IntelligenceService.shared.isAvailable
    }

    private func dismissAwayCard() {
        awayCardDismissed.insert(channel.name)
        appState.awayCardCounts[channel.name] = 0
    }

    /// Emoji that get a floating particle burst when you react with them.
    private static let celebratoryReactions: Set<String> = ["❤️", "🎉", "🔥", "😂", "👍", "🕺", "💃", "🎶", "🎷"]

    /// Fire a particle burst if `emoji` is celebratory (called from every
    /// reaction-add path). Reduce Motion suppresses the visual in the view.
    private func celebrate(_ emoji: String) {
        guard Self.celebratoryReactions.contains(emoji) else { return }
        reactionBurst = ReactionBurstEvent(emoji: emoji)
    }

    var body: some View {
        ScrollViewReader { proxy in
            ZStack(alignment: .bottom) {
                if channel.messages.isEmpty {
                    // Skeleton loading state
                    VStack(spacing: 0) {
                        Spacer()
                        ForEach(0..<5, id: \.self) { i in
                            skeletonRow(short: i % 3 == 1)
                        }
                        Spacer()
                    }
                    .redacted(reason: .placeholder)
                    .shimmering()
                }

                ScrollView {
                    // Auto-fetch older messages when the top of the list scrolls into view.
                    // The button below is kept as a manual fallback (errors, or for users
                    // who want to pull more without scrolling all the way up).
                    Color.clear
                        .frame(height: 1)
                        .onAppear { autoFetchOlder() }

                    // Pull to load older messages
                    Button(action: {
                        let oldest = channel.messages.first?.timestamp
                        appState.requestHistory(channel: channel.name, before: oldest)
                        lastHistoryFetch = Date()
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "arrow.up.circle")
                                .font(.system(size: 13))
                            Text("Load older messages")
                                .font(.fqFootnote)
                        }
                        .foregroundColor(Theme.textMuted)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(.plain)

                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(channel.messages.enumerated()), id: \.element.renderKey) { idx, msg in
                            let showHeader = shouldShowHeader(at: idx)
                            let showDate = shouldShowDateSeparator(at: idx)

                            if showDate {
                                dateSeparator(for: msg.timestamp)
                            }

                            // Unread separator
                            if let readId = lastReadId, idx > 0,
                               channel.messages[idx - 1].id == readId,
                               msg.from.lowercased() != appState.nick.lowercased() {
                                unreadSeparator
                            }

                            if msg.from.isEmpty {
                                systemMessage(msg)
                            } else if appState.isBlocked(nick: msg.from, did: channel.memberInfo(for: msg.from)?.did) {
                                // Hidden — you blocked this person.
                                EmptyView()
                            } else if msg.isDeleted {
                                deletedMessage(msg, showHeader: showHeader)
                            } else {
                                messageRow(msg, showHeader: showHeader)
                                    .swipeActions(edge: .leading, allowsFullSwipe: true) {
                                        Button {
                                            appState.replyingTo = msg
                                            UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                        } label: {
                                            Label("Reply", systemImage: "arrowshape.turn.up.left")
                                        }
                                        .tint(Theme.accent)
                                    }
                                    .contextMenu { messageContextMenu(msg) }
                            }
                        }
                    }
                    .padding(.top, 8)
                    .padding(.bottom, 4)

                    // Typing indicator
                    if !channel.activeTypers.isEmpty {
                        typingIndicator
                            .padding(.horizontal, 16)
                            .padding(.bottom, 4)
                    }

                    // Invisible anchor for scroll detection
                    GeometryReader { geo in
                        Color.clear
                            .preference(key: ScrollOffsetKey.self, value: geo.frame(in: .global).minY)
                    }
                    .frame(height: 1)
                    .id("bottom-anchor")
                }
                .background(Theme.bgPrimary)
                .scrollDismissesKeyboard(.interactively)
                .refreshable {
                    if appState.connectionState == .disconnected {
                        appState.reconnectSavedSession()
                        // Give it a moment so the spinner doesn't vanish instantly
                        try? await Task.sleep(nanoseconds: 1_500_000_000)
                    } else {
                        let oldest = channel.messages.first?.timestamp
                        appState.requestHistory(channel: channel.name, before: oldest)
                        try? await Task.sleep(nanoseconds: 500_000_000)
                    }
                }
                .onPreferenceChange(ScrollOffsetKey.self) { value in
                    // value is the minY of the bottom anchor in global coords
                    // When at bottom, it's near screen height; when scrolled up, it goes large/positive
                    let screenHeight = UIScreen.main.bounds.height
                    // If the bottom anchor is more than 150pt below the screen, user has scrolled up
                    let nearBottom = value <= screenHeight + 150
                    isNearBottom = nearBottom
                    showScrollButton = !nearBottom
                }

                // Scroll to bottom FAB with message preview
                if showScrollButton {
                    Button(action: {
                        if let last = channel.messages.last {
                            withAnimation(.easeOut(duration: 0.2)) {
                                proxy.scrollTo(last.renderKey, anchor: .bottom)
                            }
                        }
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    }) {
                        VStack(spacing: 0) {
                            // Latest message preview
                            if let last = channel.messages.last, !last.from.isEmpty {
                                HStack(spacing: 8) {
                                    UserAvatar(nick: last.from, size: 22)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(last.from)
                                            .font(.fqCaption2.weight(.bold))
                                            .foregroundColor(Theme.nickColor(for: last.from))
                                        Text(last.text.prefix(60) + (last.text.count > 60 ? "…" : ""))
                                            .font(.fqCaption)
                                            .foregroundColor(Theme.textSecondary)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    let unread = appState.unreadCounts[channel.name] ?? 0
                                    if unread > 0 {
                                        Text("\(unread)")
                                            .font(.fqCaption2.weight(.bold))
                                            .foregroundColor(.white)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Theme.accent)
                                            .cornerRadius(10)
                                    }
                                    Image(systemName: "chevron.down")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Theme.textMuted)
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                            } else {
                                HStack(spacing: 6) {
                                    Image(systemName: "chevron.down")
                                        .font(.system(size: 12, weight: .bold))
                                    Text("Scroll to bottom")
                                        .font(.fqFootnote.weight(.medium))
                                }
                                .foregroundColor(Theme.accent)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                            }
                        }
                        .background(.ultraThinMaterial)
                        .cornerRadius(14)
                        .shadow(color: .black.opacity(0.25), radius: 10, y: 4)
                    }
                    .accessibilityLabel("Scroll to latest messages")
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .animation(.spring(response: 0.3), value: showScrollButton)
                }

                // Celebratory reaction burst — floats up from the bottom.
                if let burst = reactionBurst {
                    ReactionBurstView(emoji: burst.emoji)
                        .id(burst.id)
                        .allowsHitTesting(false)
                        .onAppear {
                            // Clear after the animation so it can retrigger.
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
                                if reactionBurst?.id == burst.id { reactionBurst = nil }
                            }
                        }
                }

                // "While you were away" — a floating, on-device catch-up card
                // pinned to the top when you open a channel with a backlog.
                if showAwayCard {
                    VStack {
                        WhileYouWereAwayCard(
                            channel: channel,
                            missed: appState.awayCardCounts[channel.name] ?? 0,
                            onDismiss: { withAnimation(.spring(response: 0.4, dampingFraction: 0.85)) { dismissAwayCard() } }
                        )
                        .padding(.horizontal, 12)
                        .padding(.top, 8)
                        Spacer()
                    }
                    .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
            .animation(.spring(response: 0.45, dampingFraction: 0.85), value: showAwayCard)
            .onChange(of: channel.messages.count) {
                onNewMessages(proxy: proxy)
            }
            .onChange(of: channel.messages.last?.id) {
                onNewMessages(proxy: proxy)
            }
            .onAppear {
                // Capture current read position before marking read
                lastReadId = appState.lastReadMessageIds[channel.name]
                appState.markRead(channel.name)
                scrollToBottom(proxy: proxy)
            }
            .onChange(of: appState.activeChannel) {
                if appState.activeChannel == channel.name {
                    appState.markRead(channel.name)
                    scrollToBottom(proxy: proxy)
                }
            }
        }
        .sheet(item: $emojiPickerMessage) { msg in
            EmojiPickerSheet(message: msg, channel: channel.name)
                .presentationDetents([.medium])
                .presentationDragIndicator(.visible)
        }
        .sheet(item: $profileTarget) { target in
            UserProfileSheet(nick: target.nick, origin: target.origin,
                             account: target.account, rowTime: target.rowTime)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
        // Intercept in-app freeq:// links from message text (nick → profile,
        // #channel → switch/join); real URLs fall through to the browser.
        .environment(\.openURL, OpenURLAction(handler: handleMessageURL))
        .sheet(item: $threadMessage) { msg in
            ThreadView(rootMessage: msg, channelName: channel.name)
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
        }
        .sheet(item: $proofTarget) { target in
            VerifiedProofSheet(
                did: appState.liveDidForNick(target.nick),
                nick: target.nick,
                origin: target.origin,
                msgId: target.msgId,
                signed: target.rowSigned,
                account: target.account,
                rowTimeUnix: UInt64(target.rowTime.timeIntervalSince1970),
                senderPresent: appState.isNickPresent(target.nick),
                rowMsgId: target.rowMsgId,
                rowSigned: target.rowSigned
            )
        }
        .reportDialog($reportSource) { target, reason in
            appState.reportUser(nick: target.nick, did: target.did, reason: reason)
            ToastManager.shared.show("Reported & blocked", icon: "flag.fill")
        }
    }

    // MARK: - Scroll

    private func scrollToBottom(proxy: ScrollViewProxy) {
        // Triple-scroll: immediate + short delay + after CHATHISTORY arrives
        if let last = channel.messages.last {
            proxy.scrollTo(last.renderKey, anchor: .bottom)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            if let last = channel.messages.last {
                proxy.scrollTo(last.renderKey, anchor: .bottom)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            if let last = channel.messages.last {
                proxy.scrollTo(last.renderKey, anchor: .bottom)
            }
        }
    }

    private func onNewMessages(proxy: ScrollViewProxy) {
        guard let last = channel.messages.last else { return }
        // Always scroll if the new message is from us, or if user was near bottom
        let isOwnMessage = last.from == appState.nick
        if isOwnMessage || isNearBottom {
            withAnimation(.easeOut(duration: 0.15)) {
                proxy.scrollTo(last.renderKey, anchor: .bottom)
            }
            showScrollButton = false
            isNearBottom = true
        }
        // Mark read if this is the active channel
        if appState.activeChannel == channel.name {
            appState.markRead(channel.name)
        }
    }

    // MARK: - Context Menu

    @ViewBuilder
    private func messageContextMenu(_ msg: ChatMessage) -> some View {
        Button(action: {
            appState.replyingTo = msg
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        }) {
            Label("Reply", systemImage: "arrowshape.turn.up.left")
        }

        Button(action: {
            threadMessage = msg
        }) {
            Label("Thread", systemImage: "text.bubble")
        }

        Button(action: {
            emojiPickerMessage = msg
        }) {
            Label("React", systemImage: "face.smiling")
        }

        // Quick reactions
        ForEach(["👍", "❤️", "😂", "🎉", "🕺", "💃", "🎶", "🎷"], id: \.self) { emoji in
            Button(action: {
                celebrate(emoji)
                appState.sendReaction(target: channel.name, msgId: msg.id, emoji: emoji)
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }) {
                Text(emoji)
            }
        }

        let isAuthor = msg.from.lowercased() == appState.nick.lowercased()
        let selfIsOp = channel.memberInfo(for: appState.nick)?.isOp ?? false

        if isAuthor {
            Divider()

            Button(action: {
                appState.editingMessage = msg
            }) {
                Label("Edit", systemImage: "pencil")
            }
        }

        // Author may always delete their own; an op may delete anyone's
        // (moderation). Single source of truth: MessageActions.canDelete.
        if MessageActions.canDelete(msg, by: appState.nick, isOp: selfIsOp) {
            if !isAuthor { Divider() }
            Button(role: .destructive, action: {
                appState.deleteMessage(target: channel.name, msgId: msg.id)
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            }) {
                Label(isAuthor ? "Delete" : "Delete (mod)", systemImage: "trash")
            }
        }

        Divider()

        Button(action: {
            UIPasteboard.general.string = msg.text
            ToastManager.shared.show("Copied!", icon: "doc.on.doc.fill")
        }) {
            Label("Copy Text", systemImage: "doc.on.doc")
        }

        // Checking a signature is a question the reader asks, not a claim the
        // row makes on its own. Same label as the other clients. Profile sits
        // beside it so the identity question has a path from the same menu —
        // the two questions, both reachable, never blended.
        Button(action: {
            profileTarget = ProfileNickTarget(nick: msg.from, origin: msg.origin,
                                              account: msg.account, rowTime: msg.timestamp)
        }) {
            Label("View Profile", systemImage: "person.crop.circle")
        }

        Button(action: {
            proofTarget = .verify(msg)
        }) {
            Label("Verify Signature", systemImage: "checkmark.shield")
        }

        // PIN is op-only server-side (ERR_CHANOPRIVSNEEDED otherwise) — don't
        // offer it to non-ops; the rejection numeric isn't surfaced in UI and
        // the optimistic toast would claim success on a silent failure.
        if channel.memberInfo(for: appState.nick)?.isOp ?? false {
            Button(action: {
                appState.sendRaw("PIN \(channel.name) \(msg.id)")
                ToastManager.shared.show("Pinned", icon: "pin.fill")
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            }) {
                Label("Pin Message", systemImage: "pin")
            }
        }

        Button(action: {
            let wasBookmarked = appState.isBookmarked(msg.id)
            appState.toggleBookmark(channel: channel.name, msg: msg)
            ToastManager.shared.show(wasBookmarked ? "Removed bookmark" : "Bookmarked",
                                     icon: wasBookmarked ? "bookmark.slash" : "bookmark.fill")
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        }) {
            Label(appState.isBookmarked(msg.id) ? "Remove Bookmark" : "Bookmark",
                  systemImage: appState.isBookmarked(msg.id) ? "bookmark.slash" : "bookmark")
        }

        Button(action: {
            UIPasteboard.general.string = msg.id
            ToastManager.shared.show("Message ID copied", icon: "number")
        }) {
            Label("Copy Message ID", systemImage: "number")
        }

        // Safety — not for your own messages.
        if msg.from.lowercased() != appState.nick.lowercased() {
            Divider()
            Button(role: .destructive, action: {
                reportSource = ReportTarget(nick: msg.from,
                                            did: channel.memberInfo(for: msg.from)?.did,
                                            text: msg.text)
            }) {
                Label("Report…", systemImage: "flag")
            }
            Button(role: .destructive, action: {
                appState.blockUser(nick: msg.from, did: channel.memberInfo(for: msg.from)?.did)
                ToastManager.shared.show("Blocked \(msg.from)", icon: "hand.raised.fill")
            }) {
                Label("Block \(msg.from)", systemImage: "hand.raised")
            }
        }
    }

    // MARK: - Typing Indicator

    private var typingIndicator: some View {
        let typers = channel.activeTypers
        return HStack(spacing: 8) {
            // Whoever's actually typing, as overlapping avatars — the indicator
            // feels human when you can see who it is, not anonymous dots.
            HStack(spacing: -8) {
                ForEach(Array(typers.prefix(3)), id: \.self) { nick in
                    UserAvatar(nick: nick, size: 22)
                        .overlay(Circle().strokeBorder(Theme.bgPrimary, lineWidth: 2))
                        .transition(.scale.combined(with: .opacity))
                }
            }

            // Animated bouncing dots
            TypingDots()

            if typers.count == 1 {
                Text("\(typers[0]) is typing…")
                    .font(.fqCaption)
                    .foregroundColor(Theme.textMuted)
            } else if typers.count == 2 {
                Text("\(typers[0]) and \(typers[1]) are typing…")
                    .font(.fqCaption)
                    .foregroundColor(Theme.textMuted)
            } else if typers.count > 2 {
                Text("\(typers.count) people are typing…")
                    .font(.fqCaption)
                    .foregroundColor(Theme.textMuted)
            }
        }
        .padding(.leading, 20)
        .animation(.spring(response: 0.35, dampingFraction: 0.7), value: typers)
    }

    // MARK: - Unread Separator

    private var unreadSeparator: some View {
        HStack(spacing: 8) {
            Rectangle().fill(Color.red.opacity(0.4)).frame(height: 1)
            Text("NEW")
                .font(.fqCaption2.weight(.heavy))
                .foregroundColor(.red.opacity(0.7))
                .tracking(1)
            Rectangle().fill(Color.red.opacity(0.4)).frame(height: 1)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
    }

    // MARK: - History

    /// Fire a CHATHISTORY BEFORE request when the top of the message list comes into
    /// view, throttled to once every 2 seconds so a fast scroll-up doesn't spam the server.
    /// Skip when the channel has no messages — there's nothing to anchor the request on
    /// and the initial CHATHISTORY LATEST will populate it.
    private func autoFetchOlder() {
        guard !channel.messages.isEmpty else { return }
        let now = Date()
        guard now.timeIntervalSince(lastHistoryFetch) > 2.0 else { return }
        lastHistoryFetch = now
        let oldest = channel.messages.first?.timestamp
        appState.requestHistory(channel: channel.name, before: oldest)
    }

    // MARK: - Message Grouping

    private func shouldShowHeader(at idx: Int) -> Bool {
        guard idx > 0 else { return true }
        let prev = channel.messages[idx - 1]
        let curr = channel.messages[idx]
        if curr.from.isEmpty || prev.from.isEmpty { return true }
        if prev.from != curr.from { return true }
        // Break across a provenance boundary: a federated message (origin set)
        // must not collapse under a local sender's header, or it loses its
        // "via {origin}" and inherits the local verified/signed context.
        if prev.origin != curr.origin { return true }
        return curr.timestamp.timeIntervalSince(prev.timestamp) > 300
    }

    private func shouldShowDateSeparator(at idx: Int) -> Bool {
        guard idx > 0 else { return true }
        return !Calendar.current.isDate(
            channel.messages[idx - 1].timestamp,
            inSameDayAs: channel.messages[idx].timestamp
        )
    }

    // MARK: - System Messages

    private func dateSeparator(for date: Date) -> some View {
        HStack {
            Rectangle().fill(Theme.border).frame(height: 1)
            Text(formatDate(date))
                .font(.fqCaption2.weight(.semibold))
                .foregroundColor(Theme.textMuted)
                .padding(.horizontal, 8)
            Rectangle().fill(Theme.border).frame(height: 1)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private func systemMessage(_ msg: ChatMessage) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "arrow.right.arrow.left")
                .font(.system(size: 9))
                .foregroundColor(Theme.textMuted)
            Text(msg.text)
                .font(.fqCaption)
                .foregroundColor(Theme.textMuted)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 3)
        .frame(maxWidth: .infinity, alignment: .center)
        .id(msg.renderKey)
    }

    private func deletedMessage(_ msg: ChatMessage, showHeader: Bool) -> some View {
        HStack(spacing: 6) {
            if showHeader {
                Spacer().frame(width: 52) // avatar space
            }
            Image(systemName: "trash")
                .font(.system(size: 11))
                .foregroundColor(Theme.textMuted)
            Text("Message deleted")
                .font(.fqFootnote)
                .foregroundColor(Theme.textMuted)
                .italic()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 2)
        .id(msg.renderKey)
    }

    // MARK: - Message Rows

    private func isMention(_ msg: ChatMessage) -> Bool {
        let nick = appState.nick.lowercased()
        return msg.text.lowercased().contains("@\(nick)") ||
               msg.text.lowercased().contains(nick + ":") ||
               msg.text.lowercased().contains(nick + ",")
    }

    @ViewBuilder
    private func messageRow(_ msg: ChatMessage, showHeader: Bool) -> some View {
        let isSelf = msg.from.lowercased() == appState.nick.lowercased()
        let mention = isMention(msg) && !isSelf
        let pinned = channel.pins.contains(msg.id)
        // Resolve the sender's member entry once — it was previously scanned
        // three times per header row (verified badge, name prefix, signed
        // proof), each an O(members) lowercased linear search.
        let member = channel.memberInfo(for: msg.from)
        // What this row can honestly claim about its sender — computed by the
        // SDK from the row's own tags and the live room, never from a cache.
        // Presence is only consulted when the tags can't answer.
        let needsRoom = msg.account == nil && msg.origin == nil
        let present = needsRoom && appState.isNickPresent(msg.from)
        let rowClaim = claimForMessage(input: MessageClaimInput(
            account: msg.account,
            origin: msg.origin,
            senderPresent: present,
            senderLiveDid: present ? appState.liveDidForNick(msg.from) : nil,
            rowTimeUnix: UInt64(msg.timestamp.timeIntervalSince1970)
        ))

        VStack(alignment: .leading, spacing: 0) {
            // Reply context — tap to open thread
            if let replyId = msg.replyTo,
               let originalIdx = channel.findMessage(byId: replyId) {
                let original = channel.messages[originalIdx]
                Button(action: { threadMessage = msg }) {
                    replyContext(original)
                }
                .buttonStyle(.plain)
                .padding(.leading, 68)
                .padding(.trailing, 16)
                .padding(.top, 4)
            }

            if showHeader {
                HStack(alignment: .top, spacing: 12) {
                    // Avatar
                    UserAvatar(nick: msg.from, size: 40)

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Button(action: { profileTarget = ProfileNickTarget(nick: msg.from, origin: msg.origin, account: msg.account, rowTime: msg.timestamp) }) {
                                HStack(spacing: 4) {
                                    Text((member?.prefix ?? "") + msg.from)
                                        .font(.fqSubheadline.weight(.bold))
                                        .foregroundColor(Theme.nickColor(for: msg.from))
                                        // A DID-verified person just spoke — sweep the
                                        // name with the signal glow once, so freeq's
                                        // "provably a real person" is felt, not just read.
                                        // Only for live arrivals, never history scroll-in.
                                        .signalShimmer(active: rowClaim.showsMark && msg.timestamp.timeIntervalSinceNow > -8)
                                }
                            }
                            .buttonStyle(.plain)

                            // The mark opens the proof behind the claim it
                            // makes; the name opens the person's card.
                            if rowClaim.showsMark {
                                Button {
                                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                    proofTarget = .identity(msg)
                                } label: {
                                    VerifiedBadge(size: 12)
                                }
                                .buttonStyle(.plain)
                            }

                            // Federated: relayed from another server — peer-vouched,
                            // not verified here. Show provenance instead of the local
                            // verified/signed badges (which would overstate trust).
                            if let origin = msg.origin {
                                Text("via \(origin)")
                                    .font(.fqMonoCaption)
                                    .foregroundColor(Theme.textMuted)
                            }

                            Text(formatTime(msg.timestamp))
                                .font(.fqCaption2)
                                .foregroundColor(Theme.textMuted)

                            // No badge for a signed message: almost every
                            // message is signed, so a badge on every row says
                            // nothing. Verification is an explicit action in
                            // the context menu; only a checked mismatch marks
                            // the row.
                            if appState.checkedVerdicts[msg.id]?.marksTheRow == true {
                                Button {
                                    UIImpactFeedbackGenerator(style: .rigid).impactOccurred()
                                    proofTarget = .verify(msg)
                                } label: {
                                    Image(systemName: "exclamationmark.shield.fill")
                                        .font(.system(size: 9, weight: .semibold))
                                        .foregroundColor(Theme.danger)
                                }
                                .buttonStyle(.plain)
                            }

                            if msg.isEdited {
                                Text("edited")
                                    .font(.fqCaption2.weight(.semibold))
                                    .foregroundColor(Theme.accent)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Theme.accent.opacity(0.12))
                                    .clipShape(Capsule())
                            }
                        }

                        messageBody(msg)
                    }

                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 16)
                .padding(.top, 6)
                .padding(.bottom, 2)
            } else {
                HStack(alignment: .top, spacing: 0) {
                    // Subtle timestamp for continuation messages, revealed on the
                    // row (kept faint so the transcript reads as one voice).
                    Text(shortTime(msg.timestamp))
                        .font(.fqMonoCaption)
                        .foregroundColor(Theme.textMuted.opacity(0.5))
                        .frame(width: 56, alignment: .center)
                        .padding(.top, 3)

                    messageBody(msg)
                        .padding(.trailing, 16)
                }
                .padding(.vertical, 1)
            }

            // Reactions
            if !msg.reactions.isEmpty {
                reactionsView(msg)
                    .padding(.leading, 68)
                    .padding(.trailing, 16)
                    .padding(.top, 4)
            }
        }
        // Row emphasis, in priority order: pin > mention > your own message.
        // Own messages get a whisper-quiet signal tint so you can find your
        // voice in a busy channel without breaking the scannable left rail.
        .background(
            pinned ? Theme.warning.opacity(0.08)
            : mention ? Theme.accent.opacity(0.10)
            : isSelf ? Theme.accent.opacity(0.045)
            : Color.clear
        )
        .overlay(alignment: .leading) {
            if pinned {
                Rectangle().fill(Theme.warning).frame(width: 3)
            } else if mention {
                Rectangle().fill(Theme.accent).frame(width: 3)
            } else if isSelf {
                Rectangle().fill(Theme.accent.opacity(0.5)).frame(width: 2)
            }
        }
        // Double-tap to react with ❤️
        .onTapGesture(count: 2) {
            celebrate("❤️")
            appState.sendReaction(target: channel.name, msgId: msg.id, emoji: "❤️")
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        }
        .transition(.asymmetric(
            insertion: .move(edge: .bottom).combined(with: .opacity),
            removal: .opacity
        ))
        .id(msg.renderKey)
    }

    // MARK: - Reply Context

    private func replyContext(_ original: ChatMessage) -> some View {
        HStack(spacing: 6) {
            Capsule()
                .fill(Theme.accent)
                .frame(width: 2)

            Image(systemName: "arrowshape.turn.up.left.fill")
                .font(.fqCaption2)
                .foregroundColor(Theme.textMuted)

            Text(original.from)
                .font(.fqCaption.weight(.semibold))
                .foregroundColor(Theme.nickColor(for: original.from))

            Text(original.text)
                .font(.fqCaption)
                .foregroundColor(Theme.textMuted)
                .lineLimit(1)
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 9)
        .background(Theme.bgTertiary.opacity(0.6), in: RoundedRectangle(cornerRadius: Theme.Radius.sm, style: .continuous))
    }

    // MARK: - Reactions

    private func reactionsView(_ msg: ChatMessage) -> some View {
        HStack(spacing: 4) {
            ForEach(Array(msg.reactions.keys.sorted()), id: \.self) { emoji in
                let nicks = msg.reactions[emoji] ?? []
                let isMine = nicks.contains(where: { $0.lowercased() == appState.nick.lowercased() })

                Button(action: {
                    // Optimistic local update so the pill flips immediately;
                    // the inbound TAGMSG echo will reconcile with the server's view.
                    if isMine {
                        channel.removeReaction(msgId: msg.id, emoji: emoji, from: appState.nick)
                    } else {
                        celebrate(emoji)
                        channel.applyReaction(msgId: msg.id, emoji: emoji, from: appState.nick)
                    }
                    appState.toggleReaction(target: channel.name, msgId: msg.id, emoji: emoji, currentlyMine: isMine)
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                }) {
                    HStack(spacing: 3) {
                        Text(emoji)
                            .font(.fqFootnote)
                        if nicks.count > 1 {
                            Text("\(nicks.count)")
                                .font(.fqCaption2.weight(.semibold))
                                .foregroundColor(isMine ? Theme.accent : Theme.textSecondary)
                                .contentTransition(.numericText())
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(isMine ? Theme.accent.opacity(0.15) : Theme.bgTertiary, in: Capsule())
                    .overlay(
                        Capsule().strokeBorder(isMine ? Theme.accent.opacity(0.45) : Theme.border, lineWidth: 1)
                    )
                    .animation(.spring(response: 0.3, dampingFraction: 0.6), value: nicks.count)
                }
                .buttonStyle(.plain)
                .sensoryFeedback(.impact(weight: .light), trigger: isMine)
                .accessibilityLabel("\(emoji) reaction, \(nicks.count)")
                .accessibilityValue(nicks.sorted { $0.lowercased() < $1.lowercased() }.joined(separator: ", "))
                .accessibilityHint(isMine ? "Double-tap to remove your reaction" : "Double-tap to react")
                // Long-press to see who reacted (the touch equivalent of a
                // hover tooltip).
                .contextMenu {
                    Section("Reacted with \(emoji)") {
                        ForEach(nicks.sorted { $0.lowercased() < $1.lowercased() }, id: \.self) { nick in
                            Label(nick.lowercased() == appState.nick.lowercased() ? "\(nick) (you)" : nick,
                                  systemImage: "person.crop.circle")
                        }
                    }
                }
            }
        }
    }

    // MARK: - Message Body

    // Bluesky URL pattern: bsky.app/profile/{handle}/post/{rkey}
    private static let bskyPattern = try! NSRegularExpression(
        pattern: #"https?://bsky\.app/profile/([^/]+)/post/([a-zA-Z0-9]+)"#
    )
    // YouTube URL pattern
    private static let ytPattern = try! NSRegularExpression(
        pattern: #"(?:youtube\.com/watch\?v=|youtu\.be/)([a-zA-Z0-9_-]{11})"#
    )

    // Markdown inline patterns — compiled once (they were being recompiled on
    // every render of every visible row; NSRegularExpression construction is
    // expensive). Mirrors the cached bsky/yt patterns above.
    private static let mdCodeBlock = try! NSRegularExpression(pattern: #"```(?:\w*\n?)?([\s\S]*?)```"#)
    private static let mdBold = try! NSRegularExpression(pattern: #"\*\*(.+?)\*\*"#)
    private static let mdItalic = try! NSRegularExpression(pattern: #"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)"#)
    private static let mdStrike = try! NSRegularExpression(pattern: #"~~(.+?)~~"#)
    private static let mdInlineCode = try! NSRegularExpression(pattern: #"(?<!`)`(?!`)([^`\n]+)(?<!`)`(?!`)"#)
    private static let mdURL = try! NSRegularExpression(pattern: #"https?://[^\s<>\]\)]+"#)
    private static let mdMention = try! NSRegularExpression(pattern: #"@([A-Za-z0-9][A-Za-z0-9._-]*)"#)
    private static let mdChannel = try! NSRegularExpression(pattern: #"(?<![\w/#])#[A-Za-z0-9][A-Za-z0-9._-]*"#)

    @ViewBuilder
    private func messageBody(_ msg: ChatMessage) -> some View {
        if msg.isAction {
            Text("*\(msg.from) \(msg.text)*")
                .font(.fqSubheadline)
                .italic()
                .foregroundColor(Theme.textSecondary)
        } else if let coord = msg.coordination {
            // Agent coordination event → structured card (parity with web + macOS).
            CoordinationCardView(info: coord, text: msg.text)
        } else if let jumbo = Jumbomoji.size(msg.text) {
            // Jumbomoji: a message of just 1–3 emoji renders large.
            Text(msg.text.trimmingCharacters(in: .whitespacesAndNewlines))
                .font(.system(size: jumbo))
        } else if let (url, durationLabel) = extractVoiceMessage(msg.text) {
            // Voice messages — must check before image/video to avoid CDN URL misdetection
            InlineAudioPlayer(url: url, label: durationLabel)
        } else if let url = extractVideoURL(msg.text) {
            VStack(alignment: .leading, spacing: 6) {
                let remainingText = msg.text.replacingOccurrences(of: url.absoluteString, with: "").trimmingCharacters(in: .whitespaces)
                if !remainingText.isEmpty { styledText(remainingText) }
                InlineVideoPlayer(url: url)
            }
        } else if let url = extractAudioURL(msg.text) {
            InlineAudioPlayer(url: url, label: nil)
        } else if let url = extractImageURL(msg.text) {
            VStack(alignment: .leading, spacing: 6) {
                let remainingText = msg.text.replacingOccurrences(of: url.absoluteString, with: "").trimmingCharacters(in: .whitespaces)
                if !remainingText.isEmpty {
                    styledText(remainingText)
                }
                AsyncImage(url: url) { phase in
                    switch phase {
                    case .success(let image):
                        image
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(maxWidth: 280, maxHeight: 280)
                            .cornerRadius(8)
                            .onTapGesture {
                                appState.lightboxURL = url
                                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                            }
                    case .failure:
                        linkButton(url)
                    default:
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Theme.bgTertiary)
                            .frame(width: 200, height: 120)
                            .overlay(ProgressView().tint(Theme.textMuted))
                    }
                }
            }
        } else if let (handle, rkey) = extractBskyPost(msg.text) {
            VStack(alignment: .leading, spacing: 6) {
                styledText(msg.text)
                BlueskyEmbed(handle: handle, rkey: rkey)
            }
        } else if let videoId = extractYouTubeId(msg.text) {
            VStack(alignment: .leading, spacing: 6) {
                styledText(msg.text)
                YouTubeThumb(videoId: videoId)
            }
        } else if let url = extractURL(msg.text) {
            VStack(alignment: .leading, spacing: 6) {
                styledText(msg.text)
                LinkPreviewCard(url: url)
            }
        } else {
            styledText(msg.text)
        }
    }

    private func extractBskyPost(_ text: String) -> (String, String)? {
        let range = NSRange(text.startIndex..., in: text)
        guard let match = Self.bskyPattern.firstMatch(in: text, range: range) else { return nil }
        guard let handleRange = Range(match.range(at: 1), in: text),
              let rkeyRange = Range(match.range(at: 2), in: text) else { return nil }
        return (String(text[handleRange]), String(text[rkeyRange]))
    }

    private func extractYouTubeId(_ text: String) -> String? {
        let range = NSRange(text.startIndex..., in: text)
        guard let match = Self.ytPattern.firstMatch(in: text, range: range) else { return nil }
        guard let idRange = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[idRange])
    }

    private func styledText(_ text: String) -> some View {
        let isMention = text.lowercased().contains(appState.nick.lowercased())
        return Text(attributedMessage(text))
            .font(.fqSubheadline)
            .foregroundColor(Theme.textPrimary)
            .textSelection(.enabled)
            .padding(.horizontal, isMention ? 4 : 0)
            .padding(.vertical, isMention ? 2 : 0)
            .background(isMention ? Theme.accent.opacity(0.1) : Color.clear)
            .cornerRadius(4)
    }

    private func linkButton(_ url: URL) -> some View {
        Link(destination: url) {
            HStack(spacing: 6) {
                Image(systemName: "link")
                    .font(.system(size: 11))
                Text(url.host ?? url.absoluteString)
                    .font(.fqFootnote)
                    .lineLimit(1)
            }
            .foregroundColor(Theme.accent)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.accent.opacity(0.1))
            .cornerRadius(6)
        }
    }

    // MARK: - URL Detection

    private func extractImageURL(_ text: String) -> URL? {
        // Match explicit image file extensions
        let extPattern = #"https?://\S+\.(?:png|jpg|jpeg|gif|webp)(?:\?\S*)?"#
        if let range = text.range(of: extPattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        // Match AT Protocol CDN image URLs (cdn.bsky.app/img/...)
        let cdnPattern = #"https?://cdn\.bsky\.app/img/[^\s<]+"#
        if let range = text.range(of: cdnPattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        // Match blob proxy URLs with image mime hint
        let blobPattern = #"https?://\S+/api/v1/blob\?\S*mime=image%2F\S*"#
        if let range = text.range(of: blobPattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        return nil
    }

    private func extractVideoURL(_ text: String) -> URL? {
        let pattern = #"https?://\S+\.(?:mp4|mov|m4v|webm)(?:\?\S*)?"#
        if let range = text.range(of: pattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        // AT Protocol CDN video URLs
        let cdnPattern = #"https?://video\.bsky\.app/[^\s<]+"#
        if let range = text.range(of: cdnPattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        // Proxy blob URLs with video mime hint
        let proxyPattern = #"https?://\S+/api/v1/blob\?\S*mime=video%2F\S*"#
        if let range = text.range(of: proxyPattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        return nil
    }

    /// Detect "🎤 Voice message (0:05) https://..." pattern
    private func extractVoiceMessage(_ text: String) -> (URL, String?)? {
        guard text.contains("🎤") else { return nil }
        // Extract duration label
        let durationPattern = #"\((\d+:\d+)\)"#
        var durationLabel: String? = nil
        if let range = text.range(of: durationPattern, options: .regularExpression) {
            durationLabel = String(text[range]).trimmingCharacters(in: CharacterSet(charactersIn: "()"))
        }
        // Extract any URL
        let urlPattern = #"https?://\S+"#
        guard let urlRange = text.range(of: urlPattern, options: .regularExpression),
              var url = URL(string: String(text[urlRange])) else { return nil }

        // Proxy all audio through our server to avoid PDS Content-Disposition: attachment
        // and sandbox CSP headers that block AVPlayer/browser playback
        let urlStr = url.absoluteString
        if urlStr.contains("cdn.bsky.app/img/") {
            // Rewrite old CDN image URLs to PDS blob URLs first
            let parts = urlStr.split(separator: "/")
            if let plainIdx = parts.firstIndex(of: "plain"),
               plainIdx + 2 < parts.count {
                let did = String(parts[plainIdx + 1])
                var cidPart = String(parts[plainIdx + 2])
                if let atIdx = cidPart.firstIndex(of: "@") {
                    cidPart = String(cidPart[cidPart.startIndex..<atIdx])
                }
                let pdsUrl = "https://bsky.social/xrpc/com.atproto.sync.getBlob?did=\(did)&cid=\(cidPart)"
                let proxyUrl = "\(ServerConfig.apiBaseUrl)/api/v1/blob?url=\(pdsUrl.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? pdsUrl)"
                if let rewritten = URL(string: proxyUrl) {
                    url = rewritten
                }
            }
        } else if urlStr.contains("/xrpc/com.atproto.sync.getBlob") {
            // Proxy PDS blob URLs through our server
            let proxyUrl = "\(ServerConfig.apiBaseUrl)/api/v1/blob?url=\(urlStr.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? urlStr)"
            if let rewritten = URL(string: proxyUrl) {
                url = rewritten
            }
        }

        return (url, durationLabel)
    }

    private func extractAudioURL(_ text: String) -> URL? {
        let pattern = #"https?://\S+\.(?:m4a|mp3|ogg|wav|aac)(?:\?\S*)?"#
        if let range = text.range(of: pattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        // Proxy blob URLs with audio mime hint
        let proxyPattern = #"https?://\S+/api/v1/blob\?\S*mime=audio%2F\S*"#
        if let range = text.range(of: proxyPattern, options: .regularExpression) {
            return URL(string: String(text[range]))
        }
        return nil
    }

    private func extractURL(_ text: String) -> URL? {
        let pattern = #"https?://\S+"#
        guard let range = text.range(of: pattern, options: .regularExpression) else { return nil }
        let urlStr = String(text[range])
        return URL(string: urlStr)
    }

    // MARK: - Styled Text

    private func attributedMessage(_ text: String) -> AttributedString {
        var result = AttributedString(text)
        let nsRange = NSRange(text.startIndex..., in: text)

        // Fonts use Dynamic-Type text styles (not fixed .system(size:)) so
        // formatted message text scales with the user's content-size setting.

        // Code blocks: ```text``` (must be before inline code)
        for match in Self.mdCodeBlock.matches(in: text, range: nsRange).reversed() {
            if let range = Range(match.range, in: result) {
                result[range].font = .system(.callout, design: .monospaced)
                result[range].backgroundColor = Theme.bgTertiary
            }
        }

        // Bold: **text**
        for match in Self.mdBold.matches(in: text, range: nsRange).reversed() {
            if let range = Range(match.range, in: result) {
                result[range].font = .system(.body, weight: .bold)
            }
        }

        // Italic: *text* (but not **text**)
        for match in Self.mdItalic.matches(in: text, range: nsRange).reversed() {
            if let range = Range(match.range, in: result) {
                result[range].font = .system(.body).italic()
            }
        }

        // Strikethrough: ~~text~~
        for match in Self.mdStrike.matches(in: text, range: nsRange).reversed() {
            if let range = Range(match.range, in: result) {
                result[range].strikethroughStyle = .single
                result[range].foregroundColor = Theme.textMuted
            }
        }

        // Inline code: `text` (skip if inside code block)
        for match in Self.mdInlineCode.matches(in: text, range: nsRange).reversed() {
            if let range = Range(match.range, in: result) {
                result[range].font = .system(.body, design: .monospaced)
                result[range].backgroundColor = Theme.bgTertiary
            }
        }

        // Clickable URLs
        for match in Self.mdURL.matches(in: text, range: nsRange) {
            if let swiftRange = Range(match.range, in: text),
               let attrRange = Range(match.range, in: result),
               let url = URL(string: String(text[swiftRange])) {
                result[attrRange].link = url
                result[attrRange].foregroundColor = Theme.accent
            }
        }

        // Tappable @mentions → freeq://mention/<token> (opens the profile).
        let ns = text as NSString
        for match in Self.mdMention.matches(in: text, range: nsRange) {
            // Skip emails: require a boundary before '@'.
            let at = match.range.location
            if at > 0, let s = UnicodeScalar(UInt32(ns.character(at: at - 1))),
               CharacterSet.alphanumerics.contains(s) { continue }
            guard let attrRange = Range(match.range, in: result),
                  result[attrRange].link == nil else { continue }
            let token = ns.substring(with: match.range(at: 1))
            let encoded = token.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? token
            if let url = URL(string: "freeq://mention/\(encoded)") {
                result[attrRange].link = url
                result[attrRange].foregroundColor = Theme.accent
                result[attrRange].font = .system(.body, weight: .semibold)
            }
        }

        // Tappable #channels → freeq://channel/<name> (switch/join).
        for match in Self.mdChannel.matches(in: text, range: nsRange) {
            guard let attrRange = Range(match.range, in: result),
                  result[attrRange].link == nil else { continue }
            let name = ns.substring(with: match.range) // "#channel"
            let encoded = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
            if let url = URL(string: "freeq://channel/\(encoded)") {
                result[attrRange].link = url
                result[attrRange].foregroundColor = Theme.accent
                result[attrRange].font = .system(.body, weight: .semibold)
            }
        }

        return result
    }

    /// Intercept in-app links from message text. `freeq://mention/<token>`
    /// opens the profile; `freeq://channel/<name>` switches to (or joins) the
    /// channel; everything else opens in the browser.
    private func handleMessageURL(_ url: URL) -> OpenURLAction.Result {
        guard url.scheme == "freeq" else { return .systemAction }
        switch url.host {
        case "mention":
            let token = url.lastPathComponent.removingPercentEncoding ?? url.lastPathComponent
            profileTarget = ProfileNickTarget(nick: token, origin: nil)
            return .handled
        case "channel":
            let name = url.lastPathComponent.removingPercentEncoding ?? url.lastPathComponent
            if !appState.channels.contains(where: { $0.name.lowercased() == name.lowercased() }) {
                appState.joinChannel(name)
            }
            appState.navigate(toBuffer: name)
            return .handled
        default:
            return .systemAction
        }
    }

    // MARK: - Formatting

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "h:mm a"
        return f
    }()

    private static let shortTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "h:mm"
        return f
    }()

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMMM d, yyyy"
        return f
    }()

    private func formatTime(_ date: Date) -> String {
        Self.timeFormatter.string(from: date)
    }

    private func shortTime(_ date: Date) -> String {
        Self.shortTimeFormatter.string(from: date)
    }

    private func formatDate(_ date: Date) -> String {
        if Calendar.current.isDateInToday(date) { return "Today" }
        if Calendar.current.isDateInYesterday(date) { return "Yesterday" }
        return Self.dateFormatter.string(from: date)
    }
}

// MARK: - Emoji Picker Sheet

struct EmojiPickerSheet: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    let message: ChatMessage
    let channel: String

    let commonEmoji = ["👍", "👎", "❤️", "😂", "😮", "😢", "🎉", "🔥",
                       "🕺", "💃", "🎶", "🎷",  // freeq music/dance brand
                       "👀", "💯", "✅", "❌", "🙏", "💪", "🤔", "😍",
                       "🚀", "⭐", "🌈", "🎵", "☕", "🍕", "🐛", "💡"]

    var body: some View {
        VStack(spacing: 16) {
            Text("React to message")
                .font(.fqSubheadline.weight(.semibold))
                .foregroundColor(Theme.textPrimary)
                .padding(.top, 8)

            // Original message preview
            HStack(spacing: 8) {
                Text(message.from)
                    .font(.fqFootnote.weight(.bold))
                    .foregroundColor(Theme.nickColor(for: message.from))
                Text(message.text)
                    .font(.fqFootnote)
                    .foregroundColor(Theme.textSecondary)
                    .lineLimit(2)
            }
            .padding(12)
            .background(Theme.bgTertiary)
            .cornerRadius(8)
            .padding(.horizontal, 16)

            // Emoji grid
            LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 8), spacing: 8) {
                ForEach(commonEmoji, id: \.self) { emoji in
                    Button(action: {
                        appState.sendReaction(target: channel, msgId: message.id, emoji: emoji)
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        dismiss()
                    }) {
                        Text(emoji)
                            .font(.system(size: 28))
                            .frame(width: 40, height: 40)
                    }
                }
            }
            .padding(.horizontal, 16)

            Spacer()
        }
        .background(Theme.bgPrimary)
        .preferredColorScheme(.dark)
    }
}

// MARK: - Animated Typing Dots

struct TypingDots: View {
    @State private var animating = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: 3) {
            ForEach(0..<3, id: \.self) { i in
                Circle()
                    .fill(Theme.textMuted)
                    .frame(width: 6, height: 6)
                    .offset(y: (animating && !reduceMotion) ? -4 : 2)
                    .animation(
                        reduceMotion ? nil :
                            .easeInOut(duration: 0.4)
                            .repeatForever(autoreverses: true)
                            .delay(Double(i) * 0.15),
                        value: animating
                    )
            }
        }
        .onAppear { animating = true }
        .accessibilityLabel("Typing")
    }
}

// Helper for profile sheet binding. Carries the anchoring row's evidence when
// opened from a message, so the card's claim is computed from the row and the
// live room — never from a cache.
private struct ProfileNickTarget: Identifiable {
    let nick: String
    let origin: String?
    var account: String? = nil
    var rowTime: Date? = nil
    var id: String { nick }
}

// Which proof the sheet is open for — the sender's identity, or the checked
// answer for one message — plus the row evidence the claim is computed from.
// Shared with ThreadView, which presents the same sheet.
struct ProofTarget: Identifiable {
    let id = UUID()
    let nick: String
    let origin: String?
    let account: String?
    let rowTime: Date
    /// nil = identity only; set = check this message and lead with the answer.
    let msgId: String?
    let rowMsgId: String
    let rowSigned: Bool

    static func identity(_ msg: ChatMessage) -> ProofTarget {
        ProofTarget(nick: msg.from, origin: msg.origin, account: msg.account,
                    rowTime: msg.timestamp, msgId: nil,
                    rowMsgId: msg.id, rowSigned: msg.isSigned)
    }
    static func verify(_ msg: ChatMessage) -> ProofTarget {
        ProofTarget(nick: msg.from, origin: msg.origin, account: msg.account,
                    rowTime: msg.timestamp, msgId: msg.id,
                    rowMsgId: msg.id, rowSigned: msg.isSigned)
    }
}

// Preference key for scroll offset detection
private struct ScrollOffsetKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

// MARK: - Inline Video Player

struct InlineVideoPlayer: View {
    let url: URL
    @State private var player: AVPlayer?
    @State private var isDownloading = false
    @State private var loadError = false
    @State private var localURL: URL?
    @State private var thumbnail: UIImage?

    var body: some View {
        ZStack {
            if let player = player {
                VideoPlayer(player: player)
                    .frame(maxWidth: 300, minHeight: 180, maxHeight: 240)
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Theme.border, lineWidth: 1)
                    )
            } else {
                // Thumbnail / loading state
                ZStack {
                    if let thumb = thumbnail {
                        Image(uiImage: thumb)
                            .resizable()
                            .aspectRatio(contentMode: .fill)
                            .frame(maxWidth: 300, minHeight: 180, maxHeight: 240)
                            .clipped()
                    } else {
                        Rectangle()
                            .fill(Theme.bgTertiary)
                            .frame(maxWidth: 300, minHeight: 180, maxHeight: 240)
                    }

                    if isDownloading {
                        ProgressView()
                            .tint(.white)
                            .scaleEffect(1.2)
                            .frame(width: 56, height: 56)
                            .background(.black.opacity(0.5))
                            .cornerRadius(28)
                    } else if loadError {
                        VStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 24))
                                .foregroundColor(.white)
                            Text("Tap to retry")
                                .font(.fqCaption)
                                .foregroundColor(.white.opacity(0.8))
                        }
                        .frame(width: 80, height: 64)
                        .background(.black.opacity(0.5))
                        .cornerRadius(12)
                    } else {
                        // Play button overlay
                        Image(systemName: "play.circle.fill")
                            .font(.system(size: 52))
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, .black.opacity(0.5))
                    }
                }
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Theme.border, lineWidth: 1)
                )
                .onTapGesture { downloadAndPlay() }
            }
        }
        .onAppear { generateThumbnail() }
        .onDisappear { player?.pause() }
    }

    private func generateThumbnail() {
        // Try to get a thumbnail from the URL for preview
        // For proxy URLs this won't work until downloaded, show placeholder
    }

    private func downloadAndPlay() {
        guard !isDownloading else { return }

        // Already downloaded — play immediately
        if let local = localURL {
            setupPlayer(local)
            return
        }

        // Download first
        isDownloading = true
        loadError = false
        UIImpactFeedbackGenerator(style: .light).impactOccurred()

        Task {
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                let httpResponse = response as? HTTPURLResponse
                guard httpResponse?.statusCode == 200, !data.isEmpty else {
                    await MainActor.run { isDownloading = false; loadError = true }
                    return
                }

                let contentType = httpResponse?.value(forHTTPHeaderField: "Content-Type") ?? "video/mp4"
                let ext = contentType.contains("quicktime") || contentType.contains("mov") ? "mov" : "mp4"
                let tempURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("video_\(url.absoluteString.hashValue).\(ext)")
                try data.write(to: tempURL)

                // Generate thumbnail from first frame
                let asset = AVAsset(url: tempURL)
                let generator = AVAssetImageGenerator(asset: asset)
                generator.appliesPreferredTrackTransform = true
                generator.maximumSize = CGSize(width: 600, height: 600)
                let cgImage = try? generator.copyCGImage(at: CMTime(seconds: 0.1, preferredTimescale: 600), actualTime: nil)

                await MainActor.run {
                    if let cgImage = cgImage {
                        thumbnail = UIImage(cgImage: cgImage)
                    }
                    localURL = tempURL
                    isDownloading = false
                    // Don't auto-play — show thumbnail with play button.
                    // Next tap plays instantly from local file.
                }
            } catch {
                await MainActor.run { isDownloading = false; loadError = true }
            }
        }
    }

    private func setupPlayer(_ fileURL: URL) {
        try? AVAudioSession.sharedInstance().setCategory(.playback, mode: .default)
        try? AVAudioSession.sharedInstance().setActive(true)
        let p = AVPlayer(url: fileURL)
        player = p
        p.play()
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }
}

// MARK: - Inline Audio Player

struct InlineAudioPlayer: View {
    let url: URL
    var label: String? = nil
    @State private var player: AVPlayer?
    @State private var isPlaying = false
    @State private var progress: Double = 0
    @State private var duration: Double = 0
    @State private var timer: Timer?
    @State private var loadError = false
    @State private var statusObserver: NSKeyValueObservation?

    var body: some View {
        HStack(spacing: 12) {
            // Play/pause button
            Button(action: togglePlayback) {
                ZStack {
                    Circle()
                        .fill(loadError ? Theme.danger : Theme.accent)
                        .frame(width: 44, height: 44)
                    if loadError {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 16))
                            .foregroundColor(.white)
                    } else if isDownloading {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            .scaleEffect(0.8)
                    } else {
                        Image(systemName: isPlaying ? "pause.fill" : "play.fill")
                            .font(.system(size: 18))
                            .foregroundColor(.white)
                            .offset(x: isPlaying ? 0 : 2)
                    }
                }
            }
            .disabled(isDownloading)
            .accessibilityLabel(loadError ? "Voice message failed to load"
                                 : isPlaying ? "Pause voice message" : "Play voice message")

            VStack(alignment: .leading, spacing: 6) {
                // Label
                HStack(spacing: 6) {
                    Image(systemName: "mic.fill")
                        .font(.system(size: 11))
                        .foregroundColor(Theme.accent)
                    Text("Voice message")
                        .font(.fqFootnote.weight(.medium))
                        .foregroundColor(Theme.textPrimary)
                }

                // Progress bar
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule()
                            .fill(Theme.accent.opacity(0.2))
                            .frame(height: 4)

                        Capsule()
                            .fill(Theme.accent)
                            .frame(width: max(0, geo.size.width * CGFloat(duration > 0 ? progress / duration : 0)), height: 4)
                    }
                }
                .frame(height: 4)

                // Duration
                HStack {
                    Text(formatTime(isPlaying ? progress : 0))
                        .font(.fqMonoCaption)
                        .foregroundColor(Theme.textMuted)
                    Spacer()
                    Text(label ?? formatTime(duration))
                        .font(.fqMonoCaption)
                        .foregroundColor(Theme.textMuted)
                }
            }
        }
        .padding(12)
        .background(Theme.bgTertiary)
        .cornerRadius(14)
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Theme.border, lineWidth: 1)
        )
        .frame(maxWidth: 280)
        .onAppear { loadDuration() }
        .onDisappear { cleanup() }
    }

    private func loadDuration() {
        // If we have a label like "0:05", parse it as initial duration
        if let label = label, let parsed = parseDuration(label) {
            duration = parsed
        }
        // Also try loading from the asset
        let asset = AVURLAsset(url: url)
        Task {
            if let d = try? await asset.load(.duration) {
                let secs = CMTimeGetSeconds(d)
                if secs > 0 && secs.isFinite {
                    await MainActor.run { duration = secs }
                }
            }
        }
    }

    private func parseDuration(_ s: String) -> Double? {
        let parts = s.split(separator: ":")
        guard parts.count == 2,
              let mins = Double(parts[0]),
              let secs = Double(parts[1]) else { return nil }
        return mins * 60 + secs
    }

    @State private var localFileURL: URL?
    @State private var isDownloading = false

    private func togglePlayback() {
        // Configure audio session for playback
        try? AVAudioSession.sharedInstance().setCategory(.playback, mode: .default)
        try? AVAudioSession.sharedInstance().setActive(true)

        if isPlaying {
            player?.pause()
            timer?.invalidate()
            isPlaying = false
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            return
        }

        // If we have a local file, play it directly
        if let localURL = localFileURL {
            playFromURL(localURL)
            return
        }

        // Download first (PDS sends Content-Disposition: attachment which blocks AVPlayer streaming)
        isDownloading = true
        UIImpactFeedbackGenerator(style: .light).impactOccurred()

        Task {
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                let httpResponse = response as? HTTPURLResponse
                guard httpResponse?.statusCode == 200, !data.isEmpty else {
                    await MainActor.run {
                        isDownloading = false
                        loadError = true
                    }
                    return
                }

                // Determine extension from content-type
                let contentType = httpResponse?.value(forHTTPHeaderField: "Content-Type") ?? "audio/mp4"
                let ext = contentType.contains("m4a") || contentType.contains("mp4") ? "m4a" : "mp3"
                let tempURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("audio_\(url.absoluteString.hashValue).\(ext)")

                try data.write(to: tempURL)

                await MainActor.run {
                    localFileURL = tempURL
                    isDownloading = false
                    playFromURL(tempURL)
                }
            } catch {
                await MainActor.run {
                    isDownloading = false
                    loadError = true
                    print("Audio download error: \(error)")
                }
            }
        }
    }

    private func playFromURL(_ fileURL: URL) {
        if player == nil {
            let item = AVPlayerItem(url: fileURL)
            player = AVPlayer(playerItem: item)

            statusObserver = item.observe(\.status, options: [.new]) { item, _ in
                DispatchQueue.main.async {
                    if item.status == .failed {
                        loadError = true
                        isPlaying = false
                        timer?.invalidate()
                    } else if item.status == .readyToPlay {
                        let dur = CMTimeGetSeconds(item.duration)
                        if dur > 0 && dur.isFinite { duration = dur }
                    }
                }
            }
        }

        player?.play()
        isPlaying = true
        UIImpactFeedbackGenerator(style: .light).impactOccurred()

        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
            guard let p = player else { return }
            let secs = CMTimeGetSeconds(p.currentTime())
            if secs >= 0 && secs.isFinite { progress = secs }

            if let item = p.currentItem {
                let dur = CMTimeGetSeconds(item.duration)
                if dur > 0 && dur.isFinite {
                    duration = dur
                    if secs >= dur - 0.1 {
                        p.seek(to: .zero)
                        p.pause()
                        isPlaying = false
                        progress = 0
                        timer?.invalidate()
                    }
                }
            }
        }
    }

    private func cleanup() {
        player?.pause()
        timer?.invalidate()
        statusObserver?.invalidate()
    }

    private func formatTime(_ t: Double) -> String {
        guard t.isFinite && t >= 0 else { return "0:00" }
        let mins = Int(t) / 60
        let secs = Int(t) % 60
        return String(format: "%d:%02d", mins, secs)
    }
}

// MARK: - Skeleton Loading

extension MessageListView {
    func skeletonRow(short: Bool) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Circle()
                .fill(Theme.bgTertiary)
                .frame(width: 40, height: 40)

            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Theme.bgTertiary)
                        .frame(width: 80, height: 14)
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Theme.bgTertiary)
                        .frame(width: 40, height: 10)
                }
                RoundedRectangle(cornerRadius: 4)
                    .fill(Theme.bgTertiary)
                    .frame(width: short ? 120 : 220, height: 14)
                if !short {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Theme.bgTertiary)
                        .frame(width: 160, height: 14)
                }
            }

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }
}

// MARK: - Shimmer Effect

struct ShimmerModifier: ViewModifier {
    @State private var phase: CGFloat = -1.0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .overlay(
                GeometryReader { geo in
                    // Reduce Motion: skip the sweeping highlight (a static
                    // placeholder tint stands in) so loading skeletons don't
                    // animate for users who've asked the system not to.
                    if !reduceMotion {
                        Rectangle()
                            .fill(
                                LinearGradient(
                                    colors: [.clear, .white.opacity(0.08), .clear],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(width: geo.size.width * 0.6)
                            .offset(x: geo.size.width * phase)
                            .onAppear {
                                withAnimation(.linear(duration: 1.5).repeatForever(autoreverses: false)) {
                                    phase = 1.5
                                }
                            }
                    }
                }
                .clipped()
            )
    }
}

extension View {
    func shimmering() -> some View {
        modifier(ShimmerModifier())
    }

    /// One-time signal-glow sweep across the content when `active` — used to
    /// make a verified identity's arrival feel special. No-op under Reduce
    /// Motion.
    func signalShimmer(active: Bool) -> some View {
        modifier(SignalShimmerOnce(active: active))
    }
}

/// On-device "while you were away" catch-up card. Streams a one-sentence
/// summary of the backlog in, Apple-Intelligence style, then sits until
/// dismissed. Private + on-device — no other IRC client can do this.
struct WhileYouWereAwayCard: View {
    let channel: ChannelState
    let missed: Int
    let onDismiss: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var summary = ""
    @State private var loading = true

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.signalGradient)
                    .symbolEffect(.pulse, isActive: loading && !reduceMotion)
                Text("While you were away")
                    .font(.fqFootnote.weight(.semibold))
                    .foregroundColor(Theme.textPrimary)
                Spacer()
                Text("\(missed)")
                    .font(.fqCaption2.weight(.bold))
                    .foregroundColor(Theme.accent)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(Theme.accent.opacity(0.15), in: Capsule())
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Theme.textMuted)
                        .frame(width: 26, height: 26)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Dismiss summary")
            }

            if loading && summary.isEmpty {
                HStack(spacing: 6) {
                    ProgressView().scaleEffect(0.7).tint(Theme.accent)
                    Text("Summarizing on-device…")
                        .font(.fqCaption).foregroundColor(Theme.textMuted)
                }
            } else {
                Text(summary.isEmpty ? "Nothing much — you're basically caught up." : summary)
                    .font(.fqCallout)
                    .foregroundColor(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .animation(.easeOut(duration: 0.15), value: summary)
            }
        }
        .padding(14)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(Theme.accent.opacity(0.35), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.25), radius: 12, y: 4)
        .task {
            // Summarize the backlog that arrived while away (API caps at 40).
            let msgs = Array(channel.messages.suffix(min(missed + 2, 40)))
            let result = await IntelligenceService.shared.summarizeStreaming(msgs, in: channel.name) { partial in
                summary = partial
                loading = false
            }
            loading = false
            if summary.isEmpty, let result { summary = result }
        }
    }
}

/// Identifies a single reaction burst so the overlay retriggers on each react.
struct ReactionBurstEvent: Identifiable {
    let id = UUID()
    let emoji: String
}

/// A short burst of the reacted emoji that floats up and fades — iMessage-style
/// screen joy for a celebratory reaction. One particle system, ~1.2s, then
/// gone. No-op under Reduce Motion.
struct ReactionBurstView: View {
    let emoji: String
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var animate = false

    private let count = 14

    var body: some View {
        GeometryReader { geo in
            if !reduceMotion {
                ZStack {
                    ForEach(0..<count, id: \.self) { i in
                        Particle(emoji: emoji, index: i, count: count, size: geo.size, animate: animate)
                    }
                }
                .onAppear {
                    withAnimation(.easeOut(duration: 1.2)) { animate = true }
                }
            }
        }
        .ignoresSafeArea()
    }

    private struct Particle: View {
        let emoji: String
        let index: Int
        let count: Int
        let size: CGSize
        let animate: Bool

        // Deterministic pseudo-random spread from the index so we don't need a
        // random source (which SwiftUI would re-roll on every re-render).
        private var seed: Double { Double((index * 2654435761) % 1000) / 1000.0 }
        private var seed2: Double { Double((index * 40503) % 1000) / 1000.0 }

        var body: some View {
            let startX = size.width * (0.2 + 0.6 * seed)
            let drift = CGFloat((seed2 - 0.5) * 120)
            let rise = size.height * CGFloat(0.45 + 0.35 * seed2)
            let scale = 0.7 + 0.9 * seed

            Text(emoji)
                .font(.system(size: 26))
                .scaleEffect(animate ? scale : 0.2)
                .position(
                    x: startX + (animate ? drift : 0),
                    y: size.height - 90 - (animate ? rise : 0)
                )
                .rotationEffect(.degrees(animate ? Double((seed - 0.5) * 90) : 0))
                .opacity(animate ? 0 : 1)
        }
    }
}

/// A single left-to-right highlight sweep, masked to the content's shape, that
/// plays once when it appears. Distinct from `ShimmerModifier` (which loops for
/// loading skeletons) — this is a one-shot celebratory glint.
struct SignalShimmerOnce: ViewModifier {
    let active: Bool
    @State private var phase: CGFloat = -1.0
    @State private var done = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .overlay {
                if active && !reduceMotion && !done {
                    GeometryReader { geo in
                        LinearGradient(
                            colors: [.clear, Theme.accentLight, Theme.accent, .clear],
                            startPoint: .leading, endPoint: .trailing
                        )
                        .frame(width: geo.size.width * 0.55)
                        .offset(x: geo.size.width * phase)
                        .blendMode(.plusLighter)
                        .mask(content)
                        .allowsHitTesting(false)
                        .onAppear {
                            withAnimation(.easeInOut(duration: 0.85)) { phase = 1.7 }
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) { done = true }
                        }
                    }
                }
            }
    }
}
