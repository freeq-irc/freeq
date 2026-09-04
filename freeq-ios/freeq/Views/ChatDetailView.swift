import SwiftUI

/// Full-screen chat view — pushed from the chat list.
struct ChatDetailView: View {
    @EnvironmentObject var appState: AppState
    let channelName: String
    @State private var showingSearch = false
    @State private var showingPins = false
    // On-device "catch me up" summary.
    @State private var showingSummary = false
    @State private var summaryText: String? = nil
    @State private var summarizing = false
    @Environment(\.dismiss) var dismiss

    /// Canonical buffer key: a DM opened by nick follows its DID binding, so
    /// the view survives the thread merging under the DID mid-session.
    private var bufferKey: String {
        if channelName.hasPrefix("#") || channelName.hasPrefix("&") { return channelName }
        return appState.didForNick(channelName) ?? channelName
    }

    /// Human name for the toolbar — never a raw DID.
    private var displayName: String { appState.displayNameForKey(bufferKey) }

    private var channelState: ChannelState? {
        appState.channels.first { $0.name.lowercased() == bufferKey.lowercased() }
            ?? appState.dmBuffers.first { $0.name.lowercased() == bufferKey.lowercased() }
    }

    private var isChannel: Bool { channelName.hasPrefix("#") }

    /// True when an AV call is active in *this* channel.
    private var isCallActiveHere: Bool {
        appState.isInCall && isChannel
            && appState.currentCallChannel?.lowercased() == channelName.lowercased()
    }

    var body: some View {
        ZStack {
            Theme.bgPrimary.ignoresSafeArea()

            VStack(spacing: 0) {
                // Connection status bar — always offer a Sign out escape
                // hatch when not registered, so a stuck saved session (bad
                // broker token, revoked refresh, etc.) doesn't trap the user.
                if appState.connectionState != .registered {
                    HStack(spacing: 8) {
                        if appState.connectionState == .connecting || appState.connectionState == .connected {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "wifi.slash")
                                .font(.system(size: 12))
                        }
                        Text(appState.connectionState == .disconnected ? "Disconnected" :
                             appState.connectionState == .connecting ? "Connecting..." : "Registering...")
                            .font(.fqFootnote.weight(.medium))
                        Spacer()
                        // A button, not an instruction. This used to read
                        // "pull down to reconnect", but the pull gesture lives
                        // on the message list's ScrollView — and an empty
                        // channel has no content to pull, which is exactly
                        // when you are most likely to be disconnected. An
                        // instruction the user cannot follow is worse than no
                        // instruction: they conclude the app is broken.
                        // Pull-to-refresh still works where it works.
                        // Gated on hasSavedSession because reconnectSavedSession()
                        // no-ops without a broker token, and a button that
                        // silently does nothing is the same bug wearing a
                        // different hat. A guest's escape hatch is Sign out.
                        if appState.connectionState == .disconnected, appState.hasSavedSession {
                            Button("Reconnect") { appState.reconnectSavedSession() }
                                .font(.fqFootnote.weight(.semibold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(Color.white.opacity(0.18))
                                .clipShape(Capsule())
                                .accessibilityLabel("Reconnect")
                                .accessibilityHint("Reconnects using your saved session")
                        }
                        Button("Sign out") { appState.logout() }
                            .font(.fqFootnote.weight(.semibold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color.white.opacity(0.18))
                            .clipShape(Capsule())
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(appState.connectionState == .disconnected ? Theme.danger : Theme.warning)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .animation(.easeInOut(duration: 0.3), value: appState.connectionState)
                }

                // Access-denied banner — explains a gated join (invite-only,
                // bad key, banned, auth required) instead of failing silently.
                if let reason = channelState?.accessDeniedReason {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.slash.fill").font(.system(size: 12))
                        Text(reason).font(.fqFootnote.weight(.medium))
                        Spacer()
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Theme.warning)
                    .transition(.move(edge: .top).combined(with: .opacity))
                }

                // Voice/video call panel — pinned above the message list
                // when an AV session is active in this channel.
                if isCallActiveHere {
                    CallView(channel: channelName)
                }

                // Message list + composer — hidden while the call is
                // expanded to fill the screen.
                if !(isCallActiveHere && appState.isCallExpanded) {
                    if let channel = channelState {
                        ZStack {
                            MessageListView(channel: channel)
                                .onTapGesture {
                                    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                                }

                            // Member list slide-in
                            if appState.showMemberList {
                                HStack(spacing: 0) {
                                    Spacer()
                                    Color.black.opacity(0.3)
                                        .ignoresSafeArea()
                                        .onTapGesture { appState.showMemberList = false }
                                    MemberListView(channel: channel)
                                        .frame(width: 260)
                                        .transition(.move(edge: .trailing))
                                }
                                .animation(.easeInOut(duration: 0.2), value: appState.showMemberList)
                            }
                        }

                        ComposeView()
                    } else {
                        Spacer()
                        Text("Channel not found")
                            .foregroundColor(Theme.textMuted)
                        Spacer()
                    }
                }
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        // Handoff: advertise the open conversation so it can resume on the
        // user's Mac/iPad. Routed by freeqApp's onContinueUserActivity.
        .userActivity(FreeqActivity.channel, isActive: !channelName.isEmpty) { activity in
            activity.title = displayName
            activity.userInfo = ["channel": bufferKey]
            activity.isEligibleForHandoff = true
            activity.targetContentIdentifier = bufferKey
        }
        .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .principal) {
                VStack(spacing: 1) {
                    HStack(spacing: 4) {
                        if channelState?.isEncrypted == true {
                            Image(systemName: "lock.fill")
                                .font(.system(size: 11))
                                .foregroundColor(Theme.verify)
                                .accessibilityLabel("End-to-end encrypted")
                        }
                        Text(displayName)
                            .font(.fqCallout.weight(.semibold))
                            .foregroundColor(Theme.textPrimary)
                    }

                    if let channel = channelState {
                        if !channel.activeTypers.isEmpty {
                            Text(typingText(channel.activeTypers))
                                .font(.fqCaption2)
                                .foregroundColor(Theme.accent)
                        } else if !channel.topic.isEmpty {
                            Text(channel.topic)
                                .font(.fqCaption2)
                                .foregroundColor(Theme.textMuted)
                                .lineLimit(1)
                        } else if isChannel {
                            Text("\(channel.uniqueMemberCount) members")
                                .font(.fqCaption2)
                                .foregroundColor(Theme.textMuted)
                        }
                    }
                }
            }

            ToolbarItemGroup(placement: .topBarTrailing) {
                // Favorite toggle — pins this conversation to the top of the
                // list. Available for channels and DMs.
                Button(action: { appState.toggleFavorite(bufferKey) }) {
                    Image(systemName: appState.isFavorite(bufferKey) ? "star.fill" : "star")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(appState.isFavorite(bufferKey) ? .yellow : Theme.textSecondary)
                }
                .accessibilityLabel(appState.isFavorite(bufferKey) ? "Remove from favorites" : "Add to favorites")

                if isChannel {
                    // Voice call — green when in this call, accent when a
                    // session is active but we haven't joined, muted otherwise.
                    Button(action: { appState.startOrJoinVoice(channel: channelName) }) {
                        let inThisCall = appState.isInCall
                            && appState.currentCallChannel?.lowercased() == channelName.lowercased()
                        let sessionActive = appState.activeAvSessions[channelName.lowercased()] != nil
                        Image(systemName: inThisCall ? "speaker.wave.2.fill" : "speaker.wave.2")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(
                                inThisCall ? Theme.success
                                : (sessionActive ? Theme.accent : Theme.textSecondary)
                            )
                    }

                    Button(action: { showingSearch = true }) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 14))
                            .foregroundColor(Theme.textSecondary)
                    }

                    // Overflow menu — explicit, because one more inline item
                    // makes UIKit auto-collapse the tail into a dead system
                    // ellipsis. Members, pins (PinnedMessagesView previously
                    // had no entry point at all), and catch-me-up live here.
                    Menu {
                        Button(action: { appState.showMemberList.toggle() }) {
                            Label("Members", systemImage: "person.2")
                        }
                        Button(action: { showingPins = true }) {
                            Label("Pinned Messages", systemImage: "pin")
                        }
                        if IntelligenceService.shared.isAvailable {
                            Button(action: generateSummary) {
                                Label("Catch Me Up", systemImage: "sparkles")
                            }
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .font(.system(size: 14))
                            .foregroundColor(Theme.textSecondary)
                    }
                }
            }
        }
        .sheet(isPresented: $showingSummary) {
            CatchMeUpSheet(summary: summaryText, loading: summarizing)
                .presentationDetents([.height(260)])
                .presentationBackground(.ultraThinMaterial)
        }
        .onAppear {
            appState.activeChannel = bufferKey
            // Snapshot how much you missed BEFORE markRead clears it, so the
            // "while you were away" card knows there's a backlog to summarize.
            appState.awayCardCounts[bufferKey] = appState.unreadCounts[bufferKey] ?? 0
            appState.markRead(bufferKey)
        }
        .onDisappear {
            // Clear activeChannel so unread counting works for this channel
            if appState.activeChannel == bufferKey || appState.activeChannel == channelName {
                appState.activeChannel = nil
            }
        }
        .sheet(isPresented: $showingSearch) {
            SearchSheet()
                .presentationDetents([.large])
        }
        .sheet(isPresented: $showingPins) {
            NavigationStack {
                PinnedMessagesView(channelName: bufferKey)
            }
            .presentationDetents([.large])
        }
    }

    private func typingText(_ typers: [String]) -> String {
        switch typers.count {
        case 1: return "\(typers[0]) is typing..."
        case 2: return "\(typers[0]) and \(typers[1]) are typing..."
        default: return "Several people are typing..."
        }
    }

    private func generateSummary() {
        guard let messages = channelState?.messages, messages.count > 1 else {
            summaryText = "Not enough here to summarize yet."
            showingSummary = true
            return
        }
        summaryText = nil
        summarizing = true
        showingSummary = true
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        Task { @MainActor in
            // Stream it — the sentence types itself out live.
            let result = await IntelligenceService.shared.summarizeStreaming(messages, in: channelName) { partial in
                summaryText = partial
                summarizing = false
            }
            summarizing = false
            if (summaryText?.isEmpty ?? true) {
                summaryText = result ?? "Couldn't summarize this one."
            }
        }
    }
}

/// The "catch me up" result — a single on-device sentence, with a clear note
/// that inference never left the phone (freeq's whole ethos).
private struct CatchMeUpSheet: View {
    let summary: String?
    let loading: Bool

    var body: some View {
        VStack(spacing: Theme.Space.lg) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(Theme.signalGradient)
                Text("Catch me up")
                    .font(.fqTitle3.weight(.semibold))
                    .foregroundColor(Theme.textPrimary)
                Spacer()
            }

            Group {
                if loading {
                    HStack(spacing: 10) {
                        ProgressView().tint(Theme.accent)
                        Text("Reading the room…")
                            .font(.fqSubheadline)
                            .foregroundColor(Theme.textSecondary)
                        Spacer()
                    }
                } else if let summary {
                    Text(summary)
                        .font(.fqBody)
                        .foregroundColor(Theme.textPrimary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer(minLength: 0)

            HStack(spacing: 6) {
                Image(systemName: "lock.fill")
                    .font(.system(size: 10))
                Text("Summarized on your device — nothing left the phone.")
                    .font(.fqCaption)
            }
            .foregroundColor(Theme.textMuted)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(Theme.Space.xl)
    }
}
