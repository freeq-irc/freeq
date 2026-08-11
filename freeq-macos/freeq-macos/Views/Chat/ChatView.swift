import SwiftUI

/// Main chat area: TopBar + Search + MessageList + Typing + ComposeBar
struct ChatView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        GeometryReader { geo in
        VStack(spacing: 0) {
            TopBarView()
            Divider().overlay(Theme.borderSoft)

            if appState.showMotd && !appState.motd.isEmpty {
                MotdBanner()
                Divider().overlay(Theme.borderSoft)
            }

            if let reason = appState.activeChannelState?.accessDeniedReason {
                ChannelAccessBanner(reason: reason)
                Divider().overlay(Theme.borderSoft)
            }

            // Pinned messages bar
            if let pins = appState.activeChannelState?.pinnedMessages, !pins.isEmpty {
                PinnedMessagesBar(pins: pins)
                Divider().overlay(Theme.borderSoft)
            }

            // Search bar
            if appState.showSearch {
                SearchBar(isPresented: Binding(
                    get: { appState.showSearch },
                    set: { appState.showSearch = $0 }
                ))
                Divider().overlay(Theme.borderSoft)
            }

            if appState.isInCall, let callChannel = appState.currentCallChannel {
                // Collapsed: cap the call so the message list stays visible and
                // the video scales to fit. Expanded: the call takes the WHOLE
                // area — the message list + composer hide below it, so "expand"
                // actually fills instead of being squeezed into 60% (which cut
                // off the video / hid participants below the fold).
                CallView(channel: callChannel)
                    .frame(maxHeight: appState.isCallExpanded ? .infinity : max(220, geo.size.height * 0.6))
                if !appState.isCallExpanded {
                    Divider().overlay(Theme.borderSoft)
                }
            }

            if !(appState.isInCall && appState.isCallExpanded) {
                MessageListView(channel: appState.activeChannelState)
                Divider().overlay(Theme.borderSoft)

                // Typing indicator bar
                if let typers = appState.activeChannelState?.activeTypers, !typers.isEmpty {
                    HStack(spacing: 4) {
                        TypingDotsView()
                        Text(typingText(typers))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 4)
                    .background(Theme.surfaceSoft)
                }
                ComposeBar()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.chatBackground)
        }
    }

    private func typingText(_ typers: [String]) -> String {
        switch typers.count {
        case 1: return "\(typers[0]) is typing…"
        case 2: return "\(typers[0]) and \(typers[1]) are typing…"
        default: return "Several people are typing…"
        }
    }
}

struct ChannelAccessBanner: View {
    @Environment(AppState.self) private var appState
    let reason: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.fill")
                .font(.caption)
                .foregroundStyle(Theme.warning)

            Text(reason)
                .font(.caption.weight(.medium))
                .foregroundStyle(Theme.textPrimary)
                .lineLimit(2)

            Spacer(minLength: 8)

            if appState.authenticatedDID == nil {
                Button("Sign In") {
                    appState.disconnect()
                    appState.brokerToken = nil
                }
                .font(.caption.weight(.medium))
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Theme.warning.opacity(0.12))
    }
}

// MARK: - Server note banner

struct MotdBanner: View {
    @Environment(AppState.self) private var appState
    @State private var expanded = false

    private var motdText: String {
        appState.motd.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var previewText: String {
        motdText
            .split(separator: "\n", omittingEmptySubsequences: true)
            .first
            .map(String.init) ?? "Server announcement"
    }

    private var isLongMotd: Bool {
        motdText.count > 360 || motdText.filter(\.isNewline).count > 4
    }

    var body: some View {
        VStack(alignment: .leading, spacing: expanded ? 8 : 0) {
            HStack(spacing: 8) {
                Image(systemName: "info.circle")
                    .font(.caption)
                    .foregroundStyle(Theme.accent)

                Text("Server note")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Theme.textPrimary)

                if !expanded {
                    Text(previewText)
                        .font(.caption)
                        .foregroundStyle(Theme.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                Spacer(minLength: 8)

                Button {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        expanded.toggle()
                    }
                } label: {
                    Label(expanded ? "Hide" : "Show", systemImage: expanded ? "chevron.up" : "chevron.down")
                        .labelStyle(.titleAndIcon)
                }
                .font(.caption)
                .foregroundStyle(Theme.textSecondary)
                .buttonStyle(.plain)
                .help(expanded ? "Hide message of the day" : "Show message of the day")

                Button {
                    appState.showMotd = false
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption2)
                        .foregroundStyle(Theme.textTertiary)
                }
                .buttonStyle(.plain)
                .help("Dismiss message of the day")
            }

            if expanded {
                if isLongMotd {
                    ScrollView {
                        Text(motdText)
                            .font(.caption)
                            .foregroundStyle(Theme.textSecondary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 160)
                } else {
                    Text(motdText)
                        .font(.caption)
                        .foregroundStyle(Theme.textSecondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Theme.accentSoft.opacity(0.70))
    }
}

struct ChannelWelcomeView: View {
    @Environment(AppState.self) private var appState

    private var channel: ChannelState? { appState.activeChannelState }
    private var isChannel: Bool { channel?.isChannel ?? false }
    private var displayName: String {
        guard let name = channel?.name else { return "freeq" }
        // DID-keyed DM threads render as the peer's nick, never a raw did:….
        return isChannel
            ? name.replacingOccurrences(of: "#", with: "")
            : appState.displayNameForKey(name)
    }

    var body: some View {
        VStack(spacing: 18) {
            ZStack {
                Circle()
                    .fill(isChannel ? Theme.accentSoft : Theme.blue.opacity(0.10))
                    .frame(width: 84, height: 84)
                Image(systemName: isChannel ? "number" : "person.crop.circle.fill")
                    .font(.system(size: 34, weight: .semibold))
                    .foregroundStyle(isChannel ? Theme.accent : Theme.blue)
            }

            VStack(spacing: 6) {
                Text(isChannel ? "#\(displayName)" : displayName)
                    .font(.title.weight(.semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(Theme.textSecondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
            }

            HStack(spacing: 10) {
                if isChannel {
                    contextPill(icon: "person.2.fill", text: "\(channel?.uniqueMemberCount(resolveDid: { ProfileCache.shared.did(for: $0) }) ?? 0) members")
                    if let topic = channel?.topic, !topic.isEmpty {
                        contextPill(icon: "quote.bubble.fill", text: topic)
                    }
                // The thread's own key is the binding when it is a DID —
                // a structural fact (ruled 2026-08-11). Otherwise only a
                // live binding counts; the persisted cache never votes.
                } else if let did = (channel?.name).flatMap({ DidDisplay.isDid($0) ? $0 : nil }) ?? appState.liveDidForNick(displayName),
                          claimForPerson(input: PersonClaimInput(
                              binding: did,
                              seenOnlyViaPeer: false,
                              viaPeerOrigin: nil,
                              viaPeerHadAccount: false,
                              lookup: .notAsked
                          )).state == .atProtocol {
                    contextPill(icon: "checkmark.seal.fill", text: "AT Protocol identity")
                }
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.chatBackground)
        .allowsHitTesting(false)
    }

    private var subtitle: String {
        if isChannel {
            if let topic = channel?.topic, !topic.isEmpty {
                return topic
            }
            return "This room is quiet right now."
        }
        return "This direct message is private to the two of you. Say hello when you are ready."
    }

    private func contextPill(icon: String, text: String) -> some View {
        Label(text, systemImage: icon)
            .font(.caption.weight(.medium))
            .foregroundStyle(Theme.textSecondary)
            .lineLimit(1)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Capsule().fill(Theme.surface))
            .overlay(Capsule().strokeBorder(Theme.borderSoft, lineWidth: 1))
    }
}

struct TopBarView: View {
    @Environment(AppState.self) private var appState
    @State private var showSettings = false

    private var channel: ChannelState? { appState.activeChannelState }
    private var isChannel: Bool { channel?.isChannel ?? false }

    var body: some View {
        HStack(spacing: 10) {
            // Channel/DM name
            if isChannel {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Theme.accentSoft)
                        .frame(width: 30, height: 30)
                    Image(systemName: "number")
                        .font(.headline)
                        .foregroundStyle(Theme.accent)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(channel?.name.replacingOccurrences(of: "#", with: "") ?? "")
                        .font(.headline.weight(.semibold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("\(channel?.uniqueMemberCount(resolveDid: { ProfileCache.shared.did(for: $0) }) ?? 0) members")
                        .font(.caption2)
                        .foregroundStyle(Theme.textTertiary)
                }
            } else {
                if let name = channel?.name {
                    let dmNick = appState.displayNameForKey(name)
                    AvatarView(nick: dmNick, size: 30)
                        .overlay(alignment: .bottomTrailing) {
                            Circle()
                                .fill(isOnline ? (awayMsg != nil ? Theme.warning : Theme.success) : Theme.textTertiary.opacity(0.45))
                                .frame(width: 9, height: 9)
                                .overlay(Circle().strokeBorder(Theme.surface, lineWidth: 1.5))
                        }

                    VStack(alignment: .leading, spacing: 1) {
                        Text(dmNick)
                            .font(.headline.weight(.semibold))
                            .foregroundStyle(Theme.textPrimary)
                        Text(isOnline ? (awayMsg != nil ? "away" : "online") : "offline")
                            .font(.caption2)
                            .foregroundStyle(isOnline ? (awayMsg != nil ? Theme.warning : Theme.success) : Theme.textTertiary)
                    }
                }

                // P2P badge
                if let name = channel?.name,
                   appState.p2pDMActive.contains(name.lowercased()) {
                    Label("Direct", systemImage: "point.3.connected.trianglepath.dotted")
                        .font(.caption2)
                        .foregroundStyle(Theme.success)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Theme.success.opacity(0.10)))
                }

                if !isChannel {
                    // E2EE badge for DMs — a DID-keyed thread IS the DID.
                    let bufName = channel?.name ?? ""
                    let dmDid = DidDisplay.isDid(bufName)
                        ? bufName : ProfileCache.shared.did(for: bufName)
                    if let did = dmDid, E2eeManager.shared.hasSession(remoteDid: did) {
                        encryptedBadge
                    }
                } else if channel?.isEncrypted == true {
                    // Passphrase channel E2EE (/encrypt)
                    encryptedBadge
                        .help("Messages you send here are end-to-end encrypted. Others need the same passphrase to read them.")
                }
            }

            if isChannel, let topic = channel?.topic, !topic.isEmpty {
                Divider().frame(height: 16)
                Text(topic)
                    .font(.subheadline)
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(1)
                    .help(topic)
            }

            Spacer()

            if isChannel, let name = channel?.name {
                Button {
                    if appState.isInCall && appState.currentCallChannel?.lowercased() == name.lowercased() {
                        appState.isCallExpanded.toggle()
                    } else if !appState.isInCall {
                        appState.startOrJoinVoice(channel: name)
                    }
                } label: {
                    Image(systemName: appState.isInCall && appState.currentCallChannel?.lowercased() == name.lowercased()
                          ? "waveform.circle.fill"
                          : "phone.badge.plus")
                    .foregroundStyle(appState.isInCall ? Theme.success : Theme.textTertiary)
                }
                .buttonStyle(.plain)
                .help(appState.isInCall ? "Show active call" : "Start or join call")
            }

            // Search
            Button {
                appState.showSearch.toggle()
            } label: {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(appState.showSearch ? Theme.textPrimary : Theme.textTertiary)
            }
            .buttonStyle(.plain)
            .help("Search (⌘F)")

            // Member count + settings (channels only)
            if isChannel {
                Button {
                    showSettings = true
                } label: {
                    Label("\(channel?.uniqueMemberCount(resolveDid: { ProfileCache.shared.did(for: $0) }) ?? 0)", systemImage: "person.2")
                        .font(.caption)
                        .foregroundStyle(Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Channel settings")
                .sheet(isPresented: $showSettings) {
                    if let ch = channel {
                        ChannelSettingsSheet(channel: ch)
                            .environment(appState)
                    }
                }
            }

            // Detail panel toggle
            Button {
                appState.showDetailPanel.toggle()
            } label: {
                Image(systemName: "sidebar.trailing")
                    .foregroundStyle(appState.showDetailPanel ? Theme.textPrimary : Theme.textTertiary)
            }
            .buttonStyle(.plain)
            .help("Toggle detail panel")
        }
        .padding(.horizontal, 16)
        .frame(height: 58)
        .background(Theme.surface)
    }

    private var isOnline: Bool {
        guard let name = channel?.name else { return false }
        return appState.isNickOnline(appState.displayNameForKey(name))
    }

    private var awayMsg: String? {
        guard let name = channel?.name else { return nil }
        return appState.awayStatus(for: appState.displayNameForKey(name))
    }

    private var encryptedBadge: some View {
        HStack(spacing: 3) {
            Image(systemName: "lock.shield.fill")
                .font(.caption2)
            Text("Encrypted")
                .font(.caption2)
        }
        .foregroundStyle(Theme.success)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Capsule().fill(Theme.success.opacity(0.10)))
    }
}

// MARK: - Typing dots animation

struct TypingDotsView: View {
    @State private var phase = 0
    @State private var timer: Timer?

    var body: some View {
        HStack(spacing: 2) {
            ForEach(0..<3) { i in
                Circle()
                    .fill(.secondary)
                    .frame(width: 4, height: 4)
                    .opacity(phase == i ? 1 : 0.3)
            }
        }
        .onAppear {
            // Stash the Timer in @State so .onDisappear can invalidate
            // it. Without this, recreating the view (chat-switch, list
            // diffing) accumulates phantom timers that keep mutating
            // the destroyed @State and leak memory across long sessions.
            timer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { _ in
                phase = (phase + 1) % 3
            }
        }
        .onDisappear {
            timer?.invalidate()
            timer = nil
        }
    }
}
