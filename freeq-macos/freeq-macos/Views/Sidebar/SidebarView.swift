import SwiftUI

struct SidebarView: View {
    @Environment(AppState.self) private var appState
    @State private var showStatusEditor = false
    // Multi-select mode for bulk actions (e.g. leave several channels at once).
    @State private var isSelecting = false
    @State private var selected: Set<String> = []
    @State private var confirmLeave = false
    /// One-shot: the restored channel has been scrolled into view. Channels
    /// load incrementally after connect, so this waits for the row to exist.
    @State private var didRevealActive = false

    private func exitSelectMode() {
        isSelecting = false
        selected = []
    }

    /// The channel entries in the shared list content (order/grouping matching
    /// the visible list) — used by "Select All".
    private var selectableChannelNames: [String] {
        appState.channels.map(\.name)
    }

    /// The currently-selected entries that are channels (DMs/P2P are ignored by
    /// the bulk "Leave" action).
    private var selectedChannels: [String] {
        selected.filter { $0.hasPrefix("#") || $0.hasPrefix("&") }.sorted()
    }

    @ViewBuilder
    private var listSections: some View {
        // Favorites
        let favChannels = appState.channels.filter { appState.favorites.contains($0.name.lowercased()) }
        // Favorites roam per-DID, so a favorite can name a channel this device
        // isn't currently joined to. Both sections below filter `channels`, so
        // such a favorite would render NOWHERE — invisible and unreachable,
        // which reads as "I can't find #freeq, how do I even join it?". Show it
        // as a dimmed row that joins on click.
        let unjoinedFavorites = FavoritesSync.unjoined(
            favorites: appState.favorites,
            joined: appState.channels.map(\.name))
        if !favChannels.isEmpty || !unjoinedFavorites.isEmpty {
            Section("Favorites") {
                ForEach(favChannels) { channel in
                    ChannelRow(channel: channel,
                               isSelecting: isSelecting,
                               isSelected: selected.contains(channel.name),
                               onBeginSelect: { name in isSelecting = true; selected = [name] })
                        .tag(channel.name)
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                }
                ForEach(unjoinedFavorites, id: \.self) { name in
                    Button {
                        appState.joinChannel(name)
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "number")
                                .foregroundStyle(Theme.textSecondary)
                            Text(name.dropFirst())
                                .foregroundStyle(Theme.textSecondary)
                            Spacer()
                            Text("Join")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(Theme.accent)
                        }
                    }
                    .buttonStyle(.plain)
                    .help("Favorited on another device — click to join \(name)")
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
                }
            }
        }

        // Channels (non-favorites)
        Section("Channels") {
            ForEach(appState.channels.filter { !appState.favorites.contains($0.name.lowercased()) }) { channel in
                ChannelRow(channel: channel,
                           isSelecting: isSelecting,
                           isSelected: selected.contains(channel.name),
                           onBeginSelect: { name in isSelecting = true; selected = [name] })
                    .tag(channel.name)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
        }

        // DMs (blocked people's DMs are suppressed)
        let visibleDMs = appState.dmBuffers.filter { !appState.isBlocked(nick: $0.name) }
        if !visibleDMs.isEmpty {
            Section("Direct Messages") {
                ForEach(visibleDMs.sorted(by: { $0.lastActivity > $1.lastActivity })) { dm in
                    DMRow(dm: dm)
                        .tag(dm.name)
                        .listRowBackground(Color.clear)
                        .listRowSeparator(.hidden)
                }
            }
        }

        // P2P connections
        if !appState.p2pConnectedPeers.isEmpty {
            Section("P2P Direct") {
                ForEach(Array(appState.p2pConnectedPeers), id: \.self) { peerId in
                    Label {
                        Text(String(peerId.prefix(12)) + "…")
                            .font(.system(.body, design: .monospaced))
                    } icon: {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .foregroundStyle(Theme.success)
                    }
                    .tag("p2p:\(String(peerId.prefix(8)))")
                }
            }
        }
    }

    var body: some View {
        @Bindable var state = appState
        // In select mode the list drives a multi-selection Set (⌘/⇧-click
        // + highlight); otherwise it drives single-selection navigation. Same
        // section content feeds both so there's one source of truth.
        //
        // ScrollViewReader so the active conversation can be scrolled into
        // view. Without it the sidebar can sit scrolled anywhere while the
        // selected channel is off-screen — and because favorited channels are
        // lifted out of the alphabetical "Channels" list into "Favorites" at
        // the very top, hunting for a favorite alphabetically finds nothing.
        // That combination reads as "I'm not in #freeq, how do I join it?"
        ScrollViewReader { proxy in
            Group {
                if isSelecting {
                    List(selection: $selected) { listSections }
                } else {
                    List(selection: $state.activeChannel) { listSections }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .background(Theme.sidebarBackground)
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 0) {
                    if isSelecting { selectionBar }
                    Divider().overlay(Theme.borderSoft)
                    bottomBar
                }
            }
            .sheet(isPresented: $showStatusEditor) {
                StatusEditorSheet()
                    .environment(appState)
            }
            .onChange(of: appState.activeChannel) { _, newValue in
                if let ch = newValue {
                    reveal(ch, proxy)
                    appState.clearUnread(ch)
                    // Request DM history if no messages loaded yet. Guests skip
                    // it: guest DMs are never persisted server-side, so the
                    // request can only fail (ACCOUNT_REQUIRED noise).
                    if !ch.hasPrefix("#"), appState.authenticatedDID != nil {
                        if let dm = appState.dmBuffers.first(where: { $0.name.lowercased() == ch.lowercased() }),
                           dm.messages.isEmpty {
                            appState.requestHistory(channel: ch)
                        }
                    }
                }
            }
            // Channels arrive incrementally after connect, so the row for the
            // restored channel usually doesn't exist yet when `activeChannel`
            // is first set. Reveal it once, as soon as its row is real.
            .onChange(of: appState.channels.count) { _, _ in
                guard !didRevealActive, let ch = appState.activeChannel else { return }
                let exists = appState.channels.contains { $0.name.caseInsensitiveCompare(ch) == .orderedSame }
                    || appState.dmBuffers.contains { $0.name.caseInsensitiveCompare(ch) == .orderedSame }
                guard exists else { return }
                didRevealActive = true
                reveal(ch, proxy)
            }
        }
    }

    /// Scroll the sidebar so `id` (a channel/DM row id — both are their name)
    /// is visible. Centred so the surrounding section header is visible too,
    /// which is what tells you *why* a channel is where it is.
    private func reveal(_ id: String, _ proxy: ScrollViewProxy) {
        withAnimation(.easeOut(duration: 0.2)) {
            proxy.scrollTo(id, anchor: .center)
        }
    }

    // Bulk-action bar shown above the bottom bar while in select mode.
    @ViewBuilder
    private var selectionBar: some View {
        let allNames = selectableChannelNames
        let allSelected = !allNames.isEmpty && selectedChannels.count == allNames.count
        HStack(spacing: 10) {
            Button(allSelected ? "None" : "All") {
                selected = allSelected ? [] : Set(allNames)
            }
            .buttonStyle(.plain)
            .font(.caption.weight(.medium))
            .foregroundStyle(Theme.accent)

            Spacer()

            Text("\(selectedChannels.count) selected")
                .font(.caption)
                .foregroundStyle(Theme.textTertiary)

            Button(role: .destructive) {
                confirmLeave = true
            } label: {
                Label("Leave", systemImage: "rectangle.portrait.and.arrow.right")
                    .font(.caption.weight(.medium))
            }
            .buttonStyle(.borderless)
            .foregroundStyle(selectedChannels.isEmpty ? Theme.textTertiary : Theme.danger)
            .disabled(selectedChannels.isEmpty)

            Button("Done") { exitSelectMode() }
                .buttonStyle(.plain)
                .font(.caption.weight(.medium))
                .foregroundStyle(Theme.textSecondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Theme.surfaceElevated)
        .confirmationDialog(
            "Leave \(selectedChannels.count) channel\(selectedChannels.count == 1 ? "" : "s")?",
            isPresented: $confirmLeave,
            titleVisibility: .visible
        ) {
            Button("Leave \(selectedChannels.count)", role: .destructive) {
                appState.partChannels(selectedChannels)
                exitSelectMode()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(selectedChannels.joined(separator: ", "))
        }
    }

    @ViewBuilder
    private var bottomBar: some View {
        HStack(spacing: 8) {
            // User info
            if let did = appState.authenticatedDID {
                let isAway = appState.selfAwayReason != nil
                AvatarView(nick: appState.nick, size: 24)
                    .overlay(alignment: .bottomTrailing) {
                        Circle()
                            .fill(isAway ? Theme.warning : Theme.success)
                            .frame(width: 7, height: 7)
                            .overlay(Circle().strokeBorder(Theme.sidebarBackground, lineWidth: 1))
                    }
                VStack(alignment: .leading, spacing: 0) {
                    Text(appState.nick)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(Theme.textPrimary)
                        .lineLimit(1)
                    // A custom status shows verbatim; a plain away shows as "Away — X".
                    Text(appState.selfStatus
                        ?? appState.selfAwayReason.map { "Away — \($0)" }
                        ?? "Signed in")
                        .font(.caption2)
                        .foregroundStyle(isAway ? Theme.warning : Theme.textTertiary)
                        .lineLimit(1)
                }
                .help(isAway
                    ? "Away: \(appState.selfAwayReason ?? "") — signed in as \(did). Click to set a status."
                    : "Signed in as \(did). Click to set a status.")
                .contentShape(Rectangle())
                .onTapGesture { showStatusEditor = true }
                // A dot while this device's key is not published to the
                // account. Settings is a system scene here, so the account
                // row is the only always-visible place to say so.
                if appState.signingKeyUnpublished {
                    Circle()
                        .fill(Theme.warning)
                        .frame(width: 6, height: 6)
                }
            } else if appState.connectionState == .registered {
                Circle()
                    .fill(Theme.warning)
                    .frame(width: 8, height: 8)
                Text(appState.selfAwayReason != nil
                    ? "\(appState.nick) (guest · away)"
                    : "\(appState.nick) (guest)")
                    .font(.caption)
                    .foregroundStyle(Theme.textSecondary)
            } else {
                Circle()
                    .fill(Theme.textTertiary)
                    .frame(width: 8, height: 8)
                Text("Not connected")
                    .font(.caption)
                    .foregroundStyle(Theme.textSecondary)
            }
            Spacer()

            // P2P status
            if appState.isP2pActive {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.caption)
                    .foregroundStyle(Theme.success)
                    .help("iroh P2P: \(appState.p2pConnectedPeers.count) peers")
            }

            // Multi-select toggle (bulk-leave several channels at once)
            if !appState.channels.isEmpty {
                Button {
                    if isSelecting { exitSelectMode() } else { isSelecting = true }
                } label: {
                    Image(systemName: isSelecting ? "checkmark.circle.fill" : "checklist")
                        .foregroundStyle(isSelecting ? Theme.accent : Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help(isSelecting ? "Cancel selection" : "Select channels…")
            }

            // Join channel
            Button {
                appState.showJoinSheet = true
            } label: {
                Image(systemName: "plus.bubble")
            }
            .buttonStyle(.plain)
            .help("Join Channel (⌘J)")

            // User menu
            Menu {
                if appState.authenticatedDID != nil {
                    Button(appState.selfStatus == nil ? "Set Status…" : "Edit Status…") {
                        showStatusEditor = true
                    }
                    if appState.selfAwayReason == nil {
                        Button("Set Away") {
                            appState.setAway("AFK")
                        }
                    } else {
                        Button(appState.selfStatus == nil ? "Remove Away" : "Clear Status") {
                            appState.setAway(nil)
                        }
                    }
                    Divider()
                }
                Button("Disconnect") {
                    appState.disconnect()
                }
                if appState.authenticatedDID != nil {
                    Button("Logout", role: .destructive) {
                        appState.logout()
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .buttonStyle(.plain)
            .menuStyle(.borderlessButton)
            .frame(width: 20)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Theme.sidebarBackground)
    }
}

struct ChannelRow: View {
    @Environment(AppState.self) private var appState
    let channel: ChannelState
    /// When the sidebar is in multi-select mode, show a checkbox and drive the
    /// row highlight off `isSelected` instead of the active-channel state.
    var isSelecting: Bool = false
    var isSelected: Bool = false
    /// Enter multi-select mode from the row's context menu, pre-selecting this
    /// channel (the discoverable entry point alongside "Leave Channel").
    var onBeginSelect: ((String) -> Void)? = nil

    private var unread: Int {
        appState.unreadCounts[channel.name.lowercased()] ?? 0
    }

    private var mentions: Int {
        appState.mentionCounts[channel.name.lowercased()] ?? 0
    }

    private var isActive: Bool {
        appState.activeChannel?.lowercased() == channel.name.lowercased()
    }

    private var lastMessage: ChatMessage? {
        channel.messages.last(where: { !$0.from.isEmpty && !$0.isDeleted })
    }

    var body: some View {
        let highlighted = isSelecting ? isSelected : isActive
        HStack(spacing: 8) {
            if isSelecting {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 15))
                    .foregroundStyle(isSelected ? Theme.accent : Theme.textTertiary)
            }
        Label {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(channel.name.replacingOccurrences(of: "#", with: ""))
                        .lineLimit(1)
                        .font(.system(.body, weight: unread > 0 || isActive ? .semibold : .medium))
                        .foregroundStyle(isActive ? Theme.textPrimary : Theme.textSecondary)
                    Spacer()
                    if mentions > 0 {
                        Text("\(mentions)")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(Theme.danger))
                    } else if unread > 0 {
                        Circle()
                            .fill(Theme.accent)
                            .frame(width: 8, height: 8)
                    }
                }
                if let last = lastMessage {
                    Text("\(last.from): \(last.text)")
                        .font(.caption2)
                        .foregroundStyle(isActive ? Theme.textSecondary : Theme.textTertiary)
                        .lineLimit(1)
                }
            }
        } icon: {
            Image(systemName: channel.isEncrypted ? "lock.fill" : "number")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(channel.isEncrypted ? Theme.success : (isActive ? Theme.accent : Theme.textTertiary))
                .help(channel.isEncrypted ? "End-to-end encrypted channel" : "")
        }
        }  // end HStack (checkbox + row)
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(highlighted ? Theme.surfaceElevated : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(highlighted ? Theme.borderSoft : Color.clear, lineWidth: 1)
        )
        .contextMenu {
            Button(appState.favorites.contains(channel.name.lowercased()) ? "Unfavorite" : "Favorite") {
                appState.toggleFavorite(channel.name)
            }
            Menu("Notifications") {
                let current = appState.notifyLevel(channel.name)
                Button {
                    appState.setNotifyLevel(.all, for: channel.name)
                } label: {
                    Label("All messages", systemImage: current == .all ? "checkmark" : "")
                }
                Button {
                    appState.setNotifyLevel(.mentionsOnly, for: channel.name)
                } label: {
                    Label("Mentions only", systemImage: current == .mentionsOnly ? "checkmark" : "")
                }
                Button {
                    appState.setNotifyLevel(.muted, for: channel.name)
                } label: {
                    Label("Muted", systemImage: current == .muted ? "checkmark" : "")
                }
            }
            Divider()
            if let onBeginSelect {
                Button("Select Channels…") { onBeginSelect(channel.name) }
            }
            Button("Leave Channel") {
                appState.partChannel(channel.name)
            }
        }
        .opacity(appState.mutedChannels.contains(channel.name.lowercased()) ? 0.5 : 1)
    }
}

struct DMRow: View {
    @Environment(AppState.self) private var appState
    let dm: ChannelState

    /// The human name for this thread — a DID-keyed buffer resolves to the
    /// peer's nick (never renders raw); nick-keyed buffers pass through.
    private var displayNick: String {
        appState.displayNameForKey(dm.name)
    }

    private var isOnline: Bool {
        appState.isNickOnline(displayNick)
    }

    private var unread: Int {
        appState.unreadCounts[dm.name.lowercased()] ?? 0
    }

    private var profile: ProfileCache.Profile? {
        ProfileCache.shared.profile(for: displayNick)
    }

    private var isActive: Bool {
        appState.activeChannel?.lowercased() == dm.name.lowercased()
    }

    private var lastMessage: ChatMessage? {
        dm.messages.last(where: { !$0.isDeleted })
    }

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(profile?.displayName ?? displayNick)
                        .lineLimit(1)
                        .font(.system(.body, weight: unread > 0 || isActive ? .semibold : .medium))
                        .foregroundStyle(isActive ? Theme.textPrimary : Theme.textSecondary)

                    if appState.p2pDMActive.contains(dm.name.lowercased()) {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .font(.caption2)
                            .foregroundStyle(Theme.success)
                    }

                    Spacer()
                    if unread > 0 {
                        Text("\(unread)")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(Theme.danger))
                    }
                }
                if let last = lastMessage {
                    Text(last.text)
                        .font(.caption2)
                        .foregroundStyle(isActive ? Theme.textSecondary : Theme.textTertiary)
                        .lineLimit(1)
                }
            }
        } icon: {
            AvatarView(nick: displayNick, size: 22)
                .overlay(alignment: .bottomTrailing) {
                    Circle()
                        .fill(isOnline ? Theme.success : Theme.textTertiary.opacity(0.35))
                        .frame(width: 7, height: 7)
                        .overlay(Circle().strokeBorder(Theme.surface, lineWidth: 1))
                }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(isActive ? Theme.surfaceElevated : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(isActive ? Theme.borderSoft : Color.clear, lineWidth: 1)
        )
        .contextMenu {
            Button("Close DM") {
                appState.closeDM(dm.name)
            }
        }
    }
}
