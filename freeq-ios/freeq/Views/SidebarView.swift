import SwiftUI

struct SidebarView: View {
    @EnvironmentObject var appState: AppState
    @Binding var showingSidebar: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack(spacing: 10) {
                Image("FreeqLogo")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 32, height: 32)
                    .clipShape(RoundedRectangle(cornerRadius: 8))

                Text("freeq")
                    .font(.system(size: 20, weight: .bold, design: .rounded))
                    .foregroundColor(Theme.accent)

                Spacer()

                // Connection status dot
                Circle()
                    .fill(statusColor)
                    .frame(width: 8, height: 8)
            }
            .padding(.horizontal, 16)
            .frame(height: 56)
            .background(Theme.bgSecondary)

            Rectangle()
                .fill(Theme.border)
                .frame(height: 1)

            // Content
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    // Channels — alphabetical, case-insensitive. Matches
                    // ChatsTab so the same room is always in the same place
                    // regardless of which view the user is in.
                    let sortedChannels = appState.channels.sorted {
                        $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                    }
                    sectionHeader("CHANNELS", count: sortedChannels.count)

                    ForEach(sortedChannels) { channel in
                        channelRow(channel)
                    }

                    // DMs — most recently active first. Mirrors ChatsTab.
                    if !appState.dmBuffers.isEmpty {
                        let sortedDMs = appState.dmBuffers.sorted { $0.lastActivity > $1.lastActivity }
                        sectionHeader("DIRECT MESSAGES", count: sortedDMs.count)
                            .padding(.top, 12)

                        ForEach(sortedDMs) { dm in
                            dmRow(dm)
                        }
                    }
                }
                .padding(.vertical, 8)
            }

            Rectangle()
                .fill(Theme.border)
                .frame(height: 1)

            // User footer
            HStack(spacing: 12) {
                // Avatar
                ZStack {
                    Circle()
                        .fill(Theme.nickColor(for: appState.nick).opacity(0.2))
                        .frame(width: 36, height: 36)
                    Text(String(appState.nick.prefix(1)).uppercased())
                        .font(.fqFootnote.weight(.bold))
                        .foregroundColor(Theme.nickColor(for: appState.nick))
                }

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        Text(appState.nick)
                            .font(.fqFootnote.weight(.semibold))
                            .foregroundColor(Theme.textPrimary)
                            .lineLimit(1)

                        // Only an AT Protocol identity earns the seal
                        // (IdentityClaim rule); a self-issued did:key does not.
                        if claimForPerson(input: PersonClaimInput(
                            binding: appState.authenticatedDID,
                            seenOnlyViaPeer: false,
                            viaPeerOrigin: nil,
                            viaPeerHadAccount: false,
                            lookup: .notAsked
                        )).showsMark {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.system(size: 10))
                                .foregroundColor(Theme.accent)
                        }
                    }

                    Text(appState.authenticatedDID ?? "Guest")
                        .font(.fqCaption2)
                        .foregroundColor(Theme.textMuted)
                        .lineLimit(1)
                }

                Spacer()

                // Settings / disconnect
                Menu {
                    Button(role: .destructive, action: {
                        appState.disconnect()
                        showingSidebar = false
                    }) {
                        Label("Disconnect", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                } label: {
                    Image(systemName: "ellipsis")
                        .font(.system(size: 16))
                        .foregroundColor(Theme.textMuted)
                        .frame(width: 32, height: 32)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Theme.bgSecondary)
        }
        .background(Theme.bgPrimary)
    }

    private var statusColor: Color {
        switch appState.connectionState {
        case .registered: return Theme.success
        case .connected, .connecting: return Theme.warning
        case .disconnected: return Theme.danger
        }
    }

    private func sectionHeader(_ title: String, count: Int) -> some View {
        HStack {
            Text(title)
                .font(.fqCaption2.weight(.bold))
                .foregroundColor(Theme.textMuted)
                .kerning(0.8)
            Spacer()
            Text("\(count)")
                .font(.fqCaption2.weight(.medium))
                .foregroundColor(Theme.textMuted)
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
        .padding(.bottom, 4)
    }

    private func channelRow(_ channel: ChannelState) -> some View {
        let isActive = appState.activeChannel == channel.name

        return Button(action: {
            appState.activeChannel = channel.name
            showingSidebar = false
        }) {
            HStack(spacing: 8) {
                Text("#")
                    .font(.fqMono.weight(.medium))
                    .foregroundColor(isActive ? Theme.accent : Theme.textMuted)
                    .frame(width: 20)

                Text(String(channel.name.dropFirst()))
                    .font(.fqSubheadline.weight(isActive ? .semibold : .regular))
                    .foregroundColor(isActive ? Theme.textPrimary : Theme.textSecondary)
                    .lineLimit(1)

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
                } else if !channel.members.isEmpty {
                    Text("\(channel.uniqueMemberCount)")
                        .font(.fqCaption2)
                        .foregroundColor(Theme.textMuted)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Theme.bgTertiary)
                        .cornerRadius(4)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(isActive ? Theme.accent.opacity(0.12) : Color.clear)
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 4)
        .contextMenu {
            Button {
                appState.markRead(channel.name)
            } label: {
                Label("Mark as Read", systemImage: "checkmark.circle")
            }
            Button(role: .destructive) {
                appState.partChannel(channel.name)
            } label: {
                Label("Leave Channel", systemImage: "arrow.right.square")
            }
        }
    }

    private func dmRow(_ dm: ChannelState) -> some View {
        let isActive = appState.activeChannel == dm.name
        // Buffer key may be a DID — render the peer's nick.
        let displayNick = appState.displayNameForKey(dm.name)

        return Button(action: {
            appState.activeChannel = dm.name
            showingSidebar = false
        }) {
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(Theme.nickColor(for: displayNick).opacity(0.2))
                        .frame(width: 28, height: 28)
                    Text(String(displayNick.prefix(1)).uppercased())
                        .font(.fqCaption2.weight(.bold))
                        .foregroundColor(Theme.nickColor(for: displayNick))
                }

                Text(displayNick)
                    .font(.fqSubheadline.weight(isActive ? .semibold : .regular))
                    .foregroundColor(isActive ? Theme.textPrimary : Theme.textSecondary)
                    .lineLimit(1)

                Spacer()

                let unread = appState.unreadCounts[dm.name] ?? 0
                if unread > 0 {
                    Text("\(unread)")
                        .font(.fqCaption2.weight(.bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Theme.accent)
                        .cornerRadius(10)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(isActive ? Theme.accent.opacity(0.12) : Color.clear)
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 4)
        .contextMenu {
            Button {
                appState.markRead(dm.name)
            } label: {
                Label("Mark as Read", systemImage: "checkmark.circle")
            }
            Button(role: .destructive) {
                appState.closeDM(dm.name)
                if appState.activeChannel == dm.name {
                    appState.activeChannel = appState.channels.first?.name
                }
            } label: {
                Label("Close DM", systemImage: "xmark.circle")
            }
        }
    }
}
