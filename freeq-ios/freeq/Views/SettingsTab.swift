import SwiftUI

struct SettingsTab: View {
    @EnvironmentObject var appState: AppState
    @State private var showStatusEditor = false

    /// Start a sign-in that asks the account for permission to write this
    /// device's key records. The same link and the same in-app sheet the
    /// connect screen uses.
    private func publishKey(handle: String) {
        let encoded = handle.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? handle
        let returnTo = "\(ServerConfig.apiBaseUrl)/auth/mobile"
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        guard let url = URL(string:
            "\(appState.authBrokerBase)/auth/login?handle=\(encoded)&mobile=1&intent=enroll"
                + "&return_to=\(returnTo)") else { return }
        AuthSession.shared.start(loginURL: url) { callbackURL, _ in
            DispatchQueue.main.async {
                if let callbackURL { appState.handleAuthCallback(callbackURL) }
            }
        }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bgPrimary.ignoresSafeArea()

                List {
                    // Account
                    Section {
                        HStack(spacing: 12) {
                            UserAvatar(nick: appState.nick, size: 48)

                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 5) {
                                    Text(appState.nick)
                                        .font(.fqBody.weight(.semibold))
                                        .foregroundColor(Theme.textPrimary)

                                    if appState.authenticatedDID != nil {
                                        VerifiedBadge(size: 14)
                                    }
                                }

                                if let did = appState.authenticatedDID {
                                    Text(did)
                                        .font(.fqMonoCaption)
                                        .foregroundColor(Theme.textMuted)
                                        .lineLimit(1)
                                } else {
                                    Text("Guest")
                                        .font(.fqFootnote)
                                        .foregroundColor(Theme.textSecondary)
                                }
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)

                        // Custom status — freeq-native presence.
                        Button { showStatusEditor = true } label: {
                            HStack(spacing: 12) {
                                Image(systemName: appState.selfStatus == nil ? "face.smiling" : "circle.fill")
                                    .font(.system(size: 16))
                                    .foregroundColor(appState.selfStatus == nil ? Theme.textMuted : Theme.verify)
                                    .frame(width: 24)
                                Text(appState.selfStatus ?? "Set a status")
                                    .font(.fqSubheadline)
                                    .foregroundColor(appState.selfStatus == nil ? Theme.textSecondary : Theme.textPrimary)
                                    .lineLimit(1)
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(Theme.textMuted)
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)
                        // This device's signing key, while it is not on the
                        // account. Messages still send and still carry that
                        // key — the row is here to fix the one thing missing,
                        // and it goes away once the key is published.
                        if appState.signingKeyUnpublished {
                            HStack(spacing: 12) {
                                Image(systemName: "key.slash")
                                    .font(.system(size: 16))
                                    .foregroundColor(Theme.textMuted)
                                    .frame(width: 24)
                                Text("Key not published · this device")
                                    .font(.fqSubheadline)
                                    .foregroundColor(Theme.textPrimary)
                                Spacer()
                                // The broker's login resolves a handle, so the
                                // action is offered only where we know one.
                                if let handle = appState.accountHandle {
                                    Button("Publish key") { publishKey(handle: handle) }
                                        .font(.fqSubheadline.weight(.semibold))
                                        .foregroundColor(Theme.accent)
                                }
                            }
                            .listRowBackground(Theme.bgSecondary)
                        }
                    } header: {
                        Text("Account")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Appearance
                    Section {
                        Toggle(isOn: Binding(
                            get: { !appState.isDarkTheme },
                            set: { _ in appState.toggleTheme() }
                        )) {
                            Label("Light Theme", systemImage: "sun.max.fill")
                                .foregroundColor(Theme.textPrimary)
                        }
                        .tint(Theme.accent)
                        .listRowBackground(Theme.bgSecondary)
                    } header: {
                        Text("Appearance")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Audio — local speaker + mic test
                    Section {
                        NavigationLink {
                            AudioTestView()
                        } label: {
                            Label("Test Speaker & Microphone", systemImage: "waveform.circle")
                                .foregroundColor(Theme.textPrimary)
                        }
                        .listRowBackground(Theme.bgSecondary)
                    } header: {
                        Text("Audio")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Connection
                    Section {
                        NavigationLink {
                            BookmarksView()
                        } label: {
                            HStack {
                                Label("Saved Messages", systemImage: "bookmark.fill")
                                    .foregroundColor(Theme.textPrimary)
                                Spacer()
                                Text("\(appState.bookmarks.count)")
                                    .font(.fqFootnote)
                                    .foregroundColor(Theme.textSecondary)
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)
                    }

                    Section {
                        HStack {
                            Label("Server", systemImage: "server.rack")
                                .foregroundColor(Theme.textPrimary)
                            Spacer()
                            Text(appState.serverAddress)
                                .font(.fqFootnote)
                                .foregroundColor(Theme.textSecondary)
                        }
                        .listRowBackground(Theme.bgSecondary)

                        HStack {
                            Label("Status", systemImage: "circle.fill")
                                .foregroundColor(Theme.textPrimary)
                            Spacer()
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(statusColor)
                                    .frame(width: 8, height: 8)
                                Text(statusText)
                                    .font(.fqFootnote)
                                    .foregroundColor(Theme.textSecondary)
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)

                        HStack {
                            Label("Channels", systemImage: "number")
                                .foregroundColor(Theme.textPrimary)
                            Spacer()
                            Text("\(appState.channels.count)")
                                .font(.fqFootnote)
                                .foregroundColor(Theme.textSecondary)
                        }
                        .listRowBackground(Theme.bgSecondary)
                    } header: {
                        Text("Connection")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Safety
                    Section {
                        NavigationLink {
                            BlockedUsersView()
                        } label: {
                            HStack {
                                Label("Blocked", systemImage: "hand.raised")
                                    .foregroundColor(Theme.textPrimary)
                                Spacer()
                                if !appState.blockedNicks.isEmpty {
                                    Text("\(appState.blockedNicks.count)")
                                        .font(.fqFootnote)
                                        .foregroundColor(Theme.textSecondary)
                                }
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)

                        NavigationLink {
                            CommunityGuidelinesView()
                        } label: {
                            Label("Community Guidelines", systemImage: "checkmark.shield")
                                .foregroundColor(Theme.textPrimary)
                        }
                        .listRowBackground(Theme.bgSecondary)
                    } header: {
                        Text("Safety")
                            .foregroundColor(Theme.textMuted)
                    }

                    // About
                    Section {
                        HStack {
                            Label("Version", systemImage: "info.circle")
                                .foregroundColor(Theme.textPrimary)
                            Spacer()
                            Text("1.0.0")
                                .font(.fqFootnote)
                                .foregroundColor(Theme.textSecondary)
                        }
                        .listRowBackground(Theme.bgSecondary)

                        Link(destination: URL(string: "https://freeq.at")!) {
                            HStack {
                                Label("Website", systemImage: "globe")
                                    .foregroundColor(Theme.textPrimary)
                                Spacer()
                                Image(systemName: "arrow.up.right")
                                    .font(.system(size: 12))
                                    .foregroundColor(Theme.textMuted)
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)

                        Link(destination: URL(string: "https://github.com/freeq-irc/freeq")!) {
                            HStack {
                                Label("Source Code", systemImage: "chevron.left.forwardslash.chevron.right")
                                    .foregroundColor(Theme.textPrimary)
                                Spacer()
                                Image(systemName: "arrow.up.right")
                                    .font(.system(size: 12))
                                    .foregroundColor(Theme.textMuted)
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)
                    } header: {
                        Text("About")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Disconnect / Logout
                    Section {
                        Button(action: { appState.disconnect() }) {
                            HStack {
                                Spacer()
                                Text("Disconnect")
                                    .font(.fqCallout.weight(.medium))
                                    .foregroundColor(Theme.textSecondary)
                                Spacer()
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)

                        Button(action: { appState.logout() }) {
                            HStack {
                                Spacer()
                                Text("Log Out")
                                    .font(.fqCallout.weight(.medium))
                                    .foregroundColor(Theme.danger)
                                Spacer()
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)
                    }
                }
                .listStyle(.insetGrouped)
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
        .sheet(isPresented: $showStatusEditor) {
            StatusEditorSheet()
                .presentationDetents([.medium, .large])
        }
    }

    private var statusColor: Color {
        switch appState.connectionState {
        case .registered: return Theme.success
        case .connected, .connecting: return Theme.warning
        case .disconnected: return Theme.danger
        }
    }

    private var statusText: String {
        switch appState.connectionState {
        case .registered: return "Connected"
        case .connected: return "Registering..."
        case .connecting: return "Connecting..."
        case .disconnected: return "Disconnected"
        }
    }
}
