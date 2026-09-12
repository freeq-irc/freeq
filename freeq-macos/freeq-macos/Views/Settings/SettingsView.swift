import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        TabView {
            GeneralSettings()
                .environment(appState)
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            ConnectionSettings()
                .environment(appState)
                .tabItem {
                    Label("Connection", systemImage: "network")
                }

            AudioSettings()
                .tabItem {
                    Label("Audio", systemImage: "waveform.circle")
                }

            P2pSettings()
                .environment(appState)
                .tabItem {
                    Label("P2P / iroh", systemImage: "point.3.connected.trianglepath.dotted")
                }

            SafetySettings()
                .environment(appState)
                .tabItem {
                    Label("Safety", systemImage: "hand.raised")
                }

            ShortcutsSettings()
                .tabItem {
                    Label("Shortcuts", systemImage: "keyboard")
                }
        }
        .frame(width: 480, height: 340)
    }
}

struct GeneralSettings: View {
    @Environment(AppState.self) private var appState
    @AppStorage("freeq.showJoinPart") private var showJoinPart = true
    @AppStorage("freeq.notificationsEnabled") private var notificationsEnabled = true
    @AppStorage("freeq.notifyAllMessages") private var notifyAllMessages = false
    @AppStorage("freeq.compactMode") private var compactMode = false
    @AppStorage("freeq.soundsEnabled") private var soundsEnabled = true
    @AppStorage("freeq.appearance") private var appearanceRaw = "system"
    @AppStorage("freeq.useLegacyMessageList") private var useLegacyMessageList = false

    var body: some View {
        Form {
            Section("Appearance") {
                Picker("Theme", selection: $appearanceRaw) {
                    ForEach(AppearanceSetting.allCases, id: \.rawValue) { setting in
                        Text(setting.label).tag(setting.rawValue)
                    }
                }
                .pickerStyle(.segmented)
                Toggle("Compact message display", isOn: $compactMode)
                Toggle("Show join/part/quit messages", isOn: $showJoinPart)
            }
            Section("Notifications") {
                Toggle("Enable notifications", isOn: $notificationsEnabled)
                Toggle("Notify for all channel messages", isOn: $notifyAllMessages)
                    .disabled(!notificationsEnabled)
                Toggle("Sound effects", isOn: $soundsEnabled)
                Text(notifyAllMessages
                     ? "Notifications fire for mentions, DMs, all channel messages, and call invites (only when the app is in the background or the channel isn't on screen). DMs and mentions are marked time-sensitive so an allowed Focus can let them through."
                     : "Notifications fire for mentions, DMs, and call invites. Enable the option above to notify for all channel activity too. Set a per-channel level (all / mentions only / muted) by right-clicking a channel in the sidebar.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Auto-join Channels") {
                Text(appState.autoJoinChannels.joined(separator: ", "))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Section("Advanced") {
                Toggle("Use legacy message list (debug)", isOn: $useLegacyMessageList)
                Text("The default list is AppKit-backed (NSTableView) for smooth "
                     + "scrolling and streaming edits. Enable this to fall back to "
                     + "the older SwiftUI list for comparison.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

struct ConnectionSettings: View {
    @Environment(AppState.self) private var appState
    @State private var newAutoJoin = ""

    var body: some View {
        Form {
            Section {
                if appState.autoJoinChannels.isEmpty {
                    Text("No channels — you'll only join what you open.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(appState.autoJoinChannels, id: \.self) { ch in
                        HStack {
                            Text(ch).font(.body.monospaced())
                            Spacer()
                            Button {
                                appState.removeAutoJoin(ch)
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.red)
                            }
                            .buttonStyle(.borderless)
                            .help("Remove from auto-join (won't rejoin on connect)")
                        }
                    }
                }
                HStack {
                    TextField("#channel", text: $newAutoJoin)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(addAutoJoin)
                    Button("Add", action: addAutoJoin)
                        .disabled(newAutoJoin.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: {
                Text("Auto-join channels")
            } footer: {
                Text("These are rejoined every time you connect. Channels are added here automatically when you join them — remove any you don't want to keep rejoining.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Server") {
                LabeledContent("Address") {
                    Text(appState.serverAddress)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                }
                LabeledContent("Transport") {
                    switch appState.transportType {
                    case .iroh:
                        Label("iroh QUIC", systemImage: "bolt.fill")
                            .foregroundStyle(.green)
                    case .tls:
                        Label("TLS", systemImage: "lock.fill")
                            .foregroundStyle(.green)
                    case .tcp:
                        Label("TCP", systemImage: "network")
                            .foregroundStyle(.orange)
                    }
                }
                LabeledContent("Status") {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(statusColor)
                            .frame(width: 8, height: 8)
                        Text(statusText)
                    }
                }
            }
            Section("Identity") {
                LabeledContent("Nick") {
                    Text(appState.nick.isEmpty ? "—" : appState.nick)
                }
                LabeledContent("DID") {
                    if let did = appState.authenticatedDID {
                        Text(did)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    } else {
                        Text("Not authenticated")
                            .foregroundStyle(.secondary)
                    }
                }
                // This device's signing key, while it is not on the account.
                // Messages still send and still carry that key — the row is
                // here to fix the one thing missing, and it goes away once the
                // key is published.
                if appState.signingKeyUnpublished {
                    HStack {
                        Text("Key not published · this device")
                        Spacer()
                        // The broker's login resolves a handle, so the action
                        // is offered only where we know one.
                        if let handle = appState.accountHandle {
                            Button("Publish key") { publishKey(handle: handle) }
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    /// Start a sign-in that asks the account for permission to write this
    /// device's key records. The same flow the connect screen runs, whose link
    /// now carries `intent=enroll`.
    private func publishKey(handle: String) {
        Task {
            do {
                let (brokerToken, session) = try await BrokerAuth.startOAuth(
                    brokerBase: appState.authBrokerBase,
                    handle: handle
                )
                appState.brokerToken = brokerToken
                if let brokerToken {
                    KeychainHelper.save(key: "brokerToken", value: brokerToken)
                }
                appState.pendingWebToken = session.token
                appState.connect(nick: session.nick)
            } catch {
                appState.errorMessage = "Login failed: \(error.localizedDescription)"
            }
        }
    }

    private func addAutoJoin() {
        let ch = newAutoJoin.trimmingCharacters(in: .whitespaces)
        guard !ch.isEmpty else { return }
        appState.addAutoJoin(ch)
        newAutoJoin = ""
    }

    private var statusColor: Color {
        switch appState.connectionState {
        case .registered: .green
        case .connected: .yellow
        case .connecting: .orange
        case .disconnected: .red
        }
    }

    private var statusText: String {
        switch appState.connectionState {
        case .registered: "Registered"
        case .connected: "Connected"
        case .connecting: "Connecting…"
        case .disconnected: "Disconnected"
        }
    }
}

struct P2pSettings: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        Form {
            Section("End-to-End Encryption") {
                LabeledContent("Status") {
                    if E2eeManager.shared.isInitialized {
                        Label("Initialized", systemImage: "lock.shield.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Not initialized", systemImage: "lock.open")
                            .foregroundStyle(.secondary)
                    }
                }
                if let pubKey = E2eeManager.shared.publicKey {
                    LabeledContent("Identity Key") {
                        Text(String(pubKey.prefix(20)) + "…")
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                Text("E2EE encrypts DMs end-to-end. Both users must have E2EE enabled.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if !E2eeManager.shared.isInitialized {
                    Button("Enable E2EE") {
                        do {
                            try E2eeManager.shared.initialize()
                        } catch {
                            Log.auth.error("E2EE init failed: \(error.localizedDescription)")
                        }
                    }
                }

                Text("Active sessions: \(E2eeManager.shared.sessions.count)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("iroh P2P") {
                LabeledContent("Status") {
                    if appState.isP2pActive {
                        Label("Active", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Text("Inactive")
                            .foregroundStyle(.secondary)
                    }
                }

                if let id = appState.p2pEndpointId {
                    LabeledContent("Endpoint ID") {
                        HStack {
                            Text(id)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                                .lineLimit(1)
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(id, forType: .string)
                            } label: {
                                Image(systemName: "doc.on.doc")
                                    .font(.caption)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                LabeledContent("Connected Peers") {
                    Text("\(appState.p2pConnectedPeers.count)")
                }

                if !appState.isP2pActive {
                    Button("Start P2P") {
                        appState.startP2p()
                    }
                } else {
                    Button("Stop P2P") {
                        appState.shutdownP2p()
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}

struct ShortcutsSettings: View {
    var body: some View {
        Form {
            Section("Navigation") {
                shortcutRow("Quick Switcher", "⌘K")
                shortcutRow("Join Channel", "⌘J")
                shortcutRow("Toggle Detail Panel", "⇧⌘D")
                shortcutRow("Switch to Buffer 1-9", "⌘1–9")
                shortcutRow("Previous / Next Channel", "⌥↑ / ⌥↓")
                shortcutRow("Previous / Next Unread", "⌥⇧↑ / ⌥⇧↓")
            }
            Section("Compose") {
                shortcutRow("Send Message", "↩")
                shortcutRow("New Line", "⇧↩")
                shortcutRow("Edit Last Message", "↑ (empty input)")
                shortcutRow("Input History", "⌘↑ / ⌘↓")
                shortcutRow("Tab-complete Nick", "⇥")
                shortcutRow("Cancel Edit/Reply", "⎋")
            }
        }
        .formStyle(.grouped)
    }

    private func shortcutRow(_ action: String, _ key: String) -> some View {
        HStack {
            Text(action)
            Spacer()
            Text(key)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: 4).fill(Color(nsColor: .quaternaryLabelColor)))
        }
    }
}
