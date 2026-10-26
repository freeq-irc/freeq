import SwiftUI

/// User appearance override: follow the system (default), or pin light/dark.
enum AppearanceSetting: String, CaseIterable {
    case system, light, dark

    static var current: AppearanceSetting {
        AppearanceSetting(rawValue: UserDefaults.standard.string(forKey: "freeq.appearance") ?? "") ?? .system
    }

    /// Applies app-wide (main window, Settings scene, sheets, menus alike).
    func apply() {
        switch self {
        case .system: NSApp.appearance = nil
        case .light: NSApp.appearance = NSAppearance(named: .aqua)
        case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
        }
    }

    var label: String {
        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

@main
struct FreeqApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var appState = AppState()
    @State private var showOnboarding = !UserDefaults.standard.bool(forKey: "freeq.onboardingComplete")
    @AppStorage("freeq.appearance") private var appearanceRaw = "system"
    @Environment(\.scenePhase) private var scenePhase

    init() {
        JoinPartDisplay.migrateLegacySetting()
    }

    /// Menu item projected from the Command registry — same title,
    /// shortcut, availability, and handler the ⌘K palette uses.
    private func commandButton(_ id: String) -> some View {
        Button(CommandActions.title(id, appState)) {
            CommandActions.run(id, appState)
        }
        .keyboardShortcut(CommandActions.keyboardShortcut(id))
        .disabled(!CommandActions.isEnabled(id, appState))
    }

    var body: some Scene {
        WindowGroup {
            @Bindable var state = appState
            MainView()
                .environment(appState)
                .frame(minWidth: 700, minHeight: 400)
                .sheet(isPresented: $state.showQuickSwitcher) {
                    QuickSwitcher()
                        .environment(appState)
                }
                .sheet(isPresented: $state.showBookmarks) {
                    BookmarksPanel()
                        .environment(appState)
                }
                .sheet(isPresented: $state.showChannelList) {
                    ChannelListBrowser()
                        .environment(appState)
                }
                .sheet(isPresented: $showOnboarding) {
                    OnboardingView()
                }
                .sheet(isPresented: $state.showHelp) {
                    HelpView()
                }
                .sheet(isPresented: $state.showNewDM) {
                    NewDMSheet()
                        .environment(appState)
                }
                .onAppear {
                    AppearanceSetting.current.apply()
                    MetricKitReporter.shared.start()
                    QuickSendController.shared.installHotKey()
                    if appState.hasSavedSession && appState.connectionState == .disconnected {
                        appState.reconnectIfSaved()
                    }
                }
                .onChange(of: appearanceRaw) { _, _ in
                    AppearanceSetting.current.apply()
                }
                .onOpenURL { url in
                    // freeq://share?text=…&url=…&channel=… — from the Share
                    // Extension or any automation. Pre-fill the quick-send panel.
                    if let payload = ShareURL.parse(url) {
                        QuickSendController.shared.presentShare(payload)
                    }
                }
                .onChange(of: appState.activeChannel) { _, newValue in
                    updateWindowTitle(newValue)
                }
                .onChange(of: appState.totalUnread) { _, newValue in
                    NSApplication.shared.dockTile.badgeLabel = newValue > 0 ? "\(newValue)" : nil
                }
                .onChange(of: scenePhase) { _, phase in
                    // Regaining focus means the user is now looking at the
                    // open channel — clear its unread so the badge tracks
                    // reality (previously unread only cleared on channel
                    // switch, so a backgrounded-then-refocused window kept a
                    // stale count on the buffer already on screen).
                    if phase == .active, let channel = appState.activeChannel {
                        appState.clearUnread(channel)
                    }
                }
        }
        .commands {
            // Branded About panel (new dark-plate icon + version + credits)
            // replacing the default "About freeq" item.
            CommandGroup(replacing: .appInfo) {
                Button("About freeq") {
                    appDelegate.showAbout(nil)
                }
            }
            // All menu content projects from the Command registry
            // (CommandRegistry + CommandActions) — the ⌘K palette shows the
            // same commands, so the two can never drift.
            CommandGroup(after: .sidebar) {
                commandButton("view.toggleDetail")

                Divider()

                // Slack-compatible channel navigation muscle memory.
                commandButton("nav.prevChannel")
                commandButton("nav.nextChannel")
                commandButton("nav.prevUnread")
                commandButton("nav.nextUnread")

                Divider()

                // Jump to a favorite by number (⌃⌘1…9), matching the order
                // shown under the sidebar's Favorites header. The submenu
                // lists real channel names so the shortcuts are discoverable,
                // and rebuilds as favorites change.
                Menu("Go to Favorite") {
                    let favs = appState.favoriteChannels
                    if favs.isEmpty {
                        Button("No favorites yet") {}.disabled(true)
                    } else {
                        ForEach(Array(favs.prefix(9).enumerated()), id: \.element.id) { idx, ch in
                            Button(ch.name) { appState.switchToFavorite(idx) }
                                .keyboardShortcut(
                                    KeyEquivalent(Character("\(idx + 1)")),
                                    modifiers: [.command, .control]
                                )
                        }
                    }
                }
            }

            CommandGroup(replacing: .newItem) {
                commandButton("nav.quickSwitcher")
                commandButton("nav.newDM")
                commandButton("nav.search")
                commandButton("nav.bookmarks")
                commandButton("nav.browseChannels")
                commandButton("nav.joinChannel")

                Divider()

                ForEach(1...9, id: \.self) { i in
                    Button("Switch to Buffer \(i)") {
                        appState.switchToChannelByIndex(i - 1)
                    }
                    .keyboardShortcut(KeyEquivalent(Character("\(i)")), modifiers: .command)
                }
            }

            CommandMenu("Channel") {
                commandButton("channel.toggleFavorite")
                commandButton("channel.toggleMute")
                commandButton("channel.leave")

                Divider()

                commandButton("presence.toggleAway")
            }

            // In-call controls (Zoom's muscle memory: ⇧⌘M / ⇧⌘V / ⇧⌘S).
            CommandMenu("Call") {
                commandButton("call.toggleMute")
                commandButton("call.toggleCamera")
                commandButton("call.toggleScreen")

                Divider()

                commandButton("call.toggleExpand")
                commandButton("call.leave")
            }

            CommandGroup(replacing: .help) {
                commandButton("help.shortcuts")
                Button("IRC Commands (/help)") {
                    if let ch = appState.activeChannelState {
                        ch.appendIfNew(ChatMessage(
                            id: UUID().uuidString, from: "system",
                            text: "Type /help for a list of commands",
                            isAction: false, timestamp: Date(), replyTo: nil
                        ))
                    }
                }
            }
        }

        Settings {
            SettingsView()
                .environment(appState)
        }

        // Ambient presence: a persistent menu bar item so the call + unread
        // state live at the OS level and survive closing the window.
        MenuBarExtra {
            MenuBarView()
                .environment(appState)
        } label: {
            let unread = appState.totalUnread > 0
            let mention = appState.mentionCounts.values.contains { $0 > 0 }
            Image(systemName: MenuBarModel.iconName(
                inCall: appState.isInCall,
                muted: appState.isMuted,
                unread: unread,
                mention: mention
            ))
        }
    }

    private func updateWindowTitle(_ channel: String?) {
        // Resolve DID-keyed DM buffers to the peer's nick for the title.
        let title = channel.map { AppState.current?.displayNameForKey($0) ?? $0 }
        DispatchQueue.main.async {
            if let title {
                NSApplication.shared.mainWindow?.title = "\(title) — freeq"
            } else {
                NSApplication.shared.mainWindow?.title = "freeq"
            }
        }
    }
}
