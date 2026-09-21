import SwiftUI

/// Root view after login — WhatsApp/Telegram-style bottom tab navigation.
struct MainTabView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var networkMonitor: NetworkMonitor
    @State private var selectedTab = 0

    var body: some View {
        ZStack {
            TabView(selection: $selectedTab) {
                ChatsTab(mode: .channels)
                    .tabItem {
                        Image(systemName: "number")
                        Text("Channels")
                    }
                    .tag(0)
                    .badge(channelUnread)

                ChatsTab(mode: .dms)
                    .tabItem {
                        Image(systemName: "bubble.left.and.bubble.right.fill")
                        Text("DMs")
                    }
                    .tag(1)
                    .badge(dmUnread)

                DiscoverTab()
                    .tabItem {
                        Image(systemName: "magnifyingglass")
                        Text("Discover")
                    }
                    .tag(2)

                SettingsTab()
                    .tabItem {
                        Image(systemName: "gear")
                        Text("Settings")
                    }
                    .tag(3)
                    // A dot while this device's key is not published to the
                    // account — Settings is where it gets fixed.
                    .badge(appState.signingKeyUnpublished ? Text("●") : nil)
            }
            .tint(Theme.accent)
            .onChange(of: selectedTab) {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }

            // Image lightbox overlay
            if let url = appState.lightboxURL {
                ImageLightbox(url: url)
                    .transition(.opacity)
                    .zIndex(100)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: appState.lightboxURL != nil)
        .onChange(of: appState.pendingDMNick) {
            if appState.pendingDMNick != nil {
                selectedTab = 1 // Switch to DMs tab so ChatsTab(.dms) consumes it
            }
        }
        .withToast()
        .preferredColorScheme(.dark)
    }

    /// Unread counts split per pane. DM buffers are keyed by peer nick (no
    /// prefix); channels are keyed by `#…` (or `&…` for local-only channels).
    private var channelUnread: Int {
        appState.unreadCounts
            .filter { $0.key.hasPrefix("#") || $0.key.hasPrefix("&") }
            .values
            .reduce(0, +)
    }

    private var dmUnread: Int {
        appState.unreadCounts
            .filter { !$0.key.hasPrefix("#") && !$0.key.hasPrefix("&") }
            .values
            .reduce(0, +)
    }
}
