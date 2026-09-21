import SwiftUI

/// Root view. The decision is purely:
///   - `hasSavedSession` → MainTabView (always, with a banner if not connected)
///   - else                → ConnectView
///
/// We deliberately don't gate MainTabView on `connectionState` anymore.
/// Channels and DMs are hydrated from the on-disk cache (`flushBuffersToCache`),
/// so on cold launch the user sees their previous context instantly while the
/// network completes in the background. A small banner at the top shows the
/// connection status; if the connection comes back as `.registered`, the
/// banner dismisses itself.
///
/// The "Sign in with a different account" escape hatch lives in Settings →
/// Logout now, not as a 45-second cliff on the cold-launch spinner.
struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @AppStorage("freeq.onboardingComplete") private var onboardingComplete = false
    @State private var showOnboarding = false

    var body: some View {
        Group {
            // Show the main experience for either a persisted session
            // (cold-launch instant render from cache) or a live connection.
            if appState.hasSavedSession || appState.connectionState == .registered {
                // Regular width (iPad, landscape) → two-column split view;
                // compact (iPhone) → the bottom-tab layout, untouched.
                Group {
                    if horizontalSizeClass == .regular {
                        SplitRootView()
                    } else {
                        MainTabView()
                    }
                }
                    .safeAreaInset(edge: .top, spacing: 0) {
                        if appState.connectionState != .registered {
                            ConnectionStatusBanner()
                        }
                    }
                    .onAppear {
                        if appState.connectionState == .disconnected {
                            appState.reconnectSavedSession()
                        }
                    }
                    .transition(.opacity)
            } else {
                ConnectView()
                    .transition(.opacity.combined(with: .scale(scale: 1.02)))
            }
        }
        .animation(.easeInOut(duration: 0.35), value: appState.hasSavedSession)
        .preferredColorScheme(appState.isDarkTheme ? .dark : .light)
        // Command-driven sheets (keyboard shortcuts on iPad).
        .sheet(isPresented: $appState.showQuickSwitcher) { QuickSwitcherSheet() }
        .sheet(isPresented: $appState.showJoinSheet) { JoinChannelSheet() }
        .sheet(isPresented: $appState.showNewDMSheet) { NewDMSheet() }
        .sheet(isPresented: $appState.showSearchSheet) { SearchSheet() }
        .sheet(isPresented: $appState.showShortcutsHelp) { ShortcutsHelpSheet() }
        .sheet(isPresented: $showOnboarding) {
            OnboardingSheet { onboardingComplete = true }
        }
        .onAppear { maybeShowOnboarding() }
        .onChange(of: appState.connectionState) { maybeShowOnboarding() }
        .onChange(of: appState.hasSavedSession) { maybeShowOnboarding() }
    }

    /// First run: greet once, as soon as the main experience is reachable
    /// (saved session on cold launch, or a fresh registration).
    private func maybeShowOnboarding() {
        guard !onboardingComplete, !showOnboarding,
              appState.hasSavedSession || appState.connectionState == .registered
        else { return }
        showOnboarding = true
    }
}

/// Compact status pill that sits in the top safe-area inset when the
/// connection isn't fully `.registered`.
///
/// We deliberately hide the banner for a short grace period at start —
/// a healthy cold-launch reconnect (broker /session round-trip + WS
/// dial + SASL + RPL_WELCOME) completes in 1–3 s on a normal network,
/// and flashing "Reconnecting…" for that long is alarming for a state
/// that's actually fine. If we sail past the grace and still aren't
/// `.registered`, then the banner fades in and the user gets accurate
/// progress; if registration completes inside the grace, the banner
/// never appears at all.
struct ConnectionStatusBanner: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var networkMonitor: NetworkMonitor
    @State private var elapsed: Int = 0
    @State private var visible: Bool = false
    @State private var timer: Timer? = nil
    @State private var graceTimer: Timer? = nil

    /// Seconds we suppress the banner at start so quick reconnects are
    /// invisible. Tuned so a normal launch never shows it.
    private static let initialGraceSeconds: TimeInterval = 4

    /// After this many seconds of failed/slow connection, surface a
    /// tappable "Sign in again" affordance — the user is stuck in
    /// retry-loop territory and deserves an escape hatch instead of
    /// staring at "Still trying…" forever.
    private static let escapeHatchSeconds: Int = 20

    var body: some View {
        Group {
            if visible {
                HStack(spacing: 8) {
                    statusIcon
                    Text(statusText)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(Theme.textMuted)
                        .lineLimit(1)
                    Spacer()
                    if showEscapeHatch {
                        Button("Sign in again") {
                            appState.logout()
                        }
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(Theme.accent)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Theme.bgSecondary)
                .overlay(
                    Rectangle()
                        .frame(height: 0.5)
                        .foregroundColor(Theme.textMuted.opacity(0.2)),
                    alignment: .bottom
                )
                .transition(.move(edge: .top).combined(with: .opacity))
            } else {
                EmptyView()
            }
        }
        .animation(.easeInOut(duration: 0.2), value: visible)
        .onAppear {
            startTimer()
            startGraceTimer()
        }
        .onDisappear {
            stopTimer()
            stopGraceTimer()
        }
        .onChange(of: appState.reconnectAttempt) { _, _ in
            elapsed = 0
        }
        .onChange(of: appState.connectionState) { _, newState in
            if newState == .registered {
                // Reset for a future disconnect — next time we drop, we
                // should grant another grace period before showing.
                visible = false
                stopGraceTimer()
                elapsed = 0
            } else if visible == false && newState != .registered {
                // We were registered, just dropped. Re-grant the grace
                // period so a quick blip doesn't flash the banner.
                startGraceTimer()
            }
        }
    }

    private var showEscapeHatch: Bool {
        (appState.reconnecting || appState.connectionState == .disconnected) && elapsed >= Self.escapeHatchSeconds
    }

    private var statusIcon: some View {
        Group {
            // One steady spinner for a whole reconnect sequence, as in the chat bar.
            if appState.reconnecting {
                ProgressView().controlSize(.mini).tint(Theme.accent)
            } else {
            switch appState.connectionState {
            case .disconnected:
                if !networkMonitor.isConnected {
                    Image(systemName: "wifi.slash")
                        .foregroundColor(Theme.textMuted)
                } else {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .foregroundColor(Theme.accent)
                }
            case .connecting, .connected:
                ProgressView().controlSize(.mini).tint(Theme.accent)
            case .registered:
                EmptyView()
            }
            }
        }
        .frame(width: 14, height: 14)
    }

    private var statusText: String {
        // A reconnect sequence reads as one state, not one per attempt.
        switch appState.reconnecting ? .disconnected : appState.connectionState {
        case .disconnected:
            if !networkMonitor.isConnected { return "Offline — messages will sync when you reconnect" }
            return elapsed < 12 ? "Signing in…" : "Still trying — network looks slow"
        case .connecting:
            return elapsed < 12 ? "Signing in…" : "Still signing in…"
        case .connected:
            return "Almost there…"
        case .registered:
            return ""
        }
    }

    private func startGraceTimer() {
        stopGraceTimer()
        visible = false
        let t = Timer.scheduledTimer(withTimeInterval: Self.initialGraceSeconds, repeats: false) { _ in
            // After the grace, only reveal if we still aren't registered.
            if appState.connectionState != .registered {
                visible = true
            }
        }
        graceTimer = t
    }

    private func stopGraceTimer() {
        graceTimer?.invalidate()
        graceTimer = nil
    }

    private func startTimer() {
        elapsed = 0
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            elapsed += 1
        }
    }

    private func stopTimer() {
        timer?.invalidate()
        timer = nil
    }
}
