import Network
import Foundation

/// Monitors network connectivity and triggers reconnect when connection returns.
class NetworkMonitor: ObservableObject {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "NetworkMonitor")

    @Published var isConnected = true
    @Published var connectionType: NWInterface.InterfaceType?

    private weak var appState: AppState?
    private var wasDisconnected = false

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                let connected = path.status == .satisfied
                self?.isConnected = connected

                if path.usesInterfaceType(.wifi) {
                    self?.connectionType = .wifi
                } else if path.usesInterfaceType(.cellular) {
                    self?.connectionType = .cellular
                } else {
                    self?.connectionType = nil
                }

                // Auto-reconnect when network returns
                if connected && self?.wasDisconnected == true {
                    self?.wasDisconnected = false
                    self?.attemptReconnect()
                }

                if !connected {
                    self?.wasDisconnected = true
                }
            }
        }
        monitor.start(queue: queue)
    }

    func bind(to appState: AppState) {
        self.appState = appState
    }

    private func attemptReconnect() {
        guard let state = appState,
              state.connectionState == .disconnected,
              !state.nick.isEmpty else { return }

        // Delay slightly to let the network stabilize
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak state] in
            guard let state = state, state.connectionState == .disconnected else { return }
            // A saved session runs its one reconnect sequence now, through the
            // broker; a guest connects as before.
            if state.hasSavedSession {
                state.reconnectSavedSession(viaBroker: true)
            } else {
                state.connect(nick: state.nick)
            }
        }
    }

    deinit {
        monitor.cancel()
    }
}
