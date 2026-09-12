import SwiftUI

struct ConnectView: View {
    @Environment(AppState.self) private var appState
    @State private var handle: String = ""
    @State private var guestNick: String = ""
    @State private var isLoggingIn = false

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            // Logo area
            VStack(spacing: 12) {
                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)

                Text("freeq")
                    .font(.system(size: 36, weight: .bold, design: .rounded))

                Text("IRC with AT Protocol identity")
                    .foregroundStyle(.secondary)
            }

            // AT Protocol Login
            VStack(spacing: 12) {
                Text("Sign in with your AT Protocol handle")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                TextField("handle (e.g. alice.bsky.social)", text: $handle)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 280)
                    .onSubmit { startLogin() }

                Button {
                    startLogin()
                } label: {
                    HStack {
                        if isLoggingIn {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "person.badge.key.fill")
                        }
                        Text("Sign In")
                    }
                    .frame(maxWidth: 280)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(handle.isEmpty || isLoggingIn)
            }

            // Divider
            HStack {
                Rectangle().fill(.separator).frame(height: 1)
                Text("or").font(.caption).foregroundStyle(.tertiary)
                Rectangle().fill(.separator).frame(height: 1)
            }
            .frame(width: 280)

            // Guest connect
            HStack(spacing: 8) {
                TextField("Nickname", text: $guestNick)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
                    .onSubmit { connectGuest() }

                Button("Connect as Guest") {
                    connectGuest()
                }
                .disabled(guestNick.isEmpty)
            }

            if let error = appState.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .frame(width: 300)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func startLogin() {
        guard !handle.isEmpty else { return }
        isLoggingIn = true
        appState.errorMessage = nil

        Task {
            do {
                let (brokerToken, session) = try await BrokerAuth.startOAuth(
                    brokerBase: appState.authBrokerBase,
                    handle: handle
                )
                // broker_token is only present on the standalone broker; it
                // drives reconnect (re-minting web tokens). The embedded
                // broker omits it, so persist only when we actually got one.
                appState.brokerToken = brokerToken
                if let brokerToken {
                    KeychainHelper.save(key: "brokerToken", value: brokerToken)
                }
                appState.pendingWebToken = session.token
                KeychainHelper.save(key: "did", value: session.did)
                // The handle the account signed in under. Settings needs it to
                // start a sign-in of its own — the broker's login resolves a
                // handle, and a DID will not do.
                if !session.handle.isEmpty {
                    UserDefaults.standard.set(session.handle, forKey: "freeq.handle")
                }
                appState.connect(nick: session.nick)
            } catch {
                appState.errorMessage = "Login failed: \(error.localizedDescription)"
            }
            isLoggingIn = false
        }
    }

    private func connectGuest() {
        // Validate up front so a typo (space, leading digit, dot in a
        // handle-like nick) surfaces a precise message instead of an
        // opaque server "Invalid nick" round-trip later.
        switch Validation.validateIrcNick(guestNick) {
        case .success(let cleaned):
            guestNick = cleaned
            appState.errorMessage = nil
            appState.connect(nick: cleaned)
        case .failure(let err):
            appState.errorMessage = Self.nickErrorMessage(err)
        }
    }

    static func nickErrorMessage(_ err: Validation.NickError) -> String {
        switch err {
        case .empty:
            return "Pick a nick."
        case .tooLong(let max):
            return "Nick can be at most \(max) characters."
        case .containsWhitespace:
            return "Nick can't contain spaces."
        case .startsWithDigit:
            return "Nick can't start with a digit."
        case .invalidCharacter(let scalar):
            return "“\(scalar)” isn't allowed in a nick. Use letters, digits, or _-[]\\{}^|."
        }
    }
}
