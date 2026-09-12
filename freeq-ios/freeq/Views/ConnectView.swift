import SwiftUI

struct ConnectView: View {
    @EnvironmentObject var appState: AppState
    @State private var handle: String = UserDefaults.standard.string(forKey: "freeq.handle") ?? ""
    @State private var loading = false
    @State private var error: String? = nil
    @State private var showGuestLogin = false
    @State private var guestNick: String = ""
    @State private var guestServer: String = ServerConfig.ircServer
    @FocusState private var handleFocused: Bool
    @FocusState private var nickFocused: Bool

    private var keyboardActive: Bool { handleFocused || nickFocused }

    var body: some View {
        ZStack {
            // Background — cool graphite with a signal glow blooming from the top.
            Theme.bgPrimary.ignoresSafeArea()
            RadialGradient(
                colors: [Theme.accent.opacity(0.18), Theme.iris.opacity(0.06), .clear],
                center: .top, startRadius: 0, endRadius: 460
            )
            .ignoresSafeArea()

            // Faint protocol grid texture
            GeometryReader { geo in
                Path { path in
                    let spacing: CGFloat = 40
                    for x in stride(from: 0, through: geo.size.width, by: spacing) {
                        path.move(to: CGPoint(x: x, y: 0))
                        path.addLine(to: CGPoint(x: x, y: geo.size.height))
                    }
                    for y in stride(from: 0, through: geo.size.height, by: spacing) {
                        path.move(to: CGPoint(x: 0, y: y))
                        path.addLine(to: CGPoint(x: geo.size.width, y: y))
                    }
                }
                .stroke(Color.white.opacity(0.02), lineWidth: 0.5)
            }
            .ignoresSafeArea()

            ScrollViewReader { scrollProxy in
                ScrollView {
                    VStack(spacing: 0) {
                        Spacer(minLength: keyboardActive ? 20 : 60)

                        // Logo — shrinks and text fades when keyboard is up
                        VStack(spacing: keyboardActive ? 8 : 16) {
                            ZStack {
                                Circle()
                                    .fill(Theme.accent.opacity(0.15))
                                    .frame(width: keyboardActive ? 70 : 140, height: keyboardActive ? 70 : 140)
                                    .blur(radius: keyboardActive ? 15 : 30)

                                Image("FreeqLogo")
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: keyboardActive ? 48 : 100, height: keyboardActive ? 48 : 100)
                                    .shadow(color: Theme.accent.opacity(0.4), radius: keyboardActive ? 10 : 20)
                            }

                            VStack(spacing: 6) {
                                Text("freeq")
                                    .font(.system(size: keyboardActive ? 20 : 36, weight: .bold, design: .rounded))
                                    .foregroundColor(Theme.textPrimary)

                                Text("Decentralized chat")
                                    .font(.fqSubheadline)
                                    .foregroundColor(Theme.textSecondary)
                                    .opacity(keyboardActive ? 0 : 1)
                                    .frame(height: keyboardActive ? 0 : nil)
                                    .clipped()
                            }
                        }
                        .animation(.easeInOut(duration: 0.3), value: keyboardActive)
                        .padding(.bottom, keyboardActive ? 16 : 40)

                        // Value prop — what freeq is, for a first-timer. Collapses
                        // out of the way once they start typing.
                        if !keyboardActive && !showGuestLogin {
                            VStack(spacing: 14) {
                                valueRow(icon: "checkmark.seal.fill", tint: Theme.verify,
                                         title: "Verified identity",
                                         detail: "Every message is provably from a real person.")
                                valueRow(icon: "point.3.filled.connected.trianglepath.dotted", tint: Theme.accent,
                                         title: "Bring your graph",
                                         detail: "Your Bluesky follows come with you.")
                                valueRow(icon: "bolt.horizontal.fill", tint: Theme.iris,
                                         title: "Open by design",
                                         detail: "AT Protocol native. IRC-compatible. Open source.")
                            }
                            .padding(.horizontal, 32)
                            .padding(.bottom, 32)
                            .transition(.opacity.combined(with: .move(edge: .top)))
                        }

                        if !showGuestLogin {
                            // ── Primary: Bluesky Login ──
                            VStack(spacing: 20) {
                                // Handle input
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("BLUESKY HANDLE")
                                        .font(.fqCaption2.weight(.bold))
                                        .foregroundColor(Theme.textMuted)
                                        .kerning(1)

                                    HStack(spacing: 10) {
                                        Text("@")
                                            .font(.fqBody.weight(.medium))
                                            .foregroundColor(Theme.textMuted)

                                        TextField("", text: $handle, prompt: Text("yourname.bsky.social").foregroundColor(Theme.textMuted))
                                            .foregroundColor(Theme.textPrimary)
                                            .font(.fqCallout)
                                            .autocapitalization(.none)
                                            .disableAutocorrection(true)
                                            .keyboardType(.URL)
                                            .textContentType(.username)
                                            .focused($handleFocused)
                                            .submitLabel(.go)
                                            .onSubmit { startLogin() }
                                    }
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 12)
                                    .background(Theme.bgPrimary)
                                    .cornerRadius(10)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 10)
                                            .stroke(handleFocused ? Theme.accent : Theme.border, lineWidth: 1)
                                    )
                                    .id("handleField")
                                }

                                // Error
                                if let error = error {
                                    errorRow(error)
                                }

                                if let error = appState.errorMessage {
                                    errorRow(error)
                                }

                                // Sign in button
                                Button(action: startLogin) {
                                    HStack(spacing: 8) {
                                        if loading || appState.connectionState == .connecting {
                                            ProgressView().tint(Color(hex: "04121a")).scaleEffect(0.85)
                                        } else {
                                            Image(systemName: "person.badge.key.fill")
                                                .font(.system(size: 14))
                                        }
                                        Text(loading ? "Authenticating..." : appState.connectionState == .connecting ? "Connecting..." : "Sign in with Bluesky")
                                            .font(.fqCallout.weight(.semibold))
                                    }
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 15)
                                    .background(
                                        handle.isEmpty || loading
                                            ? AnyShapeStyle(Theme.textMuted.opacity(0.25))
                                            : AnyShapeStyle(Theme.signalGradient)
                                    )
                                    .foregroundColor(Color(hex: "04121a"))
                                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                    .shadow(color: handle.isEmpty ? .clear : Theme.accent.opacity(0.35), radius: 12, y: 4)
                                }
                                .disabled(handle.isEmpty || loading || appState.connectionState == .connecting)
                            }
                            .padding(24)
                            .glassCard()
                            .padding(.horizontal, 24)

                            // Guest option
                            Button(action: { withAnimation { showGuestLogin = true } }) {
                                Text("Continue as guest")
                                    .font(.fqFootnote)
                                    .foregroundColor(Theme.textMuted)
                            }
                            .padding(.top, 20)

                        } else {
                            // ── Guest Login ──
                            VStack(spacing: 20) {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("NICKNAME")
                                        .font(.fqCaption2.weight(.bold))
                                        .foregroundColor(Theme.textMuted)
                                        .kerning(1)

                                    HStack(spacing: 10) {
                                        Image(systemName: "person.fill")
                                            .foregroundColor(Theme.textMuted)
                                            .font(.system(size: 14))

                                        TextField("", text: $guestNick, prompt: Text("Choose a nickname").foregroundColor(Theme.textMuted))
                                            .foregroundColor(Theme.textPrimary)
                                            .font(.fqCallout)
                                            .autocapitalization(.none)
                                            .disableAutocorrection(true)
                                            .textContentType(.username)
                                            .focused($nickFocused)
                                            .submitLabel(.go)
                                            .onSubmit { connectAsGuest() }
                                    }
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 12)
                                    .background(Theme.bgPrimary)
                                    .cornerRadius(10)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 10)
                                            .stroke(nickFocused ? Theme.accent : Theme.border, lineWidth: 1)
                                    )
                                    .id("nickField")
                                }

                                if let error = appState.errorMessage {
                                    errorRow(error)
                                }

                                Button(action: connectAsGuest) {
                                    HStack(spacing: 8) {
                                        if appState.connectionState == .connecting {
                                            ProgressView().tint(Color(hex: "04121a")).scaleEffect(0.85)
                                        }
                                        Text(appState.connectionState == .connecting ? "Connecting..." : "Connect as Guest")
                                            .font(.fqCallout.weight(.semibold))
                                    }
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 15)
                                    .background(
                                        guestNick.isEmpty
                                            ? AnyShapeStyle(Theme.textMuted.opacity(0.25))
                                            : AnyShapeStyle(Theme.signalGradient)
                                    )
                                    .foregroundColor(Color(hex: "04121a"))
                                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                    .shadow(color: guestNick.isEmpty ? .clear : Theme.accent.opacity(0.35), radius: 12, y: 4)
                                }
                                .disabled(guestNick.isEmpty || appState.connectionState == .connecting)
                            }
                            .padding(24)
                            .glassCard()
                            .padding(.horizontal, 24)

                            // Back to Bluesky login
                            Button(action: { withAnimation { showGuestLogin = false } }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "arrow.left")
                                        .font(.system(size: 12))
                                    Text("Sign in with Bluesky instead")
                                        .font(.fqFootnote)
                                }
                                .foregroundColor(Theme.accent)
                            }
                            .padding(.top, 20)
                        }

                        // Extra padding so keyboard doesn't cover the field
                        Color.clear.frame(height: 120).id("bottomPadding")

                        // Footer
                        VStack(spacing: 6) {
                            Text("By continuing, you agree there is zero tolerance for objectionable content or abusive behavior.")
                                .font(.fqCaption2)
                                .foregroundColor(Theme.textMuted)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 32)
                            Text("Open source · IRC compatible · AT Protocol identity")
                                .font(.fqCaption2)
                                .foregroundColor(Theme.textMuted.opacity(0.7))
                        }
                        .padding(.bottom, 16)
                    }
                }
                .scrollDismissesKeyboard(.interactively)
                .onChange(of: handleFocused) {
                    if handleFocused {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                            withAnimation { scrollProxy.scrollTo("handleField", anchor: .center) }
                        }
                    }
                }
                .onChange(of: nickFocused) {
                    if nickFocused {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                            withAnimation { scrollProxy.scrollTo("nickField", anchor: .center) }
                        }
                    }
                }
            }
        }
        .onTapGesture {
            handleFocused = false
            nickFocused = false
        }
        .preferredColorScheme(.dark)
        .onAppear {
            // Clear loading state when returning from Safari without completing auth
            loading = false
        }
    }

    private func valueRow(icon: String, tint: Color, title: String, detail: String) -> some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(tint.opacity(0.14))
                    .frame(width: 38, height: 38)
                Image(systemName: icon)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(tint)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.fqSubheadline.weight(.semibold))
                    .foregroundColor(Theme.textPrimary)
                Text(detail)
                    .font(.fqCaption)
                    .foregroundColor(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func errorRow(_ text: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 12))
                .foregroundColor(Theme.danger)
            Text(text)
                .font(.fqFootnote)
                .foregroundColor(Theme.danger)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func startLogin() {
        guard !handle.isEmpty else { return }
        loading = true
        error = nil

        let serverBase = appState.authBrokerBase
        let returnTo = "\(ServerConfig.apiBaseUrl)/auth/mobile".addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        // `intent=enroll` asks the account for permission to write this
        // device's key records, on top of the identity-only default.
        let loginURL = "\(serverBase)/auth/login?handle=\(handle.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? handle)&mobile=1&intent=enroll&return_to=\(returnTo)"

        guard let url = URL(string: loginURL) else {
            error = "Invalid handle"
            loading = false
            return
        }

        // Save handle so we can complete login when the app reopens
        UserDefaults.standard.set(handle, forKey: "freeq.handle")
        UserDefaults.standard.set(true, forKey: "freeq.loginPending")

        // In-app OAuth sheet (ASWebAuthenticationSession) — no Safari bounce.
        // The broker redirects back via the freeq:// scheme, which the session
        // captures and hands to the same callback handler.
        AuthSession.shared.start(loginURL: url) { callbackURL, failure in
            DispatchQueue.main.async {
                loading = false
                if let callbackURL {
                    appState.handleAuthCallback(callbackURL)
                } else if let failure {
                    error = failure
                }
                // nil/nil = user dismissed the sheet — no error to show.
            }
        }
    }

    private func connectAsGuest() {
        appState.serverAddress = guestServer
        appState.connect(nick: guestNick)
    }
}
