import SwiftUI
import AVFoundation

struct ComposeView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var text: String = ""
    @FocusState private var isFocused: Bool
    @State private var completions: [String] = []

    // Voice recording state
    @State private var isRecording = false
    @State private var recorder: AVAudioRecorder?
    @State private var recordingTime: TimeInterval = 0
    @State private var recordTimer: Timer?
    @State private var recordingCancelled = false
    @State private var dragOffset: CGFloat = 0
    @State private var holdStart: Date? = nil
    @State private var holdTimer: Timer? = nil
    @State private var isUploadingVoice = false

    // On-device Apple Intelligence: suggested replies to the latest message.
    @State private var smartReplies: [String] = []

    var body: some View {
        VStack(spacing: 0) {
            Rectangle()
                .fill(Theme.border)
                .frame(height: 1)

            // Voice message upload indicator
            if isUploadingVoice {
                HStack(spacing: 8) {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: Theme.accent))
                        .scaleEffect(0.7)
                    Text("Sending voice message…")
                        .font(.fqFootnote)
                        .foregroundColor(Theme.textMuted)
                    Spacer()
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(Theme.bgTertiary)
            }

            // Nick autocomplete suggestions
            if !completions.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(completions, id: \.self) { nick in
                            Button(action: { applyCompletion(nick) }) {
                                HStack(spacing: 4) {
                                    UserAvatar(nick: nick, size: 20)
                                    Text(nick)
                                        .font(.fqFootnote.weight(.medium))
                                        .foregroundColor(Theme.textPrimary)
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Theme.bgTertiary)
                                .cornerRadius(16)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .background(Theme.bgSecondary)
            }

            // Reply / Edit context bar
            if let reply = appState.replyingTo {
                contextBar(
                    icon: "arrowshape.turn.up.left.fill",
                    label: "Replying to \(reply.from)",
                    preview: reply.text,
                    color: Theme.accent
                ) {
                    appState.replyingTo = nil
                }
            } else if let edit = appState.editingMessage {
                contextBar(
                    icon: "pencil",
                    label: "Editing message",
                    preview: edit.text,
                    color: Theme.warning
                ) {
                    appState.editingMessage = nil
                    text = ""
                }
                .onAppear { text = edit.text }
            }

            // On-device smart replies — offered only when the last message isn't
            // yours and you haven't started typing. Tapping fills the field.
            if !smartReplies.isEmpty && text.isEmpty && appState.editingMessage == nil {
                smartReplyBar
            }

            // Use ZStack with opacity to keep mic button gesture alive during recording
            ZStack {
                // Normal compose bar — hidden (not removed) during recording
                HStack(alignment: .bottom, spacing: 8) {
                    if appState.authenticatedDID != nil, let target = appState.activeChannel {
                        MediaAttachmentButton(channel: target)
                    } else {
                        Image(systemName: "plus.circle.fill")
                            .font(.system(size: 24))
                            .foregroundColor(Theme.textMuted.opacity(0.5))
                    }

                    HStack(alignment: .bottom, spacing: 6) {
                        TextField(
                            "",
                            text: $text,
                            prompt: Text(placeholder).foregroundColor(Theme.textMuted),
                            axis: .vertical
                        )
                        .foregroundColor(Theme.textPrimary)
                        .font(.fqCallout)
                        .lineLimit(1...6)
                        .focused($isFocused)
                        .submitLabel(.return)
                        .tint(Theme.accent)
                        .onChange(of: text) {
                            updateCompletions()
                            if let target = appState.activeChannel, !text.isEmpty {
                                appState.sendTyping(target: target)
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Theme.bgTertiary, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 20, style: .continuous)
                            .strokeBorder(Theme.border, lineWidth: 1)
                    )

                    if canSend {
                        Button(action: send) {
                            ZStack {
                                Circle()
                                    .fill(Theme.signalGradient)
                                    .frame(width: 36, height: 36)
                                    .shadow(color: Theme.accent.opacity(0.4), radius: 8, y: 2)
                                Image(systemName: appState.editingMessage != nil ? "checkmark" : "arrow.up")
                                    .font(.system(size: 15, weight: .bold))
                                    .foregroundColor(Color(hex: "04121a"))
                            }
                            .frame(width: 44, height: 44)  // 44pt hit target
                            .contentShape(Circle())
                        }
                        .accessibilityLabel(appState.editingMessage != nil ? "Save edit" : "Send message")
                        .keyboardShortcut(.return, modifiers: .command)  // ⌘↩ send (hardware keyboard / iPad)
                        .transition(.scale.combined(with: .opacity))
                    } else if appState.authenticatedDID != nil {
                        micButton
                            .accessibilityLabel("Hold to record voice message")
                    } else {
                        ZStack {
                            Circle()
                                .fill(Theme.textMuted.opacity(0.2))
                                .frame(width: 36, height: 36)
                            Image(systemName: "arrow.up")
                                .font(.system(size: 15, weight: .bold))
                                .foregroundColor(Theme.textMuted.opacity(0.4))
                        }
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .animation(.spring(response: 0.32, dampingFraction: 0.7), value: canSend)
                .modifier(ComposeBarBackground())
                .overlay(alignment: .top) { Rectangle().fill(Theme.border).frame(height: 1) }
                .opacity(isRecording ? 0 : 1)

                // Recording bar overlaid on top when recording
                if isRecording {
                    recordingBar
                        .transition(.opacity)
                }
            }
        }
        .task(id: smartReplyKey) { await refreshSmartReplies() }
        .onChange(of: text) { if !text.isEmpty { smartReplies = [] } }
    }

    // MARK: - Smart replies (on-device Apple Intelligence)

    /// Recompute when the conversation or its latest message changes.
    private var smartReplyKey: String {
        let ch = appState.activeChannelState
        return "\(ch?.name ?? "")|\(ch?.messages.last?.id ?? "")|\(ch?.messages.count ?? 0)"
    }

    @MainActor
    private func refreshSmartReplies() async {
        guard IntelligenceService.shared.isAvailable,
              appState.editingMessage == nil,
              let ch = appState.activeChannelState else {
            smartReplies = []
            return
        }
        let suggestions = await IntelligenceService.shared.smartReplies(ch.messages, myNick: appState.nick)
        // Only surface if the user still hasn't typed anything.
        if text.isEmpty { smartReplies = suggestions }
    }

    private var smartReplyBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Image(systemName: "sparkles")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.signalGradient)
                    .accessibilityHidden(true)
                ForEach(smartReplies, id: \.self) { suggestion in
                    Button {
                        text = suggestion
                        smartReplies = []
                        isFocused = true
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    } label: {
                        Text(suggestion)
                            .font(.fqFootnote.weight(.medium))
                            .foregroundColor(Theme.textPrimary)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                            .background(.ultraThinMaterial, in: Capsule())
                            .overlay(Capsule().strokeBorder(Theme.accent.opacity(0.35), lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
        .transition(.opacity)
    }

    // MARK: - Mic Button (hold to record)

    @GestureState private var micPressed = false
    @State private var showMicHint = false

    private var micButton: some View {
        VStack(spacing: 2) {
            ZStack {
                // Expanding ring on press
                Circle()
                    .fill(Theme.accent.opacity(micPressed ? 0.15 : 0))
                    .frame(width: micPressed ? 56 : 36, height: micPressed ? 56 : 36)
                    .animation(.easeOut(duration: 0.2), value: micPressed)

                Circle()
                    .fill(micPressed ? Theme.accent : Theme.bgTertiary)
                    .frame(width: 36, height: 36)
                    .scaleEffect(micPressed ? 1.15 : 1.0)
                    .animation(.easeOut(duration: 0.15), value: micPressed)

                Image(systemName: "mic.fill")
                    .font(.system(size: 16))
                    .foregroundColor(micPressed ? .white : Theme.accent)
                    .animation(.easeOut(duration: 0.1), value: micPressed)
            }
        }
        .gesture(
            DragGesture(minimumDistance: 0)
                .updating($micPressed) { _, state, _ in
                    state = true
                }
                .onChanged { value in
                    if !isRecording {
                        if holdStart == nil {
                            holdStart = Date()
                            holdTimer?.invalidate()
                            holdTimer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: false) { _ in
                                DispatchQueue.main.async {
                                    if holdStart != nil && !isRecording {
                                        startRecording()
                                    }
                                }
                            }
                        }
                        // Cancel timer if finger moves too much before recording starts
                        if abs(value.translation.width) > 15 || abs(value.translation.height) > 15 {
                            holdTimer?.invalidate()
                            holdTimer = nil
                            holdStart = nil
                        }
                    }
                    // Track drag offset for slide-to-cancel (works because view stays mounted via opacity)
                    if isRecording {
                        dragOffset = value.translation.width
                        recordingCancelled = dragOffset < -60
                    }
                }
                .onEnded { _ in
                    holdTimer?.invalidate()
                    holdTimer = nil
                    let wasRecording = isRecording
                    holdStart = nil
                    if wasRecording {
                        // Release sends (or cancels if slid left)
                        stopRecording()
                    } else {
                        ToastManager.shared.show("Hold to record voice message", icon: "mic.fill")
                    }
                }
        )
    }

    // MARK: - Recording Bar

    private var recordingBar: some View {
        HStack(spacing: 12) {
            // Red dot + timer
            HStack(spacing: 8) {
                Circle()
                    .fill(Theme.danger)
                    .frame(width: 10, height: 10)
                    .opacity(recordingTime.truncatingRemainder(dividingBy: 1) < 0.5 ? 1 : 0.3)

                Text(formatDuration(recordingTime))
                    .font(.system(size: 16, weight: .medium, design: .monospaced))
                    .foregroundColor(Theme.textPrimary)
            }

            Spacer()

            if recordingCancelled || dragOffset < -60 {
                HStack(spacing: 4) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14))
                    Text("Release to cancel")
                        .font(.system(size: 14, weight: .medium))
                }
                .foregroundColor(Theme.danger)
            } else {
                HStack(spacing: 4) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 11))
                    Text("Slide to cancel")
                        .font(.system(size: 13))
                }
                .foregroundColor(Theme.textMuted)
            }

            Spacer()

            // Release to send indicator
            HStack(spacing: 5) {
                Text("Release to send")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(Theme.accent)
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 22))
                    .foregroundColor(Theme.accent)
                    .symbolEffect(.pulse, isActive: !reduceMotion)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Theme.danger.opacity(0.08))
        .background(Theme.bgSecondary)
    }

    // MARK: - Voice Recording

    private func startRecording() {
        // Check permission
        switch AVAudioApplication.shared.recordPermission {
        case .denied:
            ToastManager.shared.show("Microphone access denied", icon: "mic.slash")
            return
        case .undetermined:
            AVAudioApplication.requestRecordPermission { granted in
                if granted {
                    DispatchQueue.main.async { self.startRecording() }
                }
            }
            return
        default: break
        }

        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.record, mode: .default)
            try session.setActive(true)
        } catch {
            ToastManager.shared.show("Audio error", icon: "exclamationmark.triangle")
            return
        }

        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("voice_\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44100,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.medium.rawValue,
        ]

        do {
            recorder = try AVAudioRecorder(url: tempURL, settings: settings)
            recorder?.record()
            isRecording = true
            recordingTime = 0
            recordingCancelled = false
            dragOffset = 0
            UIImpactFeedbackGenerator(style: .heavy).impactOccurred()

            recordTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
                recordingTime = recorder?.currentTime ?? 0
                if recordingTime >= 300 { stopRecording() }
            }
        } catch {
            ToastManager.shared.show("Recording failed", icon: "exclamationmark.triangle")
        }
    }

    private func stopRecording() {
        recordTimer?.invalidate()
        recordTimer = nil
        guard let recorder = recorder, isRecording else { return }
        recorder.stop()
        isRecording = false
        self.recorder = nil

        // Always deactivate audio session
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)

        let cancelled = recordingCancelled || dragOffset < -60 || recordingTime < 0.5
        dragOffset = 0
        recordingCancelled = false

        if cancelled {
            // Discard
            try? FileManager.default.removeItem(at: recorder.url)
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            ToastManager.shared.show("Voice message cancelled", icon: "xmark.circle")
            return
        }

        // Send the voice message
        guard let data = try? Data(contentsOf: recorder.url) else { return }
        let duration = formatDuration(recordingTime)
        let recordedURL = recorder.url

        guard let target = appState.activeChannel else { return }
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        isUploadingVoice = true

        Task {
            // Kick off on-device transcription in parallel with the audio
            // upload — by the time the upload finishes we usually have a
            // transcript ready to attach. If transcription fails (unauth /
            // unsupported / silent clip) we fall back to audio-only.
            async let transcript: String? = VoiceTranscriber.transcribe(recordedURL)

            defer {
                Task { @MainActor in
                    isUploadingVoice = false
                }
            }

            // Refresh broker session
            if let brokerToken = appState.brokerToken {
                let brokerBase = appState.authBrokerBase
                var req = URLRequest(url: URL(string: "\(brokerBase)/session")!)
                req.httpMethod = "POST"
                req.setValue("application/json", forHTTPHeaderField: "Content-Type")
                req.httpBody = try? JSONSerialization.data(withJSONObject: ["broker_token": brokerToken])
                _ = try? await URLSession.shared.data(for: req)
            }

            let did = appState.authenticatedDID ?? ""
            let boundary = UUID().uuidString
            var body = Data()

            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"did\"\r\n\r\n\(did)\r\n".data(using: .utf8)!)
            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"channel\"\r\n\r\n\(target)\r\n".data(using: .utf8)!)
            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"file\"; filename=\"voice.m4a\"\r\nContent-Type: audio/mp4\r\n\r\n".data(using: .utf8)!)
            body.append(data)
            body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)

            var request = URLRequest(url: URL(string: "\(ServerConfig.apiBaseUrl)/api/v1/upload")!)
            request.httpMethod = "POST"
            request.timeoutInterval = 30
            request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
            request.httpBody = body

            // Funnel through StepUpAuth so a `step_up_required` 403 drives
            // the ASWebAuthenticationSession permission prompt and retries
            // the upload once when the user grants.
            let result = await StepUpAuth.uploadWithStepUp(
                request: request, did: did, appState: appState
            )

            guard let (responseData, response) = result else {
                await MainActor.run {
                    ToastManager.shared.show("Upload failed", icon: "exclamationmark.triangle")
                }
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status == 200,
               let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
               let url = json["url"] as? String {
                let trimmedTranscript = (await transcript)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                let body: String
                if let t = trimmedTranscript, !t.isEmpty {
                    body = "🎤 Voice message (\(duration)) \(url)\n💬 \(t)"
                } else {
                    body = "🎤 Voice message (\(duration)) \(url)"
                }
                await MainActor.run {
                    appState.sendMessage(target: target, text: body)
                    ToastManager.shared.show("Voice message sent", icon: "checkmark.circle")
                }
            } else if StepUpAuth.detectStepUpRequired(status: status, body: responseData) != nil {
                // User declined or cancelled the step-up — surface clearly.
                await MainActor.run {
                    ToastManager.shared.show("Permission needed for upload", icon: "lock.shield")
                }
            } else {
                await MainActor.run {
                    ToastManager.shared.show("Upload failed", icon: "exclamationmark.triangle")
                }
            }
        }
    }

    // MARK: - Nick Autocomplete

    private func updateCompletions() {
        guard let lastWord = text.split(separator: " ").last,
              lastWord.hasPrefix("@"),
              lastWord.count > 1 else {
            completions = []
            return
        }

        let prefix = String(lastWord.dropFirst()).lowercased()
        let members = appState.activeChannelState?.members ?? []
        completions = members
            .map { $0.nick }
            .filter { $0.lowercased().hasPrefix(prefix) && $0.lowercased() != appState.nick.lowercased() }
            .sorted()
            .prefix(5)
            .map { String($0) }
    }

    private func applyCompletion(_ nick: String) {
        var words = text.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        if let lastIdx = words.indices.last, words[lastIdx].hasPrefix("@") {
            words[lastIdx] = "@\(nick)"
        }
        text = words.joined(separator: " ") + " "
        completions = []
    }

    private var canSend: Bool {
        !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var placeholder: String {
        if appState.replyingTo != nil { return "Reply..." }
        if appState.editingMessage != nil { return "Edit message..." }
        return "Message \(appState.activeChannel.map { appState.displayNameForKey($0) } ?? "")"
    }

    private func contextBar(icon: String, label: String, preview: String, color: Color, onDismiss: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            Rectangle()
                .fill(color)
                .frame(width: 3)

            Image(systemName: icon)
                .font(.system(size: 12))
                .foregroundColor(color)

            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(color)
                Text(preview)
                    .font(.system(size: 12))
                    .foregroundColor(Theme.textMuted)
                    .lineLimit(1)
            }

            Spacer()

            Button(action: onDismiss) {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 18))
                    .foregroundColor(Theme.textMuted)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Theme.bgSecondary)
    }

    private func send() {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let target = appState.activeChannel else { return }

        completions = []

        let succeeded: Bool
        if trimmed.hasPrefix("/") {
            handleCommand(trimmed)
            succeeded = true
        } else {
            succeeded = appState.sendMessage(target: target, text: trimmed)
        }

        guard succeeded else {
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            return
        }

        // Clear the buffer. Dispatch async so the assignment runs after the
        // button-tap + any in-flight IME composition settle — assigning ""
        // synchronously while the field is focused is a SwiftUI quirk that
        // leaves stale text visible in TextField(axis: .vertical).
        DispatchQueue.main.async {
            text = ""
        }
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    private func handleCommand(_ input: String) {
        let parts = input.dropFirst().split(separator: " ", maxSplits: 1)
        guard let cmd = parts.first else { return }

        switch cmd.lowercased() {
        case "join":
            if let channel = parts.dropFirst().first {
                appState.joinChannel(String(channel))
            }
        case "part", "leave":
            if let channel = appState.activeChannel {
                appState.partChannel(channel)
            }
        case "nick":
            if let newNick = parts.dropFirst().first {
                appState.sendRaw("NICK \(newNick)")
            }
        case "me":
            if let action = parts.dropFirst().first, let target = appState.activeChannel {
                appState.sendAction(to: target, text: String(action))
            }
        case "msg":
            let msgParts = input.dropFirst(5).split(separator: " ", maxSplits: 1)
            if msgParts.count == 2 {
                appState.sendMessage(target: String(msgParts[0]), text: String(msgParts[1]))
            }
        case "topic":
            if let rest = parts.dropFirst().first, let channel = appState.activeChannel {
                appState.sendRaw("TOPIC \(channel) :\(rest)")
            }
        case "encrypt", "e2ee":
            guard let channel = appState.activeChannel, channel.hasPrefix("#") else {
                ToastManager.shared.show("Encryption is only for channels", icon: "lock.slash")
                break
            }
            let passphrase = parts.dropFirst().first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            if passphrase.isEmpty {
                ToastManager.shared.show("Usage: /encrypt <passphrase>", icon: "lock")
            } else {
                appState.setChannelKey(channel, passphrase: passphrase)
                ToastManager.shared.show("\u{1F512} Encryption on — others need the same passphrase", icon: "lock.fill")
            }
        case "decrypt", "unencrypt":
            if let channel = appState.activeChannel, channel.hasPrefix("#") {
                appState.removeChannelKey(channel)
                ToastManager.shared.show("\u{1F513} Encryption off", icon: "lock.open")
            }
        // — Moderation / channel ops (sendRaw wrappers; parity with macOS) —
        case "whois", "wi":
            if let target = parts.dropFirst().first { appState.sendRaw("WHOIS \(target)") }
        case "away":
            let reason = parts.count > 1 ? String(parts[1]) : ""
            appState.sendRaw(reason.isEmpty ? "AWAY" : "AWAY :\(reason)")
        case "op", "deop", "voice", "devoice":
            if let chan = appState.activeChannel, let who = parts.dropFirst().first {
                let mode = ["op": "+o", "deop": "-o", "voice": "+v", "devoice": "-v"][cmd.lowercased()] ?? "+o"
                appState.sendRaw("MODE \(chan) \(mode) \(who)")
            }
        case "kick":
            if let chan = appState.activeChannel {
                let kp = String(parts.dropFirst().first ?? "").split(separator: " ", maxSplits: 1)
                if let who = kp.first {
                    let reason = kp.count > 1 ? " :\(kp[1])" : ""
                    appState.sendRaw("KICK \(chan) \(who)\(reason)")
                }
            }
        case "ban":
            if let chan = appState.activeChannel, let mask = parts.dropFirst().first {
                appState.sendRaw("MODE \(chan) +b \(mask)")
            }
        case "unban":
            if let chan = appState.activeChannel, let mask = parts.dropFirst().first {
                appState.sendRaw("MODE \(chan) -b \(mask)")
            }
        case "invite":
            if let chan = appState.activeChannel, let who = parts.dropFirst().first {
                appState.sendRaw("INVITE \(who) \(chan)")
            }
        case "mode", "m":
            if parts.count > 1 { appState.sendRaw("MODE \(parts[1])") }
        case "names":
            // NAMES is channel-only; activeChannel also holds DM keys (nicks
            // and DIDs), and asking about a person makes the server answer as
            // though they were a room. No-op outside channels.
            if let chan = appState.activeChannel,
               chan.hasPrefix("#") || chan.hasPrefix("&") {
                appState.sendRaw("NAMES \(chan)")
            }
        case "who":
            let target = parts.dropFirst().first.map(String.init) ?? appState.activeChannel ?? ""
            if !target.isEmpty { appState.sendRaw("WHO \(target)") }
        case "pin", "unpin":
            if let chan = appState.activeChannel, let mid = parts.dropFirst().first {
                appState.sendRaw("\(cmd.uppercased()) \(chan) \(mid)")
            }
        case "oper":
            if parts.count > 1 { appState.sendRaw("OPER \(parts[1])") }
        case "raw", "quote":
            if parts.count > 1 { appState.sendRaw(String(parts[1])) }
        default:
            appState.sendRaw(String(input.dropFirst()))
        }
    }

    private func formatDuration(_ t: TimeInterval) -> String {
        let mins = Int(t) / 60
        let secs = Int(t) % 60
        return String(format: "%d:%02d", mins, secs)
    }
}

/// Compose-bar chrome: genuine iOS 26 Liquid Glass where available, the
/// ultra-thin material as a graceful fallback on iOS 18–25.
private struct ComposeBarBackground: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content.glassEffect(.regular, in: Rectangle())
        } else {
            content.background(.ultraThinMaterial)
        }
    }
}
