import Foundation

/// Compose-input handling extracted from ComposeBar so it lives in the model
/// (single source of truth) and can be exercised both by the UI and by the
/// test-mode DebugBridge.
extension AppState {

    /// Handle one line of compose input for `target` — slash command, edit, or
    /// plain message (honoring an active reply). UI-only concerns (pending
    /// uploads, input history, clearing the field) stay in ComposeBar.
    /// Handle one submission for `target` — a slash command, or the message
    /// the compose state describes (new, edit, or reply).
    ///
    /// A multi-line body stays one message. The SDK routes it into a
    /// `draft/multiline` batch and signs what a receiver reassembles; sending
    /// one message per line — which is what this used to do — turned one
    /// thought into several, each with an id of its own.
    func submitInput(_ raw: String, target: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        // Slash commands. Checked after the edit state, so a revision that
        // starts with `/` is still text.
        if editingMessageId == nil, trimmed.hasPrefix("/") {
            handleCommand(trimmed, target: target)
            return
        }

        guard let send = ComposeSend.plan(
            target: target,
            text: raw,
            editingId: editingMessageId,
            replyToId: replyingToMessage?.id
        ) else { return }
        editingMessageId = nil
        editingText = nil
        replyingToMessage = nil
        dispatch(send)
    }

    func handleCommand(_ input: String, target: String) {
        let parts = input.dropFirst().split(separator: " ", maxSplits: 1)
        let cmd = parts.first.map(String.init)?.lowercased() ?? ""
        let arg = parts.count > 1 ? String(parts[1]) : ""

        switch cmd {
        case "join", "j":
            arg.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
                .forEach { joinChannel(String($0)) }
        case "part", "leave":
            partChannel(arg.isEmpty ? target : arg)
        case "topic", "t":
            if !arg.isEmpty { sendRaw("TOPIC \(target) :\(arg)") }
        case "nick":
            if !arg.isEmpty { sendRaw("NICK \(arg)") }
        case "me", "action":
            if !arg.isEmpty { sendAction(to: target, text: arg) }
        case "msg", "query":
            let mp = arg.split(separator: " ", maxSplits: 1)
            if mp.count == 2 {
                let dmTarget = String(mp[0])
                sendMessage(to: dmTarget, text: String(mp[1]))
                // Buffer under the canonical key (peer DID when known) so
                // the echo lands in the thread on screen; the wire keeps the
                // typed target (the SDK resolves it).
                let key = DidDisplay.isDid(dmTarget)
                    ? dmTarget : (didForNick(dmTarget) ?? dmTarget)
                let dm = getOrCreateDM(key)
                activeChannel = dm.name
            }
        case "kick", "k":
            let kp = arg.split(separator: " ", maxSplits: 1)
            if let user = kp.first {
                kickUser(target, String(user), reason: kp.count > 1 ? String(kp[1]) : nil)
            }
        case "op":
            if !arg.isEmpty { setMode(target, "+o", arg) }
        case "deop":
            if !arg.isEmpty { setMode(target, "-o", arg) }
        case "voice":
            if !arg.isEmpty { setMode(target, "+v", arg) }
        case "invite":
            if !arg.isEmpty { inviteUser(target, arg) }
        case "away":
            setAway(arg.isEmpty ? nil : arg)
        case "whois", "wi":
            if !arg.isEmpty { sendWhois(arg) }
        case "mode", "m":
            if !arg.isEmpty {
                sendRaw("MODE \(arg.hasPrefix("#") ? "" : "\(target) ")\(arg)")
            }
        case "raw", "quote":
            sendRaw(arg)
        case "p2p":
            handleP2pCommand(arg)
        case "edit", "e":
            let ep = arg.split(separator: " ", maxSplits: 1)
            if ep.count == 2, activeChannelState?.findMessage(byId: String(ep[0])) != nil {
                editMessage(target: target, msgId: String(ep[0]), newText: String(ep[1]))
            } else if !arg.isEmpty, let last = lastOwnMessage(in: target) {
                editMessage(target: target, msgId: last.id, newText: arg)
            }
        case "delete", "del":
            let mid = arg.isEmpty ? lastOwnMessage(in: target)?.id : arg.trimmingCharacters(in: .whitespaces)
            if let mid { deleteMessage(target: target, msgId: mid) }
        case "react":
            let rp = arg.split(separator: " ")
            if let emoji = rp.first {
                let mid = rp.count > 1 ? String(rp[1]) : activeChannelState?.messages.last?.id
                if let mid { sendReaction(target: target, msgId: mid, emoji: String(emoji)) }
            }
        case "reply", "re":
            let rp = arg.split(separator: " ", maxSplits: 1)
            if rp.count == 2, activeChannelState?.findMessage(byId: String(rp[0])) != nil {
                sendReply(target: target, msgId: String(rp[0]), text: String(rp[1]))
            } else if !arg.isEmpty, let last = activeChannelState?.messages.last {
                sendReply(target: target, msgId: last.id, text: arg)
            }
        case "pin":
            let mid = arg.isEmpty ? activeChannelState?.messages.last?.id : arg.trimmingCharacters(in: .whitespaces)
            if let mid { pin(msgId: mid, in: target) }
        case "unpin":
            if !arg.isEmpty { unpin(msgId: arg.trimmingCharacters(in: .whitespaces), in: target) }
        case "pins":
            fetchPins(channel: target)
        case "ban":
            sendRaw(arg.isEmpty ? "MODE \(target) +b" : "MODE \(target) +b \(arg)")
        case "unban":
            if !arg.isEmpty { sendRaw("MODE \(target) -b \(arg)") }
        case "list":
            sendRaw(arg.isEmpty ? "LIST" : "LIST \(arg)")
        case "names":
            // NAMES is channel-only; in a DM the server would echo the bare
            // nick back as a 353/366 pair (which used to mint a phantom
            // channel buffer). Just no-op outside channels.
            let namesTarget = arg.isEmpty ? target : arg
            if namesTarget.hasPrefix("#") || namesTarget.hasPrefix("&") {
                sendRaw("NAMES \(namesTarget)")
            }
        case "who":
            sendRaw("WHO \(arg.isEmpty ? target : arg)")
        case "media", "img", "upload", "crosspost":
            onComposeMediaRequest?()
        case "oper":
            if !arg.isEmpty { sendRaw("OPER \(arg)") }
        case "reconnect":
            reconnectIfSaved()
        case "search", "find":
            runBufferSearch(arg, target: target)
        case "av":
            handleAvCommand(arg, target: target)
        case "encrypt", "e2ee":
            guard target.hasPrefix("#") else {
                appendSystem("Channel encryption is only available in channels")
                break
            }
            let passphrase = arg.trimmingCharacters(in: .whitespaces)
            if passphrase.isEmpty {
                appendSystem("Usage: /encrypt <passphrase> — enables E2EE for this channel")
            } else {
                setChannelKey(target, passphrase: passphrase)
                appendSystem("🔒 End-to-end encryption enabled. All messages you send will be encrypted.")
                appendSystem("Others need the same passphrase to read your messages.")
            }
        case "decrypt", "unencrypt":
            guard target.hasPrefix("#") else { break }
            removeChannelKey(target)
            appendSystem("🔓 Encryption disabled for this channel.")
        case "help":
            for line in Self.helpLines { appendSystem(line) }
        default:
            sendRaw("\(cmd.uppercased())\(arg.isEmpty ? "" : " \(arg)")")
        }
    }

    static let helpLines = [
        "── Commands ──",
        "/join #channel · /part · /topic text",
        "/kick user · /op user · /voice user · /invite user",
        "/ban mask · /unban mask · /whois user · /away reason · /me action",
        "/msg user text · /mode +o user · /raw IRC_LINE",
        "/edit [id] text · /delete [id] · /react emoji · /reply [id] text",
        "/pin [id] · /unpin id · /pins · /list · /names · /who · /search text",
        "/media · /av start|join|leave|mute|camera|screen · /oper name pass · /reconnect",
        "/encrypt passphrase · /decrypt — channel E2EE (others need the same passphrase)",
        "/p2p start|id|connect|peers",
        "── Shortcuts ──",
        "⌘K quick switch · ⌘J join · ↑ edit last · Esc cancel edit",
    ]

    func appendSystem(_ text: String) {
        activeChannelState?.appendIfNew(ChatMessage(
            id: UUID().uuidString, from: "system", text: text,
            isAction: false, timestamp: Date(), replyTo: nil))
    }

    private func sysLine(_ text: String) -> ChatMessage {
        ChatMessage(id: UUID().uuidString, from: "system", text: text,
                    isAction: false, timestamp: Date(), replyTo: nil)
    }

    func handleP2pCommand(_ arg: String) {
        let parts = arg.split(separator: " ", maxSplits: 1)
        let subcmd = parts.first.map(String.init) ?? ""
        switch subcmd {
        case "start":
            startP2p()
            appendSystem("P2P subsystem starting…")
        case "id":
            if let id = p2pEndpointId {
                appendSystem("Your iroh endpoint: \(id)")
            } else {
                appendSystem("P2P not active. Use /p2p start")
            }
        case "connect":
            if parts.count > 1 { connectP2pPeer(String(parts[1])) }
        case "peers":
            let peers = p2pConnectedPeers
            appendSystem(peers.isEmpty ? "No P2P peers connected" : "P2P peers: \(peers.joined(separator: ", "))")
        default:
            appendSystem("P2P commands: start, id, connect <endpoint>, peers")
        }
    }

    /// `/av start|join|leave|end|mute|camera|screen` — voice/video calls.
    func handleAvCommand(_ arg: String, target: String) {
        guard target.hasPrefix("#") else {
            appendSystem("Voice calls are only available in channels")
            return
        }
        switch AvCommandParser.action(for: arg) {
        case .startOrJoin:
            startOrJoinVoice(channel: target)
        case .leave:
            leaveCall()
        case .mute:
            toggleMute()
        case .camera:
            toggleCamera()
        case .screenShare:
            toggleScreenShare()
        case .screenShareDisplay:
            if isScreenSharing {
                toggleScreenShare()
            } else {
                startScreenShare(target: nil)  // primary display, no picker
            }
        case .help:
            appendSystem("AV: start | join | leave | mute | camera | screen [display]")
        }
    }

    /// `/search <text>` — in-buffer substring search; prints matches as system lines.
    func runBufferSearch(_ query: String, target: String) {
        guard !query.isEmpty, let ch = activeChannelState else { return }
        let matches = MessageActions.searchMatches(ch.messages, query: query)
        appendSystem(matches.isEmpty
            ? "No matches for \"\(query)\""
            : "── \(matches.count) match(es) for \"\(query)\" ──")
        for m in matches.suffix(20) {
            appendSystem("[\(formatTime(m.timestamp))] \(m.from): \(m.text)")
        }
    }
}
