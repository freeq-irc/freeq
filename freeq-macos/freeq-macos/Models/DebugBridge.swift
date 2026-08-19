import AppKit
import Foundation

/// Test-mode automation bridge. Only started when `FREEQ_TEST_NICK` is set.
///
/// Polls a command file (default `/tmp/freeq-cmd`, override with
/// `FREEQ_CMD_FILE`) and, for each newly-appended line, either:
///   - routes a `#`-prefixed *directive* to navigation/UI state, or
///   - feeds anything else (plain text or `/slash` command) through the exact
///     same `AppState.submitInput` path the compose box uses.
///
/// This lets the app be driven deterministically for screenshot-based UI
/// testing without fragile GUI-event injection. It is inert in normal use.
final class DebugBridge {
    private weak var appState: AppState?
    private let path: String
    private let snapshotPath: String
    private var processedLines = 0
    private var timer: Timer?

    init(appState: AppState) {
        self.appState = appState
        // Under App Sandbox the app cannot read /tmp — only its own container.
        // Default to the container tmp (NSTemporaryDirectory) so the harness
        // actually works sandboxed; FREEQ_CMD_FILE still overrides. External
        // writers (ui-sweep.sh / test drivers) must target this container path:
        //   ~/Library/Containers/at.freeq.macos/Data/tmp/freeq-cmd
        let env = ProcessInfo.processInfo.environment
        self.path = env["FREEQ_CMD_FILE"]
            ?? (NSTemporaryDirectory() as NSString).appendingPathComponent("freeq-cmd")
        // The snapshot must land where the harness reads it. When the build
        // is unsigned (CI: CODE_SIGNING_ALLOWED=NO) no entitlements apply and
        // the app is NOT sandboxed, so NSTemporaryDirectory() is /var/folders/…
        // instead of the container — anchoring the snapshot next to the cmd
        // file keeps writer and reader on the same path either way.
        if let snap = env["FREEQ_SNAPSHOT_FILE"] {
            self.snapshotPath = snap
        } else if let cmd = env["FREEQ_CMD_FILE"] {
            self.snapshotPath = ((cmd as NSString).deletingLastPathComponent as NSString)
                .appendingPathComponent("freeq-snapshot.json")
        } else {
            self.snapshotPath = (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("freeq-snapshot.json")
        }
    }

    func start() {
        // Start from the current end of the file so we don't replay stale lines.
        // Count non-empty lines only — `echo >>` leaves a trailing newline, and
        // counting the empty final element would make us perpetually one line
        // behind (every poll would only ever see the trailing blank).
        processedLines = (try? String(contentsOfFile: path, encoding: .utf8))?
            .split(separator: "\n").count ?? 0
        NSLog("[debug-bridge] watching \(path) (starting at line \(processedLines))")
        timer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func poll() {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count > processedLines else { return }
        let newLines = lines[processedLines...]
        processedLines = lines.count
        for line in newLines {
            let cmd = line.trimmingCharacters(in: .whitespaces)
            if cmd.isEmpty { continue }
            run(cmd)
        }
    }

    private func run(_ line: String) {
        guard let app = appState else { return }
        NSLog("[debug-bridge] » \(line)")
        if line.hasPrefix("#") {
            runDirective(line, app: app)
        } else {
            let target = app.activeChannel ?? ""
            guard !target.isEmpty else {
                NSLog("[debug-bridge] no active channel for: \(line)")
                return
            }
            app.submitInput(line, target: target)
        }
    }

    /// `#`-prefixed UI/navigation directives.
    private func runDirective(_ line: String, app: AppState) {
        let parts = line.dropFirst().split(separator: " ", maxSplits: 1).map(String.init)
        let cmd = parts.first?.lowercased() ?? ""
        let arg = parts.count > 1 ? parts[1] : ""
        switch cmd {
        case "active":
            app.activeChannel = arg
        case "join":
            let ch = arg.hasPrefix("#") ? arg : "#\(arg)"
            app.joinChannel(ch)
            app.activeChannel = ch
        case "detail":
            app.showDetailPanel = (arg != "off")
        case "search":
            app.showSearch = (arg != "off")
        case "quickswitch":
            app.showQuickSwitcher = (arg != "off")
        case "bookmarks":
            app.showBookmarks = (arg != "off")
        case "channellist":
            app.showChannelList = (arg != "off")
        case "joinsheet":
            app.showJoinSheet = (arg != "off")
        case "thread":
            if let ch = app.activeChannelState,
               let idx = ch.findMessage(byId: arg) {
                app.threadRootMessage = ch.messages[idx]
            }
        case "unthread":
            app.threadRootMessage = nil
        case "settings":
            // open the standard Settings scene
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        // Composer/nav drivers — invoke the same production methods the
        // menu shortcuts and toolbar buttons call, so screenshot sweeps can
        // exercise them without GUI-event injection (which needs TCC).
        case "navnext":
            app.switchToAdjacentChannel(.next)
        case "navprev":
            app.switchToAdjacentChannel(.previous)
        case "navunread":
            app.switchToAdjacentChannel(.next, unreadOnly: true)
        case "histprev":
            ComposeNSTextView.activeInstance?.historyPrevAction?()
        case "histnext":
            ComposeNSTextView.activeInstance?.historyNextAction?()
        case "type":
            if let tv = ComposeNSTextView.activeInstance {
                tv.string = arg
                tv.delegate?.textDidChange?(
                    Notification(name: NSText.didChangeNotification, object: tv))
            }
        case "selectall":
            ComposeNSTextView.activeInstance?.selectAll(nil)
        case "submit":
            // Fire the composer's own submit (records input history etc.),
            // unlike plain-text lines which go straight to submitInput.
            ComposeNSTextView.activeInstance?.submitAction?()
        case "keychain":
            // Sandbox smoke test: the data-protection keychain with an
            // ad-hoc signature must keep working after sandboxing, or
            // session restore silently breaks. Logs a PASS/FAIL verdict.
            let key = "sandbox-probe"
            let saved = KeychainHelper.save(key: key, value: "ok-\(ProcessInfo.processInfo.processIdentifier)")
            let loaded = KeychainHelper.load(key: key)
            KeychainHelper.delete(key: key)
            NSLog("[debug-bridge] keychain probe: save=\(saved) load=\(loaded ?? "nil") verdict=\(saved && loaded != nil ? "PASS" : "FAIL")")
        case "storepath":
            let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            NSLog("[debug-bridge] cachesDir=\(caches.path)")
        // ── Message-list spike harness ──
        case "stress":
            // Inject N synthetic messages into the active channel: mixed
            // lengths, multiline, inline code, reactions, timestamps
            // spanning 30 days (exercises date separators + grouping).
            guard let ch = app.activeChannelState else { return }
            let n = Int(arg) ?? 1000
            let nicks = ["alice", "bob", "carol", "dave", "erin"]
            let now = Date()
            let start = now.addingTimeInterval(-30 * 86_400)
            let bodies = [
                "short one",
                "a somewhat longer message that wraps across a couple of lines when the window is narrow enough to matter",
                "line one\nline two\nline three",
                "with `inline code` and **bold** and _italics_ mixed in",
                String(repeating: "stress ", count: 60),
            ]
            for i in 0..<n {
                let ts = start.addingTimeInterval(Double(i) / Double(n) * 30 * 86_400)
                var msg = ChatMessage(
                    id: String(format: "stress-%06d", i),
                    from: nicks[i % nicks.count],
                    text: "#\(i) " + bodies[i % bodies.count],
                    isAction: false, timestamp: ts, replyTo: nil)
                if i % 7 == 0 { msg.reactions = ["👍": ["alice", "bob"], "🎉": ["carol"]] }
                ch.appendIfNew(msg)
            }
            NSLog("[debug-bridge] stress injected \(n), channel now \(ch.messages.count)")
        case "editstorm":
            // Streaming-edit simulation: rapid text mutations on the last
            // message, 30/s (the agent-output pattern).
            guard let ch = app.activeChannelState,
                  let last = ch.messages.last(where: { !$0.from.isEmpty }) else { return }
            let count = Int(arg) ?? 100
            Task { @MainActor in
                for i in 0..<count {
                    ch.applyEdit(originalId: last.id, newId: nil,
                                 newText: "streaming chunk \(i): " + String(repeating: "token ", count: i % 40))
                    try? await Task.sleep(nanoseconds: 33_000_000)
                }
                NSLog("[debug-bridge] editstorm done (\(count) edits)")
            }
        case "sweep":
            // Scroll the full list via the scroll-to-message path,
            // top → bottom, one hop per 400ms.
            guard let ch = app.activeChannelState else { return }
            let ids = ch.messages.enumerated()
                .filter { $0.offset % 40 == 0 }
                .map { $0.element.id }
            Task { @MainActor in
                for id in ids {
                    app.scrollToMessageId = id
                    try? await Task.sleep(nanoseconds: 400_000_000)
                }
                NSLog("[debug-bridge] sweep done (\(ids.count) hops)")
            }
        case "hitch":
            if arg == "start" { FrameHitchMonitor.shared.start() }
            else { FrameHitchMonitor.shared.stop() }
        case "dumpmsgs":
            if let ch = app.activeChannelState {
                for (i, m) in ch.messages.enumerated() {
                    NSLog("[debug-bridge] msg[\(i)] id=\(m.id.suffix(8)) from=\(m.from) del=\(m.isDeleted) text=\(m.text.prefix(24))")
                }
            }
        case "applydelete":
            // Drive the receiving-side delete path (same method the
            // +draft/delete event handler calls) for tombstone sweeps.
            if let ch = app.activeChannelState {
                let mid = arg.isEmpty
                    ? ch.messages.last(where: { !$0.isDeleted && !$0.from.isEmpty })?.id
                    : arg
                if let mid { ch.applyDelete(msgId: mid) }
            }
        case "format":
            // "#format <prefix> <suffix> [placeholder]"
            let p = arg.split(separator: " ").map(String.init)
            if p.count >= 2 {
                ComposeNSTextView.activeInstance?.applyFormat(
                    prefix: p[0], suffix: p[1],
                    placeholder: p.count > 2 ? p[2] : nil)
            }
        case "mkchannel":
            // Create a local channel buffer and select it — server-independent,
            // so the smoke harness can exercise message flows without a live
            // connection or channel post permissions.
            let ch = arg.hasPrefix("#") ? arg : "#\(arg)"
            _ = app.getOrCreateChannel(ch)
            app.activeChannel = ch
        case "localmsg":
            // Inject a deterministic message authored by us into the active
            // channel, bypassing the server — lets the smoke harness drive
            // edit/delete/react flows without depending on channel post
            // permissions. `#localmsg <id> <text>`
            guard let ch = app.activeChannelState else { return }
            let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
            let id = p.first ?? "local-1"
            let text = p.count > 1 ? p[1] : "local message"
            ch.appendIfNew(ChatMessage(
                id: id, from: app.nick, text: text,
                isAction: false, timestamp: Date(), replyTo: nil))
        case "hover":
            // Force a message row into its hovered state so the hover action
            // bar can be screenshot-verified. `#hover <id>` / `#hover` clears.
            app.debugForceHoverMsgId = arg.isEmpty ? nil : arg
        case "sysmsg":
            // Inject a join/part/quit system line (empty `from`) into the active
            // channel — lets the harness screenshot-verify the coalesced row.
            guard let ch = app.activeChannelState else { return }
            ch.appendIfNew(ChatMessage(
                id: "sys-\(ch.messages.count)-\(arg.hashValue)", from: "", text: arg,
                isAction: false, timestamp: Date(), replyTo: nil))
        case "snapshot":
            // Serialize key app state to JSON in the container so an external
            // smoke-test driver can ASSERT outcomes (not just "didn't crash").
            writeSnapshot(app: app)
        default:
            NSLog("[debug-bridge] unknown directive: \(line)")
        }
    }

    /// Snapshot of observable state the smoke harness asserts against. Written
    /// to `NSTemporaryDirectory()/freeq-snapshot.json` (container-scoped, so it
    /// works under the sandbox and the driver can read it).
    private func writeSnapshot(app: AppState) {
        struct MsgSnap: Encodable {
            let id: String, from: String, text: String, deleted: Bool
            let reactions: [String: Int]
        }
        struct Snap: Encodable {
            let connection: String
            let activeChannel: String?
            let channels: [String]
            let dms: [String]
            let messages: [MsgSnap]
        }
        let msgs = (app.activeChannelState?.messages ?? []).map { m in
            MsgSnap(id: m.id, from: m.from, text: m.text, deleted: m.isDeleted,
                    reactions: m.reactions.mapValues(\.count))
        }
        let snap = Snap(
            connection: "\(app.connectionState)",
            activeChannel: app.activeChannel,
            channels: app.channels.map(\.name),
            dms: app.dmBuffers.map(\.name),
            messages: msgs)
        let url = URL(fileURLWithPath: snapshotPath)
        do {
            let data = try JSONEncoder().encode(snap)
            try data.write(to: url)
            NSLog("[debug-bridge] snapshot written (\(msgs.count) msgs) → \(url.path)")
        } catch {
            // Silent failure here cost a CI run to diagnose — always log.
            NSLog("[debug-bridge] snapshot write FAILED → \(url.path): \(error)")
        }
    }
}
