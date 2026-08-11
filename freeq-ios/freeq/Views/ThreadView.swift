import SwiftUI

/// Thread view — shows a reply chain for a given message.
struct ThreadView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    let rootMessage: ChatMessage
    let channelName: String

    private var channel: ChannelState? {
        // Follow a nick→DID re-key so an open thread survives the DM merging
        // under its canonical (DID) key mid-session.
        let key = appState.canonicalDmKey(channelName)
        return appState.channels.first { $0.name.lowercased() == key.lowercased() }
            ?? appState.dmBuffers.first { $0.name.lowercased() == key.lowercased() }
    }

    /// Build the reply chain: walk up from rootMessage via replyTo, then show all replies to root.
    private var thread: [ChatMessage] {
        guard let ch = channel else { return [rootMessage] }

        var chain: [ChatMessage] = []

        // Walk up the parent chain
        var current: ChatMessage? = rootMessage
        while let msg = current, let replyId = msg.replyTo {
            if let idx = ch.findMessage(byId: replyId) {
                current = ch.messages[idx]
                chain.insert(current!, at: 0)
            } else {
                break
            }
        }

        // Add the root message itself
        chain.append(rootMessage)

        // Find all direct replies to the root message
        let rootId = rootMessage.id
        let replies = ch.messages.filter { $0.replyTo == rootId && $0.id != rootId }
        chain.append(contentsOf: replies)

        return chain
    }

    /// Which proof the sheet is open for: a sender's identity, or the checked
    /// answer for one message.
    @State private var proofTarget: ProofTarget? = nil

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bgPrimary.ignoresSafeArea()

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(thread.enumerated()), id: \.element.id) { idx, msg in
                            let isRoot = msg.id == rootMessage.id
                            // What this row can honestly claim about its
                            // sender — computed by the SDK from the row's own
                            // tags and the live room, never from a cache.
                            let needsRoom = msg.account == nil && msg.origin == nil
                            let present = needsRoom && appState.isNickPresent(msg.from)
                            let rowClaim = claimForMessage(input: MessageClaimInput(
                                account: msg.account,
                                origin: msg.origin,
                                senderPresent: present,
                                senderLiveDid: present ? appState.liveDidForNick(msg.from) : nil,
                                rowTimeUnix: UInt64(msg.timestamp.timeIntervalSince1970)
                            ))

                            VStack(alignment: .leading, spacing: 0) {
                                // Thread connector line
                                if idx > 0 {
                                    HStack(spacing: 0) {
                                        Rectangle()
                                            .fill(Theme.accent.opacity(0.3))
                                            .frame(width: 2, height: 16)
                                            .padding(.leading, 35)
                                        Spacer()
                                    }
                                }

                                HStack(alignment: .top, spacing: 12) {
                                    // Avatar with thread line
                                    VStack(spacing: 0) {
                                        UserAvatar(nick: msg.from, size: 36)

                                        if idx < thread.count - 1 {
                                            Rectangle()
                                                .fill(Theme.accent.opacity(0.3))
                                                .frame(width: 2)
                                                .frame(maxHeight: .infinity)
                                        }
                                    }
                                    .frame(width: 36)

                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                                            Text(((channel?.memberInfo(for: msg.from)?.prefix ?? "") + msg.from))
                                                .font(.fqFootnote.weight(.bold))
                                                .foregroundColor(Theme.nickColor(for: msg.from))

                                            // The mark opens the proof behind
                                            // the claim it makes.
                                            if rowClaim.showsMark {
                                                Button {
                                                    proofTarget = .identity(msg)
                                                } label: {
                                                    VerifiedBadge(size: 11)
                                                }
                                                .buttonStyle(.plain)
                                            }

                                            if let origin = msg.origin {
                                                Text("via \(origin)")
                                                    .font(.fqCaption2)
                                                    .foregroundColor(Theme.textMuted)
                                            }

                                            Text(formatTime(msg.timestamp))
                                                .font(.fqCaption2)
                                                .foregroundColor(Theme.textMuted)

                                            // Only a checked mismatch marks a
                                            // row; verification is asked for
                                            // from the context menu.
                                            if appState.checkedVerdicts[msg.id]?.marksTheRow == true {
                                                Button {
                                                    proofTarget = .verify(msg)
                                                } label: {
                                                    Image(systemName: "exclamationmark.shield.fill")
                                                        .font(.system(size: 9, weight: .semibold))
                                                        .foregroundColor(Theme.danger)
                                                }
                                                .buttonStyle(.plain)
                                            }
                                        }

                                        MarkdownText(raw: msg.text)
                                            .font(.fqSubheadline)
                                            .foregroundColor(Theme.textPrimary)

                                        if msg.isEdited {
                                            Text("edited")
                                                .font(.fqCaption2.weight(.semibold))
                                                .foregroundColor(Theme.accent)
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(Theme.accent.opacity(0.12))
                                                .cornerRadius(6)
                                        }

                                        // Reactions
                                        if !msg.reactions.isEmpty {
                                            HStack(spacing: 4) {
                                                ForEach(Array(msg.reactions.keys.sorted()), id: \.self) { emoji in
                                                    let nicks = msg.reactions[emoji] ?? []
                                                    HStack(spacing: 2) {
                                                        Text(emoji).font(.fqFootnote)
                                                        if nicks.count > 1 {
                                                            Text("\(nicks.count)")
                                                                .font(.fqCaption2.weight(.medium))
                                                                .foregroundColor(Theme.textSecondary)
                                                        }
                                                    }
                                                    .padding(.horizontal, 5)
                                                    .padding(.vertical, 2)
                                                    .background(Theme.bgTertiary)
                                                    .cornerRadius(4)
                                                }
                                            }
                                            .padding(.top, 2)
                                        }
                                    }

                                    Spacer(minLength: 0)
                                }
                                .padding(.horizontal, 16)
                                .padding(.vertical, 6)
                                .background(isRoot ? Theme.accent.opacity(0.05) : Color.clear)
                                .contextMenu {
                                    Button(action: { proofTarget = .verify(msg) }) {
                                        Label("Verify Signature", systemImage: "checkmark.shield")
                                    }
                                }
                            }
                        }
                    }
                    .padding(.top, 8)

                    // Reply action
                    Button(action: {
                        appState.replyingTo = rootMessage
                        dismiss()
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: "arrowshape.turn.up.left.fill")
                                .font(.system(size: 13))
                            Text("Reply to thread")
                                .font(.fqSubheadline.weight(.medium))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(Theme.accent)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 16)
                }
            }
            .navigationTitle("Thread")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                        .foregroundColor(Theme.accent)
                }
            }
            .sheet(item: $proofTarget) { target in
                VerifiedProofSheet(
                    did: appState.liveDidForNick(target.nick),
                    nick: target.nick,
                    origin: target.origin,
                    msgId: target.msgId,
                    signed: target.rowSigned,
                    account: target.account,
                    rowTimeUnix: UInt64(target.rowTime.timeIntervalSince1970),
                    senderPresent: appState.isNickPresent(target.nick),
                    rowMsgId: target.rowMsgId,
                    rowSigned: target.rowSigned
                )
            }
        }
        .preferredColorScheme(appState.isDarkTheme ? .dark : .light)
    }

    private func formatTime(_ date: Date) -> String {
        let fmt = DateFormatter()
        if Calendar.current.isDateInToday(date) {
            fmt.dateFormat = "h:mm a"
        } else {
            fmt.dateFormat = "MMM d, h:mm a"
        }
        return fmt.string(from: date)
    }
}
