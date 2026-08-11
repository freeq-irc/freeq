import SwiftUI

/// Thread view — shows a message and all its replies in a side panel.
struct ThreadView: View {
    @Environment(AppState.self) private var appState
    let rootMessage: ChatMessage
    let channel: String

    private var replies: [ChatMessage] {
        guard let ch = appState.channels.first(where: { $0.name.lowercased() == channel.lowercased() })
                ?? appState.dmBuffers.first(where: { $0.name.lowercased() == channel.lowercased() }) else { return [] }
        return ch.messages.filter { $0.replyTo == rootMessage.id }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "bubble.left.and.bubble.right")
                    .foregroundStyle(.secondary)
                Text("Thread")
                    .font(.headline)
                Spacer()
                Button {
                    appState.threadRootMessage = nil
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // Root message
                    ThreadMessageRow(message: rootMessage, isRoot: true)

                    if !replies.isEmpty {
                        HStack {
                            Rectangle()
                                .fill(.separator)
                                .frame(height: 1)
                            Text("\(replies.count) \(replies.count == 1 ? "reply" : "replies")")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Rectangle()
                                .fill(.separator)
                                .frame(height: 1)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)

                        ForEach(replies) { reply in
                            ThreadMessageRow(message: reply, isRoot: false)
                        }
                    } else {
                        VStack(spacing: 8) {
                            Image(systemName: "bubble.left")
                                .font(.title2)
                                .foregroundStyle(.tertiary)
                            Text("No replies yet")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.top, 24)
                    }
                }
            }

            Divider()

            // Quick reply
            ThreadReplyBar(rootId: rootMessage.id, channel: channel)
        }
        .frame(width: 320)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct ThreadMessageRow: View {
    @Environment(AppState.self) private var appState
    let message: ChatMessage
    let isRoot: Bool
    @State private var proofRequest: ProofRequest?
    @State private var profileNick: MentionTarget?

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Button { profileNick = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) } label: {
                AvatarView(nick: message.from, size: isRoot ? 28 : 22)
            }
            .buttonStyle(.plain)
            .help("View profile")
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(message.from)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(Theme.nickColor(for: message.from))
                    Text(formatTime(message.timestamp))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Text(message.text)
                    .font(isRoot ? .body : .callout)
                    .textSelection(.enabled)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, isRoot ? 10 : 6)
        // The same two questions the main list answers, reachable here too.
        .contextMenu {
            Button("View Profile") { profileNick = MentionTarget(nick: message.from, origin: message.origin, account: message.account, rowTime: message.timestamp, senderPresent: appState.isNickPresent(message.from)) }
            Button("Verify Signature") { proofRequest = .verify(message.id) }
        }
        .sheet(item: $proofRequest) { request in
            VerifiedProofSheet(
                did: appState.liveDidForNick(message.from),
                nick: message.from,
                origin: message.origin,
                msgId: request.msgId,
                signed: message.isSigned,
                account: message.account,
                rowTimeUnix: UInt64(message.timestamp.timeIntervalSince1970),
                senderPresent: appState.isNickPresent(message.from),
                rowMsgId: message.id,
                rowSigned: message.isSigned
            )
            .environment(appState)
        }
        .sheet(item: $profileNick) { target in
            UserProfileSheet(
                nick: target.nick,
                origin: target.origin,
                account: target.account,
                rowTime: target.rowTime,
                senderPresent: target.senderPresent
            )
            .environment(appState)
        }
        if isRoot {
            Divider().padding(.leading, 16)
        }
    }
}

struct ThreadReplyBar: View {
    @Environment(AppState.self) private var appState
    let rootId: String
    let channel: String
    @State private var text = ""

    var body: some View {
        HStack(spacing: 8) {
            TextField("Reply in thread…", text: $text)
                .textFieldStyle(.roundedBorder)
                .onSubmit { send() }
            Button { send() } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title3)
                    .foregroundStyle(text.isEmpty ? .gray : .accentColor)
            }
            .buttonStyle(.plain)
            .disabled(text.isEmpty)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private func send() {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        appState.sendReply(target: channel, msgId: rootId, text: trimmed)
        text = ""
    }
}
