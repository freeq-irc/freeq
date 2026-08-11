import SwiftUI

/// Two different questions, one window, never blended: who this person is, or
/// what checking one message's signature came back as. The request says which
/// was asked, and the sheet answers only that — a claim about a person is not
/// a claim about any message they sent. Mirrors Android's VerifiedProofSheet:
/// same claims, same language.
struct VerifiedProofSheet: View {
    /// The sender's DID, when we've resolved one. nil = a sender whose
    /// identity hasn't hydrated yet (key card is skipped).
    let did: String?
    var handle: String? = nil
    var displayName: String? = nil
    var nick: String? = nil
    /// The peer that relayed this sender's message, when it wasn't seen first
    /// hand. Anything relayed is peer-vouched and claims nothing here.
    var origin: String? = nil
    /// Set when the reader asked about one specific message.
    var msgId: String? = nil
    /// Whether that message carries a signature at all.
    var signed: Bool = true
    /// The anchoring row's evidence, when opened from a row.
    var account: String? = nil
    var rowTimeUnix: UInt64? = nil
    var senderPresent: Bool = false
    /// The row the identity mark was clicked on, so its own verdict renders
    /// beneath the identity — one sheet, content follows the message.
    var rowMsgId: String? = nil
    var rowSigned: Bool = false

    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState
    @State private var key: SigningKeyInfo? = nil
    @State private var loadingKey = true
    @State private var copied = false
    @State private var answer: VerifyAnswer? = nil
    @State private var verifying = false
    @State private var retriesLeft = VerifiedProofSheet.maxRetries

    /// A key held on another server can arrive between asks — but only a
    /// couple of times, and then the panel stops promising.
    private static let maxRetries = 2
    private static let retryDelay: Duration = .milliseconds(1200)

    private var claim: IdentityClaim {
        claimForSender(
            input: MessageClaimInput(
                account: account,
                origin: origin,
                senderPresent: senderPresent,
                senderLiveDid: did,
                rowTimeUnix: rowTimeUnix
            ),
            lookup: nick.map { appState.personLookup(for: $0) } ?? .notAsked
        )
    }

    /// The message whose verdict this sheet renders: the explicit ask, or the
    /// row the identity mark was clicked on when that row is signed.
    private var verdictMsgId: String? { msgId ?? (rowSigned ? rowMsgId : nil) }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 16) {
                    if msgId != nil {
                        messageProof
                    } else {
                        identityProof
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 16)
            }

            Divider()

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        // The window hugs its question: a one-glyph verdict doesn't get an
        // identity-sized sheet of empty space under it.
        .frame(width: 380, height: msgId != nil ? 320 : 480)
        .background(Theme.appBackground)
        .task {
            if msgId == nil {
                // The identity question. If we can't name them yet, ask —
                // otherwise this sheet would answer "unknown" without anyone
                // having asked anything.
                if claim.did == nil, origin == nil, let nick {
                    appState.lookUpIdentity(nick: nick)
                }
                await loadKey()
                if verdictMsgId != nil { await loadVerification() }
            } else {
                await loadVerification()
            }
        }
    }

    // MARK: - Identity: who this person is, never a word about any message.

    @ViewBuilder private var identityProof: some View {
        if claim.showsMark {
            seal
        }

        VStack(spacing: 4) {
            Text(SenderIdentity.title(displayName: displayName, handle: handle, nick: nick))
                .font(.title3.weight(.bold))
                .foregroundStyle(Theme.textPrimary)
                .multilineTextAlignment(.center)
            // Every state that has words names itself. Only the resolvable
            // claim wears the accent; the rest are ordinary facts and are
            // coloured like ones. An ask still out shows as motion instead.
            if claim.isPending {
                ProgressView().controlSize(.small)
            }
            if let label = claim.label {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(claim.showsMark ? Theme.verified : Theme.textTertiary)
            }
        }

        if !claim.needsKeyCard || key != nil || loadingKey, let claimLine {
            Text(claimLine)
                .font(.subheadline)
                .foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 8)
        }

        if let did = claim.did {
            proofCard(
                label: "Decentralized identifier",
                icon: "person.text.rectangle",
                value: did,
                detail: handle.map { "resolves to @\($0)" },
                copyable: true
            )
        }

        if let key {
            proofCard(
                label: "Message signing key",
                icon: "signature",
                value: key.publicKey,
                // Algorithm only. The old source suffix read "server-attested"
                // for every key (the endpoint labels them all "key-store"),
                // contradicting a device-signed verdict one card up. Trust
                // language belongs to the verdict, which carries it already.
                detail: key.algorithm.uppercased(),
                copyable: false
            )
        } else if loadingKey && claim.did != nil {
            ProgressView()
                .controlSize(.small)
                .padding(.vertical, 8)
        }

        if msgId == nil, verdictMsgId != nil {
            Divider().padding(.vertical, 4)
            messageProof
        }
    }

    /// Same claims, same language as every client; the strings live in the
    /// SDK's spec file and arrive rendered.
    private var claimLine: String? { claim.line }

    // MARK: - Message: one message's signature, and nothing else.

    /// The checked answer for one message — what the server said, in the words
    /// every client uses for that state. Whoever sent it is a separate
    /// question with a separate surface, so nothing here identifies them.
    ///
    /// Same shape as the identity side, so the two read as one family: the
    /// glyph carries the answer, the heading names it, one line says what it
    /// means.
    @ViewBuilder private var messageProof: some View {
        let copy = answer.map { SignatureVerdict.copy($0, retrying: retriesLeft > 0) }
        if verifying || answer == nil {
            ProgressView()
                .controlSize(.large)
                .padding(.top, 16)
        } else {
            ZStack {
                Circle()
                    .fill(verdictColor.opacity(0.14))
                    .frame(width: 88, height: 88)
                    .blur(radius: 10)
                Image(systemName: verdictIcon)
                    .font(.system(size: 56, weight: .semibold))
                    .foregroundStyle(verdictColor)
            }
        }

        Text(copy?.heading ?? "Checking signature…")
            .font(.title3.weight(.bold))
            .foregroundStyle(Theme.textPrimary)
            .multilineTextAlignment(.center)

        Text(copy?.line ?? "Asking the server whether this message's signature holds up.")
            .font(.subheadline)
            .foregroundStyle(answer == nil ? Theme.textSecondary : verdictColor)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 8)
    }

    private var verdictIcon: String {
        guard let answer else { return "shield" }
        switch SignatureVerdict.tone(answer.outcome) {
        case .good: return "checkmark.shield.fill"
        case .bad: return "exclamationmark.shield.fill"
        case .quiet: return "shield"
        }
    }

    /// Colour follows the tone, so only sender-device proof is green and only
    /// a mismatch is red. Every can't-know is quiet — a fact, not a warning.
    private var verdictColor: Color {
        guard let answer else { return Theme.textTertiary }
        switch SignatureVerdict.tone(answer.outcome) {
        case .good: return Theme.verified
        case .bad: return Theme.danger
        case .quiet: return Theme.textSecondary
        }
    }

    private var seal: some View {
        ZStack {
            Circle()
                .fill(Theme.verified.opacity(0.14))
                .frame(width: 88, height: 88)
                .blur(radius: 10)
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 56, weight: .semibold))
                .foregroundStyle(Theme.verified)
                .shadow(color: Theme.verified.opacity(0.4), radius: 14)
        }
    }

    private func proofCard(label: String, icon: String, value: String,
                           detail: String?, copyable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.accent)
                Text(label.uppercased())
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(Theme.textTertiary)
                    .kerning(0.6)
                Spacer()
                if copyable {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(value, forType: .string)
                        withAnimation { copied = true }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
                            withAnimation { copied = false }
                        }
                    } label: {
                        Text(copied ? "Copied" : "Copy")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(copied ? Theme.verified : Theme.accent)
                    }
                    .buttonStyle(.plain)
                }
            }
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(Theme.textPrimary)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
            if let detail {
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(Theme.textTertiary)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.surfaceSoft))
    }

    private func loadKey() async {
        guard let did = claim.did else { loadingKey = false; return }
        defer { loadingKey = false }
        let base = ServerConfig.apiBaseUrl
        let enc = did.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? did
        guard let url = URL(string: "\(base)/api/v1/signing-keys/\(enc)") else { return }
        guard let (data, response) = try? await URLSession.shared.data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        key = SigningKeyInfo.from(json: json)
    }

    /// Ask the server to check this message's signature and report exactly
    /// what came back.
    ///
    /// A key held on another server is the one can't-check a retry can outrun
    /// — answering the request is what starts the fetch — so that answer is
    /// re-asked a couple of times before it settles into the plain can't-check.
    private func loadVerification() async {
        guard let msgId = verdictMsgId else { return }
        guard self.msgId == nil ? rowSigned : signed else {
            answer = VerifyAnswer(outcome: .unsigned)
            retriesLeft = 0
            return
        }
        if let remembered = appState.checkedVerdicts[msgId] {
            answer = remembered
            retriesLeft = 0
            return
        }
        while true {
            verifying = true
            let result = await Self.check(msgId: msgId)
            verifying = false
            answer = result
            if SignatureVerdict.worthCaching(result) {
                appState.checkedVerdicts[msgId] = result
            }
            guard result.transient, retriesLeft > 0 else { break }
            retriesLeft -= 1
            try? await Task.sleep(for: Self.retryDelay)
        }
        retriesLeft = 0
    }

    private static func check(msgId: String) async -> VerifyAnswer {
        let base = ServerConfig.apiBaseUrl
        let enc = msgId.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? msgId
        guard let url = URL(string: "\(base)/api/v1/verify/\(enc)") else {
            return VerifyAnswer(outcome: .unreachable)
        }
        guard let (data, response) = try? await URLSession.shared.data(from: url),
              let http = response as? HTTPURLResponse else {
            // A network failure says nothing about the signature.
            return VerifyAnswer(outcome: .unreachable)
        }
        return SignatureVerdict.parse(status: http.statusCode, body: data)
    }
}

// MARK: - Previews

// Xcode's canvas renders these without building or running the app, which is
// the only way to see a layout change in less than a build cycle. The key card
// stays empty here — it comes from a live server — so what these show is the
// claim, the label, and how the two lines wrap at this width.

#Preview("Identity — AT Protocol") {
    VerifiedProofSheet(
        did: "did:plc:4qsyxmnsblo4luuycm3572bq",
        handle: "chadfowler.com",
        displayName: "Chad Fowler",
        nick: "chad"
    )
    .environment(AppState())
}

#Preview("Identity — self-created") {
    VerifiedProofSheet(
        did: "did:key:z6MkpdyZFX7tagEUaCBp8bwVgqBqzvLEDdi8E",
        nick: "lobot"
    )
    .environment(AppState())
}

#Preview("Identity — relayed") {
    VerifiedProofSheet(
        did: "did:plc:padwfc6z5dke5g7c3nzratdy",
        displayName: "nandi-test",
        nick: "nandi-test",
        origin: "irc.freeq.at"
    )
    .environment(AppState())
}

#Preview("Identity — nobody on file") {
    VerifiedProofSheet(did: nil, nick: "stranger")
        .environment(AppState())
}

#Preview("Message — unsigned") {
    VerifiedProofSheet(
        did: "did:plc:4qsyxmnsblo4luuycm3572bq",
        nick: "chad",
        msgId: "01KZNZCW8V3AJX29S5M2256VJB",
        signed: false
    )
    .environment(AppState())
}
