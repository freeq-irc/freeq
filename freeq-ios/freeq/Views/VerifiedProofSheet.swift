import SwiftUI

/// The proof behind an identity claim, and the checked answer for one
/// message's signature — whichever was asked for. The claim, its label, and
/// every sentence come from the SDK's spec through the FFI; the seven verdict
/// answers live in SignatureVerdict, worded identically on every client.
struct VerifiedProofSheet: View {
    /// The DID the opener resolved, when it had one. The sheet recomputes the
    /// claim itself, so this is an input, not a conclusion.
    var did: String? = nil
    var handle: String? = nil
    var displayName: String? = nil
    var nick: String? = nil
    /// Set when the sender is known only through a relaying peer.
    var origin: String? = nil
    /// Set when the reader asked about one specific message (context menu):
    /// the sheet answers only the signature question.
    var msgId: String? = nil
    /// Whether that message carries a signature at all.
    var signed: Bool = true
    /// The anchoring row's evidence, when opened from a row.
    var account: String? = nil
    var rowTimeUnix: UInt64? = nil
    var senderPresent: Bool = false
    /// The row the identity mark was tapped on, so its own verdict renders
    /// beneath the identity — one sheet, content follows the message.
    var rowMsgId: String? = nil
    var rowSigned: Bool = false

    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var key: SigningKeyInfo? = nil
    @State private var loadingKey = true
    @State private var copied = false
    @State private var answer: VerifyAnswer? = nil
    @State private var verifying = false
    @State private var retriesLeft = VerifiedProofSheet.maxRetries

    private static let maxRetries = 2
    private static let retryDelay: UInt64 = 1_200_000_000

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
    /// row the identity mark was tapped on when that row is signed.
    private var verdictMsgId: String? { msgId ?? (rowSigned ? rowMsgId : nil) }

    var body: some View {
        ZStack {
            Theme.bgPrimary.ignoresSafeArea()
            if claim.showsMark && msgId == nil {
                RadialGradient(colors: [Theme.verify.opacity(0.14), .clear],
                               center: .top, startRadius: 0, endRadius: 320)
                    .ignoresSafeArea()
            }
            ScrollView {
                VStack(spacing: Theme.Space.lg) {
                    if msgId != nil {
                        messageProof
                    } else {
                        identityProof
                    }
                    Spacer(minLength: 8)
                }
                .padding(Theme.Space.xl)
            }
        }
        .presentationDetents([.medium, .large])
        .presentationBackground(.ultraThinMaterial)
        .task {
            if msgId == nil {
                // If we can't name them yet, ask — otherwise this sheet
                // would answer "unknown" without anyone having asked.
                if claim.did == nil, origin == nil, let nick {
                    appState.lookUpIdentity(nick: nick)
                }
                await loadKey()
            }
            if verdictMsgId != nil { await loadVerification() }
        }
    }

    // ── Identity: who this person is. ──

    @ViewBuilder private var identityProof: some View {
        if claim.showsMark { seal }

        VStack(spacing: 4) {
            Text(SenderIdentity.title(displayName: displayName, handle: handle, nick: nick))
                .font(.fqTitle3.weight(.bold))
                .foregroundColor(Theme.textPrimary)
                .multilineTextAlignment(.center)
            if claim.isPending {
                ProgressView().tint(Theme.textMuted)
            }
            if let label = claim.label {
                Text(label)
                    .font(.fqFootnote)
                    .foregroundColor(claim.showsMark ? Theme.verify : Theme.textMuted)
            }
        }

        // The key-naming sentences render only while a key is present or
        // still loading — a sentence pointing at a missing card is a lie.
        if !claim.needsKeyCard || key != nil || loadingKey, let line = claim.line {
            Text(line)
                .font(.fqSubheadline)
                .foregroundColor(Theme.textSecondary)
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
                // Algorithm only — trust language belongs to the verdict.
                detail: key.algorithm.uppercased(),
                copyable: false
            )
        } else if loadingKey && claim.did != nil {
            ProgressView().tint(Theme.textMuted).padding(.vertical, 8)
        }

        // Opened from a message row: that row's own verdict, beneath the
        // identity it anchors — the verdict is never visually overridden.
        if msgId == nil, verdictMsgId != nil {
            Divider().padding(.vertical, 4)
            messageProof
        }
    }

    // ── Message: one signature's checked answer, and nothing else. ──

    @ViewBuilder private var messageProof: some View {
        let copy = answer.map { SignatureVerdict.copy($0, retrying: retriesLeft > 0) }
        VStack(spacing: Theme.Space.md) {
            if verifying || answer == nil {
                ProgressView().tint(Theme.textMuted).padding(.top, 8)
            } else {
                ZStack {
                    Circle()
                        .fill(verdictColor.opacity(0.14))
                        .frame(width: 72, height: 72)
                        .blur(radius: 10)
                    Image(systemName: verdictIcon)
                        .font(.system(size: 44, weight: .semibold))
                        .foregroundStyle(verdictColor)
                }
            }
            Text(copy?.heading ?? "Checking signature…")
                .font(.fqTitle3.weight(.bold))
                .foregroundColor(Theme.textPrimary)
                .multilineTextAlignment(.center)
            Text(copy?.line ?? "Asking the server whether this message's signature holds up.")
                .font(.fqSubheadline)
                .foregroundColor(answer == nil ? Theme.textSecondary : verdictColor)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 8)
        }
    }

    private var verdictIcon: String {
        guard let answer else { return "shield" }
        switch SignatureVerdict.tone(answer.outcome) {
        case .good: return "checkmark.shield.fill"
        case .bad: return "exclamationmark.shield.fill"
        case .quiet: return "shield"
        }
    }

    /// Colour follows the tone: green is sender-device proof alone, red is a
    /// mismatch alone, every can't-know is quiet — a fact, not a warning.
    private var verdictColor: Color {
        guard let answer else { return Theme.textMuted }
        switch SignatureVerdict.tone(answer.outcome) {
        case .good: return Theme.verify
        case .bad: return Theme.warning
        case .quiet: return Theme.textSecondary
        }
    }

    private var seal: some View {
        ZStack {
            Circle()
                .fill(Theme.verify.opacity(0.14))
                .frame(width: 96, height: 96)
                .blur(radius: 10)
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 64, weight: .semibold))
                .foregroundStyle(Theme.verify)
                .shadow(color: Theme.verify.opacity(0.5), radius: 16)
        }
        .padding(.top, 8)
    }

    private func proofCard(label: String, icon: String, value: String,
                           detail: String?, copyable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(Theme.accent)
                Text(label.uppercased())
                    .font(.fqCaption2.weight(.bold))
                    .foregroundColor(Theme.textMuted)
                    .kerning(0.6)
                Spacer()
                if copyable {
                    Button {
                        UIPasteboard.general.string = value
                        withAnimation { copied = true }
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
                            withAnimation { copied = false }
                        }
                    } label: {
                        Text(copied ? "Copied" : "Copy")
                            .font(.fqCaption2.weight(.semibold))
                            .foregroundColor(copied ? Theme.verify : Theme.accent)
                    }
                }
            }
            Text(value)
                .font(.fqMonoCaption)
                .foregroundColor(Theme.textPrimary)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
            if let detail {
                Text(detail)
                    .font(.fqCaption2)
                    .foregroundColor(Theme.textMuted)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(.thin)
    }

    /// Ask the server to check this message's signature and report exactly
    /// what came back. The one can't-check a retry can outrun is a key on
    /// another server — answering the request is what starts the fetch.
    private func loadVerification() async {
        guard let target = verdictMsgId else { return }
        guard msgId == nil ? rowSigned : signed else {
            answer = VerifyAnswer(outcome: .unsigned)
            retriesLeft = 0
            return
        }
        if let remembered = appState.checkedVerdicts[target] {
            answer = remembered
            retriesLeft = 0
            return
        }
        while true {
            verifying = true
            let result = await Self.check(msgId: target)
            verifying = false
            answer = result
            if SignatureVerdict.worthCaching(result) {
                appState.checkedVerdicts[target] = result
            }
            guard result.transient, retriesLeft > 0 else { break }
            retriesLeft -= 1
            try? await Task.sleep(nanoseconds: Self.retryDelay)
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
            return VerifyAnswer(outcome: .unreachable)
        }
        return SignatureVerdict.parse(status: http.statusCode, body: data)
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
}
