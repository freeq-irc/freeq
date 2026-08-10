import SwiftUI

/// The differentiator, made tangible: the decentralized identifier that IS
/// this person, the key their messages are signed with, and — when the reader
/// asked about a specific message — what checking that message's signature
/// actually came back as.
///
/// The answer leads when there is one. A checked verdict is what the reader
/// asked for, so it is the first thing on screen and the identity cards sit
/// underneath it; leading with a large green seal would let identity read as
/// an answer about the signature, which it is not. Green is sender-device
/// proof only: the server vouching for what it received is a fact worth
/// stating, and it stays quiet (ruled 2026-08-07 — valid is not verified).
struct VerifiedProofSheet: View {
    /// The sender's DID, when we've resolved one. nil = a sender whose
    /// identity hasn't hydrated yet (key card is skipped).
    let did: String?
    var handle: String? = nil
    var displayName: String? = nil
    var nick: String? = nil
    /// Set when the reader asked about one specific message.
    var msgId: String? = nil

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

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 16) {
                    if msgId != nil {
                        messageVerdict
                            .padding(.top, 20)
                    } else {
                        seal
                            .padding(.top, 20)
                    }

                    VStack(spacing: 4) {
                        Text(displayName ?? handle.map { "@\($0)" } ?? nick ?? "Verified identity")
                            .font(.title3.weight(.bold))
                            .foregroundStyle(Theme.textPrimary)
                            .multilineTextAlignment(.center)
                        Text("Verified via the AT Protocol")
                            .font(.caption)
                            .foregroundStyle(Theme.verified)
                    }

                    Text("This is a real, self-owned identity: the identifier below is theirs, resolved through the AT Protocol, and nobody else can claim it.")
                        .font(.subheadline)
                        .foregroundStyle(Theme.textSecondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 8)

                    if let did {
                        proofCard(
                            label: "Decentralized identifier",
                            icon: "person.text.rectangle",
                            value: did,
                            detail: handle.map { "resolves to @\($0)" },
                            copyable: true
                        )
                    } else {
                        Text("This sender's identity hasn't resolved yet.")
                            .font(.caption)
                            .foregroundStyle(Theme.textTertiary)
                    }

                    if let key {
                        proofCard(
                            label: "Message signing key",
                            icon: "signature",
                            value: key.publicKey,
                            detail: "\(key.algorithm.uppercased()) · \(key.sourceLabel)",
                            copyable: false
                        )
                    } else if loadingKey && did != nil {
                        ProgressView()
                            .controlSize(.small)
                            .padding(.vertical, 8)
                    }
                }
                .padding(.horizontal, 20)
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
        .frame(width: 380, height: 480)
        .background(Theme.appBackground)
        .task { await loadKey() }
        .task { await loadVerification() }
    }

    /// The checked answer for one message — what the server said, in the words
    /// every client uses for that state.
    @ViewBuilder private var messageVerdict: some View {
        let copy = answer.map { SignatureVerdict.copy($0, retrying: retriesLeft > 0) }
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: verdictIcon)
                .font(.system(size: 20))
                .foregroundStyle(verdictColor)
            VStack(alignment: .leading, spacing: 3) {
                Text(copy?.heading ?? "Checking signature…")
                    .font(.headline)
                    .foregroundStyle(verdictColor)
                Text(copy?.line ?? "Asking the server whether this message's signature holds up.")
                    .font(.caption)
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            if verifying {
                ProgressView().controlSize(.small)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.surfaceSoft))
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
        guard let did else { loadingKey = false; return }
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
        guard let msgId else { return }
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
