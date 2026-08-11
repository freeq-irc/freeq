import SwiftUI

/// Rich user profile sheet: avatar, Bluesky info, shared channels, DID.
struct UserProfileSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    let nick: String
    /// The peer that relayed the message this card was opened from. Anything
    /// relayed is peer-vouched and claims nothing here.
    var origin: String? = nil
    /// Opened from a local message whose sender has no DID on file — already
    /// the guest answer, so no WHOIS is sent and none is needed.
    /// The anchoring row's evidence, when opened from a message.
    var account: String? = nil
    var rowTime: Date? = nil
    var senderPresent: Bool = false

    @State private var reportTarget: ReportTarget?
    @State private var showProof = false

    private var profile: ProfileCache.Profile? {
        ProfileCache.shared.profile(for: nick)
    }
    private var did: String? {
        // ProfileCache only knows AT-resolved profiles; didForNick covers
        // everyone the app has learned a binding for, did:key bots included.
        ProfileCache.shared.did(for: nick) ?? appState.didForNick(nick)
    }
    // The SDK owns the precedence: live identity first, then the anchoring
    // row's evidence, then the lookup machine. A binding remembered from an
    // earlier session never votes — that is how one absent sender used to
    // read differently here than on web.
    private var claim: IdentityClaim {
        claimForSender(
            input: MessageClaimInput(
                account: account,
                origin: origin,
                senderPresent: senderPresent || appState.isNickPresent(nick),
                senderLiveDid: isSelf ? appState.authenticatedDID : appState.liveDidForNick(nick),
                rowTimeUnix: rowTime.map { UInt64($0.timeIntervalSince1970) }
            ),
            lookup: appState.personLookup(for: nick)
        )
    }
    private var isSelf: Bool {
        nick.lowercased() == appState.nick.lowercased()
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding(.trailing, 12)
            .padding(.top, 8)

            // Scrollable body — content length varies (bio length, shared-channel
            // count), so it must scroll rather than clip the pinned action buttons.
            ScrollView {
                VStack(spacing: 0) {
                    // Avatar
                    AvatarView(nick: nick, size: 72)
                        .padding(.top, 4)

                    // Name
                    if let displayName = profile?.displayName, !displayName.isEmpty {
                        Text(displayName)
                            .font(.title2.weight(.bold))
                            .padding(.top, 8)
                        Text("@\(profile?.handle ?? nick)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    } else {
                        Text(nick)
                            .font(.title2.weight(.bold))
                            .padding(.top, 8)
                    }

                    // What this client can honestly say about who this is —
                    // the same claim rule and language as every other surface.
                    // An ask that is out shows as motion, not as a sentence
                    // nobody can finish reading before it is replaced.
                    if claim.isPending {
                        ProgressView().controlSize(.small)
                    }
                    if let label = claim.label {
                        Text(label)
                            .font(.caption)
                            .foregroundStyle(claim.showsMark ? Theme.verified : Theme.textTertiary)
                    }
                    // The proof sheet is where the explanation lives; this
                    // card carries the sentence only for someone with no DID,
                    // where there is no sheet to open and the card is the
                    // whole answer. Everyone else gets the label, and the
                    // words are one click away behind "Identity proof".
                    if claim.did == nil, let line = claim.line {
                        Text(line)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.horizontal, 24)
                            .padding(.top, 2)
                    }

                    // DID — click for the identity/signing-key proof card
                    if let did {
                        Button { showProof = true } label: {
                            // One explicit stack: two sibling views in a
                            // button's label lay out side by side, which put
                            // the affordance next to the identifier instead of
                            // under it.
                            VStack(spacing: 3) {
                                HStack(spacing: 4) {
                                    if claim.showsMark {
                                        Image(systemName: "checkmark.seal.fill")
                                            .font(.caption)
                                            .foregroundStyle(.blue)
                                    }
                                    Text(did)
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                                // A monospace string doesn't look like a way
                                // in, and for a self-created identity it is
                                // the only one — no mark on a row leads here.
                                HStack(spacing: 2) {
                                    Text("Identity proof")
                                        .font(.caption)
                                    Image(systemName: "chevron.right")
                                        .font(.caption2)
                                }
                                .foregroundStyle(Theme.accent)
                            }
                            // Constrain the row to the card so middle
                            // truncation engages instead of overflowing.
                            .frame(maxWidth: .infinity)
                            .padding(.horizontal, 24)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(.top, 4)
                        .help(claim.label.map { "\($0) — click for proof" } ?? "Click for proof")
                    }

                    // Bio
                    if let bio = profile?.description, !bio.isEmpty {
                        Text(bio)
                            .font(.body)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 24)
                            .padding(.top, 8)
                    }

                    // Stats
                    if let p = profile {
                        HStack(spacing: 24) {
                            StatItem(label: "Posts", value: p.postsCount ?? 0)
                            StatItem(label: "Followers", value: p.followersCount ?? 0)
                            StatItem(label: "Following", value: p.followsCount ?? 0)
                        }
                        .padding(.top, 12)
                    }

                    Divider().padding(.vertical, 12)

                    // Shared channels
                    let sharedChannels = appState.channels.filter { ch in
                        ch.members.contains(where: { $0.nick.lowercased() == nick.lowercased() })
                    }
                    if !sharedChannels.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Shared Channels")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 24)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            ForEach(sharedChannels) { ch in
                                Button {
                                    appState.activeChannel = ch.name
                                    dismiss()
                                } label: {
                                    HStack {
                                        Image(systemName: "number")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                        Text(ch.name.replacingOccurrences(of: "#", with: ""))
                                            .font(.body)
                                        Spacer()
                                        Text("\(ch.members.count)")
                                            .font(.caption)
                                            .foregroundStyle(.tertiary)
                                    }
                                    .padding(.horizontal, 24)
                                    .padding(.vertical, 4)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }

            // Actions — pinned below the scroll area so they never clip.
            VStack(spacing: 8) {
                HStack(spacing: 12) {
                    Button("Send Message") {
                        appState.openDM(with: nick)
                        dismiss()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.regular)

                    // Only an AT Protocol identity has a Bluesky page; a
                    // self-issued did:key resolves nowhere.
                    if claim.state == .atProtocol,
                       let handle = profile?.handle ?? did.map({ _ in nick }),
                       let blueSkyURL = Validation.makeBlueSkyProfileURL(handle: handle) {
                        Link("View on Bluesky", destination: blueSkyURL)
                            .font(.body)
                    }
                }

                // Safety
                if !isSelf {
                    HStack(spacing: 16) {
                        if appState.isBlocked(nick: nick, did: did) {
                            Button("Unblock") {
                                appState.unblockUser(nick: nick, did: did)
                            }
                            .buttonStyle(.plain)
                            .font(.caption)
                            .foregroundStyle(Theme.accent)
                        } else {
                            Button("Report…") {
                                reportTarget = ReportTarget(nick: nick, did: did)
                            }
                            .buttonStyle(.plain)
                            .font(.caption)
                            .foregroundStyle(Theme.danger)
                            Button("Block") {
                                appState.blockUser(nick: nick, did: did)
                                dismiss()
                            }
                            .buttonStyle(.plain)
                            .font(.caption)
                            .foregroundStyle(Theme.danger)
                        }
                    }
                }
            }
            .padding(.top, 12)
            .padding(.bottom, 16)
        }
        .frame(width: 340, height: 480)
        .reportDialog($reportTarget) { t, reason in
            appState.reportUser(nick: t.nick, did: t.did, reason: reason)
            dismiss()
        }
        .sheet(isPresented: $showProof) {
            VerifiedProofSheet(
                did: claim.did,
                handle: profile?.handle,
                displayName: profile?.displayName,
                nick: nick,
                origin: origin,
                account: account,
                rowTimeUnix: rowTime.map { UInt64($0.timeIntervalSince1970) },
                senderPresent: senderPresent || appState.isNickPresent(nick)
            )
            .environment(appState)
        }
        .onAppear {
            // Ask who this is, and let the card say an ask is out — the same
            // background WHOIS as before, tracked so "unknown" is only ever
            // shown after an answer, never before one.
            if origin == nil, !isSelf { appState.lookUpIdentity(nick: nick) }
            // Fetch profile if we have DID
            if let did, profile == nil {
                ProfileCache.shared.fetchProfile(nick: nick, did: did)
            }
        }
    }
}

struct StatItem: View {
    let label: String
    let value: Int

    var body: some View {
        VStack(spacing: 2) {
            Text("\(value)")
                .font(.headline)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Previews

// The canvas renders these without building or running the app. Bio, stats and
// shared channels stay empty — they come from a live profile fetch — so what
// these show is the identity block and the identifier row beneath it, which is
// where the layout actually varies by state.

#Preview("Profile — AT Protocol") {
    ProfileCache.shared.setDid("did:plc:4qsyxmnsblo4luuycm3572bq", for: "chad")
    return UserProfileSheet(nick: "chad")
        .environment(AppState())
}

#Preview("Profile — self-created") {
    ProfileCache.shared.setDid("did:key:z6MkpdyZFX7tagEUaCBp8bwVgqBqzvLEDdi8E", for: "lobot")
    return UserProfileSheet(nick: "lobot")
        .environment(AppState())
}

#Preview("Profile — relayed") {
    ProfileCache.shared.setDid("did:plc:padwfc6z5dke5g7c3nzratdy", for: "nandi-test")
    return UserProfileSheet(nick: "nandi-test", origin: "irc.freeq.at")
        .environment(AppState())
}

#Preview("Profile — nobody on file") {
    UserProfileSheet(nick: "stranger")
        .environment(AppState())
}
