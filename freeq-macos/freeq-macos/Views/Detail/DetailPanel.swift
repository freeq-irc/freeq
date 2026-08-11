import SwiftUI

/// Right panel — Member list for channels, Profile for DMs, P2P info
struct DetailPanel: View {
    @Environment(AppState.self) private var appState

    private var channel: ChannelState? { appState.activeChannelState }

    var body: some View {
        VStack(spacing: 0) {
            if let ch = channel {
                if ch.isChannel {
                    MemberListView(channel: ch)
                } else {
                    // A DID-keyed DM buffer resolves to the peer's nick for
                    // display/presence; the key itself supplies the DID.
                    DMProfilePanel(nick: appState.displayNameForKey(ch.name), bufferKey: ch.name)
                }
            }
        }
        .background(Theme.detailBackground)
    }
}

struct MemberListView: View {
    @Environment(AppState.self) private var appState
    let channel: ChannelState
    @State private var searchText: String = ""

    private var ops: [MemberInfo] { filtered.filter(\.isOp).sorted { $0.nick < $1.nick } }
    private var voiced: [MemberInfo] { filtered.filter { !$0.isOp && $0.isVoiced }.sorted { $0.nick < $1.nick } }
    private var regular: [MemberInfo] { filtered.filter { !$0.isOp && !$0.isVoiced }.sorted { $0.nick < $1.nick } }

    private var filtered: [MemberInfo] {
        let base = channel.uniqueMembers(resolveDid: { ProfileCache.shared.did(for: $0) })
        if searchText.isEmpty { return base }
        let q = searchText.lowercased()
        return base.filter { $0.nick.lowercased().contains(q) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.caption)
                    .foregroundStyle(Theme.textTertiary)
                TextField("Search members", text: $searchText)
                    .textFieldStyle(.plain)
                    .font(.caption)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(RoundedRectangle(cornerRadius: 9).fill(Theme.surface))
            .overlay(RoundedRectangle(cornerRadius: 9).strokeBorder(Theme.borderSoft, lineWidth: 1))
            .padding(.horizontal, 12)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider().overlay(Theme.borderSoft)

            HStack {
                Text("\(channel.uniqueMemberCount(resolveDid: { ProfileCache.shared.did(for: $0) })) members")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Theme.textSecondary)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if !ops.isEmpty {
                        memberSection("Operators — \(ops.count)", members: ops)
                    }
                    if !voiced.isEmpty {
                        memberSection("Voiced — \(voiced.count)", members: voiced)
                    }
                    if !regular.isEmpty {
                        memberSection("Online — \(regular.count)", members: regular)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .background(Theme.detailBackground)
    }

    @ViewBuilder
    func memberSection(_ title: String, members: [MemberInfo]) -> some View {
        Text(title)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(Theme.textTertiary)
            .textCase(.uppercase)
            .padding(.horizontal, 12)
            .padding(.top, 12)
            .padding(.bottom, 4)

        ForEach(members) { member in
            MemberRow(member: member, channelName: channel.name)
        }
    }
}

struct MemberRow: View {
    @Environment(AppState.self) private var appState
    let member: MemberInfo
    let channelName: String
    @State private var showProfile = false
    @State private var reportTarget: ReportTarget?

    private var isSelf: Bool {
        member.nick.lowercased() == appState.nick.lowercased()
    }
    private var memberDid: String? {
        member.did ?? ProfileCache.shared.did(for: member.nick)
    }

    private var profile: ProfileCache.Profile? {
        ProfileCache.shared.profile(for: member.nick)
    }

    private var hasDid: Bool {
        // Only an AT Protocol identity earns the seal (IdentityClaim rule);
        // a self-issued did:key does not.
        // A roster row is a present person, so the cache lookup here is
        // presence-gated by construction.
        claimForPerson(input: PersonClaimInput(
            binding: member.did ?? ProfileCache.shared.did(for: member.nick),
            seenOnlyViaPeer: false,
            viaPeerOrigin: nil,
            viaPeerHadAccount: false,
            lookup: .notAsked
        )).showsMark
    }

    var body: some View {
        HStack(spacing: 8) {
            // Avatar with presence indicator
            AvatarView(nick: member.nick, size: 28)
                .overlay(alignment: .bottomTrailing) {
                    Circle()
                        .fill(member.isAway ? Theme.warning : Theme.success)
                        .frame(width: 8, height: 8)
                        .overlay(
                            Circle().strokeBorder(Theme.detailBackground, lineWidth: 1.5)
                        )
                }

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 3) {
                    if member.isOp {
                        Image(systemName: "shield.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(Theme.warning)
                    } else if member.isHalfop {
                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 9))
                            .foregroundStyle(Theme.blue)
                    } else if !member.prefix.isEmpty {
                        Text(member.prefix)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(Theme.warning)
                    }

                    // Display name or nick
                    if let displayName = profile?.displayName, !displayName.isEmpty {
                        Text(displayName)
                            .font(.system(.body, weight: member.isAway ? .regular : .medium))
                            .foregroundStyle(member.isAway ? Theme.textSecondary : Theme.textPrimary)
                            .lineLimit(1)
                    } else {
                        Text(member.nick)
                            .font(.system(.body, weight: member.isAway ? .regular : .medium))
                            .foregroundStyle(member.isAway ? Theme.textSecondary : Theme.textPrimary)
                            .lineLimit(1)
                    }

                    // Verified badge
                    if hasDid {
                        Image(systemName: "checkmark.seal.fill")
                            .font(.caption2)
                            .foregroundStyle(Theme.verified)
                            .help("AT Protocol identity")
                    }

                    if member.isAway {
                        Text("Away")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(Theme.warning)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Theme.warning.opacity(0.14))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                }

                // Handle or away message
                if let handle = profile?.handle {
                    Text("@\(handle)")
                        .font(.caption2)
                        .foregroundStyle(Theme.textTertiary)
                        .lineLimit(1)
                } else if member.isAway, let away = member.awayMsg {
                    Text(away)
                        .font(.caption2)
                        .foregroundStyle(Theme.textTertiary)
                        .lineLimit(1)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .background(RoundedRectangle(cornerRadius: 9).fill(Color.clear))
        .onTapGesture {
            // Clicking yourself opens your own card too (see your status,
            // handle, proof) — the same card everyone else sees of you.
            showProfile = true
        }
        .sheet(isPresented: $showProfile) {
            UserProfileSheet(nick: member.nick)
                .environment(appState)
        }
        .contextMenu {
            Button("Send Message") {
                appState.openDM(with: member.nick)
            }
            if let handle = profile?.handle {
                Button("View on Bluesky") {
                    if let url = URL(string: "https://bsky.app/profile/\(handle)") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
            Button("WHOIS") {
                appState.sendWhois(member.nick)
            }
            if !isSelf {
                Divider()
                Button("Report…") {
                    reportTarget = ReportTarget(nick: member.nick, did: memberDid)
                }
                if appState.isBlocked(nick: member.nick, did: memberDid) {
                    Button("Unblock \(member.nick)") {
                        appState.unblockUser(nick: member.nick, did: memberDid)
                    }
                } else {
                    Button("Block \(member.nick)", role: .destructive) {
                        appState.blockUser(nick: member.nick, did: memberDid)
                    }
                }
            }
            Divider()
            Button("Op") { appState.setMode(channelName, "+o", member.nick) }
            Button("Deop") { appState.setMode(channelName, "-o", member.nick) }
            Button("Voice") { appState.setMode(channelName, "+v", member.nick) }
            Divider()
            Button("Kick", role: .destructive) {
                appState.kickUser(channelName, member.nick)
            }
        }
        .reportDialog($reportTarget) { t, reason in
            appState.reportUser(nick: t.nick, did: t.did, reason: reason)
        }
    }
}

struct DMProfilePanel: View {
    @Environment(AppState.self) private var appState
    let nick: String
    /// The thread's buffer key — when DID-keyed, it IS the peer's DID, so
    /// identity is known even before a profile/WHOIS resolves the nick.
    var bufferKey: String? = nil
    @State private var showIdentityDetails = false

    private var isOnline: Bool { appState.isNickOnline(nick) }
    private var awayMsg: String? { appState.awayStatus(for: nick) }
    private var isP2p: Bool { appState.p2pDMActive.contains(nick.lowercased()) }
    private var profile: ProfileCache.Profile? { ProfileCache.shared.profile(for: nick) }
    private var did: String? { ProfileCache.shared.did(for: nick) }
    private var knownDid: String? {
        did ?? profile?.did
            ?? bufferKey.flatMap { DidDisplay.isDid($0) ? $0 : nil }
    }
    private var displayName: String {
        if let displayName = profile?.displayName, !displayName.isEmpty {
            return displayName
        }
        return nick
    }
    private var statusText: String {
        if !isOnline { return "Offline - messages saved" }
        if let awayMsg, !awayMsg.isEmpty { return "Away: \(awayMsg)" }
        return "Online"
    }
    private var statusIcon: String {
        if !isOnline { return "circle" }
        return awayMsg == nil ? "circle.fill" : "moon.fill"
    }
    private var statusColor: Color {
        if !isOnline { return Theme.textTertiary }
        return awayMsg == nil ? Theme.success : Theme.warning
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                DMProfileBanner(nick: nick, bannerURL: profile?.bannerURL)
                    .overlay(alignment: .bottom) {
                        AvatarView(nick: nick, size: 72)
                            .overlay(alignment: .bottomTrailing) {
                                Circle()
                                    .fill(statusColor)
                                    .frame(width: 16, height: 16)
                                    .overlay(Circle().strokeBorder(Theme.detailBackground, lineWidth: 2.5))
                            }
                            .offset(y: 36)
                    }

                VStack(spacing: 16) {
                    VStack(spacing: 6) {
                        Text(displayName)
                            .font(.title3.weight(.semibold))
                            .foregroundStyle(Theme.textPrimary)
                            .lineLimit(2)
                            .multilineTextAlignment(.center)
                            .padding(.top, 40)

                        if displayName != nick {
                            Text(nick)
                                .font(.subheadline)
                                .foregroundStyle(Theme.textSecondary)
                                .lineLimit(1)
                        }

                        if let handle = profile?.handle {
                            HStack(spacing: 4) {
                                Text("@\(handle)")
                                    .font(.callout.weight(.medium))
                                    .foregroundStyle(Theme.accent)
                                Image(systemName: "arrow.up.right")
                                    .font(.caption)
                                    .foregroundStyle(Theme.accent)
                            }
                        }

                        HStack(spacing: 8) {
                            statusPill
                            if knownDid != nil {
                                Label("Verified", systemImage: "checkmark.seal.fill")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(Theme.verified)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Capsule().fill(Theme.verified.opacity(0.10)))
                            }
                        }
                    }

                    if isP2p {
                        Label("Direct P2P available", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(Theme.success)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .frame(maxWidth: .infinity)
                            .background(RoundedRectangle(cornerRadius: 10).fill(Theme.success.opacity(0.09)))
                    }

                    if let desc = profile?.description, !desc.isEmpty {
                        Text(desc)
                            .font(.callout)
                            .lineSpacing(3)
                            .foregroundStyle(Theme.textSecondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    if let profile, hasStats(profile) {
                        HStack(spacing: 0) {
                            statItem(count: profile.postsCount ?? 0, label: "Posts")
                            statItem(count: profile.followersCount ?? 0, label: "Followers")
                            statItem(count: profile.followsCount ?? 0, label: "Following")
                        }
                        .padding(.vertical, 12)
                        .background(RoundedRectangle(cornerRadius: 12).fill(Theme.surface))
                        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.borderSoft, lineWidth: 1))
                    }

                    VStack(spacing: 8) {
                        if let handle = profile?.handle,
                           let blueSkyURL = Validation.makeBlueSkyProfileURL(handle: handle) {
                            Link(destination: blueSkyURL) {
                                actionLabel("View on Bluesky", systemImage: "arrow.up.right.square")
                                    .foregroundStyle(Theme.surface)
                                    .background(RoundedRectangle(cornerRadius: 12).fill(Theme.accent))
                            }
                            .buttonStyle(.plain)
                        }

                        Button {
                            // Refreshes the panel's identity fields, not a chat
                            // dump — keep the reply out of the conversation.
                            appState.sendWhois(nick, display: false)
                            ProfileCache.shared.fetchProfileIfPossible(nick: nick)
                        } label: {
                            actionLabel("Refresh identity", systemImage: "arrow.clockwise")
                                .foregroundStyle(Theme.textPrimary)
                                .background(RoundedRectangle(cornerRadius: 12).fill(Theme.surface))
                                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.borderSoft, lineWidth: 1))
                        }
                        .buttonStyle(.plain)
                    }

                    identityDisclosure
                }
                .padding(16)
            }
        }
        .background(Theme.detailBackground)
        .task(id: nick) {
            // Background identity hydration only — discovers the DID/handle to
            // fill this panel. display:false keeps the raw WHOIS reply out of
            // the conversation (it used to dump into every DM on open).
            appState.sendWhois(nick, display: false)
            ProfileCache.shared.fetchProfileIfPossible(nick: nick)
        }
    }

    private var statusPill: some View {
        Label(statusText, systemImage: statusIcon)
            .font(.caption.weight(.semibold))
            .foregroundStyle(statusColor)
            .lineLimit(1)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Capsule().fill(statusColor.opacity(0.10)))
    }

    private var identityDisclosure: some View {
        DisclosureGroup(isExpanded: $showIdentityDetails) {
            VStack(alignment: .leading, spacing: 10) {
                identityRow(label: "Nick", value: nick)
                if let handle = profile?.handle {
                    identityRow(label: "Bluesky", value: "@\(handle)")
                }
                if let knownDid {
                    identityRow(label: "DID", value: knownDid, monospaced: true)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(knownDid, forType: .string)
                    } label: {
                        Label("Copy DID", systemImage: "doc.on.doc")
                            .font(.caption.weight(.medium))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.accent)
                }
                Button {
                    appState.sendWhois(nick)
                } label: {
                    Label("Run WHOIS", systemImage: "terminal")
                        .font(.caption.weight(.medium))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textSecondary)
            }
            .padding(.top, 10)
        } label: {
            Label("Identity details", systemImage: "person.badge.key")
                .font(.caption.weight(.semibold))
                .foregroundStyle(Theme.textSecondary)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(Theme.surfaceSoft))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.borderSoft, lineWidth: 1))
    }

    private func actionLabel(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.callout.weight(.semibold))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 11)
            .contentShape(RoundedRectangle(cornerRadius: 12))
    }

    private func identityRow(label: String, value: String, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(Theme.textTertiary)
                .textCase(.uppercase)
            Text(value)
                .font(monospaced ? .system(size: 10, design: .monospaced) : .caption)
                .foregroundStyle(Theme.textSecondary)
                .lineLimit(3)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func hasStats(_ profile: ProfileCache.Profile) -> Bool {
        (profile.postsCount ?? 0) > 0 ||
            (profile.followersCount ?? 0) > 0 ||
            (profile.followsCount ?? 0) > 0
    }

    private func statItem(count: Int, label: String) -> some View {
        VStack(spacing: 1) {
            Text(formatCount(count))
                .font(.callout.weight(.semibold))
                .foregroundStyle(Theme.textPrimary)
            Text(label)
                .font(.caption2)
                .foregroundStyle(Theme.textTertiary)
        }
        .frame(maxWidth: .infinity)
    }

    private func formatCount(_ count: Int) -> String {
        if count >= 1_000_000 {
            return String(format: "%.1fM", Double(count) / 1_000_000).replacingOccurrences(of: ".0", with: "")
        }
        if count >= 1_000 {
            return String(format: "%.1fK", Double(count) / 1_000).replacingOccurrences(of: ".0", with: "")
        }
        return "\(count)"
    }
}

private struct DMProfileBanner: View {
    let nick: String
    let bannerURL: URL?

    var body: some View {
        Group {
            if let bannerURL {
                AsyncImage(url: bannerURL) { phase in
                    switch phase {
                    case .success(let image):
                        image
                            .resizable()
                            .aspectRatio(contentMode: .fill)
                    default:
                        fallback
                    }
                }
            } else {
                fallback
            }
        }
        .frame(height: 96)
        .clipped()
    }

    private var fallback: some View {
        LinearGradient(
            colors: [
                Theme.nickColor(for: nick).opacity(0.30),
                Theme.accentSoft,
                Theme.surfaceSoft,
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }
}
