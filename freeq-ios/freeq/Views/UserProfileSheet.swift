import SwiftUI

/// Profile sheet shown when tapping a user in member list or message header.
struct UserProfileSheet: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    let nick: String
    /// The peer that relayed the message this card was opened from. Anything
    /// relayed is peer-vouched and claims nothing here.
    var origin: String? = nil
    /// The anchoring row's evidence, when opened from a message.
    var account: String? = nil
    var rowTime: Date? = nil
    /// When opened from People search / graph browsing (not a freeq member), the
    /// AT identifier (DID or handle) to show directly — bypasses nick→DID
    /// resolution and the freeq-only actions.
    var directActor: String? = nil
    @State private var profile: BlueskyProfile? = nil
    @State private var loading = true
    @State private var recentPosts: [BskyFeedItem] = []
    @State private var loadingFeed = false
    /// The AT identifier we actually resolved/used — powers the tappable
    /// follower/following graph lists.
    @State private var resolvedActor: String? = nil
    /// What freeq knows about this identity — presence, nick, shared channels.
    @State private var freeqIdentity: FreeqIdentity? = nil
    @State private var showProof = false
    @State private var reportSource: ReportTarget? = nil
    /// Viewer↔subject graph relationship (follows you / mutual).
    @State private var relationship: BlueskyGraph.Relationship? = nil

    /// True when this is a stranger from the graph, not a freeq member.
    private var isDirect: Bool { directActor != nil }

    private var isSelf: Bool { nick.lowercased() == appState.nick.lowercased() }

    /// The identity the claim may treat as live: the session's own DID, the
    /// live room binding, or — for a graph-browse profile — the AT identifier
    /// the person was opened by. Never a remembered cache.
    private var liveDid: String? {
        if isDirect { return resolvedActor?.hasPrefix("did:") == true ? resolvedActor : nil }
        if isSelf { return appState.authenticatedDID }
        return appState.liveDidForNick(nick)
    }

    /// The DID this card can display and open the proof sheet for: the
    /// claim's own answer first, then what the app knows for display —
    /// mirrors macOS (ProfileCache there). The display layer never votes on
    /// the claim; it only keeps the proof path reachable.
    private var proofDid: String? {
        if let d = claim.did { return d }
        if isDirect { return resolvedActor?.hasPrefix("did:") == true ? resolvedActor : nil }
        return appState.didForNick(nick) ?? AvatarCache.shared.did(for: nick)
    }

    // The SDK owns the precedence: live identity first, then the anchoring
    // row's evidence, then the lookup machine. A binding remembered from an
    // earlier session never votes.
    private var claim: IdentityClaim {
        claimForSender(
            input: MessageClaimInput(
                account: account,
                origin: origin,
                senderPresent: !isDirect && appState.isNickPresent(nick),
                senderLiveDid: liveDid,
                rowTimeUnix: rowTime.map { UInt64($0.timeIntervalSince1970) }
            ),
            lookup: isDirect ? .notAsked : appState.personLookup(for: nick)
        )
    }

    /// The freeq nick we can actually Message, if this identity is on freeq and
    /// isn't us. Falls back to the nick this sheet was opened with when the
    /// directory lookup has nothing — did:key identities (bots) never resolve
    /// there, but a channel member with a known nick is still messageable
    /// (startDM canonicalizes to the DID-keyed thread via getOrCreateDM).
    private var messageableNick: String? {
        if let n = freeqIdentity?.nick, !n.isEmpty,
           n.lowercased() != appState.nick.lowercased() {
            return n
        }
        guard !isDirect, !nick.isEmpty,
              nick.lowercased() != appState.nick.lowercased() else { return nil }
        return nick
    }

    /// Channels we share with this person (intersection of theirs and ours).
    private var sharedChannels: [String] {
        guard let theirs = freeqIdentity?.channels else { return [] }
        let mine = Set(appState.channels.map { $0.name.lowercased() })
        return theirs.filter { mine.contains($0.lowercased()) }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bgPrimary.ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 20) {
                        // Avatar
                        UserAvatar(nick: nick, size: 80)
                            .padding(.top, 24)

                        // Name + what this client can honestly say about who
                        // this is — the same claim rule and language as every
                        // other surface.
                        VStack(spacing: 4) {
                            HStack(spacing: 6) {
                                Text(headerTitle)
                                    .font(.fqTitle3.weight(.bold))
                                    .foregroundColor(Theme.textPrimary)

                                // The mark opens the proof behind the claim.
                                if claim.showsMark {
                                    Button { showProof = true } label: {
                                        VerifiedBadge(size: 16)
                                    }
                                    .buttonStyle(.plain)
                                }
                            }

                            // An ask that is out shows as motion, not as a
                            // sentence nobody can finish reading before it is
                            // replaced. A graph-browse profile makes no claim
                            // until its identifier resolves to a DID.
                            if claim.isPending {
                                ProgressView()
                                    .tint(Theme.textMuted)
                                    .scaleEffect(0.8)
                            }
                            if !isDirect || claim.did != nil, let label = claim.label {
                                Text(label)
                                    .font(.fqFootnote)
                                    .foregroundColor(claim.showsMark ? Theme.verify : Theme.textMuted)
                            }

                            if let away = appState.awayMessage(for: nick) {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(Theme.warning)
                                        .frame(width: 8, height: 8)
                                    Text("Away")
                                        .font(.fqCaption.weight(.semibold))
                                        .foregroundColor(Theme.warning)
                                }
                                if !away.isEmpty {
                                    Text(away)
                                        .font(.fqFootnote)
                                        .foregroundColor(Theme.textMuted)
                                }
                            }

                            if let p = profile {
                                if let displayName = p.displayName, !displayName.isEmpty {
                                    Text(displayName)
                                        .font(.fqSubheadline)
                                        .foregroundColor(Theme.textSecondary)
                                }
                                HStack(spacing: 6) {
                                    Text("@\(p.handle)")
                                        .font(.fqFootnote)
                                        .foregroundColor(Theme.textMuted)
                                    if let rel = relationship {
                                        if rel.isMutual {
                                            Text("mutual")
                                                .font(.system(size: 10, weight: .semibold))
                                                .foregroundColor(Theme.verify)
                                                .padding(.horizontal, 6).padding(.vertical, 2)
                                                .background(Theme.verify.opacity(0.14), in: Capsule())
                                        } else if rel.followsMe {
                                            Text("follows you")
                                                .font(.system(size: 10, weight: .semibold))
                                                .foregroundColor(Theme.iris)
                                                .padding(.horizontal, 6).padding(.vertical, 2)
                                                .background(Theme.iris.opacity(0.14), in: Capsule())
                                        }
                                    }
                                }
                            }
                        }

                        // The proof sheet is where the explanation lives; the
                        // card carries the sentence only for someone with no
                        // DID, where there is no sheet to open and the card is
                        // the whole answer. Everyone else gets the label, and
                        // the words are one tap away behind "Identity proof".
                        if claim.did == nil, !isDirect, let line = claim.line {
                            Text(line)
                                .font(.fqFootnote)
                                .foregroundColor(Theme.textSecondary)
                                .multilineTextAlignment(.center)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.horizontal, 32)
                        }

                        // DID — tap for the identity/signing-key proof card. A
                        // monospace string doesn't look like a way in, and for
                        // a self-issued identity it is the only one — no mark
                        // on a row leads here.
                        if let did = proofDid {
                            Button { showProof = true } label: {
                                VStack(spacing: 3) {
                                    Text(did)
                                        .font(.fqMonoCaption)
                                        .foregroundColor(Theme.textMuted)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    HStack(spacing: 2) {
                                        Text("Identity proof")
                                            .font(.fqFootnote)
                                        Image(systemName: "chevron.right")
                                            .font(.fqCaption2)
                                    }
                                    .foregroundColor(Theme.accent)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.horizontal, 24)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }

                        // Bio
                        if let bio = profile?.description, !bio.isEmpty {
                            Text(bio)
                                .font(.fqFootnote)
                                .foregroundColor(Theme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 32)
                        }

                        // Stats — Followers / Following are tappable into the
                        // navigable graph; Posts is informational.
                        if let p = profile {
                            HStack(spacing: 24) {
                                if let actor = resolvedActor {
                                    NavigationLink {
                                        GraphListView(title: "Followers", source: .followers(actor: actor))
                                    } label: {
                                        statItem(count: p.followersCount ?? 0, label: "Followers")
                                    }
                                    .buttonStyle(.plain)
                                    NavigationLink {
                                        GraphListView(title: "Following", source: .follows(actor: actor))
                                    } label: {
                                        statItem(count: p.followsCount ?? 0, label: "Following")
                                    }
                                    .buttonStyle(.plain)
                                } else {
                                    statItem(count: p.followersCount ?? 0, label: "Followers")
                                    statItem(count: p.followsCount ?? 0, label: "Following")
                                }
                                statItem(count: p.postsCount ?? 0, label: "Posts")
                            }
                            .padding(.vertical, 8)
                        }

                        // freeq presence — the freeq-native half of the profile.
                        if let fid = freeqIdentity, fid.isOnFreeq {
                            freeqCard(fid)
                        }

                        // Actions
                        VStack(spacing: 12) {
                            // Message — works for anyone freeq can reach, whether
                            // you opened them from a channel or found them in the
                            // graph. Resolved to their freeq nick.
                            if let target = messageableNick {
                                Button(action: { startDM(target) }) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "bubble.left.fill")
                                            .font(.system(size: 13))
                                        Text("Message")
                                            .font(.fqSubheadline.weight(.semibold))
                                    }
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 13)
                                    .background(Theme.signalGradient)
                                    .foregroundColor(Color(hex: "04121a"))
                                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                    .shadow(color: Theme.accent.opacity(0.3), radius: 10, y: 3)
                                }
                            }

                            // Follow / Following — a real graph write, delegated
                            // to the broker (which holds the OAuth session).
                            // Hidden until the deployed broker supports it.
                            if relationship != nil, appState.brokerToken != nil,
                               let actor = resolvedActor, actor.hasPrefix("did:"),
                               actor != appState.authenticatedDID {
                                followButton(actor: actor)
                            }

                            // View on Bluesky
                            if let p = profile,
                               let profileURL = URL(string: "https://bsky.app/profile/\((p.handle.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? p.handle))") {
                                Link(destination: profileURL) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "arrow.up.right")
                                            .font(.system(size: 13))
                                        Text("View on Bluesky")
                                            .font(.fqSubheadline.weight(.medium))
                                    }
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 12)
                                    .background(Theme.bgTertiary)
                                    .foregroundColor(Theme.textPrimary)
                                    .cornerRadius(10)
                                }
                            }

                            // Safety — block / report (not on your own profile).
                            if nick.lowercased() != appState.nick.lowercased() {
                                HStack(spacing: 12) {
                                    Button(role: .destructive) {
                                        reportSource = ReportTarget(nick: freeqIdentity?.nick ?? nick, did: resolvedActor)
                                    } label: {
                                        Label("Report", systemImage: "flag")
                                            .font(.fqFootnote.weight(.medium))
                                            .frame(maxWidth: .infinity)
                                            .padding(.vertical, 10)
                                            .background(Theme.bgTertiary, in: RoundedRectangle(cornerRadius: 10))
                                            .foregroundColor(Theme.danger)
                                    }
                                    Button {
                                        appState.blockUser(nick: freeqIdentity?.nick ?? nick, did: resolvedActor)
                                        dismiss()
                                    } label: {
                                        Label("Block", systemImage: "hand.raised")
                                            .font(.fqFootnote.weight(.medium))
                                            .frame(maxWidth: .infinity)
                                            .padding(.vertical, 10)
                                            .background(Theme.bgTertiary, in: RoundedRectangle(cornerRadius: 10))
                                            .foregroundColor(Theme.danger)
                                    }
                                }
                            }
                        }
                        .padding(.horizontal, 24)

                        if loading {
                            ProgressView()
                                .tint(Theme.textMuted)
                                .padding(.top, 8)
                        }

                        // Recent Bluesky posts
                        if !recentPosts.isEmpty {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("Recent Posts")
                                    .font(.fqFootnote.weight(.semibold))
                                    .foregroundColor(Theme.textMuted)
                                    .padding(.horizontal, 16)

                                ForEach(recentPosts, id: \.uri) { item in
                                    if let rkey = item.uri.split(separator: "/").last.map(String.init),
                                       let handle = profile?.handle {
                                        BlueskyEmbed(handle: handle, rkey: rkey)
                                            .padding(.horizontal, 16)
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.top, 16)
                        } else if loadingFeed {
                            ProgressView()
                                .tint(Theme.textMuted)
                                .padding(.top, 16)
                        }

                        Spacer()
                    }
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                        .foregroundColor(Theme.accent)
                }
            }
        }
        .preferredColorScheme(.dark)
        .task {
            // Ask who this is, and let the card say an ask is out — tracked so
            // "unknown" is only ever shown after an answer, never before one.
            // Relayed senders are the peer's to answer, never WHOISed here.
            if origin == nil, !isSelf, !isDirect {
                appState.lookUpIdentity(nick: nick)
            }
            await fetchProfile()
        }
        .sheet(isPresented: $showProof) {
            VerifiedProofSheet(
                did: claim.did,
                handle: profile?.handle,
                displayName: profile?.displayName,
                nick: isDirect ? nil : nick,
                origin: origin,
                account: account,
                rowTimeUnix: rowTime.map { UInt64($0.timeIntervalSince1970) },
                senderPresent: !isDirect && appState.isNickPresent(nick)
            )
        }
        .reportDialog($reportSource) { target, reason in
            appState.reportUser(nick: target.nick, did: target.did, reason: reason)
            dismiss()
        }
    }

    /// The big name at the top: the resolved Bluesky name when browsing the
    /// graph, otherwise the freeq nick.
    private var headerTitle: String {
        if isDirect {
            if let p = profile {
                if let d = p.displayName, !d.trimmingCharacters(in: .whitespaces).isEmpty { return d }
                return "@\(p.handle)"
            }
            return nick
        }
        return nick
    }

    private func statItem(count: Int, label: String) -> some View {
        VStack(spacing: 2) {
            Text(formatCount(count))
                .font(.fqCallout.weight(.bold))
                .foregroundColor(Theme.textPrimary)
            Text(label)
                .font(.fqCaption2)
                .foregroundColor(Theme.textMuted)
        }
    }

    private func formatCount(_ n: Int) -> String {
        if n >= 1_000_000 { return "\(n / 1_000_000)M" }
        if n >= 1_000 { return "\(n / 1_000)K" }
        return "\(n)"
    }

    @State private var followBusy = false

    @ViewBuilder
    private func followButton(actor: String) -> some View {
        let following = relationship?.iFollow == true
        Button {
            toggleFollow(actor: actor)
        } label: {
            HStack(spacing: 8) {
                if followBusy {
                    ProgressView().scaleEffect(0.8).tint(following ? Theme.textSecondary : Theme.accent)
                } else {
                    Image(systemName: following ? "person.fill.checkmark" : "person.badge.plus")
                        .font(.system(size: 13))
                }
                Text(following ? "Following" : "Follow")
                    .font(.fqSubheadline.weight(.semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(following ? AnyShapeStyle(Theme.bgTertiary) : AnyShapeStyle(Theme.accent.opacity(0.16)))
            .foregroundColor(following ? Theme.textSecondary : Theme.accent)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(following ? Theme.border : Theme.accent.opacity(0.4), lineWidth: 1)
            )
        }
        .disabled(followBusy)
    }

    private func toggleFollow(actor: String) {
        guard let token = appState.brokerToken, let rel = relationship, !followBusy else { return }
        followBusy = true
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
        Task { @MainActor in
            defer { followBusy = false }
            if rel.iFollow {
                guard let uri = rel.followingURI else { return }
                switch await BlueskyGraph.unfollow(followURI: uri, brokerToken: token) {
                case .done:
                    relationship = BlueskyGraph.Relationship(
                        followsMe: rel.followsMe, iFollow: false, followingURI: nil)
                case .unsupported:
                    relationship = nil // hide the button this launch
                case .failed(let why):
                    appState.errorMessage = "Unfollow failed: \(why)"
                }
            } else {
                switch await BlueskyGraph.follow(subjectDID: actor, brokerToken: token) {
                case .done:
                    // Re-fetch to pick up the new record's URI for a later unfollow.
                    if let me = appState.authenticatedDID {
                        let rels = await BlueskyGraph.relationships(viewer: me, others: [actor])
                        relationship = rels[actor] ?? BlueskyGraph.Relationship(
                            followsMe: rel.followsMe, iFollow: true, followingURI: nil)
                    }
                case .unsupported:
                    relationship = nil
                case .failed(let why):
                    appState.errorMessage = "Follow failed: \(why)"
                }
            }
        }
    }

    private func startDM(_ target: String) {
        let _ = appState.getOrCreateDM(target)
        appState.pendingDMNick = target
        dismiss()
    }

    /// freeq presence card — where this person is right now, and the rooms you
    /// share. The part no other chat app can show, because it's tied to a real
    /// verified identity.
    private func freeqCard(_ fid: FreeqIdentity) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                PresenceDot(presence: fid.online ? .online : .offline, size: 9)
                Text(fid.online ? "Online on freeq" : "On freeq")
                    .font(.fqFootnote.weight(.semibold))
                    .foregroundColor(fid.online ? Theme.verify : Theme.textSecondary)
                if fid.isAgent {
                    Text("· agent")
                        .font(.fqMonoCaption)
                        .foregroundColor(Theme.iris)
                }
                Spacer()
            }
            let shared = sharedChannels
            if !shared.isEmpty {
                Text("You're both in \(shared.prefix(3).joined(separator: ", "))\(shared.count > 3 ? " +\(shared.count - 3)" : "")")
                    .font(.fqCaption)
                    .foregroundColor(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let first = fid.channels.first {
                Text("In \(first)\(fid.channels.count > 1 ? " +\(fid.channels.count - 1)" : "")")
                    .font(.fqCaption)
                    .foregroundColor(Theme.textMuted)
                    .lineLimit(1)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(.thin)
        .padding(.horizontal, 24)
    }

    private func fetchProfile() async {
        // Graph browsing / People search: we already hold a real AT identifier,
        // so use it directly (no nick→DID resolution, no did:key guard).
        if let direct = directActor {
            await MainActor.run { resolvedActor = direct }
            await loadProfile(actor: direct)
            return
        }
        // Resolve ONLY by the server-verified DID. We must NOT fall back to
        // the nick (nor a guessed "<nick>.bsky.social"): nicks are freely
        // chosen, so resolving from one shows a STRANGER's profile, avatar
        // and feed for whoever happens to match — e.g. tapping the AI being
        // "olive" surfacing the unrelated real account olive.bsky.social.
        // Identity on freeq is the DID bound at SASL; without one there is no
        // Bluesky profile to show. did:key users (guests, AI beings) have
        // none either.
        let did = await MainActor.run { () -> String? in
            // 1. Member-roster DID.
            for ch in appState.channels {
                if let m = ch.members.first(where: { $0.nick.lowercased() == nick.lowercased() }),
                   let d = m.did, !d.isEmpty {
                    return d
                }
            }
            // 2. DID seen on a message's account tag (retained by AvatarCache).
            //    Covers senders whose DID rode the message, not the roster —
            //    custom-domain handles and federated senders. This is the same
            //    source that resolves their avatar + verified badge on the row.
            if let cached = AvatarCache.shared.did(for: nick), !cached.isEmpty {
                return cached
            }
            // 3. Own profile: the authenticated session DID (mirrors Android).
            if nick.lowercased() == appState.nick.lowercased(),
               let own = appState.authenticatedDID, !own.isEmpty {
                return own
            }
            return nil
        }
        guard let actor = did, !actor.hasPrefix("did:key:") else {
            await MainActor.run { loading = false }
            return
        }
        await MainActor.run { resolvedActor = actor }
        await loadProfile(actor: actor)
    }

    /// Fetch and populate the profile card for an AT identifier (DID or handle),
    /// then load its recent posts. Shared by nick-resolution and direct-actor
    /// (graph) paths.
    private func loadProfile(actor: String) async {
        // Resolve what freeq knows about this identity in parallel — presence,
        // nick (so Message works), shared channels — and how the viewer relates
        // to them on the graph (follows you / mutual).
        if actor.hasPrefix("did:") {
            let fid = await FreeqDirectory.shared.identity(for: actor)
            await MainActor.run { freeqIdentity = fid }
            if let me = await MainActor.run(body: { appState.authenticatedDID }),
               me.hasPrefix("did:"), me != actor {
                let rels = await BlueskyGraph.relationships(viewer: me, others: [actor])
                await MainActor.run { relationship = rels[actor] }
            }
        }
        let urlStr = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=\(actor.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? actor)"
        guard let url = URL(string: urlStr) else {
            await MainActor.run { loading = false }
            return
        }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                await MainActor.run { loading = false }
                return
            }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            guard let json = json else {
                await MainActor.run { loading = false }
                return
            }

            // Trust the DID-resolved handle, not the nick.
            let resolvedHandle = json["handle"] as? String ?? actor
            await MainActor.run {
                profile = BlueskyProfile(
                    handle: resolvedHandle,
                    displayName: json["displayName"] as? String,
                    description: json["description"] as? String,
                    avatar: json["avatar"] as? String,
                    followersCount: json["followersCount"] as? Int,
                    followsCount: json["followsCount"] as? Int,
                    postsCount: json["postsCount"] as? Int
                )
                loading = false
                loadingFeed = true
            }
            await fetchAuthorFeed(actor: resolvedHandle)
        } catch {
            await MainActor.run { loading = false }
        }
    }

    private func fetchAuthorFeed(actor: String) async {
        let urlStr = "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=\(actor.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? actor)&limit=5&filter=posts_no_replies"
        guard let url = URL(string: urlStr) else {
            await MainActor.run { loadingFeed = false }
            return
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                await MainActor.run { loadingFeed = false }
                return
            }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let feed = (json?["feed"] as? [[String: Any]]) ?? []
            let items: [BskyFeedItem] = feed.compactMap { entry in
                guard let post = entry["post"] as? [String: Any],
                      let uri = post["uri"] as? String else { return nil }
                let record = post["record"] as? [String: Any]
                let text = record?["text"] as? String ?? ""
                return BskyFeedItem(uri: uri, text: text)
            }
            await MainActor.run {
                recentPosts = items
                loadingFeed = false
            }
        } catch {
            await MainActor.run { loadingFeed = false }
        }
    }
}

struct BskyFeedItem {
    let uri: String
    let text: String
}

struct BlueskyProfile {
    let handle: String
    let displayName: String?
    let description: String?
    let avatar: String?
    let followersCount: Int?
    let followsCount: Int?
    let postsCount: Int?
}
