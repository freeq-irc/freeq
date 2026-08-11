import SwiftUI

/// A person as freeq sees them: their Bluesky graph identity plus what freeq
/// knows (are they here, online, in which channels, under what nick).
struct FreeqPerson: Identifiable {
    let actor: BskyActor
    let identity: FreeqIdentity?
    /// How the signed-in viewer relates to this person on the graph
    /// (follows you / you follow / mutual). nil when signed out.
    var relationship: BlueskyGraph.Relationship? = nil
    var id: String { actor.did }
    var onFreeq: Bool { identity?.isOnFreeq ?? false }
}

/// Avatar for a Bluesky actor resolved straight from the graph, with an
/// optional freeq presence pip riveted on.
struct BskyAvatar: View {
    let urlString: String?
    let seed: String
    var size: CGFloat = 46
    var presence: PresenceDot.Presence? = nil

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            Group {
                if let s = urlString, let url = URL(string: s) {
                    AsyncImage(url: url) { image in
                        image.resizable().scaledToFill()
                    } placeholder: { initials }
                } else {
                    initials
                }
            }
            .frame(width: size, height: size)
            .clipShape(Circle())
            .overlay(Circle().strokeBorder(.white.opacity(0.10), lineWidth: 1))

            if let presence {
                PresenceDot(presence: presence, size: size * 0.30, ringColor: Theme.bgPrimary)
                    .offset(x: 1, y: 1)
            }
        }
    }

    private var initials: some View {
        let color = Theme.nickColor(for: seed)
        return ZStack {
            LinearGradient(colors: [color, color.opacity(0.72)], startPoint: .top, endPoint: .bottom)
            Text(String(seed.prefix(1)).uppercased())
                .font(.system(size: size * 0.42, weight: .semibold, design: .rounded))
                .foregroundColor(Color(hex: "04121a").opacity(0.88))
        }
    }
}

/// One person in a list — Bluesky identity plus a freeq presence line and a
/// Message affordance when they're actually reachable on freeq.
struct PersonRow: View {
    let person: FreeqPerson
    var onMessage: (() -> Void)? = nil

    private var presence: PresenceDot.Presence? {
        guard let id = person.identity, id.isOnFreeq else { return nil }
        return id.online ? .online : .offline
    }

    var body: some View {
        HStack(spacing: 12) {
            BskyAvatar(urlString: person.actor.avatar, seed: person.actor.handle,
                       size: 48, presence: presence)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(person.actor.title)
                        .font(.fqSubheadline.weight(.semibold))
                        .foregroundColor(Theme.textPrimary)
                        .lineLimit(1)
                    // Only an AT Protocol identity earns the seal
                    // (IdentityClaim rule); a self-issued did:key does not.
                    if claimForPerson(input: PersonClaimInput(
                        binding: person.actor.did,
                        seenOnlyViaPeer: false,
                        viaPeerOrigin: nil,
                        viaPeerHadAccount: false,
                        lookup: .notAsked
                    )).showsMark {
                        VerifiedBadge(size: 12)
                    }
                    if person.identity?.isAgent == true {
                        Text("AGENT")
                            .font(.system(size: 8, weight: .bold, design: .monospaced))
                            .foregroundColor(Theme.iris)
                            .padding(.horizontal, 4).padding(.vertical, 1)
                            .background(Theme.iris.opacity(0.16), in: Capsule())
                    }
                    // Graph social proof — mutual beats follows-you.
                    if let rel = person.relationship {
                        if rel.isMutual {
                            relChip("mutual", tint: Theme.verify)
                        } else if rel.followsMe {
                            relChip("follows you", tint: Theme.iris)
                        }
                    }
                }
                Text("@\(person.actor.handle)")
                    .font(.fqMonoCaption)
                    .foregroundColor(Theme.textMuted)
                    .lineLimit(1)
                freeqLine
            }
            Spacer(minLength: 0)
            if person.onFreeq, let onMessage {
                Button(action: onMessage) {
                    Image(systemName: "bubble.left.fill")
                        .font(.system(size: 15))
                        .foregroundStyle(Theme.signalGradient)
                        .padding(8)
                        .background(Theme.accent.opacity(0.12), in: Circle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
    }

    private func relChip(_ label: String, tint: Color) -> some View {
        Text(label)
            .font(.system(size: 9, weight: .semibold))
            .foregroundColor(tint)
            .padding(.horizontal, 5).padding(.vertical, 1.5)
            .background(tint.opacity(0.14), in: Capsule())
    }

    @ViewBuilder private var freeqLine: some View {
        if let id = person.identity, id.isOnFreeq {
            HStack(spacing: 5) {
                Text(id.online ? "on freeq · online" : "on freeq")
                    .font(.fqCaption.weight(.medium))
                    .foregroundColor(id.online ? Theme.verify : Theme.textSecondary)
                if let ch = id.channels.first {
                    Text("· \(ch)\(id.channels.count > 1 ? " +\(id.channels.count - 1)" : "")")
                        .font(.fqMonoCaption)
                        .foregroundColor(Theme.textMuted)
                        .lineLimit(1)
                }
            }
            .padding(.top, 1)
        } else if let d = person.actor.description?.trimmingCharacters(in: .whitespacesAndNewlines), !d.isEmpty {
            Text(d)
                .font(.fqCaption)
                .foregroundColor(Theme.textSecondary)
                .lineLimit(2)
                .padding(.top, 1)
        }
    }
}

/// A scrollable list of people from the graph (followers / following), each
/// annotated with their freeq presence. Tapping opens a profile; the Message
/// button DMs anyone who's on freeq.
struct GraphListView: View {
    enum Source: Equatable {
        case followers(actor: String)
        case follows(actor: String)
    }

    let title: String
    let source: Source
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    @State private var people: [FreeqPerson] = []
    @State private var loading = true
    @State private var selected: BskyActor? = nil

    var body: some View {
        ZStack {
            Theme.bgPrimary.ignoresSafeArea()
            if loading {
                ProgressView().tint(Theme.accent)
            } else if people.isEmpty {
                EmptyStateView(icon: "person.2", title: "No one here yet",
                               message: "This list is empty on Bluesky.")
            } else {
                List {
                    ForEach(people) { person in
                        Button { selected = person.actor } label: {
                            PersonRow(person: person, onMessage: person.onFreeq ? { message(person) } : nil)
                        }
                        .buttonStyle(.plain)
                        .listRowBackground(Theme.bgSecondary)
                        .listRowSeparatorTint(Theme.border)
                    }
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .task { await load() }
        .sheet(item: $selected) { actor in
            UserProfileSheet(nick: actor.handle, directActor: actor.did)
        }
    }

    private func message(_ person: FreeqPerson) {
        guard let nick = person.identity?.nick else { return }
        _ = appState.getOrCreateDM(nick)
        appState.pendingDMNick = nick
        dismiss()
    }

    private func load() async {
        let actors: [BskyActor]
        switch source {
        case .followers(let a): actors = await BlueskyGraph.followers(of: a)
        case .follows(let a): actors = await BlueskyGraph.follows(of: a)
        }
        people = await PeopleResolver.resolve(actors, viewer: appState.authenticatedDID)
        loading = false
    }
}

/// Batch-annotates Bluesky actors with their freeq identity and (when the
/// viewer is signed in) their graph relationship to the viewer.
enum PeopleResolver {
    static func resolve(_ actors: [BskyActor], viewer: String? = nil) async -> [FreeqPerson] {
        let dids = actors.map(\.did)
        async let identityMap = FreeqDirectory.shared.identities(for: dids)
        let relMap: [String: BlueskyGraph.Relationship]
        if let viewer, viewer.hasPrefix("did:") {
            relMap = await BlueskyGraph.relationships(viewer: viewer, others: dids.filter { $0 != viewer })
        } else {
            relMap = [:]
        }
        let ids = await identityMap
        return actors.map { FreeqPerson(actor: $0, identity: ids[$0.did], relationship: relMap[$0.did]) }
    }

    /// freeq people first (online first), then everyone else.
    static func sorted(_ people: [FreeqPerson]) -> [FreeqPerson] {
        people.sorted { a, b in
            let ao = a.identity?.online == true, bo = b.identity?.online == true
            if ao != bo { return ao }
            if a.onFreeq != b.onFreeq { return a.onFreeq }
            return a.actor.title.localizedCaseInsensitiveCompare(b.actor.title) == .orderedAscending
        }
    }
}

/// People — the human side of discovery. Leads with your Bluesky graph mapped
/// onto freeq ("who that I follow is here?"), then opens up to a search of the
/// whole network — with every result telling you whether you can actually
/// reach them on freeq.
struct PeopleSearchView: View {
    @EnvironmentObject var appState: AppState
    @State private var query = ""
    @State private var results: [FreeqPerson] = []
    @State private var followsOnFreeq: [FreeqPerson] = []
    @State private var loadingFollows = true
    @State private var searching = false
    @State private var selected: BskyActor? = nil
    @State private var searchTask: Task<Void, Never>? = nil
    @FocusState private var focused: Bool

    private var isSearching: Bool { !query.trimmingCharacters(in: .whitespaces).isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            searchBar
            content
        }
        .background(Theme.bgPrimary)
        .task { await loadFollows() }
        .sheet(item: $selected) { actor in
            UserProfileSheet(nick: actor.handle, directActor: actor.did)
        }
    }

    private var searchBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15)).foregroundColor(Theme.textMuted)
            TextField("", text: $query,
                      prompt: Text("Search everyone on the network…").foregroundColor(Theme.textMuted))
                .foregroundColor(Theme.textPrimary)
                .font(.fqCallout)
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .keyboardType(.twitter)
                .submitLabel(.search)
                .focused($focused)
                .onChange(of: query) { runSearch() }
            if searching {
                ProgressView().scaleEffect(0.7).tint(Theme.textMuted)
            } else if !query.isEmpty {
                Button { query = ""; results = [] } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 16)).foregroundColor(Theme.textMuted)
                }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(Theme.bgSecondary, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .padding(.horizontal, 16).padding(.top, 8).padding(.bottom, 4)
    }

    @ViewBuilder private var content: some View {
        if isSearching {
            searchResults
        } else {
            yourPeople
        }
    }

    // MARK: Your people (graph × freeq)

    @ViewBuilder private var yourPeople: some View {
        if appState.authenticatedDID == nil {
            Spacer()
            EmptyStateView(icon: "person.crop.circle.badge.questionmark",
                           title: "Sign in to see your people",
                           message: "Sign in with Bluesky and freeq will show which of the people you follow are here.")
            Spacer()
        } else if loadingFollows {
            Spacer()
            VStack(spacing: 12) {
                ProgressView().tint(Theme.accent)
                Text("Finding your people on freeq…")
                    .font(.fqFootnote).foregroundColor(Theme.textMuted)
            }
            Spacer()
        } else if followsOnFreeq.isEmpty {
            Spacer()
            EmptyStateView(icon: "sparkle.magnifyingglass",
                           title: "None of your follows are here yet",
                           message: "The people you follow on Bluesky aren't on freeq yet — search the network to find new people, and invite the rest.")
            Spacer()
        } else {
            ScrollView {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    Section {
                        ForEach(followsOnFreeq) { person in
                            personRow(person)
                        }
                    } header: {
                        sectionHeader("People you follow, on freeq", count: followsOnFreeq.count)
                    }
                }
                .padding(.top, 4)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    // MARK: Search results

    @ViewBuilder private var searchResults: some View {
        if results.isEmpty {
            Spacer()
            if searching {
                ProgressView().tint(Theme.accent)
            } else {
                EmptyStateView(icon: "magnifyingglass", title: "No people found",
                               message: "Try a different name or handle.")
            }
            Spacer()
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(results) { person in
                        personRow(person)
                    }
                }
                .padding(.top, 4)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    private func personRow(_ person: FreeqPerson) -> some View {
        VStack(spacing: 0) {
            Button { selected = person.actor } label: {
                PersonRow(person: person, onMessage: person.onFreeq ? { message(person) } : nil)
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 16)
            Divider().background(Theme.border).padding(.leading, 76)
        }
    }

    private func sectionHeader(_ title: String, count: Int) -> some View {
        HStack {
            Text(title.uppercased())
                .font(.fqCaption2.weight(.bold))
                .foregroundColor(Theme.textMuted)
                .kerning(0.6)
            Text("\(count)")
                .font(.fqCaption2.weight(.bold))
                .foregroundColor(Theme.accent)
            Spacer()
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(Theme.bgPrimary)
    }

    private func message(_ person: FreeqPerson) {
        guard let nick = person.identity?.nick else { return }
        _ = appState.getOrCreateDM(nick)
        appState.pendingDMNick = nick
    }

    private func loadFollows() async {
        guard let myDID = appState.authenticatedDID else { loadingFollows = false; return }
        let follows = await BlueskyGraph.follows(of: myDID, limit: 100)
        let resolved = await PeopleResolver.resolve(follows, viewer: myDID)
        followsOnFreeq = PeopleResolver.sorted(resolved.filter { $0.onFreeq })
        loadingFollows = false
    }

    private func runSearch() {
        searchTask?.cancel()
        let q = query.trimmingCharacters(in: .whitespaces)
        guard q.count >= 2 else { results = []; searching = false; return }
        searching = true
        searchTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 280_000_000)
            if Task.isCancelled { return }
            let actors = await BlueskyGraph.searchActors(q)
            if Task.isCancelled { return }
            let resolved = await PeopleResolver.resolve(actors, viewer: appState.authenticatedDID)
            if Task.isCancelled { return }
            results = resolved
            searching = false
        }
    }
}
