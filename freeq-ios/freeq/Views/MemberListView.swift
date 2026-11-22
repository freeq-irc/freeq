import SwiftUI

struct MemberListView: View {
    @ObservedObject var channel: ChannelState
    @State private var profileNick: String? = nil

    private var dedupedMembers: [MemberInfo] { channel.uniqueMembers }

    private var ops: [MemberInfo] {
        dedupedMembers.filter { $0.isOp }.sorted { $0.nick.lowercased() < $1.nick.lowercased() }
    }

    private var halfops: [MemberInfo] {
        dedupedMembers.filter { $0.isHalfop && !$0.isOp }.sorted { $0.nick.lowercased() < $1.nick.lowercased() }
    }

    private var voiced: [MemberInfo] {
        dedupedMembers.filter { $0.isVoiced && !$0.isOp && !$0.isHalfop }.sorted { $0.nick.lowercased() < $1.nick.lowercased() }
    }

    private var regular: [MemberInfo] {
        dedupedMembers.filter { !$0.isOp && !$0.isHalfop && !$0.isVoiced }.sorted { $0.nick.lowercased() < $1.nick.lowercased() }
    }

    /// Agents get their own section, apart from the room's people.
    private var people: [MemberInfo] { regular.filter { !$0.isAgent } }
    private var agents: [MemberInfo] { regular.filter(\.isAgent) }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Members")
                    .font(.fqFootnote.weight(.bold))
                    .foregroundColor(Theme.textSecondary)
                Spacer()
                Text("\(dedupedMembers.count)")
                    .font(.fqFootnote.weight(.medium))
                    .foregroundColor(Theme.textMuted)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Rectangle()
                .fill(Theme.border)
                .frame(height: 1)

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if !ops.isEmpty {
                        memberSection("OPERATORS — \(ops.count)", members: ops)
                    }
                    if !halfops.isEmpty {
                        memberSection("MODERATORS — \(halfops.count)", members: halfops)
                    }
                    if !voiced.isEmpty {
                        memberSection("VOICED — \(voiced.count)", members: voiced)
                    }
                    if !people.isEmpty {
                        memberSection("MEMBERS — \(people.count)", members: people)
                    }
                    if !agents.isEmpty {
                        memberSection("AGENTS — \(agents.count)", members: agents)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .background(Theme.bgSecondary)
        .overlay(
            Rectangle()
                .fill(Theme.border)
                .frame(width: 1),
            alignment: .leading
        )
        .sheet(item: Binding(
            get: { profileNick.map { ProfileTarget(nick: $0) } },
            set: { profileNick = $0?.nick }
        )) { target in
            UserProfileSheet(nick: target.nick)
                .presentationDetents([.medium, .large])
                .presentationDragIndicator(.visible)
        }
    }

    private func memberSection(_ title: String, members: [MemberInfo]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(.fqCaption2.weight(.bold))
                .foregroundColor(Theme.textMuted)
                .kerning(0.5)
                .padding(.horizontal, 16)
                .padding(.top, 12)
                .padding(.bottom, 6)

            ForEach(members) { member in
                memberRow(member)
            }
        }
    }

    /// An agent at work: presence says so, or its AWAY is an agent status.
    private func isWorking(_ member: MemberInfo) -> Bool {
        guard member.isAgent else { return false }
        if member.presenceState == "executing" { return true }
        return member.presenceState == nil && AgentStatus.parse(member.awayMsg) != nil
    }

    private func memberRow(_ member: MemberInfo) -> some View {
        Button(action: { profileNick = member.nick }) {
            HStack(spacing: 10) {
                // Avatar with presence dot
                UserAvatar(nick: member.nick, size: 32)
                    .overlay(
                        Circle()
                            .fill(isWorking(member) ? Theme.accent : (member.isAway ? Theme.warning : Theme.success))
                            .frame(width: 10, height: 10)
                            .overlay(
                                Circle()
                                    .stroke(Theme.bgSecondary, lineWidth: 2)
                            )
                            .offset(x: 2, y: 2),
                        alignment: .bottomTrailing
                    )

                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 4) {
                        if member.isOp {
                            Image(systemName: "shield.fill")
                                .font(.system(size: 9))
                                .foregroundColor(Theme.warning)
                        } else if member.isHalfop {
                            Image(systemName: "shield.lefthalf.filled")
                                .font(.system(size: 9))
                                .foregroundColor(Theme.accent)
                        }
                        Text(member.nick)
                            .font(.fqFootnote.weight(.medium))
                            .foregroundColor(member.isAway ? Theme.textMuted : Theme.textPrimary)
                            .lineLimit(1)

                        // Only an AT Protocol identity earns the seal
                        // (IdentityClaim rule); a self-issued did:key does
                        // not. A roster row is a present person, so the cache
                        // lookup here is presence-gated by construction.
                        if claimForPerson(input: PersonClaimInput(
                            binding: member.did ?? AvatarCache.shared.did(for: member.nick),
                            seenOnlyViaPeer: false,
                            viaPeerOrigin: nil,
                            viaPeerHadAccount: false,
                            lookup: .notAsked
                        )).showsMark {
                            VerifiedBadge(size: 11)
                        }

                        if member.isAgent {
                            HStack(spacing: 2) {
                                Image(systemName: "cpu")
                                    .font(.system(size: 9, weight: .bold))
                                Text("AGENT")
                                    .font(.system(size: 9, weight: .bold))
                            }
                            .foregroundColor(Theme.accent)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 2)
                            .background(Theme.accent.opacity(0.15))
                            .cornerRadius(6)
                            .accessibilityLabel("Agent")
                        }

                        // An agent's AWAY means it is working, not gone.
                        if member.isAway && !isWorking(member) {
                            Text("Away")
                                .font(.fqCaption2.weight(.semibold))
                                .foregroundColor(Theme.warning)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Theme.warning.opacity(0.15))
                                .cornerRadius(6)
                        }
                    }
                    if let activity = member.activityLabel {
                        Text(activity)
                            .font(.fqCaption2)
                            .foregroundColor(Theme.accent)
                            .lineLimit(2)
                            .truncationMode(.tail)
                    } else if member.isAway, let away = AgentStatus.displayAway(member.awayMsg) {
                        Text(away)
                            .font(.fqCaption2)
                            .foregroundColor(Theme.textMuted)
                            .lineLimit(2)
                            .truncationMode(.tail)
                    }
                }

                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 5)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// Helper for sheet binding
private struct ProfileTarget: Identifiable {
    let nick: String
    var id: String { nick }
}
