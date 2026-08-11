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
                    if !regular.isEmpty {
                        memberSection("MEMBERS — \(regular.count)", members: regular)
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

    private func memberRow(_ member: MemberInfo) -> some View {
        Button(action: { profileNick = member.nick }) {
            HStack(spacing: 10) {
                // Avatar with presence dot
                UserAvatar(nick: member.nick, size: 32)
                    .overlay(
                        Circle()
                            .fill(member.isAway ? Theme.warning : Theme.success)
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

                        if member.isAway {
                            Text("Away")
                                .font(.fqCaption2.weight(.semibold))
                                .foregroundColor(Theme.warning)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Theme.warning.opacity(0.15))
                                .cornerRadius(6)
                        }
                    }
                    if member.isAway, let away = member.awayMsg {
                        Text(away)
                            .font(.fqCaption2)
                            .foregroundColor(Theme.textMuted)
                            .lineLimit(1)
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
