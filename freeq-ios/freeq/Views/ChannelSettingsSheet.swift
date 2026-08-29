import SwiftUI

/// Channel settings sheet — topic editing, channel info, leave.
struct ChannelSettingsSheet: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    let channel: ChannelState

    @State private var editingTopic = false
    @State private var topicDraft: String = ""

    private var isOp: Bool {
        channel.memberInfo(for: appState.nick)?.isOp ?? false
    }

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bgPrimary.ignoresSafeArea()

                List {
                    // Channel info
                    Section {
                        HStack(spacing: 12) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(Theme.accent.opacity(0.15))
                                    .frame(width: 48, height: 48)
                                Text("#")
                                    .font(.fqMono.weight(.bold))
                                    .foregroundColor(Theme.accent)
                            }

                            VStack(alignment: .leading, spacing: 3) {
                                Text(channel.name)
                                    .font(.fqBody.weight(.bold))
                                    .foregroundColor(Theme.textPrimary)

                                Text("\(channel.uniqueMemberCount) members")
                                    .font(.fqFootnote)
                                    .foregroundColor(Theme.textSecondary)
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)
                    }

                    // Topic
                    Section {
                        if editingTopic {
                            VStack(alignment: .leading, spacing: 8) {
                                TextField("Channel topic", text: $topicDraft, axis: .vertical)
                                    .font(.fqSubheadline)
                                    .foregroundColor(Theme.textPrimary)
                                    .lineLimit(1...5)
                                    .tint(Theme.accent)

                                HStack {
                                    Button("Cancel") {
                                        editingTopic = false
                                        topicDraft = channel.topic
                                    }
                                    .font(.fqFootnote.weight(.medium))
                                    .foregroundColor(Theme.textSecondary)

                                    Spacer()

                                    Button("Save") {
                                        appState.sendRaw("TOPIC \(channel.name) :\(topicDraft)")
                                        editingTopic = false
                                    }
                                    .font(.fqFootnote.weight(.bold))
                                    .foregroundColor(Theme.accent)
                                }
                            }
                            .listRowBackground(Theme.bgSecondary)
                        } else {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text("Topic")
                                        .font(.fqFootnote.weight(.semibold))
                                        .foregroundColor(Theme.textMuted)
                                    Spacer()
                                    if isOp {
                                        Button(action: {
                                            topicDraft = channel.topic
                                            editingTopic = true
                                        }) {
                                            Image(systemName: "pencil")
                                                .font(.system(size: 13))
                                                .foregroundColor(Theme.accent)
                                        }
                                    }
                                }

                                if channel.topic.isEmpty {
                                    Text("No topic set")
                                        .font(.fqFootnote)
                                        .foregroundColor(Theme.textMuted)
                                        .italic()
                                } else {
                                    Text(channel.topic)
                                        .font(.fqFootnote)
                                        .foregroundColor(Theme.textSecondary)
                                        .textSelection(.enabled)
                                }
                            }
                            .listRowBackground(Theme.bgSecondary)
                        }
                    } header: {
                        Text("Topic")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Members preview
                    Section {
                        let ops = channel.members.filter { $0.isOp }
                        if !ops.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Operators")
                                    .font(.fqCaption.weight(.bold))
                                    .foregroundColor(Theme.textMuted)
                                    .kerning(0.5)

                                ForEach(ops) { member in
                                    HStack(spacing: 8) {
                                        UserAvatar(nick: member.nick, size: 28)
                                        Text(member.nick)
                                            .font(.fqFootnote)
                                            .foregroundColor(Theme.textPrimary)
                                        if member.isVerified {
                                            VerifiedBadge(size: 12)
                                        }
                                        // Agent badge — only when the server
                                        // said so; unlabelled stays a person.
                                        if member.isAgent {
                                            Image(systemName: "cpu")
                                                .font(.system(size: 10, weight: .semibold))
                                                .foregroundColor(Theme.accent)
                                        }
                                        // What it is doing right now, if it
                                        // says. An idle agent shows nothing.
                                        if let activity = member.activityLabel {
                                            Text(activity)
                                                .font(.fqCaption2)
                                                .foregroundColor(Theme.accent)
                                                .lineLimit(1)
                                        }
                                        Spacer()
                                        Image(systemName: "shield.fill")
                                            .font(.system(size: 11))
                                            .foregroundColor(Theme.warning)
                                    }
                                }
                            }
                            .listRowBackground(Theme.bgSecondary)
                        }
                    } header: {
                        Text("Members (\(channel.uniqueMemberCount))")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Notifications
                    Section {
                        Toggle(isOn: Binding(
                            get: { appState.isMuted(channel.name) },
                            set: { _ in appState.toggleMute(channel.name) }
                        )) {
                            Label("Mute Notifications", systemImage: appState.isMuted(channel.name) ? "bell.slash.fill" : "bell.fill")
                                .foregroundColor(Theme.textPrimary)
                        }
                        .tint(Theme.accent)
                        .listRowBackground(Theme.bgSecondary)
                    } header: {
                        Text("Notifications")
                            .foregroundColor(Theme.textMuted)
                    }

                    // Pinned Messages
                    Section {
                        NavigationLink {
                            PinnedMessagesView(channelName: channel.name)
                        } label: {
                            Label("Pinned Messages", systemImage: "pin.fill")
                                .foregroundColor(Theme.textPrimary)
                        }
                        .listRowBackground(Theme.bgSecondary)
                    }

                    // Actions
                    Section {
                        Button(action: {
                            appState.partChannel(channel.name)
                            dismiss()
                        }) {
                            HStack {
                                Spacer()
                                Text("Leave Channel")
                                    .font(.fqCallout.weight(.medium))
                                    .foregroundColor(Theme.danger)
                                Spacer()
                            }
                        }
                        .listRowBackground(Theme.bgSecondary)
                    }
                }
                .listStyle(.insetGrouped)
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Channel Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .foregroundColor(Theme.accent)
                }
            }
            .toolbarBackground(.ultraThinMaterial, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
        .preferredColorScheme(.dark)
    }
}
