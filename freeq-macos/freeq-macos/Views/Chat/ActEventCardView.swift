import SwiftUI

/// One task event, as the line its sender wrote beside it.
///
/// The event itself rides as a TAGMSG the message list never shows; this card
/// is the line beside it. The headline is the word for the verb that event
/// carried, never one read off the task's state, so a progress report never
/// reads as a claim.
///
/// An act card is the coloured class: one hue, taken from the register of the
/// state its step lands the action in, on the headline word, a left edge every
/// act card carries, and the border. The generic event card wears neither, and
/// the edge is how a reader tells the two apart.
struct ActEventCardView: View {
    let card: ActCard
    let at: Date
    /// Scrolls the list to a neighbouring card's line. Absent in previews.
    var onJumpToMessage: ((String) -> Void)?
    /// Resolves a DID or nick to what a reader should see. Identity in previews.
    var resolveName: (String) -> String = { $0 }

    @State private var sealOpen = false
    @State private var ctxHovering = false

    private var neighbours: ActNeighbours {
        actCardNeighbours(task: card.task, event: card.event)
    }
    /// The hue this card's register wears, in this app's own tokens. A system
    /// verb draws no card at all, so the fallback is only ever reached by a
    /// verb the rules file has not been taught.
    private var hue: Color {
        switch ActVerbs.register(card.event.verb) ?? .neutralEnd {
        case .new: return Theme.purple
        case .inProgress: return Theme.blue
        case .endedWell: return Theme.success
        case .didNotEndWell: return Theme.danger
        case .neutralEnd: return Theme.warning
        }
    }
    private var kind: String { card.event.fields["act"] ?? card.task.kind }
    /// The award's winner is the author of the bid it names; absent when that
    /// bid never reached this client.
    private var winnerDid: String? {
        guard let accepts = card.event.fields["act-accepts"] else { return nil }
        return card.task.events.first(where: { $0.eventId == accepts })?.did
    }
    private var facts: [(String, String)] {
        ActFacts.facts(
            card.event.fields,
            isOpener: ActVerbs.register(card.event.verb) == .new,
            resolve: resolveName,
            winnerDid: winnerDid)
    }
    private var extraFields: [(String, String)] { ActFacts.unknownFields(card.event.fields) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Text(ActVerbs.emoji(card.event.verb)).font(.system(size: 11))
                Text(ActVerbs.headline(card.event.verb))
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(hue)
                    .textCase(.uppercase)
                Text(Self.shortTaskId(card.task.taskId))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.textTertiary)
                // The seal: monochrome always, never the card's hue — a seal
                // that borrowed the hue would read as part of the outcome
                // rather than as a statement about the rules.
                Button { sealOpen.toggle() } label: {
                    Image(systemName: "checkmark.seal")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textTertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("What the server enforced")
                Spacer(minLength: 0)
                Text(Self.time.string(from: at))
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.textTertiary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.cardHeaderStrip)
            .popover(isPresented: $sealOpen, arrowEdge: .bottom) {
                SealPanelView(kind: kind, verb: card.event.verb)
            }

            VStack(alignment: .leading, spacing: 3) {
                if !card.task.title.isEmpty {
                    Text(card.task.title)
                        .font(.system(size: 13))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // The same key/value rows the generic card gives its payload,
                // so a fact and a payload field read alike wherever they are
                // met. The card body is the title and these rows: every value
                // the card carries arrives here under a key. A field with no
                // label of its own still shows, under its raw key, so nothing
                // signed is ever invisible.
                // Keys in one aligned column, values in a second: every
                // value starts at the same x, as on the web card.
                Grid(alignment: .topLeading, horizontalSpacing: 8, verticalSpacing: 3) {
                    ForEach(facts + extraFields, id: \.0) { fact in
                        GridRow {
                            Text(fact.0)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.textTertiary)
                                .gridColumnAlignment(.leading)
                            // A value wraps to the width it is given; past six
                            // lines it ends in an ellipsis rather than growing
                            // the card without bound. The context row's value
                            // opens its URL; every other value is text.
                            Group {
                                if fact.0 == ActFacts.ctxLabel, let url = URL(string: fact.1) {
                                    // Underlines while the pointer is on it, the
                                    // way a link does on the web. The accent
                                    // colour Link already wears is left alone.
                                    Link(fact.1, destination: url)
                                        .underline(ctxHovering)
                                        .onHover { ctxHovering = $0 }
                                } else {
                                    Text(fact.1)
                                        .foregroundStyle(Theme.textSecondary)
                                        .textSelection(.enabled)
                                }
                            }
                            .font(.system(size: 11, design: .monospaced))
                            .lineLimit(6)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)

            if neighbours.prev != nil || neighbours.next != nil, let jump = onJumpToMessage {
                Divider()
                HStack(spacing: 0) {
                    if let prev = neighbours.prev {
                        Button("← prev") { jump(prev) }
                            .buttonStyle(.plain)
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textTertiary)
                    }
                    Spacer(minLength: 0)
                    if let next = neighbours.next {
                        Button("next →") { jump(next) }
                            .buttonStyle(.plain)
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textTertiary)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
            }
        }
        .overlay(alignment: .leading) {
            // Every act card carries an edge — it is also the act-vs-generic tell.
            Rectangle().fill(hue).frame(width: 3)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(hue.opacity(0.3), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .frame(maxWidth: 460, alignment: .leading)
    }

    /// The task id, shortened the way the web's badge shortens it.
    private static func shortTaskId(_ id: String) -> String {
        id.count > 10 ? String(id.prefix(10)) + "…" : id
    }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f
    }()
}

/// The disclosure behind the seal: what the server enforced on this one step,
/// and the way through to the whole action.
///
/// The sentence is picked off the role the rules file gives the verb, never off
/// the verb's name and never off the kind. A verb the rules file does not name
/// has no rule about a person to state, so the panel states none.
///
/// There is no link to a full history here: this app has no task timeline
/// surface to open.
struct SealPanelView: View {
    let kind: String
    let verb: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(SealPanelCopy.header(kind))
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)
            if let sentence = SealPanelCopy.sentence(verb) {
                Text(sentence)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textTertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(width: 300, alignment: .leading)
    }
}
