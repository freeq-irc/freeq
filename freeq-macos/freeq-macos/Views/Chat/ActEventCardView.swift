import SwiftUI

/// One task event, as the line its sender wrote beside it.
///
/// The event itself rides as a TAGMSG the message list never shows; this card
/// is the line beside it. The headline is the word for the verb that event
/// carried, never one read off the task's state, so a progress report never
/// reads as a claim.
///
/// Laid out like the web client's card (`freeq-app/src/components/ActCards.tsx`
/// and its `CardFrame`) and the Android app's `ActEventCard`: a header strip
/// carrying the icon, the headline, the shortened task id and the time, over a
/// body of title, note and context link.
struct ActEventCardView: View {
    let card: ActCard
    let at: Date
    /// Scrolls the list to a neighbouring card's line. Absent in previews.
    var onJumpToMessage: ((String) -> Void)?

    private var neighbours: ActNeighbours {
        actCardNeighbours(task: card.task, event: card.event)
    }
    private var note: String? { card.event.fields["act-note"] }
    private var ctx: String? { card.event.fields["act-ctx"] }
    private var ctxHash: String? { card.event.fields["act-ctx-h"] }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header strip.
            HStack(spacing: 6) {
                Text("📋")
                    .font(.system(size: 11))
                Text(ActVerbs.headline(card.event.verb))
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Text(Self.shortTaskId(card.task.taskId))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Theme.textTertiary)
                Spacer(minLength: 0)
                Text(Self.time.string(from: at))
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.textTertiary)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.surface.opacity(0.5))

            // Body.
            VStack(alignment: .leading, spacing: 3) {
                if !card.task.title.isEmpty {
                    Text(card.task.title)
                        .font(.system(size: 13))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let note, !note.isEmpty {
                    Text(note)
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.textSecondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let ctx, !ctx.isEmpty {
                    if let url = URL(string: ctx) {
                        Link(ctx, destination: url)
                            .font(.system(size: 11))
                    } else {
                        Text(ctx)
                            .font(.system(size: 11))
                            .textSelection(.enabled)
                    }
                    // The hash is what the signature covers, so it rides along
                    // for anyone checking the bytes they fetched.
                    if let ctxHash, !ctxHash.isEmpty {
                        Text(ctxHash)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Theme.textTertiary)
                            .textSelection(.enabled)
                    }
                }
                // The cards either side of this one on the same task, absent
                // at each end. Nothing is offered for a move the home signed:
                // it wrote no line, so there is no card to land on.
                if let onJumpToMessage, neighbours.prev != nil || neighbours.next != nil {
                    HStack(spacing: 12) {
                        if let prev = neighbours.prev {
                            Button("← prev") { onJumpToMessage(prev) }
                                .buttonStyle(.plain)
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.textTertiary)
                        }
                        if let next = neighbours.next {
                            Button("next →") { onJumpToMessage(next) }
                                .buttonStyle(.plain)
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.textTertiary)
                        }
                    }
                    .padding(.top, 2)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Theme.border.opacity(0.5), lineWidth: 1)
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
