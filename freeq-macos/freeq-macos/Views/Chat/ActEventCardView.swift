import SwiftUI

/// The one layout every event card renders through — the web `CardFrame`
/// arrangement: a header strip over a padded body, an optional prev/next
/// footer behind a hairline, an accent edge for marked events, a hairline
/// border, clip and width cap. Both the act and coordination families use
/// it; layout decisions live here and nowhere else.
struct EventCard<Content: View>: View {
    let icon: String
    let label: String
    var detail: String? = nil
    var time: String? = nil
    var accent: Color? = nil
    var onPrev: (() -> Void)? = nil
    var onNext: (() -> Void)? = nil
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Text(icon).font(.system(size: 11))
                Text(label)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                    .textCase(.uppercase)
                if let detail {
                    Text(detail)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
                Spacer(minLength: 0)
                if let time {
                    Text(time)
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.textTertiary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.cardHeaderStrip)

            VStack(alignment: .leading, spacing: 3) {
                content
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)

            if onPrev != nil || onNext != nil {
                Divider()
                HStack(spacing: 0) {
                    if let onPrev {
                        Button("← prev", action: onPrev)
                            .buttonStyle(.plain)
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textTertiary)
                    }
                    Spacer(minLength: 0)
                    if let onNext {
                        Button("next →", action: onNext)
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
            if let accent {
                Rectangle().fill(accent).frame(width: 2)
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Theme.border.opacity(0.5), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .frame(maxWidth: 460, alignment: .leading)
    }
}

/// One task event, as the line its sender wrote beside it.
///
/// The event itself rides as a TAGMSG the message list never shows; this card
/// is the line beside it. The headline is the word for the verb that event
/// carried, never one read off the task's state, so a progress report never
/// reads as a claim.
struct ActEventCardView: View {
    let card: ActCard
    let at: Date
    /// Scrolls the list to a neighbouring card's line. Absent in previews.
    var onJumpToMessage: ((String) -> Void)?

    private var neighbours: ActNeighbours {
        actCardNeighbours(task: card.task, event: card.event)
    }
    /// Painted in this app's own theme, and only for the moves that put work
    /// on a plate, end well, or fail — an edge on every card says nothing.
    private var accentColor: Color? {
        switch ActVerbs.accent(card.event.verb) {
        case .handoff: return Theme.purple
        case .success: return Theme.success
        case .failure: return Theme.danger
        case .none: return nil
        }
    }
    private var note: String? { card.event.fields["act-note"] }
    private var ctx: String? { card.event.fields["act-ctx"] }
    private var ctxHash: String? { card.event.fields["act-ctx-h"] }

    private var prevAction: (() -> Void)? {
        guard let jump = onJumpToMessage, let prev = neighbours.prev else { return nil }
        return { jump(prev) }
    }
    private var nextAction: (() -> Void)? {
        guard let jump = onJumpToMessage, let next = neighbours.next else { return nil }
        return { jump(next) }
    }

    var body: some View {
        EventCard(
            icon: ActVerbs.emoji(card.event.verb),
            label: ActVerbs.headline(card.event.verb),
            detail: Self.shortTaskId(card.task.taskId),
            time: Self.time.string(from: at),
            accent: accentColor,
            onPrev: prevAction,
            onNext: nextAction
        ) {
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
        }
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
