import SwiftUI

/// A coordination event as a card — one card for every event type there is.
///
/// There is no list of types that card and no per-type face, so an event this
/// app has never been taught reads exactly like one it knows. Grayscale and
/// edgeless throughout: colour and a left edge belong to the act cards, and
/// are how a reader tells the two classes apart.
struct CoordinationCardView: View {
    let info: CoordinationInfo
    let text: String
    var at: Date?

    private var rows: [PayloadRow] { EventCardPayload.rows(info.payload) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Text("◇")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textMuted)
                Text(info.eventType.lowercased())
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                Spacer(minLength: 0)
                if let at {
                    Text(Self.time.string(from: at))
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.textMuted)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.cardHeaderStrip)

            VStack(alignment: .leading, spacing: 4) {
                if !text.isEmpty {
                    Text(text)
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.textSecondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // Keys in one aligned column, values in a second: every
                // value starts at the same x, as on the web card.
                Grid(alignment: .topLeading, horizontalSpacing: 8, verticalSpacing: 4) {
                    ForEach(rows, id: \.key) { row in
                        GridRow {
                            Text(row.key)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.textMuted)
                                .gridColumnAlignment(.leading)
                            // A value wraps to the width it is given; past six
                            // lines it ends in an ellipsis rather than growing
                            // the card without bound.
                            Text(row.value)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.textSecondary)
                                .textSelection(.enabled)
                                .lineLimit(6)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
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
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f
    }()
}
