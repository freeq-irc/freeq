import SwiftUI

/// Renders an agent coordination event as a structured card — the macOS
/// analogue of the web `CoordinationCards`. Driven by the pure
/// `CoordinationCard` style policy; a tag-unaware fallback (plain text) is
/// never reached because the row only builds this when `coordination != nil`.
struct CoordinationCardView: View {
    let info: CoordinationInfo
    let text: String
    @State private var expanded = false

    private var style: CoordinationCard.Style { CoordinationCard.style(for: info) }

    /// The act cards' left-edge accent, adopted here so both families speak
    /// one language: nil for routine events, an edge for the marked ones.
    private var accentColor: Color? {
        switch style.accent {
        case .neutral: return nil
        case .agent: return Theme.purple
        case .success: return Theme.success
        case .error: return Theme.danger
        }
    }

    var body: some View {
        EventCard(
            icon: style.icon,
            label: style.label,
            detail: info.taskId.map { $0.count > 10 ? String($0.prefix(10)) + "…" : $0 },
            accent: accentColor
        ) {
            if !text.isEmpty {
                Text(text)
                    .font(.system(size: 13))
                    .foregroundStyle(bodyColor)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if style.expandablePayload, let payload = CoordinationCard.prettyPayload(info.payload) {
                Button {
                    expanded.toggle()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: expanded ? "chevron.down" : "chevron.right")
                            .font(.system(size: 9))
                        Text(expanded ? "Hide payload" : "Show payload")
                            .font(.system(size: 11))
                    }
                    .foregroundStyle(Theme.textTertiary)
                }
                .buttonStyle(.plain)
                if expanded {
                    Text(payload)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 5))
                }
            }
        }
    }

    private var bodyColor: Color {
        switch style.accent {
        case .success: return Theme.success
        case .error: return Theme.danger
        default: return Theme.textSecondary
        }
    }
}
