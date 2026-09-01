import SwiftUI

/// Renders an agent coordination event as a structured card — the iOS
/// analogue of the web `CoordinationCards` and the macOS `CoordinationCardView`.
/// Driven by the shared pure `CoordinationCard` style policy.
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
        case .agent: return Theme.iris
        case .success: return Theme.success
        case .error: return Theme.danger
        }
    }

    private var bodyColor: Color {
        switch style.accent {
        case .success: return Theme.success
        case .error: return Theme.danger
        default: return Theme.textSecondary
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
                    .font(.system(size: 14))
                    .foregroundStyle(bodyColor)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if style.expandablePayload,
               let payload = CoordinationCard.prettyPayload(info.payload) {
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: expanded ? "chevron.down" : "chevron.right")
                            .font(.system(size: 9))
                        Text(expanded ? "Hide payload" : "Show payload")
                            .font(.system(size: 11))
                    }
                    .foregroundStyle(Theme.textMuted)
                }
                .buttonStyle(.plain)
                if expanded {
                    Text(payload)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Theme.bgElevated, in: RoundedRectangle(cornerRadius: 6))
                }
            }
        }
    }
}
