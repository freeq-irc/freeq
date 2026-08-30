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

    private var accentColor: Color {
        switch style.accent {
        case .neutral: return Theme.border
        case .agent: return Theme.purple
        case .success: return Theme.success
        case .error: return Theme.danger
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header strip
            HStack(spacing: 6) {
                Text(style.icon)
                Text(style.label)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                    .textCase(.uppercase)
                if let task = info.taskId {
                    Text(task.count > 10 ? String(task.prefix(10)) + "…" : task)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.surface.opacity(0.5))

            // Body
            VStack(alignment: .leading, spacing: 6) {
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
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(accentColor.opacity(0.5), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .frame(maxWidth: 460, alignment: .leading)
    }

    private var bodyColor: Color {
        switch style.accent {
        case .success: return Theme.success
        case .error: return Theme.danger
        default: return Theme.textSecondary
        }
    }
}
