import SwiftUI

/// Renders an agent coordination event as a structured card — the iOS
/// analogue of the web `CoordinationCards` and the macOS `CoordinationCardView`.
/// Driven by the shared pure `CoordinationCard` style policy.
struct CoordinationCardView: View {
    let info: CoordinationInfo
    let text: String
    @State private var expanded = false

    private var style: CoordinationCard.Style { CoordinationCard.style(for: info) }

    private var accentColor: Color {
        switch style.accent {
        case .neutral: return Theme.borderStrong
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
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Text(style.icon)
                Text(style.label.uppercased())
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                if let task = info.taskId {
                    Text(task.count > 10 ? String(task.prefix(10)) + "…" : task)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Theme.textMuted)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.bgElevated)

            VStack(alignment: .leading, spacing: 6) {
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
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
        }
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(accentColor.opacity(0.5), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .frame(maxWidth: 420, alignment: .leading)
    }
}
