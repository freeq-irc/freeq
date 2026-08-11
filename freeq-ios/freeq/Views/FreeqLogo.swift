import SwiftUI

/// Programmatic freeq logo — no image asset needed.
/// Gradient "f" lettermark in a rounded square.
struct FreeqLogo: View {
    let size: CGFloat

    var body: some View {
        ZStack {
            // Rounded square background with gradient
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [Color(hex: "6c63ff"), Color(hex: "4f46e5")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .frame(width: size, height: size)

            // Subtle inner glow
            RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
                .fill(
                    RadialGradient(
                        colors: [Color.white.opacity(0.15), Color.clear],
                        center: .topLeading,
                        startRadius: 0,
                        endRadius: size * 0.8
                    )
                )
                .frame(width: size, height: size)

            // "f" lettermark
            Text("f")
                .font(.system(size: size * 0.55, weight: .bold, design: .rounded))
                .foregroundColor(.white)
                .offset(x: -size * 0.02, y: size * 0.02)
        }
    }
}

/// Small inline verified badge — checkmark in accent circle.
/// Earned identity trust — a verified AT Protocol DID. Painted in the "verify"
/// green (never the accent), so verification reads as its own distinct signal
/// throughout the app.
struct VerifiedBadge: View {
    let size: CGFloat

    var body: some View {
        Image(systemName: "checkmark.seal.fill")
            .font(.system(size: size, weight: .semibold))
            .foregroundStyle(Theme.verify)
            .accessibilityLabel("AT Protocol identity")
    }
}
