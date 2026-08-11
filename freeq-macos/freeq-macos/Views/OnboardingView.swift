import SwiftUI

/// First-time onboarding — shown once on first launch.
struct OnboardingView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Logo
            VStack(spacing: 12) {
                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.blue.gradient)
                Text("freeq")
                    .font(.system(size: 36, weight: .bold, design: .rounded))
                Text("Decentralized IRC with AT Protocol Identity")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            Spacer().frame(height: 32)

            // Features
            VStack(alignment: .leading, spacing: 16) {
                FeatureRow(icon: "person.badge.shield.checkmark", color: .blue,
                           title: "AT Protocol Identity",
                           desc: "Sign in with your Bluesky account for an AT Protocol identity")
                FeatureRow(icon: "lock.fill", color: .green,
                           title: "Cryptographic Signatures",
                           desc: "Messages are signed — non-repudiable and tamper-proof")
                FeatureRow(icon: "point.3.connected.trianglepath.dotted", color: .purple,
                           title: "Peer-to-Peer",
                           desc: "Direct P2P messaging via iroh when both users are online")
                FeatureRow(icon: "number", color: .orange,
                           title: "Full IRC",
                           desc: "Channels, DMs, ops, kicks, modes — the full IRC experience")
            }
            .padding(.horizontal, 40)

            Spacer().frame(height: 32)

            // Shortcuts
            VStack(alignment: .leading, spacing: 8) {
                Text("Quick shortcuts")
                    .font(.headline)
                HStack(spacing: 20) {
                    ShortcutPill(keys: "⌘K", label: "Switch")
                    ShortcutPill(keys: "⌘F", label: "Search")
                    ShortcutPill(keys: "⌘J", label: "Join")
                    ShortcutPill(keys: "⇧⌘B", label: "Bookmarks")
                }
            }

            Spacer()

            Button("Get Started") {
                UserDefaults.standard.set(true, forKey: "freeq.onboardingComplete")
                dismiss()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.bottom, 24)
        }
        .frame(width: 500, height: 520)
    }
}

struct FeatureRow: View {
    let icon: String
    let color: Color
    let title: String
    let desc: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(color)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.body.weight(.semibold))
                Text(desc)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct ShortcutPill: View {
    let keys: String
    let label: String

    var body: some View {
        HStack(spacing: 4) {
            Text(keys)
                .font(.system(.caption, design: .monospaced).weight(.bold))
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color(nsColor: .controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 4))
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
