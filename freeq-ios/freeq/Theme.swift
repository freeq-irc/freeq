import SwiftUI

/// The "Signal" design system.
///
/// One reviewable source of truth for color, space, radius, materials, and
/// type. Colors are defined in-code as adaptive light/dark pairs (no asset
/// catalog round-trip), so the whole palette reads top-to-bottom here.
///
/// Design thesis: freeq is a human name over a cryptographic fact. The palette
/// is a cool graphite ground with one luminous **signal** accent (frequency /
/// live), a **verify** green reserved for earned identity trust, and Liquid
/// Glass instead of flat fills. Type scales with Dynamic Type end to end.
enum Theme {

    // MARK: Backgrounds — cool graphite (dark) / cool near-white (light)
    static let bgPrimary   = Color(light: 0xFBFCFE, dark: 0x070A10)
    static let bgSecondary = Color(light: 0xF1F4F9, dark: 0x0C1119)
    static let bgTertiary  = Color(light: 0xE7ECF3, dark: 0x131B28)
    static let bgHover     = Color(light: 0xDDE4EE, dark: 0x1A2436)
    /// A slightly raised surface for cards floating over bgPrimary.
    static let bgElevated  = Color(light: 0xFFFFFF, dark: 0x0F1622)
    /// The tinted strip across a card's header. Ink-based in light because
    /// `bgElevated` is pure white there and vanished on a white card; dark
    /// keeps bgElevated's value, so dark is unchanged.
    static let cardHeaderStrip = Color(light: Color.black.opacity(0.05), dark: bgElevated)

    // MARK: Text
    static let textPrimary   = Color(light: 0x0B1220, dark: 0xEAF1F9)
    static let textSecondary = Color(light: 0x48566C, dark: 0x93A2B8)
    static let textMuted     = Color(light: 0x7B8698, dark: 0x5E6B7E)

    // MARK: Accent — "signal" cyan (deeper in light for contrast on white)
    static let accent      = Color(light: 0x0B96A8, dark: 0x35D6E7)
    static let accentLight = Color(light: 0x35D6E7, dark: 0x7FE9F3)
    /// A ready-made signal gradient for rings, send buttons, active states.
    static let signalGradient = LinearGradient(
        colors: [Color(hex: "35D6E7"), Color(hex: "0E8FA1")],
        startPoint: .topLeading, endPoint: .bottomTrailing)

    // MARK: Semantic
    /// Earned identity trust — verified DID, signed message. Reserved; never
    /// decorative.
    static let verify  = Color(light: 0x0F9A63, dark: 0x4ADE9B)
    static let success = verify                       // back-compat alias
    static let warning = Color(light: 0xB9761A, dark: 0xF5B544)
    static let danger  = Color(light: 0xDA3B3B, dark: 0xFB6B6B)
    /// Secondary brand hue — presence, links-in-glass, subtle depth.
    static let iris    = Color(light: 0x4E60D8, dark: 0x8A9BFF)
    /// In-progress register on act cards; the web token's values (--color-blue).
    static let blue    = Color(light: 0x3B7DFF, dark: 0x5C9EFF)

    // MARK: Borders — hairlines read as translucent, not painted lines
    static let border       = Color(light: Color.black.opacity(0.08),
                                     dark:  Color.white.opacity(0.10))
    static let borderStrong = Color(light: Color.black.opacity(0.14),
                                     dark:  Color.white.opacity(0.18))

    // MARK: Nick colors — harmonized, vivid, legible on both grounds
    static let nickColors: [Color] = [
        Color(hex: "35D6E7"), // signal cyan
        Color(hex: "4ADE9B"), // mint
        Color(hex: "8A9BFF"), // iris
        Color(hex: "FF8FA3"), // rose
        Color(hex: "F5B544"), // amber
        Color(hex: "B18CFF"), // violet
        Color(hex: "48C9E0"), // sky
        Color(hex: "6EE7B7"), // spring
        Color(hex: "FF9E64"), // coral
        Color(hex: "E68CF0"), // orchid
    ]

    static func nickColor(for nick: String) -> Color {
        let hash = nick.unicodeScalars.reduce(0) { $0 &+ Int($1.value) }
        return nickColors[abs(hash) % nickColors.count]
    }

    // MARK: - Spacing scale (4-pt rhythm)
    enum Space {
        static let xs: CGFloat = 4
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let xl: CGFloat = 24
        static let xxl: CGFloat = 32
        static let xxxl: CGFloat = 48
    }

    // MARK: - Corner radius scale (was 9 ad-hoc values app-wide)
    enum Radius {
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let card: CGFloat = 18
        static let xl: CGFloat = 22
        static let pill: CGFloat = 999
    }

    // Fallback hex-based colors for when the view is built before the
    // environment resolves (kept for back-compat call sites).
    static let bgPrimaryHex = Color(hex: "070A10")
    static let bgSecondaryHex = Color(hex: "0C1119")
}

// MARK: - Dynamic Type typography
//
// Every role scales with the user's text-size setting (semantic UIFont text
// styles under the hood). Replaces the app's 318 hardcoded `.system(size:)`
// calls: pick the role, not the pixel.
extension Font {
    static let fqLargeTitle = Font.system(.largeTitle, design: .default).weight(.bold)
    static let fqTitle      = Font.system(.title2, design: .default).weight(.bold)
    static let fqTitle3     = Font.system(.title3).weight(.semibold)
    static let fqHeadline   = Font.system(.headline)                    // 17 semibold
    static let fqBody       = Font.system(.body)                        // 17
    static let fqCallout    = Font.system(.callout)                     // 16
    static let fqCalloutSemibold = Font.system(.callout).weight(.semibold)
    static let fqSubheadline = Font.system(.subheadline)               // 15 — message body
    static let fqSubheadlineSemibold = Font.system(.subheadline).weight(.semibold)
    static let fqFootnote   = Font.system(.footnote)                    // 13
    static let fqCaption    = Font.system(.caption)                     // 12
    static let fqCaption2   = Font.system(.caption2)                    // 11 — timestamps
    /// The "machine" voice — DIDs, #channels, handles, signatures.
    static let fqMono       = Font.system(.footnote, design: .monospaced)
    static let fqMonoCaption = Font.system(.caption2, design: .monospaced)
}

// MARK: - Liquid Glass surfaces
//
// Semantic material tiers so chrome (tab / nav / compose bars, call HUD,
// sheets) stops using flat opaque fills. Use via `.glass(_:)`.
enum GlassTier {
    case thin    // tab bar, chips
    case regular // sheets, cards, compose bar
    case thick   // call HUD, modals over video

    var material: Material {
        switch self {
        case .thin: return .ultraThinMaterial
        case .regular: return .regularMaterial
        case .thick: return .thickMaterial
        }
    }
}

extension View {
    /// A rounded Liquid Glass surface with a hairline edge — the app's
    /// standard raised container.
    func glassCard(_ tier: GlassTier = .regular,
                   radius: CGFloat = Theme.Radius.card) -> some View {
        self
            .background(tier.material, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Theme.border, lineWidth: 1)
            )
    }

    /// Fill an edge-to-edge bar (nav / tab / compose) with glass instead of a
    /// painted color, with a hairline separator on the given edge.
    func glassBar(_ tier: GlassTier = .thin, separator: Edge.Set = .top) -> some View {
        self
            .background(tier.material)
            .overlay(alignment: separator == .top ? .top : .bottom) {
                Rectangle().fill(Theme.border).frame(height: 1)
            }
    }
}

// MARK: - Color helpers
extension Color {
    /// Adaptive color from two hex values (light appearance, dark appearance).
    init(light: UInt, dark: UInt) {
        self.init(uiColor: UIColor { trait in
            trait.userInterfaceStyle == .dark
                ? UIColor(Color(hex: String(format: "%06X", dark)))
                : UIColor(Color(hex: String(format: "%06X", light)))
        })
    }

    /// Adaptive color from two SwiftUI Colors (for translucent tokens).
    init(light: Color, dark: Color) {
        self.init(uiColor: UIColor { trait in
            trait.userInterfaceStyle == .dark ? UIColor(dark) : UIColor(light)
        })
    }

    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 6:
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8:
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}
