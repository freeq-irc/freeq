import SwiftUI

/// Design tokens for freeq macOS. Every token is dynamic — a warm light
/// palette and a matching warm dark palette, resolved per the effective
/// appearance (so the app follows the system, and the user override in
/// Settings works per-window).
enum Theme {
    /// A color that resolves against the current appearance at draw time.
    private static func dynamic(light: NSColor, dark: NSColor) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
        })
    }

    private static func rgb(_ r: Double, _ g: Double, _ b: Double, _ a: Double = 1) -> NSColor {
        NSColor(srgbRed: r, green: g, blue: b, alpha: a)
    }

    // Brand
    static let accent = dynamic(
        light: rgb(0.00, 0.58, 0.50),
        dark: rgb(0.10, 0.72, 0.62))
    static let accentSoft = dynamic(
        light: rgb(0.88, 0.97, 0.95),
        dark: rgb(0.09, 0.22, 0.20))
    static let blue = dynamic(
        light: rgb(0.22, 0.47, 0.88),
        dark: rgb(0.40, 0.62, 1.00))
    static let purple = dynamic(
        light: rgb(0.48, 0.38, 0.86),
        dark: rgb(0.62, 0.53, 1.00))

    // Backgrounds — warm light / warm dark.
    static let appBackground = dynamic(
        light: rgb(0.965, 0.965, 0.950),
        dark: rgb(0.118, 0.118, 0.128))
    static let sidebarBackground = dynamic(
        light: rgb(0.945, 0.948, 0.930),
        dark: rgb(0.098, 0.100, 0.110))
    static let chatBackground = dynamic(
        light: rgb(0.992, 0.990, 0.980),
        dark: rgb(0.138, 0.138, 0.148))
    static let detailBackground = dynamic(
        light: rgb(0.972, 0.972, 0.955),
        dark: rgb(0.128, 0.128, 0.138))
    static let surface = dynamic(
        light: .white,
        dark: rgb(0.165, 0.165, 0.175))
    /// The tinted strip across a card's header. Ink-based in light because
    /// `surface` is pure white there and vanished on a white card; the dark
    /// value is `surface` at half opacity, flattened, so dark is unchanged.
    static let cardHeaderStrip = dynamic(
        light: rgb(0, 0, 0, 0.05),
        dark: rgb(0.165, 0.165, 0.175, 0.5))
    static let surfaceSoft = dynamic(
        light: rgb(0.982, 0.980, 0.966),
        dark: rgb(0.188, 0.188, 0.198))
    static let surfaceElevated = dynamic(
        light: .white,
        dark: rgb(0.192, 0.192, 0.205))

    // Text
    static let textPrimary = dynamic(
        light: rgb(0.105, 0.110, 0.125),
        dark: rgb(0.930, 0.930, 0.945))
    static let textSecondary = dynamic(
        light: rgb(0.390, 0.400, 0.430),
        dark: rgb(0.660, 0.670, 0.700))
    static let textTertiary = dynamic(
        light: rgb(0.575, 0.580, 0.610),
        dark: rgb(0.500, 0.510, 0.540))

    // Semantic
    static let success = dynamic(
        light: rgb(0.10, 0.68, 0.34),
        dark: rgb(0.22, 0.78, 0.44))
    static let warning = dynamic(
        light: rgb(0.88, 0.50, 0.12),
        dark: rgb(0.98, 0.62, 0.24))
    static let danger = dynamic(
        light: rgb(0.84, 0.18, 0.20),
        dark: rgb(0.96, 0.34, 0.36))
    static let verified = dynamic(
        light: rgb(0.18, 0.42, 0.92),
        dark: rgb(0.40, 0.62, 1.00))

    // Border
    static let border = dynamic(
        light: rgb(0.845, 0.845, 0.825),
        dark: rgb(0.300, 0.300, 0.320))
    static let borderSoft = dynamic(
        light: rgb(0.910, 0.908, 0.890),
        dark: rgb(0.225, 0.225, 0.245))
    static let hairline = dynamic(
        light: rgb(0, 0, 0, 0.06),
        dark: rgb(1, 1, 1, 0.08))

    // Messages
    static let outgoingBubble = dynamic(
        light: rgb(0.220, 0.455, 0.835),
        dark: rgb(0.260, 0.500, 0.900))
    static let incomingBubble = dynamic(
        light: rgb(0.935, 0.932, 0.910),
        dark: rgb(0.200, 0.200, 0.220))
    static let systemPill = dynamic(
        light: rgb(0.925, 0.940, 0.955),
        dark: rgb(0.180, 0.200, 0.230))

    // Nick colors (consistent with web + iOS; bright enough for both modes)
    static let nickColors: [Color] = [
        Color(red: 1.0, green: 0.43, blue: 0.71),    // #ff6eb4
        Color(red: 0.0, green: 0.83, blue: 0.67),     // #00d4aa
        Color(red: 1.0, green: 0.71, blue: 0.28),     // #ffb547
        Color(red: 0.36, green: 0.62, blue: 1.0),     // #5c9eff
        Color(red: 0.69, green: 0.55, blue: 1.0),     // #b18cff
        Color(red: 1.0, green: 0.58, blue: 0.28),     // #ff9547
        Color(red: 0.0, green: 0.77, blue: 1.0),      // #00c4ff
        Color(red: 1.0, green: 0.36, blue: 0.36),     // #ff5c5c
        Color(red: 0.49, green: 0.87, blue: 0.49),    // #7edd7e
        Color(red: 1.0, green: 0.52, blue: 0.82),     // #ff85d0
    ]

    static func nickColor(for nick: String) -> Color {
        var h: Int = 0
        for char in nick.unicodeScalars {
            h = Int(char.value) &+ ((h &<< 5) &- h)
        }
        return nickColors[abs(h) % nickColors.count]
    }
}
