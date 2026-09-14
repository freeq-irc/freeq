import Foundation

/// Classifies the server notice that refuses this device's signing key
/// (FAIL MSGSIG KEY_RETIRED, which the SDK hands on as `MSGSIG KEY_RETIRED
/// <reason>`) and says what follows. Pure/Foundation → unit-testable.
/// Mirrors the iOS `RefusedKeyNotice`.
enum RefusedKeyNotice {
    struct Refusal: Equatable {
        /// The sentence the sign-in screen shows.
        let line: String
        /// The saved login is cleared, the way sign-out clears it.
        let clearsSavedLogin: Bool
        /// Whether the disconnect that follows may reconnect.
        let schedulesReconnect: Bool
    }

    static let line = "This device was signed out from another device. Sign in again to continue."

    /// The refusal a notice carries; nil for any other notice.
    static func parse(_ text: String) -> Refusal? {
        guard text.hasPrefix("MSGSIG KEY_RETIRED") else { return nil }
        return Refusal(line: line, clearsSavedLogin: true, schedulesReconnect: false)
    }
}
