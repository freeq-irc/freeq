import Foundation

/// Classifies the server notice that refuses this device's signing key
/// (FAIL MSGSIG KEY_RETIRED or KEY_EXPIRED, which the SDK hands on as
/// `MSGSIG KEY_RETIRED <reason>`) and says what follows. Either way the saved
/// login goes: a reconnect on it is not a fresh sign-in, so it would present
/// the same key, and only a fresh sign-in replaces an expired one.
/// Pure/Foundation → unit-testable.
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
    static let expiredLine = "This device's signing key has expired. Sign in again to continue."

    /// The refusal a notice carries; nil for any other notice.
    static func parse(_ text: String) -> Refusal? {
        let shown: String
        if text.hasPrefix("MSGSIG KEY_RETIRED") {
            shown = line
        } else if text.hasPrefix("MSGSIG KEY_EXPIRED") {
            shown = expiredLine
        } else {
            return nil
        }
        return Refusal(line: shown, clearsSavedLogin: true, schedulesReconnect: false)
    }
}
