import Foundation

/// Classifies the server notice that refuses this device's signing key
/// (FAIL MSGSIG KEY_RETIRED, which the SDK hands on as `MSGSIG KEY_RETIRED
/// <reason>`) and says what follows. Pure/Foundation → unit-testable.
/// Mirrors the macOS `RefusedKeyNotice`.
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

/// What follows when the broker refuses the saved login itself: a `/session`
/// call that failed. Pure/Foundation → unit-testable.
enum RefusedLogin {
    /// The sentence the sign-in screen shows; the broker 401's own words.
    static let line = "Session expired — please sign in again"

    enum Next: Equatable {
        /// Show the sign-in screen with `line`, clearing the saved login first
        /// when it is still held.
        case signIn(line: String, clearsSavedLogin: Bool)
        /// Keep the saved login; the reconnect loop tries again.
        case retry
    }

    /// A 401 ends the login on its first answer, pressed or automatic: the
    /// server can end a login before this device offers any token. Any other
    /// failure retries.
    static func afterBrokerFailure(status: Int, savedLoginCleared: Bool) -> Next {
        guard status == 401 else { return .retry }
        return .signIn(line: line, clearsSavedLogin: !savedLoginCleared)
    }

    /// Seconds before asking again: never under one, so refusals cannot spin.
    static func reconnectDelay(_ delay: Double) -> Double {
        max(1, delay)
    }

    /// What a refused connect (its web token, or this device's key) comes to.
    /// When its token followed a refused one, the broker would only hand over
    /// another the server refuses, so the login ends.
    static func afterConnectRefused(tokenFollowsRefusal: Bool) -> Next {
        tokenFollowsRefusal ? .signIn(line: line, clearsSavedLogin: true) : .retry
    }
}
