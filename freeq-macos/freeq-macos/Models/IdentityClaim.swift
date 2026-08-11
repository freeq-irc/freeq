import Foundation

/// The identity-claim rule does not live here. Its states, precedence, and
/// every user-facing string come from the SDK (spec/identity-claims.json),
/// reached through the FFI's claimForMessage / claimForPerson /
/// claimForSender — the same rule, byte for byte, that web and Android
/// render. This file keeps only the app-side lookup plumbing that feeds it.
enum IdentityLookup: Equatable {
    /// No ask has gone out, or the surface never asks.
    case notAsked
    /// An ask is out and unanswered.
    case inFlight
    /// The answer came back and named no account.
    case noAccount
    /// The answer named a DID this session, so the binding is live-known
    /// even when the person is in no roster right now.
    case answeredDid
}

/// What to call this person on a surface about them. Anyone we can name is
/// named; a message row always has a nick, so the empty fallback is
/// unreachable in practice.
enum SenderIdentity {
    static func title(displayName: String?, handle: String?, nick: String?) -> String {
        if let displayName, !displayName.isEmpty { return displayName }
        if let handle, !handle.isEmpty { return "@\(handle)" }
        if let nick, !nick.isEmpty { return nick }
        return ""
    }
}
