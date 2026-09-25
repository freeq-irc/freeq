import Foundation

// The decisions about this device's keys that need no Keychain and no
// generated bindings, so they compile — and are tested — outside the app
// target. The Keychain store and the broker call live in `DeviceKey.swift`.

/// What the broker's answer to a key record means.
///
/// Only the middle one asks anything of the user: the account will not take a
/// write from this session, so the key stays where it is and keeps signing
/// until they sign in again.
enum EnrollAnswerKind: Equatable {
    case published
    case needsSignIn
    case failed
}

enum EnrollAnswer {
    /// 200 is the write landing; 401–403 is the account declining it;
    /// everything else — a broker fault, a PDS fault, no network at all — is
    /// not the user's to fix and says nothing to them.
    static func kind(status: Int) -> EnrollAnswerKind {
        if status == 200 { return .published }
        if (401...403).contains(status) { return .needsSignIn }
        return .failed
    }
}

/// The one line the room is told when the key could not be published.
///
/// Said once per session: the SDK re-offers the key on every connect, and a
/// repeated line would read as a new fault each time. Messages keep sending
/// and keep carrying that key — they just show the weaker mark.
final class SigningKeyNotice {

    static let line =
        "Security upgrade available: publish your key so others can verify messages from this device. Open Settings to publish it."

    private var told = false

    /// The line, the first time it is asked for; nil after that.
    func next() -> String? {
        if told { return nil }
        told = true
        return Self.line
    }

    func forget() {
        told = false
    }
}

/// The Keychain names one account's device key is kept under, so each
/// account signed in on this device has a key of its own.
struct DeviceKeyNames: Equatable {
    let seed: String
    let createdAt: String
    let recordUri: String
    let refused: String

    init(did: String) {
        seed = "deviceKeySeed:\(did)"
        createdAt = "deviceKeyCreatedAt:\(did)"
        recordUri = "deviceKeyRecordUri:\(did)"
        refused = "deviceKeyRefused:\(did)"
    }

    /// The names every account shared before keys were kept per account:
    /// never read, and deleted once.
    static let legacy = ["deviceKeySeed", "deviceKeyCreatedAt", "deviceKeyRecordUri", "deviceKeyRefused"]
}
