import Foundation

// What this client can say about a message's signature.
//
// The check is the SDK's own, made here on the device: it rebuilds the signed
// document from the line and looks the signer's key up in their identity
// records, their DID document, or the server's key store. The verdict arrives
// on the message, or shortly after it as a verdict event. Nothing here fetches
// anything.
//
// The verdict rides on the row as `VerdictInfo`, a pure-Foundation mirror of
// the FFI's `SignatureVerdict` — the same arrangement `CoordinationInfo` has
// against the FFI's coordination event, so these models and their tests stay
// free of the generated bindings. The mapping from the FFI lives in AppState,
// which sees both.

/// The seven answers a signature check can come to.
///
/// `unverifiable` covers a signature whose key no source holds, or a format
/// this build cannot read; `invalid` means the key the signature names was
/// found and the signature does not match it; `retired` means it was made with
/// a key its owner had already retired. `unsigned` is a third thing again —
/// there was never a signature, so nothing was checked and nothing failed.
/// `pending` means the key is still being looked up.
enum VerdictKind: String, Codable, Equatable, CaseIterable {
    case device
    case server
    case unsigned
    case unverifiable
    case invalid
    case retired
    case pending
}

/// How far a device key has got: vouched for by the sender's server, or
/// published in their identity record.
enum VerdictLayer: String, Codable, Equatable {
    case vouched
    case published
}

/// One verdict, as the row carries it and the cache keeps it.
struct VerdictInfo: Codable, Equatable {
    let kind: VerdictKind
    let layer: VerdictLayer?
    let kid: String?
    let keySource: String?
    /// The SDK's sentence for this state. Every freeq client shows these same
    /// words; they come from `spec/verdict-model.json` and are never
    /// paraphrased per platform.
    let sentence: String

    init(
        kind: VerdictKind,
        layer: VerdictLayer? = nil,
        kid: String? = nil,
        keySource: String? = nil,
        sentence: String
    ) {
        self.kind = kind
        self.layer = layer
        self.kid = kid
        self.keySource = keySource
        self.sentence = sentence
    }
}

/// How loudly a verdict is allowed to speak. Green only for sender proof; red
/// only where a signature was found and did not hold; everything else is a
/// quiet statement of fact.
enum VerdictTone: Equatable {
    case good
    case bad
    case quiet
}

/// One answer in two parts: what it is, and what it means for the reader. The
/// line is the SDK's sentence; the heading and the tone are this client's.
struct VerdictCopy: Equatable {
    let heading: String
    let line: String
}

/// Presenting a verdict: the heading it wears, the colour it earns, and
/// whether it marks the message row.
enum VerdictDisplay {

    static func tone(_ kind: VerdictKind) -> VerdictTone {
        switch kind {
        case .device: .good
        case .invalid, .retired: .bad
        // A server vouch is quiet like every other not-proven state: valid is
        // not verified (ruled 2026-08-07).
        case .server, .unsigned, .unverifiable, .pending: .quiet
        }
    }

    /// The reader is asking one question — who vouches for this message — so
    /// the heading answers it and the sentence says what that means.
    static func heading(_ kind: VerdictKind) -> String {
        switch kind {
        case .device: "Verified"
        case .server: "Server Signed"
        case .unsigned: "Unsigned"
        case .unverifiable: "Signature Not Supported"
        // A signature made after its key was retired is an invalid one.
        case .invalid, .retired: "Signature Invalid"
        case .pending: "Verification in Progress"
        }
    }

    /// Whether a verdict leaves a mark on the row. Signing is the default
    /// state of a message and a default earns no ink, so only a signature that
    /// was found and did not hold marks it.
    static func marksTheRow(_ kind: VerdictKind) -> Bool {
        kind == .invalid || kind == .retired
    }

    static func copy(_ verdict: VerdictInfo) -> VerdictCopy {
        VerdictCopy(heading: heading(verdict.kind), line: verdict.sentence)
    }
}
