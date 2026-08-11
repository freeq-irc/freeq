import Foundation

// The data behind the proof sheet: the message-signing key published at
// `/api/v1/signing-keys/{did}` and the checked answer from
// `/api/v1/verify/{msgid}`. Pure parsing + presentation strings — the sheet
// does the fetching; these stay testable under `swift test`.

/// What checking a message's signature can come back as.
///
/// `unverifiable` covers a signature from before the current canonical form,
/// or one made with a key the server does not hold. `invalid` means the key
/// the signature names was found and the signature does not match it.
/// `unreachable` means the check itself failed — network down, proxy fault,
/// server error — which is a fact about the network and not a verdict about
/// the message.
enum VerifyOutcome: Equatable {
    case device
    case server
    case unsigned
    case unverifiable
    case invalid
    case unreachable
}

/// How loudly a verdict is allowed to speak. Green only after the server
/// answered valid *and* the sender's own key signed it; red only after the
/// server answered invalid; everything else is a quiet statement of fact.
enum VerdictTone: Equatable {
    case good
    case bad
    case quiet
}

/// One answer in two parts: what it is, and what it means for the reader.
/// Every client carries the same pair for the same state; how they are laid
/// out on a given surface is that surface's business.
struct VerdictCopy: Equatable {
    let heading: String
    let line: String
}

/// A checked answer, with the one distinction inside `unverifiable` that
/// changes what happens next: a signature naming a key this server simply
/// hasn't fetched yet is `transient` — answering the request is what starts
/// the fetch, so asking again shortly usually resolves it. Every other flavour
/// is final.
struct VerifyAnswer: Equatable {
    let outcome: VerifyOutcome
    var transient: Bool = false

    /// Sender proof only. A server signature is the server vouching for what
    /// it received — a valid fact, not a verification of the sender.
    var isVerified: Bool { outcome == .device }

    var isInvalid: Bool { outcome == .invalid }

    /// Whether this answer shows a marker on the message row. Only a mismatch
    /// does, and only after the server said so — almost every message is
    /// signed, so a marker on all of them would say nothing.
    var marksTheRow: Bool { isInvalid }
}

/// Reading `GET /api/v1/verify/{msgid}`.
///
/// Verification is an explicit request — the UI asks only when the user does —
/// and the answer says only what it can support. Kept pure and separate from
/// the fetch so each distinction is assertable. Mirrors the web client's
/// `verify-signature.ts` and Android's `SignatureVerdict.kt`; the strings were
/// agreed line by line across clients and are not paraphrased per platform.
enum SignatureVerdict {

    static func parse(status: Int, body: Data?) -> VerifyAnswer {
        guard (200..<300).contains(status) else {
            // A 4xx is the server answering "no record of that id" — a
            // can't-check. A 5xx means the check never happened.
            return VerifyAnswer(outcome: status < 500 ? .unverifiable : .unreachable)
        }
        guard let body,
              let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let v = json["verification"] as? [String: Any]
        else { return VerifyAnswer(outcome: .unverifiable) }

        let verifiedBy = v["verified_by"] as? String ?? ""
        // `verdict` is the server's three-way answer; fall back to the older
        // boolean for a server that predates it. An old server's `false` means
        // "could not confirm", which is not the same as "forged" — reading it
        // as an accusation would warn about messages nobody impugned.
        let verdict = (v["verdict"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? ((v["valid"] as? Bool ?? false) ? "valid" : "unverifiable")

        switch verdict {
        case "valid":
            return VerifyAnswer(outcome: verifiedBy == "client-session-key" ? .device : .server)
        case "invalid":
            return VerifyAnswer(outcome: .invalid)
        default:
            // The server names its reason, and "nobody signed it" is a
            // different fact from "I couldn't check it" — a guest's message is
            // not a failed check.
            if verifiedBy == "unsigned" { return VerifyAnswer(outcome: .unsigned) }
            return VerifyAnswer(
                outcome: .unverifiable,
                transient: verifiedBy == "unverifiable-unknown-key"
            )
        }
    }

    static func tone(_ outcome: VerifyOutcome) -> VerdictTone {
        switch outcome {
        case .device: .good
        case .invalid: .bad
        // A server vouch is quiet like every other not-proven state.
        case .server, .unsigned, .unverifiable, .unreachable: .quiet
        }
    }

    /// What the answer is, and what it means for the person reading it.
    ///
    /// The reader is asking one question — who vouches for this message — so
    /// the heading answers it and the line says what that means for them.
    ///
    /// - Parameter retrying: whether the caller is still going to ask again.
    ///   The fetching-a-key answer holds only while that is true: a panel that
    ///   promises it is still checking after it has stopped is lying, so once
    ///   the retries are gone it decays into the plain can't-check.
    static func copy(_ answer: VerifyAnswer, retrying: Bool = false) -> VerdictCopy {
        switch answer.outcome {
        case .device:
            return VerdictCopy(
                heading: "Verified",
                line: "Signed on the sender's device."
            )
        case .server:
            return VerdictCopy(
                heading: "Server Signed",
                line: "The server confirms it arrived from the sender's account, but they "
                    + "didn't sign it themselves — so you're taking the server's word for it."
            )
        case .unsigned:
            return unsigned
        case .invalid:
            return VerdictCopy(
                heading: "Signature Invalid",
                line: "This message is signed, but the signature doesn't check out. "
                    + "Treat it with suspicion."
            )
        case .unverifiable:
            if answer.transient && retrying { return checking }
            return VerdictCopy(
                heading: "Signature Not Supported",
                line: "The server can't check this signature — usually an older message, "
                    + "sometimes a newer app."
            )
        case .unreachable:
            return VerdictCopy(
                heading: "Unable to Verify",
                line: "The app couldn't reach the server, so this signature hasn't been "
                    + "checked yet."
            )
        }
    }

    /// A message nobody signed. Not a failed check and not a doubt about the
    /// sender — there is simply nothing to check, and asking the server would
    /// only produce a can't-check that reads like a fault.
    static let unsigned = VerdictCopy(
        heading: "Unsigned",
        line: "Nothing was signed — there is no signature to check. Typical for guest "
            + "accounts and messages from legacy servers."
    )

    /// The one can't-check a retry can outrun: the key belongs to someone on
    /// another server, and answering the request is what starts the fetch.
    static let checking = VerdictCopy(
        heading: "Verification in Progress",
        line: "The sender's key is on another server. We're fetching it now — this will "
            + "answer in a moment."
    )

    /// A settled answer is the same every time it is asked; a transient or
    /// failed one deserves a fresh try.
    static func worthCaching(_ answer: VerifyAnswer) -> Bool {
        !answer.transient && answer.outcome != .unreachable
    }
}

/// A sender's published message-signing key.
struct SigningKeyInfo: Equatable {
    let publicKey: String
    let algorithm: String
    let source: String

    // No label is derived from `source`. It used to read "client-session" for
    // a key a device had registered, and the sheet said so; since the durable
    // key store landed it reads "key-store" for everything, and every key that
    // endpoint can return was registered by a client anyway — so the
    // distinction it once drew no longer exists. Who signed a message is the
    // verdict's answer, and the verdict already gives it.

    /// Parse the `/api/v1/signing-keys/{did}` response body.
    static func from(json: [String: Any]) -> SigningKeyInfo? {
        guard let pk = json["public_key"] as? String else { return nil }
        return SigningKeyInfo(
            publicKey: pk,
            algorithm: json["algorithm"] as? String ?? "ed25519",
            source: json["source"] as? String ?? ""
        )
    }
}
