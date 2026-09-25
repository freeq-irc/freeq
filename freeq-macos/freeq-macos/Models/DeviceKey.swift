import Foundation
import os.log

/// This device's signing keys, one per account, and the way each reaches its
/// account. Sign-out keeps each account's key.
///
/// The key is one 32-byte seed that outlives a session, so messages from this
/// Mac keep signing with the same key and a reader can learn it once. It lives
/// in the Keychain beside `brokerToken`, under the same accessibility, and
/// never syncs off the device. Kept in step with the iOS copy.
final class KeychainDeviceKeyStore: DeviceKeyStore {

    private static let log = Logger(subsystem: "at.freeq.macos", category: "devicekey")

    init() {
        Self.dropLegacy()
    }

    func load(did: String) throws -> StoredDeviceKey? {
        let names = DeviceKeyNames(did: did)
        guard let encoded = KeychainHelper.load(key: names.seed),
              let createdAt = KeychainHelper.load(key: names.createdAt)
        else { return nil }
        // An unreadable seed is a key this device no longer has: say so and
        // let the SDK mint a fresh one rather than failing the connect.
        guard let seed = Data(base64Encoded: encoded) else {
            Self.log.warning("stored seed unreadable, minting a new key")
            return nil
        }
        return StoredDeviceKey(
            seed: seed,
            createdAt: createdAt,
            recordUri: KeychainHelper.load(key: names.recordUri),
            refused: KeychainHelper.load(key: names.refused) != nil
        )
    }

    func save(did: String, key: StoredDeviceKey) throws {
        let names = DeviceKeyNames(did: did)
        _ = KeychainHelper.save(key: names.seed, value: key.seed.base64EncodedString())
        _ = KeychainHelper.save(key: names.createdAt, value: key.createdAt)
        if let uri = key.recordUri {
            _ = KeychainHelper.save(key: names.recordUri, value: uri)
        } else {
            KeychainHelper.delete(key: names.recordUri)
        }
        if key.refused {
            _ = KeychainHelper.save(key: names.refused, value: "1")
        } else {
            KeychainHelper.delete(key: names.refused)
        }
    }

    /// Whether the key this device holds for `did` is published to that
    /// account.
    func isPublished(did: String) -> Bool {
        KeychainHelper.load(key: DeviceKeyNames(did: did).recordUri) != nil
    }

    /// The key every account shared before keys were kept per account: every
    /// account that signed in here signed with it, so it is thrown away, and
    /// each account makes its own at its next connect.
    private static func dropLegacy() {
        for name in DeviceKeyNames.legacy where KeychainHelper.load(key: name) != nil {
            KeychainHelper.delete(key: name)
        }
    }
}

/// The FFI's word for what `EnrollAnswer` decided.
private func ffiOutcome(_ kind: EnrollAnswerKind) -> EnrollOutcome {
    switch kind {
    case .published: .published
    case .needsSignIn: .needsSignIn
    case .failed: .failed
    }
}

/// Publishing this device's key record through the broker, the one party that
/// holds the account's token. The SDK calls this off the connect path, on a
/// thread of its own, so the wait here never delays a connect.
final class BrokerEnrollment: Enrollment {

    private let brokerBase: @Sendable () -> String
    private let brokerToken: @Sendable () -> String?

    init(
        brokerBase: @escaping @Sendable () -> String,
        brokerToken: @escaping @Sendable () -> String?
    ) {
        self.brokerBase = brokerBase
        self.brokerToken = brokerToken
    }

    func publish(recordJson: String, signerPublicKey: String) throws -> EnrollResult {
        guard let token = brokerToken() else {
            return EnrollResult(outcome: .needsSignIn, recordUri: nil, detail: "no broker session")
        }
        guard let url = URL(string: "\(brokerBase())/enroll") else {
            return EnrollResult(outcome: .failed, recordUri: nil, detail: "bad broker base")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        // The record goes out as the SDK serialized it. Its `bindingSig` is
        // over the record's own canonical form, so re-encoding it here would
        // only risk changing what was signed.
        request.httpBody = Data(
            ("{\"broker_token\":\(Self.quoted(token)),\"record\":\(recordJson)"
                + ",\"signer_public_key\":\(Self.quoted(signerPublicKey))}").utf8
        )

        var body: Data?
        var status = 0
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { data, response, _ in
            body = data
            status = (response as? HTTPURLResponse)?.statusCode ?? 0
            done.signal()
        }.resume()
        done.wait()

        let kind = EnrollAnswer.kind(status: status)
        guard kind == .published else {
            // A network failure lands here as status 0 — `failed`, which says
            // nothing to the user; the SDK offers the key again next connect.
            return EnrollResult(
                outcome: ffiOutcome(kind),
                recordUri: nil,
                detail: "broker returned \(status)"
            )
        }
        let uri = body
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            .flatMap { $0?["uri"] as? String }
        return EnrollResult(outcome: .published, recordUri: uri, detail: nil)
    }

    /// JSON-quote one string. These two are an opaque token and a multibase
    /// key, so the quote, the backslash and the control range are all that can
    /// appear needing an escape.
    private static func quoted(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }
}
