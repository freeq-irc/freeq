import XCTest
@testable import FreeqMacosCore

/// What a verdict is allowed to claim, and the words it wears.
///
/// The check itself is the SDK's and its own vectors cover it. What these pin
/// is the app's side: every state carries the SDK's sentence unaltered, only
/// sender proof is spoken about in green, and only a signature that was found
/// and did not hold marks a row. Alongside them, the two decisions about this
/// device's own key that need neither the Keychain nor the bindings.
final class SignatureProofTests: XCTestCase {

    private func verdict(
        _ kind: VerdictKind,
        sentence: String = "the sentence the SDK gave",
        layer: VerdictLayer? = nil
    ) -> VerdictInfo {
        VerdictInfo(kind: kind, layer: layer, kid: "kid", keySource: nil, sentence: sentence)
    }

    // MARK: - The words

    func testEveryStateShowsTheSentenceTheSdkGaveIt() {
        // The words live in spec/verdict-model.json and reach this client
        // through the FFI, so no platform words its own and no state is left
        // without one.
        for kind in VerdictKind.allCases {
            let v = verdict(kind, sentence: "sentence for \(kind.rawValue)")
            XCTAssertEqual(VerdictDisplay.copy(v).line, "sentence for \(kind.rawValue)")
        }
    }

    func testTheLayerADeviceSignatureRestsOnRidesAlong() {
        let vouched = verdict(
            .device,
            sentence: "Signed on the sender’s device. Key vouched for by their server.",
            layer: .vouched
        )
        XCTAssertEqual(vouched.layer, .vouched)
        XCTAssertEqual(
            VerdictDisplay.copy(vouched).line,
            "Signed on the sender’s device. Key vouched for by their server."
        )
    }

    func testEveryAnswerSaysWhatItIsAndWhatItMeans() {
        for kind in VerdictKind.allCases {
            let copy = VerdictDisplay.copy(verdict(kind))
            XCTAssertFalse(copy.heading.isEmpty, "\(kind)")
            XCTAssertFalse(copy.line.isEmpty, "\(kind)")
            // The heading is the answer, not a restatement of the line.
            XCTAssertNotEqual(copy.heading, copy.line, "\(kind)")
        }
    }

    // MARK: - What each answer is allowed to claim

    func testOnlySenderProofGetsTheSuccessTone() {
        XCTAssertEqual(VerdictDisplay.tone(.device), .good)
        XCTAssertEqual(VerdictDisplay.heading(.device), "Signed")
        // Valid is not verified: the server vouching for what it received is
        // a fact about the server, not proof from the sender.
        XCTAssertEqual(VerdictDisplay.tone(.server), .quiet)
        XCTAssertNotEqual(VerdictDisplay.heading(.server), "Signed")
        for kind: VerdictKind in [.invalid, .retired] {
            XCTAssertEqual(VerdictDisplay.tone(kind), .bad, "\(kind)")
        }
        for kind: VerdictKind in [.unsigned, .unverifiable, .pending] {
            XCTAssertEqual(VerdictDisplay.tone(kind), .quiet, "\(kind) is a fact, never a warning")
        }
    }

    func testAnUnsignedMessageIsNotAFailedCheck() {
        XCTAssertEqual(VerdictDisplay.heading(.unsigned), "Unsigned")
        XCTAssertEqual(VerdictDisplay.tone(.unsigned), .quiet)
    }

    // MARK: - This device's key

    func testARefusalAsksForASignInAndTellsTheRoomOnce() {
        XCTAssertEqual(EnrollAnswer.kind(status: 401), .needsSignIn)
        XCTAssertEqual(EnrollAnswer.kind(status: 402), .needsSignIn)
        XCTAssertEqual(EnrollAnswer.kind(status: 403), .needsSignIn)

        // Nothing here touches the connection: the only thing a refusal
        // produces is the line, and only the first time.
        let notice = SigningKeyNotice()
        XCTAssertEqual(notice.next(), SigningKeyNotice.line)
        XCTAssertNil(notice.next())
        XCTAssertNil(notice.next())
    }

    func testTheLineNamesTheOneThingLeftToDo() {
        XCTAssertEqual(
            SigningKeyNotice.line,
            "Security upgrade available: publish your key so others can verify messages from this device. Open Settings to publish it."
        )
    }

    func testAWriteThatLandedIsPublishedAndEveryFaultIsAFailure() {
        XCTAssertEqual(EnrollAnswer.kind(status: 200), .published)
        // A fault at the broker or the PDS is not the user's to fix; a network
        // failure arrives as status 0 and is the same kind of silence.
        for status in [0, 400, 404, 500, 502, 504] {
            XCTAssertEqual(EnrollAnswer.kind(status: status), .failed, "\(status)")
        }
    }
}
