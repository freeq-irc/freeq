import XCTest
@testable import FreeqIosCore

/// The proof sheet's data layer: reading `/api/v1/verify/{msgid}` and
/// `/api/v1/signing-keys/{did}`, and the answers those readings are allowed to
/// give. The wording is fleet-wide and agreed line by line — these tests pin
/// the distinctions, not the prose style.
final class SignatureProofTests: XCTestCase {

    private func body(_ json: String) -> Data { Data(json.utf8) }

    // MARK: - Parsing

    func testClientSessionKeyIsDeviceProof() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"verdict":"valid","verified_by":"client-session-key"}}"#))
        XCTAssertEqual(a.outcome, .device)
        XCTAssertTrue(a.isVerified)
    }

    func testServerKeyIsAVouchNotDeviceProof() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"verdict":"valid","verified_by":"server-key"}}"#))
        XCTAssertEqual(a.outcome, .server)
        XCTAssertFalse(a.isVerified, "the server vouching is not the sender proving")
    }

    func testInvalidIsItsOwnAnswer() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"verdict":"invalid","verified_by":"client-session-key"}}"#))
        XCTAssertEqual(a.outcome, .invalid)
        XCTAssertTrue(a.marksTheRow, "only a mismatch marks a row")
    }

    func testUnsignedIsNotAFailedCheck() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"verdict":"unverifiable","verified_by":"unsigned"}}"#))
        XCTAssertEqual(a.outcome, .unsigned)
        XCTAssertFalse(a.marksTheRow)
    }

    func testUnknownKeyIsTransient() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"verdict":"unverifiable","verified_by":"unverifiable-unknown-key"}}"#))
        XCTAssertEqual(a.outcome, .unverifiable)
        XCTAssertTrue(a.transient, "answering the request is what starts the key fetch")
        XCTAssertFalse(SignatureVerdict.worthCaching(a))
    }

    func testOtherUnverifiableIsFinal() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"verdict":"unverifiable","verified_by":"retired-format"}}"#))
        XCTAssertEqual(a.outcome, .unverifiable)
        XCTAssertFalse(a.transient)
        XCTAssertTrue(SignatureVerdict.worthCaching(a))
    }

    /// An older server answers with a boolean only. Its `false` means "could
    /// not confirm", which is not an accusation.
    func testLegacyBooleanTrueIsRead() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"valid":true,"verified_by":"client-session-key"}}"#))
        XCTAssertEqual(a.outcome, .device)
    }

    func testLegacyBooleanFalseIsNotAnAccusation() {
        let a = SignatureVerdict.parse(status: 200, body: body(
            #"{"verification":{"valid":false,"verified_by":"server-key"}}"#))
        XCTAssertEqual(a.outcome, .unverifiable)
        XCTAssertNotEqual(a.outcome, .invalid)
    }

    func testNullVerificationIsACantCheck() {
        let a = SignatureVerdict.parse(status: 200, body: body(#"{"verification":null}"#))
        XCTAssertEqual(a.outcome, .unverifiable)
    }

    func testNotFoundIsACantCheck() {
        XCTAssertEqual(SignatureVerdict.parse(status: 404, body: nil).outcome, .unverifiable)
    }

    /// A 5xx means the check never happened — saying "could not be checked
    /// here" would claim the server considered it.
    func testServerErrorIsUnreachable() {
        let a = SignatureVerdict.parse(status: 503, body: nil)
        XCTAssertEqual(a.outcome, .unreachable)
        XCTAssertFalse(SignatureVerdict.worthCaching(a), "a failed check deserves a fresh try")
    }

    func testGarbageBodyIsACantCheck() {
        XCTAssertEqual(SignatureVerdict.parse(status: 200, body: body("not json")).outcome,
                       .unverifiable)
    }

    // MARK: - What each answer is allowed to claim

    /// The 2026-08-07 ruling: valid is not verified. A server-key outcome
    /// never wears the word, and never wears success styling.
    func testServerVouchNeverClaimsVerified() {
        let copy = SignatureVerdict.copy(VerifyAnswer(outcome: .server))
        XCTAssertFalse(copy.heading.contains("Verified"))
        XCTAssertFalse(copy.line.contains("Verified"))
        XCTAssertEqual(SignatureVerdict.tone(.server), .quiet)
    }

    func testOnlyDeviceProofIsGreen() {
        XCTAssertEqual(SignatureVerdict.tone(.device), .good)
        XCTAssertEqual(SignatureVerdict.copy(VerifyAnswer(outcome: .device)).heading, "Verified")
    }

    func testOnlyAMismatchIsRed() {
        XCTAssertEqual(SignatureVerdict.tone(.invalid), .bad)
        for outcome: VerifyOutcome in [.server, .unsigned, .unverifiable, .unreachable] {
            XCTAssertEqual(SignatureVerdict.tone(outcome), .quiet,
                           "\(outcome) is a fact, never a warning")
        }
    }

    func testCantCheckDoesNotReadAsAFault() {
        let copy = SignatureVerdict.copy(VerifyAnswer(outcome: .unverifiable))
        XCTAssertEqual(copy.heading, "Signature Not Supported")
        XCTAssertFalse(copy.line.lowercased().contains("suspicion"))
    }

    func testUnreachableBlamesTheNetworkNotTheMessage() {
        let copy = SignatureVerdict.copy(VerifyAnswer(outcome: .unreachable))
        XCTAssertEqual(copy.heading, "Unable to Verify")
        XCTAssertTrue(copy.line.contains("couldn't reach the server"))
    }

    func testUnsignedSaysThereIsNothingToCheck() {
        let copy = SignatureVerdict.copy(VerifyAnswer(outcome: .unsigned))
        XCTAssertEqual(copy.heading, "Unsigned")
        XCTAssertTrue(copy.line.contains("Nothing was signed"))
    }

    /// The fetching-a-key answer shows only while the surface will actually
    /// re-ask; once it stops, it decays into the plain can't-check.
    func testCheckingAnswerOnlyWhileRetrying() {
        let transient = VerifyAnswer(outcome: .unverifiable, transient: true)
        XCTAssertEqual(SignatureVerdict.copy(transient, retrying: true).heading,
                       "Verification in Progress")
        XCTAssertEqual(SignatureVerdict.copy(transient, retrying: false).heading,
                       "Signature Not Supported")
    }

    // MARK: - SigningKeyInfo

    func testParsesSigningKeyWithDefaults() {
        let k = SigningKeyInfo.from(json: ["public_key": "z6Mk..."])
        XCTAssertEqual(k?.publicKey, "z6Mk...")
        XCTAssertEqual(k?.algorithm, "ed25519")
    }

    func testMissingPublicKeyYieldsNil() {
        XCTAssertNil(SigningKeyInfo.from(json: ["algorithm": "ed25519"]))
    }
}
