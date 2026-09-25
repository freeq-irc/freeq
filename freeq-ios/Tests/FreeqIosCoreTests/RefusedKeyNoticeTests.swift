import XCTest
@testable import FreeqIosCore

/// Classifying the notice a server sends when it refuses this device's
/// signing key (FAIL MSGSIG KEY_RETIRED or KEY_EXPIRED), and what follows
/// from it.
final class RefusedKeyNoticeTests: XCTestCase {

    func testRefusalShowsTheSentenceClearsTheLoginAndDoesNotReconnect() {
        let parsed = RefusedKeyNotice.parse(
            "MSGSIG KEY_RETIRED This device was signed out from another device. Sign in again to continue.")
        XCTAssertEqual(parsed?.line, "This device was signed out from another device. Sign in again to continue.")
        XCTAssertEqual(parsed?.clearsSavedLogin, true)
        XCTAssertEqual(parsed?.schedulesReconnect, false)
    }

    func testExpiryShowsItsOwnSentenceClearsTheLoginAndDoesNotReconnect() {
        let parsed = RefusedKeyNotice.parse(
            "MSGSIG KEY_EXPIRED This device's signing key has expired. Sign in again to continue.")
        XCTAssertEqual(parsed?.line, "This device's signing key has expired. Sign in again to continue.")
        XCTAssertEqual(parsed?.clearsSavedLogin, true)
        XCTAssertEqual(parsed?.schedulesReconnect, false)
    }

    func testIgnoresOtherNotices() {
        XCTAssertNil(RefusedKeyNotice.parse("MSGSIG INVALID_KEY Expected 32-byte key"))
        XCTAssertNil(RefusedKeyNotice.parse("CHATHISTORY INVALID_TARGET gnap Unknown target"))
        XCTAssertNil(RefusedKeyNotice.parse("#secret This channel requires authentication — sign in to join"))
        XCTAssertNil(RefusedKeyNotice.parse(""))
    }

    // MARK: - RefusedLogin

    func testBroker401OnAnAutomaticReconnectEndsTheLoginAndShowsSignIn() {
        // No press, no refused token before it: the server ended the login first.
        XCTAssertEqual(
            RefusedLogin.afterBrokerFailure(status: 401, savedLoginCleared: false),
            .signIn(line: "Session expired — please sign in again", clearsSavedLogin: true))
    }

    func testBroker401WithTheLoginAlreadyClearedShowsSignInWithoutClearingAgain() {
        XCTAssertEqual(
            RefusedLogin.afterBrokerFailure(status: 401, savedLoginCleared: true),
            .signIn(line: "Session expired — please sign in again", clearsSavedLogin: false))
    }

    func testOtherBrokerFailuresRetry() {
        for status in [0, 502, 503, 504, -1009] {
            XCTAssertEqual(
                RefusedLogin.afterBrokerFailure(status: status, savedLoginCleared: false),
                .retry, "status \(status)")
        }
    }

    func testReconnectWaitsAtLeastASecond() {
        XCTAssertEqual(RefusedLogin.reconnectDelay(0), 1)
        XCTAssertEqual(RefusedLogin.reconnectDelay(15), 15)
    }

    func testARefusalOfTheTokenTheBrokerAnsweredAfterARefusedOneEndsTheLogin() {
        XCTAssertEqual(
            RefusedLogin.afterConnectRefused(tokenFollowsRefusal: true),
            .signIn(line: "Session expired — please sign in again", clearsSavedLogin: true))
        XCTAssertEqual(RefusedLogin.afterConnectRefused(tokenFollowsRefusal: false), .retry)
    }
}
