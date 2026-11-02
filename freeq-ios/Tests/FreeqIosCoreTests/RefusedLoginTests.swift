import XCTest
@testable import FreeqIosCore

/// What follows when the broker refuses the saved login (`RefusedLogin`).
final class RefusedLoginTests: XCTestCase {

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
