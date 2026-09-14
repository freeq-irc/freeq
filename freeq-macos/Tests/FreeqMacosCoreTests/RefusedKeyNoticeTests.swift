import XCTest
@testable import FreeqMacosCore

/// Classifying the notice a server sends when it refuses this device's
/// signing key (FAIL MSGSIG KEY_RETIRED), and what follows from it.
final class RefusedKeyNoticeTests: XCTestCase {

    private let text =
        "MSGSIG KEY_RETIRED This device was signed out from another device. Sign in again to continue."

    func testRefusalShowsTheSentenceClearsTheLoginAndDoesNotReconnect() {
        let parsed = RefusedKeyNotice.parse(text)
        XCTAssertEqual(parsed?.line, "This device was signed out from another device. Sign in again to continue.")
        XCTAssertEqual(parsed?.clearsSavedLogin, true)
        XCTAssertEqual(parsed?.schedulesReconnect, false)
    }

    func testIgnoresOtherNotices() {
        XCTAssertNil(RefusedKeyNotice.parse("MSGSIG INVALID_KEY Expected 32-byte key"))
        XCTAssertNil(RefusedKeyNotice.parse("CHATHISTORY INVALID_TARGET gnap Unknown target"))
        XCTAssertNil(RefusedKeyNotice.parse(""))
    }

    func testRefusalRoutesToKeyRetired() {
        XCTAssertEqual(ServerNoticeRouter.route(text), .keyRetired(RefusedKeyNotice.parse(text)!))
    }
}
