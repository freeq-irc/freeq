import XCTest
@testable import FreeqIosCore

/// The identity-claim rule is not tested here: it lives in the SDK, pinned by
/// the executable vectors in spec/identity-claims.json, and this client only
/// renders what the FFI hands it. What remains app-owned is the naming helper.
final class IdentityClaimTests: XCTestCase {
    func test_a_display_name_wins_over_everything() {
        XCTAssertEqual(SenderIdentity.title(displayName: "Nap", handle: "zapnap.bsky.social", nick: "zapnap"), "Nap")
    }

    func test_a_handle_wears_its_at_sign() {
        XCTAssertEqual(SenderIdentity.title(displayName: nil, handle: "zapnap.bsky.social", nick: "zapnap"), "@zapnap.bsky.social")
    }

    func test_a_bare_nick_is_a_fine_name() {
        XCTAssertEqual(SenderIdentity.title(displayName: "", handle: "", nick: "zapnap"), "zapnap")
    }

    func test_nothing_at_all_names_nobody_rather_than_inventing_a_phrase() {
        // "Unidentified sender" was deleted by ruling: a message row always
        // has a nick, so the phrase was unreachable and said nothing.
        XCTAssertEqual(SenderIdentity.title(displayName: nil, handle: nil, nick: ""), "")
    }
}
