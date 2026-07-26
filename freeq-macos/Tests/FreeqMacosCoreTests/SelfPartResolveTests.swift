import XCTest

@testable import FreeqMacosCore

/// The multi-device PART hazard.
///
/// Reported symptom: "when I play freeqworld something weird happens with my channel
/// memberships — I just lost #freeq and I wasn't even using it." The server still had
/// the subscription (`user_channels` still listed `#freeq`) and no PART or KICK
/// appeared in its logs for that identity, which places the loss in the client.
///
/// Cause: a second session signed in as the same DID shares the nick, so its PART
/// arrived here looking exactly like our own, and the self-branch dropped the channel
/// and rewrote the persisted auto-join list.
final class SelfPartResolveTests: XCTestCase {

    func testAPartWeAskedForLeavesTheChannel() {
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "chadfowler.com",
            myNick: "chadfowler.com",
            pendingRequests: ["#freeq": Date()]
        )
        XCTAssertEqual(d, .leaveChannel)
    }

    func testAnotherDevicesPartDoesNotRemoveOurChannel() {
        // The reported bug. Same nick, but we never asked to leave.
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "chadfowler.com",
            myNick: "chadfowler.com",
            pendingRequests: [:]
        )
        XCTAssertEqual(d, .ignoreOtherDevice)
    }

    func testCaseAndChannelAreMatchedInsensitively() {
        let d = SelfPartResolve.decide(
            channel: "#FreeQ",
            partNick: "ChadFowler.com",
            myNick: "chadfowler.com",
            pendingRequests: ["#freeq": Date()]
        )
        XCTAssertEqual(d, .leaveChannel)
    }

    func testAPartForADifferentChannelIsNotOurs() {
        // We asked to leave #other; a PART for #freeq is another device's.
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "chadfowler.com",
            myNick: "chadfowler.com",
            pendingRequests: ["#other": Date()]
        )
        XCTAssertEqual(d, .ignoreOtherDevice)
    }

    func testAStaleRequestDoesNotClaimALaterForeignPart() {
        // Requests match on channel name only, so an unexpired-forever record would
        // let a foreign PART minutes later look like the answer to ours.
        let old = Date().addingTimeInterval(-(SelfPartResolve.requestValidity + 5))
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "chadfowler.com",
            myNick: "chadfowler.com",
            pendingRequests: ["#freeq": old]
        )
        XCTAssertEqual(d, .ignoreOtherDevice)
    }

    func testARequestJustInsideTheWindowIsStillOurs() {
        let recent = Date().addingTimeInterval(-(SelfPartResolve.requestValidity - 1))
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "chadfowler.com",
            myNick: "chadfowler.com",
            pendingRequests: ["#freeq": recent]
        )
        XCTAssertEqual(d, .leaveChannel)
    }

    func testSomebodyElsesPartOnlyTouchesTheRoster() {
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "zapnap",
            myNick: "chadfowler.com",
            pendingRequests: [:]
        )
        XCTAssertEqual(d, .removeMember(nick: "zapnap"))
    }

    func testAGuestWithNoNickIsNotMistakenForUs() {
        // Defensive: an empty local nick must not make every PART look like ours.
        let d = SelfPartResolve.decide(
            channel: "#freeq",
            partNick: "someone",
            myNick: "",
            pendingRequests: [:]
        )
        XCTAssertEqual(d, .removeMember(nick: "someone"))
    }
}
