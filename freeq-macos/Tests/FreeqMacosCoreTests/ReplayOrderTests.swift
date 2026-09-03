import XCTest
@testable import FreeqMacosCore

/// The server's replay `time` tag is second-precision, so an act offer and
/// its accept minted in the same second arrive with equal timestamps. Swift's
/// sort is not stable, so the comparator itself has to break the tie; feeding
/// the same pair in both input orders is the deterministic way to show it does.
final class ReplayOrderTests: XCTestCase {
    private let offerId = "01M1FDM7HM4E9H8FPB7ND1DZKA"
    private let acceptId = "01M1FDM7HQ7Z9K2XR4V6TB0C3E"

    private func msg(_ id: String, _ seconds: TimeInterval) -> ChatMessage {
        ChatMessage(
            id: id, from: "agent", text: "x", isAction: false,
            timestamp: Date(timeIntervalSince1970: seconds), replyTo: nil
        )
    }

    func testSameSecondPairOrdersByMsgidFromEitherInputOrder() {
        let offer = msg(offerId, 1_756_760_000)
        let accept = msg(acceptId, 1_756_760_000)

        for input in [[offer, accept], [accept, offer]] {
            XCTAssertEqual(
                input.sorted(by: ChatMessage.replayOrder).map(\.id),
                [offerId, acceptId]
            )
        }
    }

    func testTimestampStillWinsOverMsgid() {
        // The tiebreak must not outrank the clock: the lower msgid is the
        // later row here, and it has to sort last.
        let later = msg(offerId, 1_756_760_100)
        let earlier = msg(acceptId, 1_756_760_000)

        XCTAssertEqual(
            [later, earlier].sorted(by: ChatMessage.replayOrder).map(\.id),
            [acceptId, offerId]
        )
    }
}
