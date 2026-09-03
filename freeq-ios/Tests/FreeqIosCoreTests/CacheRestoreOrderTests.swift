import XCTest
@testable import FreeqIosCore

/// `buffers.json` is a JSON array, so it hands rows back in exactly the order
/// they were written — a same-second pair written inverted stays inverted for
/// the life of the cache, and `appendIfNew` appends rather than reorders when
/// timestamps are equal. Hydrate therefore sorts on the way in. These drive
/// that sort + append with the same pair in both stored orders.
final class CacheRestoreOrderTests: XCTestCase {
    private let offerId = "01M1FDM7HM4E9H8FPB7ND1DZKA"
    private let acceptId = "01M1FDM7HQ7Z9K2XR4V6TB0C3E"
    private let sameSecond = Date(timeIntervalSince1970: 1_756_760_000)

    private func msg(_ id: String, _ when: Date) -> ChatMessage {
        ChatMessage(id: id, from: "agent", text: "x", isAction: false,
                    timestamp: when, replyTo: nil)
    }

    /// The hydrate step as `AppState.hydrateBuffersFromCache` performs it.
    private func restore(_ stored: [ChatMessage]) -> [String] {
        let buffer = ChannelState(name: "#order")
        for m in stored.sorted(by: ChatMessage.replayOrder) { buffer.appendIfNew(m) }
        return buffer.messages.map(\.id)
    }

    func testSameSecondPairRestoresOfferFirstFromEitherStoredOrder() {
        let offer = msg(offerId, sameSecond)
        let accept = msg(acceptId, sameSecond)

        XCTAssertEqual(restore([offer, accept]), [offerId, acceptId])
        XCTAssertEqual(restore([accept, offer]), [offerId, acceptId])
    }

    func testRestoreKeepsTheClockAboveTheTiebreak() {
        // The lower id is the later row here, and it has to restore last.
        let later = msg(offerId, sameSecond.addingTimeInterval(100))
        let earlier = msg(acceptId, sameSecond)

        XCTAssertEqual(restore([later, earlier]), [acceptId, offerId])
    }

    /// A pair with equal timestamps must not be reordered by `appendIfNew`
    /// itself — it appends on a tie, which is what makes the sort above the
    /// only thing deciding their order.
    func testAppendIfNewPreservesOrderOnEqualTimestamps() {
        let buffer = ChannelState(name: "#order")
        buffer.appendIfNew(msg(acceptId, sameSecond))
        buffer.appendIfNew(msg(offerId, sameSecond))
        XCTAssertEqual(buffer.messages.map(\.id), [acceptId, offerId])
    }
}
