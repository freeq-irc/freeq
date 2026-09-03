import XCTest
@testable import FreeqMacosCore

/// `messages.timestamp` is REAL seconds, so an act offer and its accept
/// minted in the same second are equal on it. Without a second key the page
/// SQLite hands back is arbitrary and can differ launch to launch, and the
/// cache is loaded before replay — replay dedupes by id and never reorders
/// what the cache already placed. These write the same pair in both orders
/// and require the same read-back each time.
final class MessageStoreOrderTests: XCTestCase {
    private let offerId = "01M1FDM7HM4E9H8FPB7ND1DZKA"
    private let acceptId = "01M1FDM7HQ7Z9K2XR4V6TB0C3E"
    private let sameSecond = Date(timeIntervalSince1970: 1_756_760_000)

    private func freshStore() -> MessageStore {
        let path = NSTemporaryDirectory() + "freeq-order-\(UUID().uuidString).sqlite"
        return MessageStore(path: path)
    }

    private func msg(_ id: String, _ when: Date) -> ChatMessage {
        ChatMessage(id: id, from: "agent", text: "x", isAction: false,
                    timestamp: when, replyTo: nil)
    }

    func testSameSecondPairReadsBackOfferFirstFromEitherWriteOrder() async {
        for written in [[offerId, acceptId], [acceptId, offerId]] {
            let db = freshStore()
            for id in written {
                await db.store(msg(id, sameSecond), channel: "#order")
            }
            let back = await db.loadMessages(channel: "#order")
            XCTAssertEqual(back.map(\.id), [offerId, acceptId],
                           "written \(written)")
        }
    }

    func testLoadIsAscendingByTimestampFirst() async {
        // The tiebreak must not outrank the clock: the lower id is the later
        // row here, and it has to read back last.
        let db = freshStore()
        await db.store(msg(offerId, sameSecond.addingTimeInterval(100)), channel: "#order")
        await db.store(msg(acceptId, sameSecond), channel: "#order")

        let back = await db.loadMessages(channel: "#order")
        XCTAssertEqual(back.map(\.id), [acceptId, offerId])
    }
}
