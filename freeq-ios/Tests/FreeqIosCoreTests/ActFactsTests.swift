import XCTest
@testable import FreeqIosCore

/// The labelled facts an act card draws — the same strings the web client and
/// the Android app read from the shared copy file, so a card says the same
/// thing wherever it is read.
final class ActFactsTests: XCTestCase {
    private let resolve: (String) -> String = { $0 == "did:key:zWORKER" ? "cardworker2" : $0 }

    func testADirectedOfferNamesItsRecipientResolved() {
        XCTAssertTrue(
            ActFacts.facts(["act-to": "did:key:zWORKER"], isOpener: true, resolve: resolve)
                .elementsEqual([("offered to", "cardworker2")], by: ==))
    }

    func testAnOpenerIsOfferedToAnyoneAndAFollowUpClaimsNothing() {
        XCTAssertTrue(ActFacts.facts([:], isOpener: true, resolve: resolve)
            .elementsEqual([("offered to", "anyone")], by: ==))
        XCTAssertTrue(ActFacts.facts([:], isOpener: false, resolve: resolve).isEmpty)
    }

    func testMoneyIsLabelledPriceOnOffersAndBidOnBids() {
        XCTAssertTrue(
            ActFacts.facts(["act-price": "250 USD"], isOpener: true, resolve: resolve)
                .elementsEqual([("offered to", "anyone"), ("price", "250 USD")], by: ==))
        XCTAssertTrue(
            ActFacts.facts(["act-bid": "200 USD"], isOpener: false, resolve: resolve)
                .elementsEqual([("bid", "200 USD")], by: ==))
    }

    func testDeadlinesCarryATimeValueAndGarbageIsSkipped() {
        let f = ActFacts.facts(["act-deadline": "1788000000"], isOpener: true, resolve: resolve)
        XCTAssertTrue(f[0] == ("offered to", "anyone"))
        XCTAssertEqual(f[1].0, "deadline")
        XCTAssertFalse(f[1].1.isEmpty)
        XCTAssertTrue(ActFacts.facts(["act-deadline": "soon"], isOpener: false, resolve: resolve).isEmpty)
    }

    func testABidDeadlineGetsItsOwnLabel() {
        let f = ActFacts.facts(["act-bid-deadline": "1788000000"], isOpener: true, resolve: resolve)
        XCTAssertEqual(f[1].0, "bids close")
    }

    func testCapabilitiesAreLabelledAsRequiredSkills() {
        XCTAssertTrue(
            ActFacts.facts(["act-caps": "demo"], isOpener: true, resolve: resolve)
                .elementsEqual([("offered to", "anyone"), ("skills required", "demo")], by: ==))
    }

    func testTheAwardsWinnerGetsAnAwardedToLine() {
        XCTAssertTrue(
            ActFacts.facts([:], isOpener: false, resolve: resolve, winnerDid: "did:key:zWORKER")
                .elementsEqual([("awarded to", "cardworker2")], by: ==))
    }

    func testTheNoteIsARowOfTheGridNotALineUnderIt() {
        XCTAssertTrue(
            ActFacts.facts(["act-note": "two days"], isOpener: false, resolve: resolve)
                .elementsEqual([("note", "two days")], by: ==))
    }

    func testTheContextLinkIsARow() {
        XCTAssertTrue(
            ActFacts.facts(["act-ctx": "https://example.org/a"], isOpener: false, resolve: resolve)
                .elementsEqual([("context", "https://example.org/a")], by: ==))
    }

    func testTheContextHashIsARow() {
        XCTAssertTrue(
            ActFacts.facts(["act-ctx-h": "sha256:9f00"], isOpener: false, resolve: resolve)
                .elementsEqual([("hash", "sha256:9f00")], by: ==))
    }

    func testThePayeeResolvesADidAndShowsAnythingElseAsSent() {
        XCTAssertTrue(
            ActFacts.facts(["act-pay-to": "did:key:zWORKER"], isOpener: false, resolve: resolve)
                .elementsEqual([("pay to", "cardworker2")], by: ==))
        XCTAssertTrue(
            ActFacts.facts(["act-pay-to": "0xdeadbeef"], isOpener: false, resolve: resolve)
                .elementsEqual([("pay to", "0xdeadbeef")], by: ==))
    }

    func testThePaymentIsARow() {
        XCTAssertTrue(
            ActFacts.facts(["act-tx": "eth:0xdemo"], isOpener: false, resolve: resolve)
                .elementsEqual([("payment", "eth:0xdemo")], by: ==))
    }

    func testTheActionARevisionReplacesIsARowUnderItsRawId() {
        XCTAssertTrue(
            ActFacts.facts(["act-replaces": "01JOLD"], isOpener: false, resolve: resolve)
                .elementsEqual([("replaces", "01JOLD")], by: ==))
    }

    func testTheScopeIsARow() {
        XCTAssertTrue(
            ActFacts.facts(["act-scope": "room"], isOpener: false, resolve: resolve)
                .elementsEqual([("scope", "room")], by: ==))
    }

    func testTheSevenFollowTheLabelledFactsInTheirOwnFixedOrder() {
        let f = ActFacts.facts([
            "act-price": "250 USD", "act-caps": "url_fetch", "act-note": "two days",
            "act-ctx": "https://example.org/a", "act-ctx-h": "sha256:9f00",
            "act-pay-to": "did:key:zW", "act-tx": "eth:0xdemo",
            "act-replaces": "01JOLD", "act-scope": "room",
        ], isOpener: true, resolve: resolve)
        XCTAssertTrue(f.elementsEqual([
            ("offered to", "anyone"),
            ("price", "250 USD"),
            ("skills required", "url_fetch"),
            ("note", "two days"),
            ("context", "https://example.org/a"),
            ("hash", "sha256:9f00"),
            ("pay to", "did:key:zW"),
            ("payment", "eth:0xdemo"),
            ("replaces", "01JOLD"),
            ("scope", "room"),
        ], by: ==))
    }

    func testUnlabelledFieldsKeepTheirKeysAndKnownOnesNeverDo() {
        XCTAssertTrue(ActFacts.unknownFields(["act-mystery": "y"])
            .elementsEqual([("mystery", "y")], by: ==))
        XCTAssertTrue(ActFacts.unknownFields([
            "act-pay-to": "did:key:zW", "act-tx": "eth:0xabc",
            "act-replaces": "01JOLD", "act-scope": "room",
        ]).isEmpty)
        XCTAssertTrue(ActFacts.unknownFields([
            "act": "handoff", "act-verb": "offer", "act-id": "X", "act-to": "d",
            "act-title": "t", "act-note": "n", "act-ctx": "u", "act-ctx-h": "h", "act-deadline": "1",
            "act-bid-deadline": "1", "act-caps": "c", "act-price": "p",
            "act-bid": "b", "act-accepts": "e", "act-subject": "s",
            "act-pay-to": "p2", "act-tx": "tx", "act-replaces": "r", "act-scope": "sc",
        ]).isEmpty)
    }
}
