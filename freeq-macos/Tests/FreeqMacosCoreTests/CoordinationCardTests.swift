import XCTest
@testable import FreeqMacosCore

/// The payload rule every event card renders through — the same rule the web
/// and Android clients apply, so one payload reads the same on all four.
final class CoordinationCardTests: XCTestCase {

    /// The wire form: percent-encoded in the tag.
    private func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func rows(_ raw: String?) -> [PayloadRow] { EventCardPayload.rows(raw) }

    func testAnObjectGivesOneRowPerTopLevelKeyInOrder() {
        XCTAssertEqual(rows(enc(#"{"to":"bob","why":"capacity"}"#)),
                       [PayloadRow(key: "to", value: "bob"),
                        PayloadRow(key: "why", value: "capacity")])
    }

    func testAStringValueShowsAsItselfAndTheRestAsCompactJSON() {
        XCTAssertEqual(
            rows(enc(#"{"note":"half done","n":3,"ok":true,"tags":["a","b"],"deep":{"x":1},"nil":null}"#)),
            [PayloadRow(key: "note", value: "half done"),
             PayloadRow(key: "n", value: "3"),
             PayloadRow(key: "ok", value: "true"),
             PayloadRow(key: "tags", value: #"["a","b"]"#),
             PayloadRow(key: "deep", value: #"{"x":1}"#),
             PayloadRow(key: "nil", value: "null")])
    }

    func testANumberKeepsTheSpellingTheDocumentGaveIt() {
        XCTAssertEqual(rows(enc(#"{"load":0.3}"#)), [PayloadRow(key: "load", value: "0.3")])
        XCTAssertEqual(rows(enc(#"{"n":1.0}"#)), [PayloadRow(key: "n", value: "1.0")])
        XCTAssertEqual(rows(enc(#"{"big":1e2}"#)), [PayloadRow(key: "big", value: "1e2")])
    }

    func testANestedObjectShowsAsWrittenInItsOwnKeyOrder() {
        XCTAssertEqual(rows(enc(#"{"deep":{"b":1,"a":2}}"#)),
                       [PayloadRow(key: "deep", value: #"{"b":1,"a":2}"#)])
    }

    func testWhitespaceBetweenTokensGoesButNotInsideAString() {
        XCTAssertEqual(rows(enc(#"{ "deep" : { "b" : "x y" } }"#)),
                       [PayloadRow(key: "deep", value: #"{"b":"x y"}"#)])
    }

    func testAnArrayOrAScalarPayloadKeepsItsSpelling() {
        XCTAssertEqual(rows(enc("[1.0, 2]")), [PayloadRow(key: "payload", value: "[1.0,2]")])
        XCTAssertEqual(rows(enc("1e2")), [PayloadRow(key: "payload", value: "1e2")])
    }

    func testAnEmptyObjectGivesNoRows() {
        XCTAssertEqual(rows(enc("{}")), [])
    }

    func testAnArrayIsOneRowKeyedPayload() {
        XCTAssertEqual(rows(enc(#"[1,"two",{"three":3}]"#)),
                       [PayloadRow(key: "payload", value: #"[1,"two",{"three":3}]"#)])
    }

    func testAScalarIsOneRowKeyedPayload() {
        XCTAssertEqual(rows(enc("42")), [PayloadRow(key: "payload", value: "42")])
        XCTAssertEqual(rows(enc("true")), [PayloadRow(key: "payload", value: "true")])
        XCTAssertEqual(rows(enc("null")), [PayloadRow(key: "payload", value: "null")])
        XCTAssertEqual(rows(enc(#""just words""#)),
                       [PayloadRow(key: "payload", value: "just words")])
    }

    func testTextThatIsNotJSONRidesRawInThePayloadRow() {
        XCTAssertEqual(rows(enc("half the build is red")),
                       [PayloadRow(key: "payload", value: "half the build is red")])
    }

    func testAMalformedPercentEscapeKeepsTheTagValue() {
        XCTAssertEqual(rows("100%-sure"), [PayloadRow(key: "payload", value: "100%-sure")])
    }

    /// Percent-decoding is not form decoding: `+` is not a space.
    func testAPlusSignStaysAPlusSign() {
        XCTAssertEqual(rows("a+b"), [PayloadRow(key: "payload", value: "a+b")])
    }

    func testNoPayloadAtAllGivesNoRows() {
        XCTAssertEqual(rows(nil), [])
        XCTAssertEqual(rows(""), [])
        XCTAssertEqual(rows("   "), [])
    }
}
