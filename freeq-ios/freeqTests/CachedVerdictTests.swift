import XCTest
@testable import freeq

/// A signed row is mapped with whatever the SDK had at delivery, which for a
/// key still being looked up is `.pending`. The settled answer arrives later
/// as a `Verdict` event and is filed in `checkedVerdicts`, never written back
/// to the row, so a cache snapshot that copies `m.verdict` persists every
/// signed row as pending.
///
/// These live in the Xcode test target rather than
/// `Tests/FreeqIosCoreTests/`: `CachedMessage` is declared in `AppState.swift`,
/// which the SwiftPM package excludes (`freeq-ios/Package.swift:30`), so
/// `swift test` cannot see it. `xcodebuild test` runs this.
final class CachedVerdictTests: XCTestCase {

    private func row(_ id: String, verdict: VerdictInfo?) -> ChatMessage {
        var m = ChatMessage(
            id: id, from: "alice", text: "hello", isAction: false,
            timestamp: Date(timeIntervalSince1970: 1_000), replyTo: nil,
            isSigned: true
        )
        m.verdict = verdict
        return m
    }

    private let settled = VerdictInfo(
        kind: .device,
        layer: .vouched,
        kid: "kid-settled",
        keySource: "identity-record",
        sentence: "Signed on the sender’s device."
    )

    private let pending = VerdictInfo(
        kind: .pending,
        kid: "kid-settled",
        sentence: "Checking this signature…"
    )

    func testSettledVerdictReplacesThePendingOneTheRowWasMappedWith() {
        let cached = CachedMessage(row("01PENDING", verdict: pending), settled: settled)
        XCTAssertEqual(cached.verdict?.kind, .device)
        XCTAssertEqual(cached.verdict?.layer, .vouched)
        XCTAssertEqual(cached.verdict?.keySource, "identity-record")
        // And it survives the round trip the cache actually performs.
        let coded = try! JSONEncoder().encode(cached)
        let back = try! JSONDecoder().decode(CachedMessage.self, from: coded)
        XCTAssertEqual(back.verdict?.kind, .device)
        XCTAssertEqual(back.toChatMessage().verdict?.kind, .device)
    }

    func testRowWithNoSettledVerdictKeepsItsOwn() {
        let invalid = VerdictInfo(
            kind: .invalid,
            kid: "kid-1",
            keySource: "identity-record",
            sentence: "This message is signed, but the signature doesn’t check out."
        )
        let cached = CachedMessage(row("01OWN", verdict: invalid), settled: nil)
        XCTAssertEqual(cached.verdict?.kind, .invalid)
        XCTAssertEqual(cached.verdict?.kid, "kid-1")
    }

    func testSettledVerdictIsWrittenForARowThatCarriedNone() {
        let cached = CachedMessage(row("01NONE", verdict: nil), settled: settled)
        XCTAssertEqual(cached.verdict?.kind, .device)
    }
}
