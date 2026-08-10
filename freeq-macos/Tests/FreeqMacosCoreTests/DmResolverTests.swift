import XCTest
@testable import FreeqMacosCore

/// Learning who a bare nick is before the first DM to them — and never
/// charging the user for the answer not arriving.
///
/// The resolver's timeout rides the main queue (the thread every caller is
/// already on), so these tests stay on the main thread and let `wait` spin the
/// run loop rather than blocking it with `await`.
@MainActor
final class DmResolverTests: XCTestCase {

    private var asked: [String] = []

    private func resolver(
        bindings: [String: String] = [:],
        timeout: TimeInterval = 0.2
    ) -> DmResolver {
        asked = []
        return DmResolver(
            timeout: timeout,
            nickToDid: { bindings[$0.lowercased()] },
            askWhois: { [weak self] in self?.asked.append($0) }
        )
    }

    /// Run `resolve` to completion without blocking the main queue.
    private func resolved(_ r: DmResolver, _ target: String,
                          file: StaticString = #filePath, line: UInt = #line) -> String? {
        let done = expectation(description: "resolved \(target)")
        var venue: String?
        Task { @MainActor in
            venue = await r.resolve(target)
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
        return venue
    }

    // MARK: - Nothing to ask

    func testChannelNeedsNoResolution() {
        let r = resolver()
        XCTAssertEqual(r.venueIfSettled("#freeq"), "#freeq")
        XCTAssertEqual(resolved(r, "#freeq"), "#freeq")
        XCTAssertTrue(asked.isEmpty, "a channel is already a venue a signature can name")
    }

    func testDidTargetNeedsNoResolution() {
        let r = resolver()
        XCTAssertEqual(resolved(r, "did:plc:abc123"), "did:plc:abc123")
        XCTAssertTrue(asked.isEmpty)
    }

    func testKnownNickResolvesWithoutAsking() {
        let r = resolver(bindings: ["bob": "did:plc:bob"])
        XCTAssertEqual(r.venueIfSettled("bob"), "did:plc:bob")
        XCTAssertEqual(resolved(r, "Bob"), "did:plc:bob")
        XCTAssertTrue(asked.isEmpty)
    }

    // MARK: - Asking

    func testUnknownNickIsUnsettledUntilAsked() {
        let r = resolver()
        XCTAssertNil(r.venueIfSettled("stranger"),
                     "an unasked stranger is exactly the case a short wait can fix")
    }

    func testAnswerArrivingInTimeAddressesTheDid() {
        let r = resolver(timeout: 5)
        let done = expectation(description: "resolved")
        var venue: String?
        Task { @MainActor in
            venue = await r.resolve("stranger")
            done.fulfill()
        }
        // The WHOIS answer lands while the send is still waiting.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            r.learned(nick: "Stranger", did: "did:plc:stranger")
        }
        wait(for: [done], timeout: 5)
        XCTAssertEqual(venue, "did:plc:stranger")
        XCTAssertEqual(asked, ["stranger"])
    }

    func testSilentPeerStillGetsTheMessageAtTheirNick() {
        let r = resolver(timeout: 0.05)
        XCTAssertEqual(resolved(r, "ghost"), "ghost",
                       "a peer that never answers must not cost the message")
        XCTAssertEqual(asked, ["ghost"])
    }

    /// Once asked and unanswered, later messages must not pay the wait again.
    func testSecondMessageToASilentPeerDoesNotWait() {
        let r = resolver(timeout: 0.05)
        _ = resolved(r, "ghost")
        XCTAssertEqual(r.venueIfSettled("ghost"), "ghost")
        XCTAssertEqual(resolved(r, "ghost"), "ghost")
        XCTAssertEqual(asked, ["ghost"], "the question is not asked twice in a session")
    }

    func testProbeAsksWithoutWaiting() {
        let r = resolver()
        r.probe("stranger")
        XCTAssertEqual(asked, ["stranger"])
        r.probe("stranger")
        XCTAssertEqual(asked, ["stranger"])
    }

    func testProbeIgnoresChannelsAndKnownPeers() {
        let r = resolver(bindings: ["bob": "did:plc:bob"])
        r.probe("#freeq")
        r.probe("bob")
        r.probe("did:plc:abc")
        XCTAssertTrue(asked.isEmpty)
    }

    /// A binding learned once serves every later send, with no second WHOIS.
    func testLearnedBindingIsReused() {
        let r = resolver()
        r.probe("stranger")
        r.learned(nick: "stranger", did: "did:plc:stranger")
        XCTAssertEqual(r.venueIfSettled("STRANGER"), "did:plc:stranger")
        XCTAssertEqual(resolved(r, "stranger"), "did:plc:stranger")
        XCTAssertEqual(asked, ["stranger"])
    }

    /// A new connection may be a new server, whose answers are its own.
    func testResetForgetsWhatWasLearned() {
        let r = resolver(timeout: 0.05)
        r.probe("stranger")
        r.learned(nick: "stranger", did: "did:plc:stranger")
        r.reset()
        XCTAssertNil(r.venueIfSettled("stranger"))
        _ = resolved(r, "stranger")
        XCTAssertEqual(asked, ["stranger", "stranger"])
    }

    /// A send waiting when the connection drops must not hang forever.
    func testResetReleasesAWaitingSend() {
        let r = resolver(timeout: 30)
        let done = expectation(description: "released")
        var venue: String?
        Task { @MainActor in
            venue = await r.resolve("stranger")
            done.fulfill()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { r.reset() }
        wait(for: [done], timeout: 5)
        XCTAssertEqual(venue, "stranger")
    }
}
