import XCTest
@testable import FreeqMacosCore

/// The word each verb shows a reader — the same rows the web client and the
/// Android app read, so the same move is called the same thing wherever it is
/// read.
final class ActVerbsTests: XCTestCase {

    func testEveryVerbHasItsWord() {
        let expected = [
            "offer": "offered",
            "accept": "accepted",
            "decline": "declined",
            "claim": "claimed",
            "progress": "in progress",
            "complete": "completed",
            "fail": "failed",
            "cancel": "cancelled",
            "bid": "bid",
            "award": "awarded",
            "submit": "submitted",
            "revise": "revisions requested",
            "accept-work": "accepted",
            "forfeit": "forfeited",
            "confirm": "confirmed",
            "expire": "expired",
        ]
        for (verb, word) in expected {
            XCTAssertEqual(ActVerbs.headline(verb), word, "verb \(verb)")
        }
    }

    func testAVerbWithNoRowShowsItself() {
        // Which is how a kind may add one without this having to be taught it.
        XCTAssertEqual(ActVerbs.headline("escalate"), "escalate")
        XCTAssertEqual(ActVerbs.headline(""), "")
    }

    func testEveryVerbHasItsGlyph() {
        let expected = [
            "offer": "📋",
            "accept": "👍",
            "decline": "👎",
            "claim": "✋",
            "progress": "📌",
            "complete": "🎉",
            "fail": "❌",
            "cancel": "🚫",
            "bid": "💰",
            "award": "🏆",
            "submit": "📤",
            "revise": "🔁",
            "accept-work": "✅",
            "forfeit": "🏳️",
        ]
        for (verb, glyph) in expected {
            XCTAssertEqual(ActVerbs.emoji(verb), glyph, "verb \(verb)")
        }
    }

    func testAVerbWithNoRowGetsThePin() {
        // Same discipline as the word table: a kind may add a move without
        // this having to be taught it.
        XCTAssertEqual(ActVerbs.emoji("escalate"), "📌")
        XCTAssertEqual(ActVerbs.emoji(""), "📌")
    }

    func testTheHomesOwnVerbsCarryTheGlyphsTheirLinesOpenWith() {
        XCTAssertEqual(ActVerbs.emoji("confirm"), "✔️")
        XCTAssertEqual(ActVerbs.emoji("expire"), "⌛")
    }

    func testAnOpeningMoveIsNewAndTheMovesOntoAPlateAreInProgress() {
        XCTAssertEqual(ActVerbs.register("offer"), .new)
        XCTAssertEqual(ActVerbs.register("award"), .inProgress)
        XCTAssertEqual(ActVerbs.register("claim"), .inProgress)
        XCTAssertEqual(ActVerbs.register("accept"), .inProgress)
    }

    func testAGoodEndAndABadOneEachHaveARegister() {
        XCTAssertEqual(ActVerbs.register("complete"), .endedWell)
        XCTAssertEqual(ActVerbs.register("accept-work"), .endedWell)
        XCTAssertEqual(ActVerbs.register("fail"), .didNotEndWell)
        XCTAssertEqual(ActVerbs.register("forfeit"), .didNotEndWell)
        XCTAssertEqual(ActVerbs.register("cancel"), .didNotEndWell)
        XCTAssertEqual(ActVerbs.register("decline"), .didNotEndWell)
    }

    /// A step that lands where it started is in-progress whatever state that is.
    func testTheTwoAdditiveVerbsAreInProgress() {
        XCTAssertEqual(ActVerbs.register("bid"), .inProgress)
        XCTAssertEqual(ActVerbs.register("progress"), .inProgress)
    }

    func testTheVerbsAHomeSignsForItselfHaveNoRegisterSoTheyCannotCard() {
        XCTAssertNil(ActVerbs.register("confirm"))
        XCTAssertNil(ActVerbs.register("expire"))
        XCTAssertNil(ActVerbs.register("auto-accept"))
    }

    func testAVerbNobodyTaughtItFallsToTheNeutralEnd() {
        XCTAssertEqual(ActVerbs.register("escalate"), .neutralEnd)
        XCTAssertEqual(ActVerbs.register(""), .neutralEnd)
    }

    /// The home's own verbs write no companion line, so they have no card —
    /// their words and glyphs are read on a system line, off the same tables.
    func testTheHomeOwnVerbsHaveWordsAndGlyphsForTheirSystemLines() {
        XCTAssertEqual(ActVerbs.headline("confirm"), "confirmed")
        XCTAssertEqual(ActVerbs.headline("expire"), "expired")
        XCTAssertEqual(ActVerbs.headline("auto-accept"), "accepted (review window closed)")
        XCTAssertEqual(ActVerbs.emoji("confirm"), "✔️")
        XCTAssertEqual(ActVerbs.emoji("expire"), "⌛")
        XCTAssertEqual(ActVerbs.emoji("auto-accept"), "⏱️")
    }
}

/// The seal panel's words, and the tables that pick them.
///
/// The prose lives in `spec/act-card-copy.json` and this client bundles a copy;
/// the first test pins the two byte-identical. The register and role tables are
/// checked against `spec/act-transitions.json` itself, so a verb added to the
/// rules file cannot quietly go uncovered.
final class SealPanelCopyTests: XCTestCase {

    /// The repo's `spec/` directory, found by walking up from this file.
    private func specFile(_ name: String) -> URL {
        var dir = URL(fileURLWithPath: #filePath)
            .resolvingSymlinksInPath()
            .deletingLastPathComponent()
        while dir.path != "/" {
            let candidate = dir.appendingPathComponent("spec/\(name)")
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        XCTFail("spec/\(name) not found above \(#filePath)")
        return URL(fileURLWithPath: "/dev/null")
    }

    func testTheBundledCopyIsByteIdenticalToTheCanonicalOne() throws {
        let bundled = try XCTUnwrap(SealPanelCopy.bundledText,
                                    "act-card-copy.json is not in the bundle")
        XCTAssertEqual(
            bundled,
            try String(contentsOf: specFile("act-card-copy.json"), encoding: .utf8),
            "refresh with: cp spec/act-card-copy.json freeq-macos/freeq-macos/Models/act-card-copy.json")
    }

    func testTheHeaderTakesTheKindOffTheEventTagUppercased() {
        XCTAssertEqual(SealPanelCopy.header("handoff"), "HANDOFF: Rules Enforced")
        XCTAssertEqual(SealPanelCopy.header("bounty"), "BOUNTY: Rules Enforced")
        XCTAssertEqual(SealPanelCopy.header("society-question"),
                       "SOCIETY-QUESTION: Rules Enforced")
    }

    func testTheLinkIsLabelledFromTheSpecFile() {
        XCTAssertEqual(SealPanelCopy.linkText(), "View full history")
    }

    func testEachRoleGetsItsOwnSentence() {
        XCTAssertEqual(
            SealPanelCopy.sentence("offer"),
            "This opened a task with known rules: who may take it, who may work it, who may finish it. Every later step is checked against those rules before the server accepts it — an illegal step is refused and never appears here.")
        let offeree = "Only the person this task was offered to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here."
        XCTAssertEqual(SealPanelCopy.sentence("accept"), offeree)
        XCTAssertEqual(SealPanelCopy.sentence("decline"), offeree)
        let assignee = "Only the worker this task is assigned to could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here."
        for verb in ["progress", "complete", "fail", "submit", "forfeit"] {
            XCTAssertEqual(SealPanelCopy.sentence(verb), assignee, verb)
        }
        let offerer = "Only the person who posted this task could take this step. The server checked that before accepting it — this step from anyone else is refused and never appears here."
        for verb in ["cancel", "award", "revise", "accept-work"] {
            XCTAssertEqual(SealPanelCopy.sentence(verb), offerer, verb)
        }
        let anyone = "Any signed-in account could take this step, and the server checked it was legal from the task's current state before accepting it — an illegal step is refused and never appears here."
        XCTAssertEqual(SealPanelCopy.sentence("claim"), anyone)
        XCTAssertEqual(SealPanelCopy.sentence("bid"), anyone)
    }

    func testASystemVerbAndAnUnknownVerbClaimNothing() {
        for verb in ["confirm", "expire", "auto-accept", "nobody-taught-this"] {
            XCTAssertNil(SealPanelCopy.sentence(verb), verb)
        }
    }

    // ── The tables, against the rules file ──

    private struct Row {
        let verb: String
        let from: [String]
        let to: String
        let who: String
    }

    private func rules() throws -> (rows: [Row], openers: Set<String>) {
        let data = try Data(contentsOf: specFile("act-transitions.json"))
        let doc = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let kinds = try XCTUnwrap(doc["kinds"] as? [String: Any])
        var rows: [Row] = []
        var openers = Set<String>()
        for (_, value) in kinds {
            let kind = try XCTUnwrap(value as? [String: Any])
            let opens = try XCTUnwrap(kind["opens"] as? [String: Any])
            openers.insert(try XCTUnwrap(opens["verb"] as? String))
            for raw in try XCTUnwrap(kind["transitions"] as? [[String: Any]]) {
                let from: [String]
                if let many = raw["from"] as? [String] { from = many }
                else { from = [try XCTUnwrap(raw["from"] as? String)] }
                rows.append(Row(verb: try XCTUnwrap(raw["verb"] as? String),
                                from: from,
                                to: try XCTUnwrap(raw["to"] as? String),
                                who: try XCTUnwrap(raw["who"] as? String)))
            }
        }
        return (rows, openers)
    }

    func testEveryOpeningVerbLandsInTheNewRegister() throws {
        let (_, openers) = try rules()
        XCTAssertFalse(openers.isEmpty)
        for verb in openers { XCTAssertEqual(ActVerbs.register(verb), .new, verb) }
    }

    func testTheRegisterIsTheRegisterOfTheStateTheStepLandsIn() throws {
        let byState: [String: ActRegister] = [
            "open": .new, "offered": .new,
            "assigned": .inProgress, "under_review": .inProgress,
            "completed": .endedWell, "accepted": .endedWell,
            "failed": .didNotEndWell, "forfeited": .didNotEndWell,
            "cancelled": .didNotEndWell, "declined": .didNotEndWell,
        ]
        let (rows, _) = try rules()
        for row in rows {
            if row.who == "system" {
                XCTAssertNil(ActVerbs.register(row.verb), row.verb)
                continue
            }
            // A step that lands where it started is in-progress whatever
            // state that is.
            let additive = row.from.contains(row.to)
            let want = additive ? ActRegister.inProgress : byState[row.to]
            XCTAssertNotNil(want, "no register for state \(row.to)")
            XCTAssertEqual(ActVerbs.register(row.verb), want, row.verb)
        }
    }

    func testEveryNonSystemRowReportsItsOwnWhoAsTheRole() throws {
        let (rows, openers) = try rules()
        for verb in openers { XCTAssertEqual(ActVerbs.whoRole(verb), "opener", verb) }
        for row in rows {
            if row.who == "system" { XCTAssertNil(ActVerbs.whoRole(row.verb), row.verb) }
            else { XCTAssertEqual(ActVerbs.whoRole(row.verb), row.who, row.verb) }
        }
    }

    func testEveryRoleTheRulesFileUsesHasASentence() throws {
        let data = try Data(contentsOf: specFile("act-card-copy.json"))
        let doc = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let panel = try XCTUnwrap(doc["seal_panel"] as? [String: Any])
        let sentences = try XCTUnwrap(panel["sentences"] as? [String: String])
        let (rows, _) = try rules()
        var roles: Set<String> = ["opener"]
        for row in rows where row.who != "system" { roles.insert(row.who) }
        for role in roles { XCTAssertNotNil(sentences[role], role) }
    }
}
