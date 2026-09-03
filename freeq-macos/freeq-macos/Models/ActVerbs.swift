import Foundation

/// The word and glyph each task verb shows a reader.
///
/// The headline of a card is the word for the verb its event carried — the
/// verb is on the wire and the client computes nothing from it, so a progress
/// report never reads as a claim. The rows live in the bundled copy of
/// `spec/act-card-copy.json`, the same file the other three clients read, so
/// the same move is called the same thing wherever it is read. A verb with no
/// row shows itself, with the fallback glyph, which is how a kind may add a
/// move without any client being taught it.
enum ActVerbs {
    private struct VerbRow: Decodable { let word: String; let glyph: String }

    private static let verbRows: [String: VerbRow] = {
        guard let data = SealPanelCopy.bundledText?.data(using: .utf8),
              let doc = try? JSONDecoder().decode(CopyDoc.self, from: data)
        else { return [:] }
        return doc.verbs
    }()

    private static let fallbackGlyph: String = {
        guard let data = SealPanelCopy.bundledText?.data(using: .utf8),
              let doc = try? JSONDecoder().decode(CopyDoc.self, from: data)
        else { return "📌" }
        return doc.fallback_glyph
    }()

    private struct CopyDoc: Decodable {
        let verbs: [String: VerbRow]
        let fallback_glyph: String
    }

    static func headline(_ verb: String) -> String { verbRows[verb]?.word ?? verb }

    static func emoji(_ verb: String) -> String { verbRows[verb]?.glyph ?? fallbackGlyph }

    /// The register a card wears: the state the step it carries lands the
    /// action in, as a role rather than a colour — each client paints the role
    /// in its own theme.
    ///
    /// Read off `spec/act-transitions.json`: the `to` of the row the verb
    /// matched, except that a step landing where it started is in-progress
    /// whatever state that is. A row whose `who` is `system` writes no card and
    /// so has no register; a verb with no row at all falls to the neutral end.
    private static let registers: [String: ActRegister?] = [
        // lands open / offered
        "offer": .new,
        // lands assigned / under_review, and the two additive steps
        "accept": .inProgress,
        "claim": .inProgress,
        "award": .inProgress,
        "submit": .inProgress,
        "revise": .inProgress,
        "progress": .inProgress,
        "bid": .inProgress,
        // lands completed / accepted
        "complete": .endedWell,
        "accept-work": .endedWell,
        // lands failed / forfeited / cancelled / declined
        "fail": .didNotEndWell,
        "forfeit": .didNotEndWell,
        "cancel": .didNotEndWell,
        "decline": .didNotEndWell,
        // The rows a home signs for itself. No card, so no register.
        "confirm": ActRegister?.none,
        "expire": ActRegister?.none,
        "auto-accept": ActRegister?.none,
    ]

    static func register(_ verb: String) -> ActRegister? {
        guard let row = registers[verb] else { return .neutralEnd }
        return row
    }

    /// Who the rules file lets take this step — the `who` of the row the verb
    /// matched, and the key the seal panel picks its sentence by.
    ///
    /// An opening verb has no transition row of its own and reports `opener`.
    /// A system row and an unteached verb report nothing, because neither has
    /// a rule about a person to state.
    private static let whos: [String: String?] = [
        "offer": "opener",
        "accept": "offeree",
        "decline": "offeree",
        "claim": "anyone",
        "bid": "anyone",
        "progress": "assignee",
        "complete": "assignee",
        "fail": "assignee",
        "submit": "assignee",
        "forfeit": "assignee",
        "cancel": "offerer",
        "award": "offerer",
        "revise": "offerer",
        "accept-work": "offerer",
        "confirm": String?.none,
        "expire": String?.none,
        "auto-accept": String?.none,
    ]

    static func whoRole(_ verb: String) -> String? {
        guard let row = whos[verb] else { return nil }
        return row
    }
}

/// The register a card wears, as a role rather than a colour — each client
/// paints it in its own theme.
enum ActRegister: Equatable { case new, inProgress, endedWell, didNotEndWell, neutralEnd }

/// The seal panel's words, read from the bundled copy of
/// `spec/act-card-copy.json`.
///
/// The prose is not written here and is not written in the other three clients
/// either: all four read the same file so a sentence cannot drift between them.
/// A test pins the bundled copy byte-identical to the canonical file.
enum SealPanelCopy {

    /// The bundled file's bytes, so a test can pin them against the canonical
    /// spec file without reaching into another target's bundle.
    static let bundledText: String? = {
        var bundles: [Bundle] = [.main]
        #if SWIFT_PACKAGE
        bundles.insert(.module, at: 0)
        #endif
        for bundle in bundles {
            guard let url = bundle.url(forResource: "act-card-copy", withExtension: "json"),
                  let text = try? String(contentsOf: url, encoding: .utf8)
            else { continue }
            return text
        }
        return nil
    }()

    private static let panel: [String: Any] = {
        guard let data = bundledText?.data(using: .utf8),
              let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let panel = doc["seal_panel"] as? [String: Any]
        else { return [:] }
        return panel
    }()

    /// `HANDOFF: Rules Enforced` — the kind comes off the event's own act tag.
    static func header(_ kind: String) -> String {
        let format = panel["header_format"] as? String ?? "<KIND>: Rules Enforced"
        return format.replacingOccurrences(of: "<KIND>", with: kind.uppercased())
    }

    static func linkText() -> String {
        panel["link_text"] as? String ?? "View full history"
    }

    /// What the server enforced on this step, in one sentence.
    ///
    /// Chosen off the `who` of the transition row the verb matched — never off
    /// the verb's name and never off the kind. A system row and a verb with no
    /// row at all claim nothing, so neither gets a sentence.
    static func sentence(_ verb: String) -> String? {
        guard let role = ActVerbs.whoRole(verb),
              let sentences = panel["sentences"] as? [String: String]
        else { return nil }
        return sentences[role]
    }
}
