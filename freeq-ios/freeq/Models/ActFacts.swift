import Foundation

/// The facts grid: an act card labels the machine fields it understands,
/// instead of listing them raw — audience, money, deadlines, capabilities, the
/// note, the context link and its hash, and the payment and revision fields.
/// The labels live in the bundled copy of `spec/act-card-copy.json`, the same
/// file the other clients read; the card body is the title and this one grid,
/// so no value is ever drawn without its key. A field with no label still
/// draws, under its own key (`unknownFields`), so nothing signed is ever
/// invisible. Mirrors the web `act-facts.ts`.
enum ActFacts {

    private static let copy: [String: String] = {
        guard let data = SealPanelCopy.bundledText?.data(using: .utf8),
              let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let facts = doc["facts"] as? [String: String]
        else { return [:] }
        return facts
    }()

    private static func time(_ unixSeconds: String) -> String? {
        guard let n = Int64(unixSeconds), n > 0 else { return nil }
        return Self.formatter.string(from: Date(timeIntervalSince1970: TimeInterval(n)))
    }

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, HH:mm"
        return f
    }()

    /// The labelled facts for one event, in a fixed order: audience, winner,
    /// money, deadlines, capabilities, then the note, the context link and its
    /// hash, then pay to, payment, replaces and scope. `isOpener` is whether
    /// the event created the action — only an opener is offered to anyone.
    static func facts(
        _ fields: [String: String],
        isOpener: Bool,
        resolve: (String) -> String = { $0 },
        winnerDid: String? = nil
    ) -> [(String, String)] {
        var out: [(String, String)] = []
        if let to = fields["act-to"], let label = copy["offered_to"] {
            out.append((label, resolve(to)))
        } else if isOpener, let label = copy["offered_to"], let anyone = copy["anyone"] {
            out.append((label, anyone))
        }
        if let winnerDid, let label = copy["awarded_to"] {
            out.append((label, resolve(winnerDid)))
        }
        if let price = fields["act-price"], let label = copy["price"] {
            out.append((label, price))
        }
        if let bid = fields["act-bid"], let label = copy["bid"] {
            out.append((label, bid))
        }
        if let d = fields["act-deadline"], let t = time(d), let label = copy["deadline"] {
            out.append((label, t))
        }
        if let d = fields["act-bid-deadline"], let t = time(d), let label = copy["bid_deadline"] {
            out.append((label, t))
        }
        if let caps = fields["act-caps"], let label = copy["caps"] {
            out.append((label, caps))
        }
        if let note = fields["act-note"], let label = copy["note"] {
            out.append((label, note))
        }
        if let ctx = fields["act-ctx"], let label = copy["ctx"] {
            out.append((label, ctx))
        }
        // The hash is what the signature covers, so it rides along for anyone
        // checking the bytes they fetched.
        if let hash = fields["act-ctx-h"], let label = copy["ctx_h"] {
            out.append((label, hash))
        }
        // `act-pay-to` may be a DID or a plain payment address, so only a DID
        // goes through the resolver; anything else is shown exactly as sent.
        if let payTo = fields["act-pay-to"], let label = copy["pay_to"] {
            out.append((label, payTo.hasPrefix("did:") ? resolve(payTo) : payTo))
        }
        if let tx = fields["act-tx"], let label = copy["tx"] {
            out.append((label, tx))
        }
        if let replaces = fields["act-replaces"], let label = copy["replaces"] {
            out.append((label, replaces))
        }
        if let scope = fields["act-scope"], let label = copy["scope"] {
            out.append((label, scope))
        }
        return out
    }

    /// The label the context row carries, so a renderer can draw that one value
    /// as a link without holding the word itself.
    static var ctxLabel: String { copy["ctx"] ?? "" }

    /// The `act-*` fields the card labels or consumes structurally.
    private static let known: Set<String> = [
        "act", "act-verb", "act-id", "act-title", "act-to", "act-note", "act-ctx", "act-ctx-h",
        "act-deadline", "act-bid-deadline", "act-caps", "act-price", "act-bid",
        "act-accepts", "act-subject", "act-pay-to", "act-tx", "act-replaces", "act-scope",
    ]

    /// Fields the card has no label for, under their raw keys — the
    /// unknown-verb law's sibling. Sorted by key: a Swift dictionary keeps no
    /// arrival order to preserve.
    static func unknownFields(_ fields: [String: String]) -> [(String, String)] {
        fields
            .filter { $0.key.hasPrefix("act-") && !known.contains($0.key) }
            .map { (String($0.key.dropFirst("act-".count)), $0.value) }
            .sorted { $0.0 < $1.0 }
    }
}
